//! The venture's billing module (issue #177, ADR 0202): one paid plan sold
//! through Polar as Merchant of Record. Accounts are auth subjects — checkout
//! and portal take the account from the verified caller, never the body — and
//! no event ever deletes a row; disputes flag only, until lost, via the
//! hourly poll (Polar sends no dispute webhooks).

mod map;

use std::sync::Arc;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use cratefield_adapter_polar::CustomerIds;
use cratefield_core::axum::body::Bytes;
use cratefield_core::axum::extract::State;
use cratefield_core::axum::http::{HeaderMap, StatusCode};
use cratefield_core::axum::response::{IntoResponse, Response};
use cratefield_core::axum::routing::post;
use cratefield_core::axum::{Json, Router};
use cratefield_core::billing::{
    Environment, LifecyclePolicy, PeriodType, Status, SubscriptionState, Transition, gives_access,
    transition,
};
use cratefield_core::{
    Action, AnyError, Auth, AuthError, BoxFuture, Clock, Config, ConfigError, Database, DbError,
    Dispute, DisputeListRequest, DisputePhase, Inbox, Migrations, Module, ModuleContext, Payments,
    PaymentsError, Port, Problem, ProblemDef, RoutePolicy, Row, SLUGS, SqlMigration, Statement,
    Surface, SystemClock,
};

/// The hourly cron the dispute poll runs on (`wrangler.toml` wires it).
pub const DISPUTE_POLL_CRON: &str = "0 * * * *";

/// One poll walks at most this many dispute pages.
const MAX_DISPUTE_PAGES: usize = 5;

/// 409 for a lost optimistic race: the row moved between the event's read
/// and its write, nothing committed, and Polar's redelivery lands on the
/// state that won.
const STATE_MOVED: ProblemDef = ProblemDef {
    slug: "billing-state-moved",
    status: StatusCode::CONFLICT,
    title: "the billing state changed mid-flight",
    description: "A billing event lost an optimistic-concurrency race and must be redelivered.",
};

/// How storing one event went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stored {
    /// Committed: the claim, the row and the audit row are in.
    Applied,
    /// A duplicate delivery, a stale event, or one that cannot apply.
    Duplicate,
    /// The optimistic write lost a race and committed nothing — not even its
    /// claim — so the delivery should come back and land on what won.
    Conflict,
}

/// The billing module, mounted at `/v1/billing`.
#[derive(Debug, Default, Clone, Copy)]
pub struct Billing;

impl Billing {
    /// The plan `account_id` is on at `now`. A database error is an `Err`,
    /// never a silent [`Plan::Free`].
    pub async fn plan(
        &self,
        db: &dyn Database,
        account_id: &str,
        now: OffsetDateTime,
    ) -> Result<Plan, DbError> {
        let (state, _) = snapshot(db, account_id).await?;
        Ok(entitlements(state.as_ref(), now))
    }
}

/// Free or paid — the whole plan vocabulary of this venture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    Free,
    Paid,
}

/// The pure judgement the venture owns: a stored state, a moment, a plan.
#[must_use]
pub fn entitlements(state: Option<&SubscriptionState>, now: OffsetDateTime) -> Plan {
    match state {
        Some(state) if gives_access(state, now) => Plan::Paid,
        _ => Plan::Free,
    }
}

struct ModuleState {
    ctx: ModuleContext,
}

fn environment_of(config: &dyn Config) -> Environment {
    match config.get("POLAR_ENVIRONMENT") {
        Some(value) if value.eq_ignore_ascii_case("production") => Environment::Production,
        _ => Environment::Sandbox,
    }
}

impl Module for Billing {
    fn name(&self) -> &'static str {
        "billing"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::Db, Port::Payments]
    }

    fn optional(&self) -> &'static [Port] {
        &[Port::Auth, Port::Clock]
    }

    fn tables(&self) -> &'static [&'static str] {
        &["billing_accounts", "billing_audit", "billing_inbox"]
    }

    fn migrations(&self) -> Migrations {
        // `migrations/0007_billing_init.sql`, embedded: wrangler numbering is
        // 0007, the module's own set starts at 0001.
        const MIGRATIONS: [SqlMigration; 1] = [SqlMigration::new(
            "0001",
            "init",
            include_str!("../../migrations/0007_billing_init.sql"),
        )];
        const _: () = cratefield_core::assert_migration_set(&MIGRATIONS);
        Migrations { sqlite: &MIGRATIONS, postgres: &[] }
    }

    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        let mut error = ConfigError::new();
        for key in ["POLAR_ENVIRONMENT", "POLAR_PRODUCT_ANNUAL", "POLAR_PRODUCT_MONTHLY"] {
            if let Some(value) = cfg.get(key)
                && value.trim().is_empty()
            {
                error.push(format!("billing config {key} is set but blank"));
            }
        }
        if let Some(environment) = cfg.get("POLAR_ENVIRONMENT")
            && !environment.trim().is_empty()
            && !matches!(environment.trim(), "production" | "sandbox")
        {
            error.push(format!(
                "billing config POLAR_ENVIRONMENT is {environment:?}; expected \"production\" or \"sandbox\""
            ));
        }
        if error.is_empty() { Ok(()) } else { Err(error) }
    }

    fn router(&self, ctx: ModuleContext) -> Router {
        let state = Arc::new(ModuleState { ctx });
        Router::new()
            .route("/webhook", post(webhook))
            .route("/checkout", post(checkout))
            .route("/portal", post(portal))
            .with_state(state)
    }

    fn surface(&self) -> Surface {
        Surface::new()
            .action(Action::post("webhook", "/webhook").policy(RoutePolicy::Signature))
            .action(Action::post("checkout", "/checkout"))
            .action(Action::post("portal", "/portal"))
    }

    fn scheduled<'a>(
        &'a self,
        ctx: &'a ModuleContext,
        cron: &'a str,
    ) -> BoxFuture<'a, Result<(), AnyError>> {
        Box::pin(async move {
            if cron == DISPUTE_POLL_CRON { poll_disputes(ctx).await } else { Ok(()) }
        })
    }
}

/// `POST /v1/billing/webhook`: verify the Standard Webhooks signature, map
/// what this venture has use for onto the lifecycle, and fold each event
/// through `transition` in one atomic batch. Anything unmapped is a quiet
/// `200` — a `500` only buys endless retries.
async fn webhook(
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(payments) = state.ctx.ports.payments.clone() else {
        return Problem::not_ready("billing is not configured").into_response();
    };
    let event = match payments.verify_webhook_request(&headers, body.as_ref()).await {
        Ok(event) => event,
        Err(error) => return payments_problem(&error),
    };
    let Some(db) = state.ctx.ports.db.clone() else {
        return Problem::not_ready("the database is missing").into_response();
    };
    let now = now_of(&state.ctx);
    let stamp = iso(now);
    let environment = environment_of(&*state.ctx.ports.config);
    let mut applied = 0usize;
    for polar in cratefield_adapter_polar::normalize(&event, CustomerIds::External) {
        let outcome = if let Some(order) = map::paid_order(&polar) {
            let Some(account) = account_for(
                &*db,
                order.account_id.as_deref(),
                order.subscription_id.as_deref(),
                Some(&order.order_id),
            )
            .await
            else {
                tracing::info!(event_id = %event.id, "billing event for an unknown account");
                continue;
            };
            let key = format!("{}:order.paid", event.id);
            record_order(&*db, &account, &order, &key, &stamp, now).await
        } else {
            let Some(mapped) = map::to_lifecycle(&polar, &event, environment, now) else {
                continue;
            };
            let Some(account) = account_for(
                &*db,
                mapped.account_id.as_deref(),
                mapped.subscription_id.as_deref(),
                mapped.order_id.as_deref(),
            )
            .await
            else {
                tracing::info!(event_id = %event.id, "billing event for an unknown account");
                continue;
            };
            let key = mapped.dedup_key(&event.id);
            apply(&*db, &account, &mapped, None, &key, &stamp, now).await
        };
        match outcome {
            Ok(Stored::Applied) => applied += 1,
            Ok(Stored::Duplicate) => {}
            Ok(Stored::Conflict) => return Problem::new(&STATE_MOVED).into_response(),
            Err(error) => {
                tracing::warn!(error = %error, event_id = %event.id, "a billing event could not be stored");
                return Problem::internal().into_response();
            }
        }
    }
    Json(serde_json::json!({ "ok": true, "applied": applied })).into_response()
}

/// `POST /v1/billing/checkout` `{"interval":"annual"|"monthly"}` — annual by
/// default; the account is the verified caller's, never the body's.
async fn checkout(
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (account, payments) = match caller_and_payments(&state, &headers).await {
        Ok(both) => both,
        Err(response) => return response,
    };
    let asked = serde_json::from_slice::<serde_json::Value>(&body).ok();
    let interval = if asked
        .as_ref()
        .and_then(|value| value.get("interval"))
        .and_then(serde_json::Value::as_str)
        == Some("monthly")
    {
        "monthly"
    } else {
        "annual"
    };
    let product_key =
        if interval == "monthly" { "POLAR_PRODUCT_MONTHLY" } else { "POLAR_PRODUCT_ANNUAL" };
    let Some(product) = state.ctx.ports.config.get(product_key).filter(|id| !id.trim().is_empty())
    else {
        return Problem::not_ready(format!(
            "billing is not on sale ({product_key} is not configured)"
        ))
        .into_response();
    };
    let base = &state.ctx.venture.public_url;
    let request = cratefield_core::SubscriptionCheckoutRequest {
        customer_ref: Some(account.clone()),
        customer_email: None,
        price_ref: product,
        trial_days: None,
        success_url: format!("{base}/billing/welcome"),
        cancel_url: format!("{base}/billing"),
        metadata: [("account_id".to_owned(), account.clone())].into_iter().collect(),
        // Rotating like the portal key: an expired session URL is not
        // replayed forever.
        idempotency_key: format!(
            "checkout:{account}:{interval}:{}",
            now_of(&state.ctx).unix_timestamp()
        ),
    };
    match payments.create_subscription_checkout(&request).await {
        Ok(session) => {
            Json(serde_json::json!({ "url": session.url, "interval": interval })).into_response()
        }
        Err(error) => payments_problem(&error),
    }
}

/// `POST /v1/billing/portal`: Polar's hosted portal URL for the caller.
async fn portal(State(state): State<Arc<ModuleState>>, headers: HeaderMap) -> Response {
    let (account, payments) = match caller_and_payments(&state, &headers).await {
        Ok(both) => both,
        Err(response) => return response,
    };
    let base = &state.ctx.venture.public_url;
    let request = cratefield_core::PortalSessionRequest {
        customer_ref: account.clone(),
        return_url: format!("{base}/billing"),
        idempotency_key: format!("portal:{}:{}", account, now_of(&state.ctx).unix_timestamp()),
    };
    match payments.create_portal_session(&request).await {
        Ok(session) => Json(serde_json::json!({ "url": session.url })).into_response(),
        Err(error) => payments_problem(&error),
    }
}

#[expect(
    clippy::result_large_err,
    reason = "a `Problem` response is the error type across every handler; boxing it \
              would cost an allocation on each refusal for no gain"
)]
async fn caller_and_payments(
    state: &ModuleState,
    headers: &HeaderMap,
) -> Result<(String, Arc<dyn Payments>), Response> {
    let account = account_of(state, headers).await?;
    let payments = state
        .ctx
        .ports
        .payments
        .clone()
        .ok_or_else(|| Problem::not_ready("billing is not configured").into_response())?;
    Ok((account, payments))
}

#[expect(
    clippy::result_large_err,
    reason = "a `Problem` response is the error type across every handler; boxing it \
              would cost an allocation on each refusal for no gain"
)]
async fn account_of(state: &ModuleState, headers: &HeaderMap) -> Result<String, Response> {
    // No auth port is the deployment's misconfiguration (503); an anonymous
    // caller's is their 401; an unreachable provider is no reason to bill
    // anonymously (503).
    let Some(auth) = state.ctx.ports.auth.clone() else {
        return Err(Problem::not_ready(
            "billing needs an identity provider to name an account (no auth port is wired)",
        )
        .into_response());
    };
    match auth.identify(headers).await {
        Ok(caller) => caller.id().map_or_else(|| Err(unauthenticated()), |id| Ok(id.to_owned())),
        Err(AuthError::Unavailable(detail)) => {
            tracing::warn!(%detail, "the identity provider could not be reached");
            Err(Problem::not_ready("the identity provider is unavailable").into_response())
        }
        Err(AuthError::NotVerified) | Err(_) => Err(unauthenticated()),
    }
}

fn unauthenticated() -> Response {
    Problem::new(&SLUGS.unauthenticated).into_response()
}

/// A bad signature is the caller's 400, everything else the deployment's
/// 503; upstream detail hits the log, never the response.
fn payments_problem(error: &PaymentsError) -> Response {
    match error {
        PaymentsError::SignatureInvalid(detail) => {
            tracing::warn!(%detail, "a billing webhook signature was refused");
            Problem::validation_failed("webhook signature verification failed").into_response()
        }
        other => {
            tracing::warn!(error = %other, "a billing request failed");
            Problem::not_ready("billing is not available").into_response()
        }
    }
}

/// The dispute poll (`scheduled`, hourly): open, won and lost are read from
/// `list_disputes` — a bounded page walk, open steps before terminal ones.
async fn poll_disputes(ctx: &ModuleContext) -> Result<(), AnyError> {
    let (Some(payments), Some(db)) = (ctx.ports.payments.clone(), ctx.ports.db.clone()) else {
        return Ok(());
    };
    let now = now_of(ctx);
    let stamp = iso(now);
    let environment = environment_of(&*ctx.ports.config);
    let mut cursor = None;
    for _ in 0..MAX_DISPUTE_PAGES {
        if ctx.scheduled.exhausted(now) {
            break;
        }
        let page = match payments
            .list_disputes(&DisputeListRequest { open_only: false, cursor: cursor.clone() })
            .await
        {
            Ok(page) => page,
            Err(PaymentsError::NotConfigured) => break,
            Err(error) => {
                tracing::warn!(error = %error, "the dispute poll failed");
                break;
            }
        };
        let mut steps: Vec<&Dispute> = page.disputes.iter().collect();
        steps.sort_by_key(|dispute| !matches!(dispute.status.phase(), DisputePhase::Open));
        for dispute in steps {
            if ctx.scheduled.exhausted(now) {
                break;
            }
            let Some(account) = account_for(
                &*db,
                dispute.customer_ref.as_deref(),
                None,
                Some(&dispute.payment_ref),
            )
            .await
            else {
                tracing::info!(dispute = %dispute.id, "a polled dispute for an unknown account");
                continue;
            };
            let mapped = map::dispute_lifecycle(dispute, environment, now);
            let disputed = matches!(dispute.status.phase(), DisputePhase::Open);
            match apply(
                &*db,
                &account,
                &mapped,
                Some(disputed),
                &mapped.event.event_id,
                &stamp,
                now,
            )
            .await
            {
                Ok(Stored::Conflict) => {
                    tracing::info!(dispute = %dispute.id, "a dispute step lost a race; the next poll retries")
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(error = %error, dispute = %dispute.id, "a dispute step could not be stored")
                }
            }
        }
        cursor = page.next;
        if cursor.is_none() {
            break;
        }
    }
    Ok(())
}

/// Folds one lifecycle event into an account: the Inbox claim, the
/// conditional row write and the audit row commit together or not at all.
async fn apply(
    db: &dyn Database,
    account_id: &str,
    mapped: &map::Mapped,
    disputed: Option<bool>,
    key: &str,
    stamp: &str,
    now: OffsetDateTime,
) -> Result<Stored, DbError> {
    let (prior, version) = snapshot(db, account_id).await?;
    let next = match transition(prior.as_ref(), &mapped.event, &LifecyclePolicy::default()) {
        Transition::Apply(next) => next,
        Transition::IgnoreStale => return Ok(Stored::Duplicate),
        Transition::Invalid(reason) => {
            tracing::info!(account_id, key, reason, "a billing event cannot apply");
            return Ok(Stored::Duplicate);
        }
    };
    let before = entitlements(prior.as_ref(), now);
    let after = entitlements(Some(&next), now);
    commit(
        db,
        key,
        stamp,
        state_upsert(account_id, mapped, &next, disputed, key, stamp, version),
        audit(key, account_id, &map::kind_label(&mapped.event.kind), before, after, stamp),
    )
    .await
}

/// An `order.paid` keeps the order id a dispute resolves by, and its audit
/// row records the plan it found — changed by nothing.
async fn record_order(
    db: &dyn Database,
    account_id: &str,
    order: &map::PaidOrder,
    key: &str,
    stamp: &str,
    now: OffsetDateTime,
) -> Result<Stored, DbError> {
    let (prior, version) = snapshot(db, account_id).await?;
    let plan = entitlements(prior.as_ref(), now);
    commit(
        db,
        key,
        stamp,
        order_upsert(account_id, order, key, stamp, version),
        audit(key, account_id, "order.paid", plan, plan, stamp),
    )
    .await
}

/// Claims the key and applies the write in one atomic batch — then reads
/// back whether the optimistic write won. A loser's batch unclaims its own
/// key (`unclaim_if_lost`), so a lost race commits nothing at all and the
/// caller answers 409 for Polar to redeliver onto the state that won.
async fn commit(
    db: &dyn Database,
    key: &str,
    stamp: &str,
    write: Statement,
    audit_row: Statement,
) -> Result<Stored, DbError> {
    let inbox = Inbox::new("billing_inbox");
    let effect = [write, audit_row, unclaim_if_lost(key)];
    match inbox.claim_with(db, key, stamp, &effect).await? {
        false => Ok(Stored::Duplicate),
        true if inbox.seen(db, key).await? => Ok(Stored::Applied),
        _ => Ok(Stored::Conflict),
    }
}

/// Whose account an event is about: the checkout's external customer id
/// first, else the ids earlier webhooks kept on the row.
async fn account_for(
    db: &dyn Database,
    account: Option<&str>,
    subscription_id: Option<&str>,
    order_id: Option<&str>,
) -> Option<String> {
    if let Some(account) = account {
        return Some(account.to_owned());
    }
    for (column, value) in [("subscription_id", subscription_id), ("last_order_id", order_id)] {
        let Some(value) = value else { continue };
        let Ok(rows) = db
            .query(&Statement::with_values(
                format!("SELECT account_id FROM billing_accounts WHERE {column} = ? LIMIT 1"),
                vec![value.into()],
            ))
            .await
        else {
            continue;
        };
        if let Some(found) = rows.first().and_then(|row| row.get::<String>("account_id")) {
            return Some(found);
        }
    }
    None
}

/// The stored state with the `version` an optimistic write must match;
/// `None` state is the row's life before its first lifecycle event.
async fn snapshot(
    db: &dyn Database,
    account_id: &str,
) -> Result<(Option<SubscriptionState>, i64), DbError> {
    let rows = db
        .query(&Statement::with_values(
            "SELECT status, period_type, renews, access_until, last_event_at, revoked, version \
             FROM billing_accounts WHERE account_id = ?",
            vec![account_id.into()],
        ))
        .await?;
    let row = rows.first();
    Ok((row.and_then(state_of), row.and_then(|row| row.get::<i64>("version")).unwrap_or(0)))
}

fn state_of(row: &Row) -> Option<SubscriptionState> {
    let at =
        |text: Option<String>| text.and_then(|text| OffsetDateTime::parse(&text, &Rfc3339).ok());
    Some(SubscriptionState {
        status: status_of(&row.get::<String>("status")?),
        period_type: period_type_of(
            &row.get::<String>("period_type").unwrap_or_else(|| "normal".into()),
        ),
        renews: row.get::<i64>("renews").unwrap_or(0) != 0,
        access_until: at(row.get::<String>("access_until")),
        pending_product: None,
        last_event_at: at(Some(row.get::<String>("last_event_at")?))?,
        revoked: row.get::<i64>("revoked").unwrap_or(0) != 0,
    })
}

/// The lifecycle write: a conditional upsert whose `WHERE version = ?` is
/// the compare-and-swap. Columns the event did not carry are COALESCEd
/// against what is stored; the dispute flag is passed only by dispute
/// steps; the winner marks the row with its key. Nothing here deletes.
fn state_upsert(
    account_id: &str,
    mapped: &map::Mapped,
    state: &SubscriptionState,
    disputed: Option<bool>,
    key: &str,
    stamp: &str,
    version: i64,
) -> Statement {
    Statement::with_values(
        "INSERT INTO billing_accounts \
           (account_id, subscription_id, last_order_id, product_id, status, period_type, \
            renews, access_until, last_event_at, revoked, disputed, version, last_event_id, \
            updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, 0), 1, ?, ?) \
         ON CONFLICT(account_id) DO UPDATE SET \
           subscription_id = COALESCE(excluded.subscription_id, billing_accounts.subscription_id), \
           last_order_id = COALESCE(excluded.last_order_id, billing_accounts.last_order_id), \
           product_id = COALESCE(excluded.product_id, billing_accounts.product_id), \
           status = excluded.status, period_type = excluded.period_type, renews = excluded.renews, \
           access_until = excluded.access_until, last_event_at = excluded.last_event_at, \
           revoked = excluded.revoked, \
           disputed = COALESCE(excluded.disputed, billing_accounts.disputed), \
           version = billing_accounts.version + 1, last_event_id = excluded.last_event_id, \
           updated_at = excluded.updated_at \
         WHERE billing_accounts.version = ?",
        vec![
            account_id.into(),
            mapped.subscription_id.clone().into(),
            mapped.order_id.clone().into(),
            mapped.product_id.clone().into(),
            status_name(state.status).into(),
            period_type_name(state.period_type).into(),
            i64::from(state.renews).into(),
            state.access_until.map(iso).into(),
            iso(state.last_event_at).into(),
            i64::from(state.revoked).into(),
            disputed.map(i64::from).into(),
            key.into(),
            stamp.into(),
            version.into(),
        ],
    )
}

/// The identity write an `order.paid` is: the order id, the subscription it
/// belongs to, nothing else — the plan columns are not touched.
fn order_upsert(
    account_id: &str,
    order: &map::PaidOrder,
    key: &str,
    stamp: &str,
    version: i64,
) -> Statement {
    Statement::with_values(
        "INSERT INTO billing_accounts \
           (account_id, subscription_id, last_order_id, status, period_type, renews, revoked, \
            disputed, last_event_at, version, last_event_id, updated_at) \
         VALUES (?, ?, ?, 'incomplete', 'normal', 0, 0, 0, ?, 1, ?, ?) \
         ON CONFLICT(account_id) DO UPDATE SET \
           last_order_id = excluded.last_order_id, \
           subscription_id = COALESCE(excluded.subscription_id, billing_accounts.subscription_id), \
           version = billing_accounts.version + 1, last_event_id = excluded.last_event_id, \
           updated_at = excluded.updated_at \
         WHERE billing_accounts.version = ?",
        vec![
            account_id.into(),
            order.subscription_id.clone().into(),
            order.order_id.clone().into(),
            stamp.into(),
            key.into(),
            stamp.into(),
            version.into(),
        ],
    )
}

/// The audit row — guarded by the winner's mark, so it exists exactly when
/// this event's write won the race and the trail never lies.
fn audit(
    key: &str,
    account_id: &str,
    kind: &str,
    before: Plan,
    after: Plan,
    stamp: &str,
) -> Statement {
    let name = |plan: Plan| if matches!(plan, Plan::Paid) { "paid" } else { "free" };
    Statement::with_values(
        "INSERT INTO billing_audit (id, account_id, source, kind, plan_before, plan_after, at) \
         SELECT ?, ?, ?, ?, ?, ?, ? \
         WHERE EXISTS (SELECT 1 FROM billing_accounts WHERE account_id = ? AND last_event_id = ?)",
        vec![
            key.into(),
            account_id.into(),
            key.into(),
            kind.into(),
            name(before).into(),
            name(after).into(),
            stamp.into(),
            account_id.into(),
            key.into(),
        ],
    )
}

/// Undoes this batch's own claim when the write lost the race (no audit row
/// under the key): the key stays free for Polar's redelivery to re-run.
fn unclaim_if_lost(key: &str) -> Statement {
    Statement::with_values(
        "DELETE FROM billing_inbox WHERE event_key = ? \
         AND NOT EXISTS (SELECT 1 FROM billing_audit WHERE id = ?)",
        vec![key.into(), key.into()],
    )
}

/// The `status`/`period_type` storage vocabulary, both directions.
const STATUSES: &[(&str, Status)] = &[
    ("incomplete", Status::Incomplete),
    ("active", Status::Active),
    ("grace", Status::InGracePeriod),
    ("retry", Status::InBillingRetry),
    ("paused", Status::Paused),
    ("expired", Status::Expired),
    ("revoked", Status::Revoked),
];

const PERIOD_TYPES: &[(&str, PeriodType)] = &[
    ("normal", PeriodType::Normal),
    ("trial", PeriodType::Trial),
    ("intro", PeriodType::Intro),
    ("promotional", PeriodType::Promotional),
    ("prepaid", PeriodType::Prepaid),
];

fn status_name(status: Status) -> &'static str {
    STATUSES.iter().find(|&&(_, named)| named == status).map_or("incomplete", |&(name, _)| name)
}

fn status_of(name: &str) -> Status {
    STATUSES
        .iter()
        .find(|&&(stored, _)| stored == name)
        .map_or(Status::Incomplete, |&(_, status)| status)
}

fn period_type_name(period_type: PeriodType) -> &'static str {
    PERIOD_TYPES
        .iter()
        .find(|&&(_, named)| named == period_type)
        .map_or("normal", |&(name, _)| name)
}

fn period_type_of(name: &str) -> PeriodType {
    PERIOD_TYPES
        .iter()
        .find(|&&(stored, _)| stored == name)
        .map_or(PeriodType::Normal, |&(_, period)| period)
}

fn now_of(ctx: &ModuleContext) -> OffsetDateTime {
    match ctx.ports.clock.as_ref() {
        Some(clock) => clock.now(),
        None => SystemClock.now(),
    }
}

/// RFC 3339 for storage: whole seconds, UTC (`Z`).
fn iso(at: OffsetDateTime) -> String {
    at.replace_nanosecond(0)
        .unwrap_or(at)
        .format(&Rfc3339)
        .unwrap_or_else(|_| at.unix_timestamp().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_adapter_sqlite::SqliteDatabase;
    use serde_json::json;
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-10-09 08:00 UTC);
    const KEY: &str = "evt_9:subscription.active";

    fn db() -> Arc<SqliteDatabase> {
        let db = Arc::new(SqliteDatabase::in_memory().expect("in-memory sqlite"));
        db.apply_migrations("billing", Billing.migrations().sqlite)
            .expect("the billing migrations apply");
        db
    }

    async fn seeded(db: &SqliteDatabase, version: i64) {
        db.execute(&Statement::with_values(
            "INSERT INTO billing_accounts (account_id, status, last_event_at, version, updated_at) \
             VALUES (?, 'revoked', '2026-10-01T00:00:00Z', ?, '2026-10-01T00:00:00Z')",
            vec!["acc_1".into(), version.into()],
        ))
        .await
        .unwrap_or_else(|error| panic!("the seed writes: {error}"));
    }

    /// The write a `subscription.active` for acc_1 makes, at `version` —
    /// mapped through the adapter's own normalizer, the delivery path.
    fn started(version: i64) -> Statement {
        let event = cratefield_core::WebhookEvent {
            id: "evt_9".to_owned(),
            kind: "subscription.active".to_owned(),
            data: json!({
                "id": "sub_1", "status": "active", "product_id": "prod_annual",
                "customer_id": "cus_1", "cancel_at_period_end": false,
                "customer": { "id": "cus_1", "external_id": "acc_1" }
            }),
        };
        let mapped = cratefield_adapter_polar::normalize(&event, CustomerIds::External)
            .into_iter()
            .find_map(|polar| map::to_lifecycle(&polar, &event, Environment::Sandbox, NOW))
            .expect("an active subscription maps");
        let next = match transition(None, &mapped.event, &LifecyclePolicy::default()) {
            Transition::Apply(next) => next,
            Transition::IgnoreStale | Transition::Invalid(_) => {
                panic!("a start applies to a fresh account")
            }
        };
        state_upsert("acc_1", &mapped, &next, None, KEY, "stamp", version)
    }

    fn audit_row() -> Statement {
        audit(KEY, "acc_1", "subscription.started", Plan::Free, Plan::Paid, "stamp")
    }

    #[pollster::test]
    async fn a_stale_version_write_commits_nothing() {
        let db = db();
        seeded(&db, 3).await;
        // Version 2 is stale: another delivery moved the row first.
        let outcome =
            commit(&*db, KEY, "stamp", started(2), audit_row()).await.expect("the commit answers");
        assert_eq!(outcome, Stored::Conflict);
        // Nothing committed — no audit row, and the Inbox key is free again,
        // so Polar's redelivery re-runs the whole event on the winner's state.
        assert_eq!(count_of(&db, "SELECT COUNT(*) AS n FROM billing_audit"), 0);
        assert_eq!(count_of(&db, "SELECT COUNT(*) AS n FROM billing_inbox"), 0);
        assert_eq!(
            count_of(&db, "SELECT COUNT(*) AS n FROM billing_accounts WHERE version = 3"),
            1,
            "the winner's row is untouched"
        );
    }

    #[pollster::test]
    async fn a_fresh_version_write_commits_and_a_replay_does_not() {
        let db = db();
        seeded(&db, 3).await;
        let outcome =
            commit(&*db, KEY, "stamp", started(3), audit_row()).await.expect("the commit answers");
        assert_eq!(outcome, Stored::Applied);
        assert_eq!(count_of(&db, "SELECT COUNT(*) AS n FROM billing_audit"), 1);
        assert_eq!(count_of(&db, "SELECT COUNT(*) AS n FROM billing_inbox"), 1);
        assert_eq!(
            count_of(
                &db,
                "SELECT COUNT(*) AS n FROM billing_accounts WHERE version = 4 AND last_event_id = 'evt_9:subscription.active'"
            ),
            1,
            "the version bumped and the row carries the winner's key"
        );

        // The same event again: a duplicate, writing nothing twice.
        let replay =
            commit(&*db, KEY, "stamp", started(4), audit_row()).await.expect("the replay answers");
        assert_eq!(replay, Stored::Duplicate);
        assert_eq!(count_of(&db, "SELECT COUNT(*) AS n FROM billing_audit"), 1);
    }

    fn count_of(db: &SqliteDatabase, sql: &str) -> i64 {
        let rows =
            pollster::block_on(db.query(&Statement::new(sql.to_owned()))).expect("the count reads");
        rows.first().and_then(|row| row.get::<i64>("n")).unwrap_or(0)
    }
}
