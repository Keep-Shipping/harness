//! Edit as code (issue #170): console forms whose submit is a Terraform
//! pull request. A signed-in person fills a plain-words form; the module
//! turns it into one HCL file in the infra repository's per-zone module,
//! opens a pull request through the outbox, and the repository's workflow
//! plans the change and posts the plan back. A person reads the plan on the
//! edit's page — removals and replacements make them type the zone's name —
//! and approval fires a `repository_dispatch` so the same workflow applies
//! the exact plan file that was checked. The console never calls the
//! Cloudflare API to mutate anything: the pull request is the only write.
//!
//! Everything here rides ports the venture already composes (Db, HttpClient,
//! Clock) plus Auth, IdGen and Defer when present — the runtime may wire no
//! auth provider, so a missing Auth port is a 503 page and an anonymous
//! caller a 401 page, not a boot failure. The plan callback authenticates a
//! machine instead: a runner token compared in constant time.

mod change;
mod github;
mod page;

use crate::edits::change::PlanView;
use cratefield_core::axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, RawQuery, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use cratefield_core::{
    AnyError, Auth, AuthError, BoxFuture, Clock, Config, ConfigError, DataKind, Database, DbError,
    Disposition, DrainOptions, DrainReport, HttpClient, Migrations, Module, ModuleConfig,
    ModuleContext, Outbox, OutboxRecord, PersonalDataSet, Port, Problem, ProblemDef, Processed,
    Row, SLUGS, ScheduledBudget, SqlMigration, Statement, SystemClock, bearer_token,
    constant_time_eq,
};
use serde_json::{Value, json};
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// The edit-as-code module, mounted at `/v1/edits`.
pub struct Edits;

impl Edits {
    const NAME: &'static str = "edits";
}

/// The module's outbox table (its DDL lives in this module's migrations).
const OUTBOX_TABLE: &str = "edits_outbox";

/// Outbox topics: open the pull request, then fire the approval dispatch.
const TOPIC_OPEN_PR: &str = "github.open_pr";
const TOPIC_DISPATCH: &str = "github.repository_dispatch";

/// The `repository_dispatch` event type the infra workflow filters on.
pub(crate) const EVENT_TYPE: &str = "keepshipping-edit-approved";

/// Branch prefix for an edit's pull request: `ks-edit/<id>`.
const BRANCH_PREFIX: &str = "ks-edit";

/// The plan callback body ceiling (`tofu show -json` of a zone-sized plan).
const PLAN_BODY_LIMIT: usize = 512 * 1024;

/// The module's body ceiling: the plan callback plus form headroom.
const MAX_BODY: usize = PLAN_BODY_LIMIT + 64 * 1024;

/// Deliveries before an outbox row's failure marks the edit failed.
const MAX_ATTEMPTS: i64 = 12;

static MIGRATIONS: [SqlMigration; 1] =
    [SqlMigration::new("0001", "init", include_str!("migrations/0001_init.sql"))];
const _: () = cratefield_core::assert_migration_set(&MIGRATIONS);

/// A plan callback refused because the edit already carries an approval:
/// after approval the plan is frozen, so a late callback must not move it.
const ALREADY_APPROVED: ProblemDef = ProblemDef {
    slug: "edit-already-approved",
    status: StatusCode::CONFLICT,
    title: "this edit is already approved",
    description: "A plan callback arrived for an edit whose plan was already approved.",
};

/// A plan callback body over the ceiling.
const PLAN_TOO_LARGE: ProblemDef = ProblemDef {
    slug: "edit-plan-too-large",
    status: StatusCode::PAYLOAD_TOO_LARGE,
    title: "the plan is too large to store",
    description: "The plan callback body exceeded the module's plan ceiling.",
};

/// What the module holds about a person, declared once.
static PERSONAL_DATA: [PersonalDataSet; 2] = [
    PersonalDataSet {
        table: "edits",
        subject: "author",
        kind: DataKind::Identifier,
        disposition: Disposition::Retain(
            "the row is the audit trail of what was changed in the infrastructure and by \
             whom; it cannot be erased without falsifying the record",
        ),
        description: "who asked for this change",
        redacted: &[],
        subject_via: None,
    },
    PersonalDataSet::none("edits_outbox", "queued deliveries name the edit, not a person"),
];

impl Module for Edits {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    /// Db, HttpClient and Clock are what the outbox delivery needs; the rest
    /// degrades honestly: no Auth is a 503 page, no IdGen a derived id, no
    /// Defer just "the cron will deliver it".
    fn requires(&self) -> &'static [Port] {
        &[Port::Db, Port::HttpClient, Port::Clock]
    }

    fn optional(&self) -> &'static [Port] {
        &[Port::Auth, Port::IdGen, Port::Defer]
    }

    fn tables(&self) -> &'static [&'static str] {
        &["edits", "edits_outbox"]
    }

    fn personal_data(&self) -> &'static [PersonalDataSet] {
        &PERSONAL_DATA
    }

    /// Required configuration, reported together: where the pull requests
    /// go (`owner/name`, base branch, infra directory), and the two
    /// secrets — the GitHub token that opens them and the runner token the
    /// CI plan callback must present.
    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        let cfg = ModuleConfig::new(Self::NAME, cfg);
        let mut errors = ConfigError::new();
        let repo = cfg.get_str("REPO", "");
        let (owner, name) = repo.split_once('/').unwrap_or(("", ""));
        if owner.is_empty() || name.is_empty() || repo.contains(char::is_whitespace) {
            errors.push("EDITS_REPO must be `owner/name`, like keepshipping/infra.");
        }
        if cfg.get_str("BASE_BRANCH", "").trim().is_empty() {
            errors
                .push("EDITS_BASE_BRANCH must name the branch pull requests target, usually main.");
        }
        if cfg.get_opt("GITHUB_TOKEN").is_some_and(|token| token.trim().is_empty()) {
            errors.push("EDITS_GITHUB_TOKEN is set but empty; unset it or fill it in.");
        }
        if cfg.get_opt("RUNNER_TOKEN").is_some_and(|token| token.trim().is_empty()) {
            errors.push("EDITS_RUNNER_TOKEN is set but empty; unset it or fill it in.");
        }
        if let Some(base) = cfg.get_opt("GITHUB_API_BASE")
            && !base.starts_with("https://")
            && !base.starts_with("http://")
        {
            errors.push(
                "EDITS_GITHUB_API_BASE must start with https:// (it overrides api.github.com).",
            );
        }
        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }

    fn migrations(&self) -> Migrations {
        Migrations::sqlite(&MIGRATIONS)
    }

    /// The plan callback can carry a whole `tofu show -json` dump, which is
    /// why this module's ceiling is the plan limit plus form headroom rather
    /// than the 64 KiB default.
    fn max_body_bytes(&self, _cfg: &dyn Config) -> usize {
        MAX_BODY
    }

    fn router(&self, ctx: ModuleContext) -> Router {
        Router::new()
            .route("/", get(list_page).post(create))
            .route("/new", get(new_page))
            .route("/{id}", get(detail_page))
            .route("/{id}/plan", post(plan_post))
            .route("/{id}/approve", post(approve))
            .layer(DefaultBodyLimit::max(MAX_BODY))
            .with_state(Arc::new(ctx))
    }

    /// The cron drain: deliver whatever the immediate attempt missed. Any
    /// trigger drains — an extra cron costs a cheap claim query, and a
    /// missed one strands pull requests.
    fn scheduled<'a>(
        &'a self,
        ctx: &'a ModuleContext,
        _cron: &'a str,
    ) -> BoxFuture<'a, Result<(), AnyError>> {
        Box::pin(async move {
            let (Some(db), Some(http)) = (ctx.ports.db.clone(), ctx.ports.http.clone()) else {
                return Ok(());
            };
            let clock = clock_of(ctx);
            drain(Arc::clone(&db), http, Arc::clone(&ctx.config), &*clock, &ctx.scheduled)
                .await
                .map(|_| ())
                .map_err(|error| Box::new(error) as AnyError)
        })
    }
}

// -- shared helpers ----------------------------------------------------------

fn now_of(ctx: &ModuleContext) -> OffsetDateTime {
    ctx.ports.clock.as_ref().map_or_else(|| SystemClock.now(), |clock| clock.now())
}

fn clock_of(ctx: &ModuleContext) -> Arc<dyn Clock> {
    ctx.ports.clock.clone().unwrap_or_else(|| Arc::new(SystemClock))
}

/// An edit id when no IdGen port is wired (the runtime always wires one;
/// this keeps `propose` usable in tests): the clock's nanos, hex.
fn id_of(ctx: &ModuleContext) -> String {
    ctx.ports.id_gen.as_ref().map_or_else(
        || format!("ks{:x}", now_of(ctx).unix_timestamp_nanos().max(0) as u64),
        |id_gen| id_gen.ulid(),
    )
}

/// RFC 3339 for storage: whole seconds, UTC (`Z`).
fn iso(at: OffsetDateTime) -> String {
    at.replace_nanosecond(0)
        .unwrap_or(at)
        .format(&Rfc3339)
        .unwrap_or_else(|_| at.unix_timestamp().to_string())
}

/// Parses `a=1&b=2` (form or query) encoding: `+` is a space, `%XX` a byte.
fn urlencoded(raw: &str) -> Vec<(String, String)> {
    form_urlencoded::parse(raw.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

/// The first value a submitted form carried for `name`.
pub(crate) fn param<'a>(params: &'a [(String, String)], name: &str) -> Option<&'a str> {
    params.iter().find(|(key, _)| key.as_str() == name).map(|(_, value)| value.as_str())
}

fn html(status: StatusCode, body: String) -> Response {
    (status, [(header::CONTENT_TYPE, "text/html; charset=utf-8")], body).into_response()
}

fn col(row: &Row, name: &str) -> String {
    row.get::<String>(name).unwrap_or_default()
}

/// A nullable integer column. The storage port hands integers back typed
/// (so `i64` reads them) and `Option<i64>` is not convertible at all — an
/// integer stored as text is parsed as the fallback.
fn opt_i64(row: &Row, name: &str) -> Option<i64> {
    if let Some(value) = row.get::<i64>(name) {
        return Some(value);
    }
    row.get::<Option<String>>(name).unwrap_or(None).and_then(|value| value.parse().ok())
}

fn opt_col(row: &Row, name: &str) -> Option<String> {
    row.get::<Option<String>>(name).unwrap_or(None).filter(|value| !value.is_empty())
}

/// Who is asking, or the page that says why not: no auth port is a 503
/// ("not ready"), a failed credential or no credential a 401 page. The
/// refusal is `(status, body)` — a full `Response` is too large to carry
/// as an `Err`. `path` is where the caller came from, so the 401 page's
/// sign-in link can lead straight back.
async fn author_of(
    ctx: &ModuleContext,
    headers: &HeaderMap,
    path: &str,
) -> Result<String, (StatusCode, String)> {
    let Some(auth) = ctx.ports.auth.clone() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            page::not_ready("sign-in is not configured for this deployment"),
        ));
    };
    match auth.identify(&session_credentials(headers)).await {
        Ok(caller) => {
            caller.id().filter(|id| !id.is_empty()).map(str::to_owned).ok_or_else(|| {
                (StatusCode::UNAUTHORIZED, page::signed_out(sign_in_link(ctx, path)))
            })
        }
        Err(AuthError::Unavailable(_)) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            page::not_ready("the identity provider is unavailable"),
        )),
        Err(_) => Err((StatusCode::UNAUTHORIZED, page::signed_out(sign_in_link(ctx, path)))),
    }
}

/// The credentials a browser brings: an `Authorization` header when the
/// page's fetch sent one, otherwise the console's session cookie
/// (`ks_console`, set by the console sign-in — the cookie contract in
/// docs/EDIT_AS_CODE.md) as that header. See
/// [`crate::signin::session_credentials`].
fn session_credentials(headers: &HeaderMap) -> HeaderMap {
    crate::signin::session_credentials(headers)
}

/// Where the 401 page should send a signed-out visitor: the console's own
/// sign-in (`/console/login?next=<where they were>`), unless the deployment
/// names another sign-in page (`EDITS_SIGN_IN_URL`, a non-secret var) —
/// then that page plus `return=<where they were>`.
fn sign_in_link(ctx: &ModuleContext, path: &str) -> Option<String> {
    let configured = ModuleConfig::new(Edits::NAME, ctx.config.as_ref()).get_opt("SIGN_IN_URL");
    let Some(base) = configured.as_deref().map(str::trim).filter(|base| !base.is_empty()) else {
        return Some(crate::signin::login_href(path));
    };
    let glue = if base.contains('?') { '&' } else { '?' };
    let back = form_urlencoded::Serializer::new(String::new())
        .append_pair("return", &format!("{}{path}", ctx.venture.public_url))
        .finish();
    Some(format!("{base}{glue}{back}"))
}

fn console_url(ctx: &ModuleContext, id: &str) -> String {
    format!("{}/v1/edits/{id}", ctx.venture.public_url)
}

/// The pull request body: what was asked, who asked, and what happens next.
fn pr_body(author: &str, summary_md: &str, console: &str) -> String {
    format!(
        "## What was asked\n\n{summary_md}\n\nOpened by {author} from the Keep Shipping console: {console}\n\nApplying is a separate, human step — the workflow plans this change and posts the plan to the console, where a person approves it. Approval fires this repository's `{EVENT_TYPE}` dispatch.\n",
    )
}

/// The outbox payload that opens one pull request.
fn pr_payload(
    cfg: &ModuleConfig,
    id: &str,
    zone: &str,
    title: &str,
    body: &str,
    files: &[(String, String)],
) -> String {
    json!({
        "edit_id": id,
        "repo": cfg.get_str("REPO", ""),
        "branch": format!("{BRANCH_PREFIX}/{}", id.to_ascii_lowercase()),
        "base": cfg.get_str("BASE_BRANCH", "main"),
        "title": title,
        "body": body,
        "zone": zone,
        "files": files.iter().map(|(path, content)| json!({"path": path, "content": content})).collect::<Vec<_>>(),
    })
    .to_string()
}

fn insert_edit(change: &change::Change, id: &str, author: &str, now: &str) -> Statement {
    Statement::with_values(
        "INSERT INTO edits (id, kind, zone, title, summary_md, file_path, author, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'opening', ?, ?)",
        vec![
            id.into(),
            change.kind.into(),
            change.zone.clone().into(),
            change.title.clone().into(),
            change.summary_md.clone().into(),
            change.files.first().map_or_else(String::new, |(path, _)| path.clone()).into(),
            author.into(),
            now.into(),
            now.into(),
        ],
    )
}

/// Kicks the outbox through `Defer`, so delivery is immediate when the
/// runtime allows it and the cron catches it when not.
fn deliver_soon(ctx: &ModuleContext) {
    let Some(defer) = ctx.ports.defer.clone() else {
        return;
    };
    let (Some(db), Some(http)) = (ctx.ports.db.clone(), ctx.ports.http.clone()) else {
        return;
    };
    let clock = clock_of(ctx);
    let config = Arc::clone(&ctx.config);
    defer.wait_until(Box::pin(async move {
        let budget = ScheduledBudget::unbounded();
        if let Err(error) = drain(db, http, config, &*clock, &budget).await {
            tracing::warn!(%error, "edits: the immediate delivery failed; the cron will retry");
        }
    }));
}

/// The GitHub tokens one drain pass may use, and the endpoint they go to.
struct Tokens {
    /// `EDITS_GITHUB_TOKEN`, when it is set.
    configured: Option<String>,
    /// The console's own GitHub connection, opened from its stored row.
    stored: Option<String>,
    db: Arc<dyn Database>,
    http: Arc<dyn HttpClient>,
    base: String,
}

impl Tokens {
    /// The personal connection for one record: the configured token, else the
    /// stored one; an onboarding edit's own repository uses the stored one.
    fn personal(&self, own_repository: bool) -> Option<github::GitHub> {
        let token = if own_repository {
            self.stored.clone()
        } else {
            self.configured.clone().or_else(|| self.stored.clone())
        };
        token.map(|token| github::GitHub::new(Arc::clone(&self.http), token, self.base.clone()))
    }

    /// The client for one record and whether it is the app's. The console's
    /// GitHub App goes first when one of its installations covers the
    /// repository. Otherwise, or when the app is not connected, the personal
    /// connection. A record with neither waits and is retried.
    async fn client(
        &self,
        repo: Option<&str>,
        own_repository: bool,
        now: i64,
    ) -> Result<(github::GitHub, bool), github::Failure> {
        if let Some((owner, name)) = repo.and_then(|repo| repo.split_once('/')) {
            let app = crate::github::app::token_for_repo(
                Arc::clone(&self.db),
                &*self.http,
                owner,
                name,
                now,
            )
            .await;
            match app {
                Ok(Some(app)) => {
                    return Ok((
                        github::GitHub::new(Arc::clone(&self.http), app.token, self.base.clone()),
                        true,
                    ));
                }
                Ok(None) => {}
                Err(failed) => tracing::warn!(
                    message = failed.message,
                    "edits: the github app could not be used; trying the stored token"
                ),
            }
        }
        self.personal(own_repository).map(|github| (github, false)).ok_or_else(|| {
            github::Failure::retryable(
                "no GitHub token is connected for this change yet; connect GitHub on the console"
                    .to_owned(),
            )
        })
    }
}

/// One drain pass over the module's outbox: open pull requests and fire
/// approval dispatches, with the approvals module's lease and backoff
/// posture. With neither `EDITS_GITHUB_TOKEN` nor a connected GitHub account
/// there is simply nothing to deliver yet.
async fn drain(
    db: Arc<dyn Database>,
    http: Arc<dyn HttpClient>,
    config: Arc<dyn Config>,
    clock: &dyn Clock,
    budget: &ScheduledBudget,
) -> Result<DrainReport, DbError> {
    let cfg = ModuleConfig::new(Edits::NAME, config.as_ref());
    let configured = cfg.get_opt("GITHUB_TOKEN");
    let legacy_secret = config.get("HARNESS_SECRET");
    let stored = crate::github::stored_token(Arc::clone(&db), legacy_secret.as_deref()).await;
    // The app is a connection too: with it installed there is delivery to do
    // even when no token is configured or stored.
    let app = crate::github::app::app_row(Arc::clone(&db)).await.ok().flatten().is_some();
    if configured.is_none() && stored.is_none() && !app {
        return Ok(cratefield_core::DrainReport::default());
    }
    let tokens = Tokens {
        configured,
        stored,
        db: Arc::clone(&db),
        http,
        base: cfg.get_str("GITHUB_API_BASE", github::API_BASE),
    };
    let db: &dyn Database = db.as_ref();
    Outbox::new(OUTBOX_TABLE)
        .drain_within(
            db,
            clock,
            budget,
            DrainOptions { limit: 10, lease: time::Duration::minutes(5), subrequests_per_item: 12 },
            |record| handle_record(&tokens, db, clock, record),
        )
        .await
}

/// One outbox record's delivery, and what its failure means. A delivery the
/// app is refused (`403`/`404`) is tried once more with the personal token,
/// when there is one. A permanent refusal (or enough retries) marks the edit
/// failed so the page says so; everything else reschedules with a doubling
/// backoff.
async fn handle_record(
    tokens: &Tokens,
    db: &dyn Database,
    clock: &dyn Clock,
    record: OutboxRecord,
) -> Processed {
    let now = iso(clock.now());
    let unix = clock.now().unix_timestamp();
    let (own, repo) = match record.topic.as_str() {
        TOPIC_OPEN_PR => (false, payload_field(&record, "repo")),
        TOPIC_DISPATCH => {
            (edit_has_own_repository(db, &record).await, payload_field(&record, "repo"))
        }
        _ => {
            return finish(db, clock, &record, Ok(())).await;
        }
    };
    let outcome = match tokens.client(repo.as_deref(), own, unix).await {
        Ok((github, via_app)) => match deliver(db, &record, &github, &now).await {
            Err(failure) if via_app && failure.refused => match tokens.personal(own) {
                Some(personal) => deliver(db, &record, &personal, &now).await,
                None => Err(failure),
            },
            other => other,
        },
        Err(failure) => Err(failure),
    };
    finish(db, clock, &record, outcome).await
}

/// Sends one record with one connection: the pull request's open, or the
/// approval's dispatch.
async fn deliver(
    db: &dyn Database,
    record: &OutboxRecord,
    github: &github::GitHub,
    now: &str,
) -> Result<(), github::Failure> {
    match record.topic.as_str() {
        TOPIC_OPEN_PR => open_edit_pr(github, db, record, now).await,
        _ => github.dispatch(&record.payload).await,
    }
}

/// What a record's outcome does: done, or retried later, or the edit failed.
async fn finish(
    db: &dyn Database,
    clock: &dyn Clock,
    record: &OutboxRecord,
    outcome: Result<(), github::Failure>,
) -> Processed {
    match outcome {
        Ok(()) => Processed::Done,
        Err(failure) => {
            let give_up = failure.permanent || record.attempts + 1 >= MAX_ATTEMPTS;
            if give_up {
                if let Some(edit_id) = payload_edit_id(record) {
                    fail_edit(db, &edit_id, &failure.reason).await;
                }
                Processed::Done
            } else {
                let next = clock.now() + time::Duration::minutes(1 << record.attempts.clamp(0, 6));
                Processed::RetryAt(next)
            }
        }
    }
}

/// Whether the edit a record belongs to lives in its own repository (set when
/// the edit was opened), rather than the configured one.
async fn edit_has_own_repository(db: &dyn Database, record: &OutboxRecord) -> bool {
    let Some(edit_id) = payload_edit_id(record) else {
        return false;
    };
    db.query(&Statement::with_values("SELECT repo FROM edits WHERE id = ?", vec![edit_id.into()]))
        .await
        .ok()
        .and_then(|rows| rows.rows.into_iter().next())
        .and_then(|row| opt_col(&row, "repo"))
        .is_some()
}

/// A top-level text field of an outbox row's payload (the repository an open
/// or a dispatch names), when there is one.
fn payload_field(record: &OutboxRecord, name: &str) -> Option<String> {
    let payload: Value = serde_json::from_str(&record.payload).ok()?;
    payload.get(name).and_then(Value::as_str).map(str::to_owned)
}

/// The edit an outbox row belongs to, from either topic's payload.
fn payload_edit_id(record: &OutboxRecord) -> Option<String> {
    let payload: Value = serde_json::from_str(&record.payload).ok()?;
    payload.get("edit_id").and_then(Value::as_str).map(str::to_owned).or_else(|| {
        payload.pointer("/body/client_payload/edit_id").and_then(Value::as_str).map(str::to_owned)
    })
}

/// The open-the-PR conversation for one edit, and the row update that links
/// the edit to the pull request. Guarded on `status = 'opening'` so a
/// replayed delivery after the update cannot restart the workflow's story.
async fn open_edit_pr(
    github: &github::GitHub,
    db: &dyn Database,
    record: &OutboxRecord,
    now: &str,
) -> Result<(), github::Failure> {
    let payload: Value = serde_json::from_str(&record.payload)
        .map_err(|_| github::Failure::permanent("the open_pr payload is not JSON".to_owned()))?;
    let field = |name: &str| {
        payload.get(name).and_then(Value::as_str).map(str::to_owned).ok_or_else(|| {
            github::Failure::permanent(format!("the open_pr payload names no {name}"))
        })
    };
    let edit_id = field("edit_id")?;
    let repo = field("repo")?;
    let branch = field("branch")?;
    let base = field("base")?;
    let title = field("title")?;
    let body = field("body")?;
    let files: Vec<(String, String)> = payload
        .get("files")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|file| {
            let path = file.get("path").and_then(Value::as_str)?;
            let content = file.get("content").and_then(Value::as_str)?;
            Some((path.to_owned(), content.to_owned()))
        })
        .collect();
    if files.is_empty() {
        return Err(github::Failure::permanent("the open_pr payload names no files".to_owned()));
    }
    let pull = github::open_pr(github, &repo, &branch, &base, &title, &body, &files).await?;
    db.execute(&Statement::with_values(
        "UPDATE edits SET status = 'awaiting', pr_number = ?, pr_url = ?, pr_head_sha = ?, updated_at = ? WHERE id = ? AND status = 'opening'",
        vec![
            (pull.number as i64).into(),
            pull.url.clone().into(),
            pull.head_sha.clone().into(),
            now.into(),
            edit_id.into(),
        ],
    ))
    .await
    .map_err(|error| github::Failure::retryable(format!("{error}")))?;
    Ok(())
}

/// Records on the edit why its delivery gave up. An approved edit keeps its
/// status (its plan was approved and is what it is) but shows the error, so
/// the page says why the apply dispatch never went out.
async fn fail_edit(db: &dyn Database, edit_id: &str, reason: &str) {
    let short: String = reason.chars().take(500).collect();
    let _ = db
        .execute(&Statement::with_values(
            "UPDATE edits SET error = ?, status = CASE WHEN status = 'approved' THEN status \
             ELSE 'failed' END WHERE id = ?",
            vec![short.into(), edit_id.into()],
        ))
        .await;
}

/// The runner token for one repository: lowercase hex of HMAC-SHA256 keyed by
/// the console's runner key over the repository's name, lowercased. The
/// infrastructure repository's workflow presents it at the plan callback, so a
/// token leaked from one repository's secrets does not open another's edits.
pub(crate) fn runner_token_for(key: &str, repo: &str) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    use std::fmt::Write as _;
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key.as_bytes())
        .expect("hmac takes a key of any length");
    mac.update(repo.to_ascii_lowercase().as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in mac.finalize().into_bytes() {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Whether a plan callback may write to an edit: the repository's own runner
/// token, or, for an edit in the configured repository, the raw runner key
/// (older workflows post with it).
fn runner_authorized(key: &str, presented: &str, edit_repo: &str, configured: &str) -> bool {
    let key = key.trim();
    let target = if edit_repo.is_empty() { configured } else { edit_repo };
    let per_repo = runner_token_for(key, target);
    let in_configured = edit_repo.is_empty() || edit_repo.eq_ignore_ascii_case(configured);
    constant_time_eq(presented.as_bytes(), per_repo.as_bytes())
        || (in_configured && constant_time_eq(presented.as_bytes(), key.as_bytes()))
}

/// The signed-in person, or the page that says why not. `$path` is where
/// the caller is, so the 401 page can lead them back; `_` when the handler
/// never uses the name.
macro_rules! author_or_return {
    ($ctx:expr, $headers:expr, $path:expr, $author:pat) => {
        let $author = match author_of(&$ctx, &$headers, $path).await {
            Ok(author) => author,
            Err((status, body)) => return html(status, body),
        };
    };
}

// -- pages -------------------------------------------------------------------

/// `GET /v1/edits` — every change, newest first, with the chooser.
async fn list_page(State(ctx): State<Arc<ModuleContext>>, headers: HeaderMap) -> Response {
    author_or_return!(ctx, headers, "/v1/edits", _);
    let Some(db) = ctx.ports.db.clone() else {
        return html(
            StatusCode::SERVICE_UNAVAILABLE,
            page::not_ready("the database is not wired up"),
        );
    };
    let rows = db
        .query(&Statement::with_values(
            "SELECT id, title, zone, status, created_at FROM edits ORDER BY created_at DESC LIMIT 100",
            Vec::new(),
        ))
        .await;
    match rows {
        Ok(rows) => html(
            StatusCode::OK,
            page::list(
                &rows
                    .rows
                    .iter()
                    .map(|row| page::ListRow {
                        id: col(row, "id"),
                        title: col(row, "title"),
                        zone: col(row, "zone"),
                        status: col(row, "status"),
                        created_at: col(row, "created_at"),
                    })
                    .collect::<Vec<_>>(),
            ),
        ),
        Err(error) => Problem::internal().with_detail(error.to_string()).into_response(),
    }
}

/// `GET /v1/edits/new?kind=&zone=` — one kind's form, the zone prefilled
/// when the query named it; an unknown kind gets the chooser instead.
async fn new_page(
    State(ctx): State<Arc<ModuleContext>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    author_or_return!(ctx, headers, "/v1/edits/new", _);
    let params = query.as_deref().map(urlencoded).unwrap_or_default();
    match param(&params, "kind").filter(|kind| change::form(kind).is_some()) {
        Some(kind) => html(StatusCode::OK, page::form(kind, &params, &[])),
        None => html(StatusCode::OK, page::chooser()),
    }
}

/// `POST /v1/edits` — validate the form, record the edit, queue the pull
/// request, and send the person to the edit's page.
async fn create(
    State(ctx): State<Arc<ModuleContext>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    author_or_return!(ctx, headers, "/v1/edits", author);
    let Some(db) = ctx.ports.db.clone() else {
        return html(
            StatusCode::SERVICE_UNAVAILABLE,
            page::not_ready("the database is not wired up"),
        );
    };
    let params = urlencoded(&String::from_utf8_lossy(&body));
    let kind = param(&params, "kind").unwrap_or_default().to_owned();
    let cfg = ModuleConfig::new(Edits::NAME, ctx.config.as_ref());
    let id = id_of(&ctx);
    match change::parse(&kind, &params, &id, &cfg.get_str("INFRA_DIR", "")) {
        Err(errors) => html(StatusCode::BAD_REQUEST, page::form(&kind, &params, &errors)),
        Ok(change) => {
            let now = iso(now_of(&ctx));
            let body = pr_body(&author, &change.summary_md, &console_url(&ctx, &id));
            let payload = pr_payload(&cfg, &id, &change.zone, &change.title, &body, &change.files);
            let outbox = Outbox::new(OUTBOX_TABLE);
            let enqueue = outbox.enqueue_statement(
                &format!("{id}:open"),
                TOPIC_OPEN_PR,
                &payload,
                Some(&author),
                &now,
            );
            let insert = insert_edit(&change, &id, &author, &now);
            match db.batch_atomic(&[insert, enqueue]).await {
                Ok(()) => {
                    deliver_soon(&ctx);
                    Redirect::to(&format!("/v1/edits/{id}")).into_response()
                }
                Err(error) => Problem::internal().with_detail(error.to_string()).into_response(),
            }
        }
    }
}

/// `GET /v1/edits/<id>` — the ask, the pull request, and the plan in words.
async fn detail_page(
    State(ctx): State<Arc<ModuleContext>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    author_or_return!(ctx, headers, &format!("/v1/edits/{id}"), _);
    let Some(db) = ctx.ports.db.clone() else {
        return html(
            StatusCode::SERVICE_UNAVAILABLE,
            page::not_ready("the database is not wired up"),
        );
    };
    let row = match find_edit(&*db, &id).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return html(
                StatusCode::NOT_FOUND,
                page::page(
                    "Not found",
                    "<section><h1>Not found</h1><p>No change carries that reference.</p></section>",
                ),
            );
        }
        Err(error) => return Problem::internal().with_detail(error.to_string()).into_response(),
    };
    let changes = col(&row, "changes_json");
    let detail = page::Detail {
        id: col(&row, "id"),
        title: col(&row, "title"),
        zone: col(&row, "zone"),
        status: col(&row, "status"),
        summary_md: col(&row, "summary_md"),
        file_path: col(&row, "file_path"),
        pr_number: opt_i64(&row, "pr_number"),
        pr_url: opt_col(&row, "pr_url"),
        plan: (!changes.is_empty()).then(|| PlanView::from_json(&changes)),
        plan_sha256: opt_col(&row, "plan_sha256").unwrap_or_default(),
        approver: opt_col(&row, "approver"),
        approved_at: opt_col(&row, "approved_at"),
        error: opt_col(&row, "error"),
    };
    html(StatusCode::OK, page::detail(&detail))
}

/// `POST /v1/edits/<id>/plan` — the CI callback. Bearer runner token; the
/// body is the workflow's `{head_sha, plan_file_sha256?, plan}` JSON. The
/// parsed resource changes and the body's sha256 are stored; an already
/// approved edit refuses the update with a 409.
async fn plan_post(
    State(ctx): State<Arc<ModuleContext>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let cfg = ModuleConfig::new(Edits::NAME, ctx.config.as_ref());
    let Some(expected) = cfg.get_opt("RUNNER_TOKEN") else {
        return Problem::not_ready("the runner token is not configured").into_response();
    };
    let Some(presented) = bearer_token(&headers) else {
        return Problem::new(&SLUGS.unauthenticated).into_response();
    };
    if body.len() > PLAN_BODY_LIMIT {
        return Problem::new(&PLAN_TOO_LARGE).into_response();
    }
    let Ok(posted) = serde_json::from_slice::<Value>(&body) else {
        return Problem::validation_failed("the plan body is not JSON").into_response();
    };
    let head_sha = posted.get("head_sha").and_then(Value::as_str).unwrap_or_default();
    if head_sha.len() != 40 || !head_sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Problem::validation_failed(
            "the plan body needs head_sha, the 40-character commit the pull request is at",
        )
        .into_response();
    }
    let plan_file_sha256 = posted.get("plan_file_sha256").and_then(Value::as_str);
    if let Some(digest) = plan_file_sha256
        && (digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Problem::validation_failed(
            "plan_file_sha256 must be the 64-character sha256 of the saved plan file",
        )
        .into_response();
    }
    let Some(plan) = posted.get("plan").filter(|plan| plan.is_object()) else {
        return Problem::validation_failed(
            "the plan body needs plan, the object `tofu show -json` printed",
        )
        .into_response();
    };
    let Some(db) = ctx.ports.db.clone() else {
        return Problem::not_ready("the database is not wired up").into_response();
    };
    // The edit is looked up before the token is judged, because the token is
    // judged against the edit's repository. A missing edit reads as refused, the
    // same as a wrong token, so the callback cannot tell which ids exist.
    let row = match find_edit(&*db, &id).await {
        Ok(Some(row)) => row,
        Ok(None) => return Problem::new(&SLUGS.unauthenticated).into_response(),
        Err(error) => return Problem::internal().with_detail(error.to_string()).into_response(),
    };
    if !runner_authorized(&expected, presented, &col(&row, "repo"), &cfg.get_str("REPO", "")) {
        return Problem::new(&SLUGS.unauthenticated).into_response();
    }
    if col(&row, "status") == "approved" {
        return Problem::new(&ALREADY_APPROVED).into_response();
    }
    let changes = change::extract(plan);
    let plan_sha256 = sha256_hex(&body);
    let updated = db
        .execute(&Statement::with_values(
            "UPDATE edits SET status = 'planned', changes_json = ?, plan_sha256 = ?, plan_file_sha256 = ?, pr_head_sha = ?, updated_at = ? WHERE id = ? AND status != 'approved'",
            vec![
                changes.to_string().into(),
                plan_sha256.into(),
                plan_file_sha256.unwrap_or_default().into(),
                head_sha.into(),
                iso(now_of(&ctx)).into(),
                id.into(),
            ],
        ))
        .await;
    match updated {
        Ok(1) => cratefield_core::axum::Json(json!({"ok": true})).into_response(),
        Ok(_) => Problem::new(&ALREADY_APPROVED).into_response(),
        Err(error) => Problem::internal().with_detail(error.to_string()).into_response(),
    }
}

/// `POST /v1/edits/<id>/approve` — only a planned edit can be approved; a
/// plan that removes anything demands the zone's name typed back. Approval
/// and the `repository_dispatch` enqueue commit in one batch, so the
/// dispatch either exists with the approval or not at all.
async fn approve(
    State(ctx): State<Arc<ModuleContext>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    author_or_return!(ctx, headers, &format!("/v1/edits/{id}"), author);
    let Some(db) = ctx.ports.db.clone() else {
        return html(
            StatusCode::SERVICE_UNAVAILABLE,
            page::not_ready("the database is not wired up"),
        );
    };
    let cfg = ModuleConfig::new(Edits::NAME, ctx.config.as_ref());
    let row = match find_edit(&*db, &id).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return html(
                StatusCode::NOT_FOUND,
                page::page(
                    "Not found",
                    "<section><h1>Not found</h1><p>No change carries that reference.</p></section>",
                ),
            );
        }
        Err(error) => return Problem::internal().with_detail(error.to_string()).into_response(),
    };
    // An edit opened for a specific repository (onboarding) dispatches there;
    // every other edit dispatches to the configured one.
    let repo = match col(&row, "repo") {
        repo if repo.is_empty() => cfg.get_str("REPO", ""),
        repo => repo,
    };
    if repo.is_empty() {
        return html(
            StatusCode::SERVICE_UNAVAILABLE,
            page::not_ready("the infrastructure repository is not configured"),
        );
    }
    if col(&row, "status") != "planned" {
        let why = if col(&row, "status") == "approved" {
            "This change is already approved; the workflow is applying it."
        } else {
            "The plan has not arrived yet, so there is nothing to approve."
        };
        return html(
            StatusCode::BAD_REQUEST,
            page::page(
                "Not ready to approve",
                &format!("<section><h1>Not ready to approve</h1><p>{why}</p></section>"),
            ),
        );
    }
    let zone = col(&row, "zone");
    let stored_sha = col(&row, "plan_sha256");
    let plan = PlanView::from_json(&col(&row, "changes_json"));
    let form = urlencoded(&String::from_utf8_lossy(&body));
    let confirm = param(&form, "confirm").unwrap_or_default();
    if plan.risky() && confirm != zone {
        return html(
            StatusCode::BAD_REQUEST,
            page::page(
                "Type the zone name",
                &format!(
                    "<section><h1>Type the zone name</h1><p>This plan removes things. To \
                     approve it, type the zone's name (<code>{}</code>) in the confirmation \
                     box on the change's page.</p></section>",
                    page::escape(&zone),
                ),
            ),
        );
    }
    // The approval names the plan the person read (a hidden field). If the
    // workflow has posted a newer plan since the page loaded, refuse rather
    // than apply something they never saw.
    if param(&form, "saw").unwrap_or_default() != stored_sha {
        return html(
            StatusCode::CONFLICT,
            page::page(
                "The plan changed",
                "<section><h1>The plan changed</h1><p>A newer plan arrived while this page was \
                 open. Read it again, then approve from the fresh page.</p></section>",
            ),
        );
    }
    let now = iso(now_of(&ctx));
    let mut client_payload = json!({
        "edit_id": col(&row, "id"),
        "pr_number": opt_i64(&row, "pr_number").unwrap_or(0),
        "head_sha": col(&row, "pr_head_sha"),
        "plan_sha256": col(&row, "plan_sha256"),
        "approver": author,
        "zone": zone,
    });
    if let Some(digest) = opt_col(&row, "plan_file_sha256") {
        client_payload["plan_file_sha256"] = Value::from(digest);
    }
    let envelope = github::dispatch_envelope(&repo, EVENT_TYPE, client_payload);
    let outbox = Outbox::new(OUTBOX_TABLE);
    let enqueue = outbox.enqueue_statement(
        &format!("{}:dispatch", col(&row, "id")),
        TOPIC_DISPATCH,
        &envelope,
        Some(&author),
        &now,
    );
    let update = Statement::with_values(
        "UPDATE edits SET status = 'approved', approver = ?, approved_at = ?, updated_at = ? WHERE id = ? AND status = 'planned' AND plan_sha256 = ?",
        vec![
            author.into(),
            now.clone().into(),
            now.into(),
            col(&row, "id").into(),
            stored_sha.into(),
        ],
    );
    match db.batch_atomic(&[update, enqueue]).await {
        Ok(()) => {
            deliver_soon(&ctx);
            Redirect::to(&format!("/v1/edits/{}", col(&row, "id"))).into_response()
        }
        Err(error) => Problem::internal().with_detail(error.to_string()).into_response(),
    }
}

async fn find_edit(db: &dyn Database, id: &str) -> Result<Option<Row>, cratefield_core::DbError> {
    let rows = db
        .query(&Statement::with_values("SELECT * FROM edits WHERE id = ?", vec![id.into()]))
        .await?;
    Ok(rows.rows.into_iter().next())
}

/// Lowercase hex sha256 — what the plan callback stores so the workflow and
/// the console can agree on which plan was read.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencoded_decodes_forms_and_queries() {
        let params = urlencoded("zone=example.com&name=a%2Fb+cd&empty=&flag");
        assert_eq!(param(&params, "zone"), Some("example.com"));
        assert_eq!(param(&params, "name"), Some("a/b cd"));
        assert_eq!(param(&params, "empty"), Some(""));
        assert_eq!(param(&params, "flag"), Some(""));
        assert_eq!(param(&params, "missing"), None);
    }

    #[test]
    fn config_validation_speaks_in_config_keys() {
        use cratefield_core::MapConfig;
        let edits = Edits;
        let bad = edits
            .validate_config(&MapConfig::from_pairs([("EDITS_REPO", "keepshipping")]))
            .expect_err("missing pieces");
        assert!(bad.problems.iter().any(|line| line.contains("EDITS_REPO")), "{bad:?}");
        assert!(bad.problems.iter().any(|line| line.contains("EDITS_BASE_BRANCH")), "{bad:?}");
        edits
            .validate_config(&MapConfig::from_pairs([
                ("EDITS_REPO", "keepshipping/infra"),
                ("EDITS_BASE_BRANCH", "main"),
            ]))
            .expect("the minimum configuration");
    }

    /// The column names a CREATE TABLE block declares: the first word of each
    /// line inside one, skipping constraints.
    fn table_columns(sql: &str) -> Vec<String> {
        let mut columns = Vec::new();
        let mut inside = false;
        for line in sql.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("CREATE TABLE") {
                inside = true;
                continue;
            }
            if trimmed.starts_with(')') {
                inside = false;
            }
            let word = trimmed.split_whitespace().next().unwrap_or_default();
            let constraint = matches!(
                word.to_ascii_uppercase().as_str(),
                "PRIMARY" | "UNIQUE" | "CHECK" | "FOREIGN"
            );
            if inside && !word.is_empty() && !constraint {
                columns.push(word.to_owned());
            }
        }
        columns
    }

    #[test]
    fn the_venture_migration_creates_every_column_the_module_migration_does() {
        let module = include_str!("migrations/0001_init.sql");
        let venture = include_str!("../../migrations/0013_edits.sql");
        let wanted = table_columns(module);
        assert!(wanted.contains(&"repo".to_owned()), "the module declares edits.repo");
        for column in &wanted {
            assert!(
                table_columns(venture).contains(column) || venture.contains(&format!("{column} ")),
                "migrations/0013_edits.sql is missing column {column}"
            );
        }
        assert!(venture.contains("CREATE TABLE IF NOT EXISTS edits_outbox"));
    }

    #[test]
    fn a_runner_token_is_derived_per_repository_and_ignores_case() {
        let a = runner_token_for("runner-key", "nick/shop-infra");
        assert_eq!(a.len(), 64);
        assert_eq!(a, runner_token_for("runner-key", "Nick/Shop-Infra"));
        assert_ne!(a, runner_token_for("runner-key", "nick/other-infra"));
        assert_ne!(a, runner_token_for("other-key", "nick/shop-infra"));
    }

    #[test]
    fn a_callback_is_judged_against_its_own_repository() {
        let key = "runner-key";
        let own = runner_token_for(key, "nick/shop-infra");
        assert!(runner_authorized(key, &own, "nick/shop-infra", "keepshipping/infra"));
        let other = runner_token_for(key, "nick/other-infra");
        assert!(!runner_authorized(key, &other, "nick/shop-infra", "keepshipping/infra"));
        // The raw key opens only the configured repository's edits.
        assert!(!runner_authorized(key, key, "nick/shop-infra", "keepshipping/infra"));
        assert!(runner_authorized(key, key, "", "keepshipping/infra"));
        assert!(runner_authorized(key, key, "keepshipping/infra", "keepshipping/infra"));
    }
}
