//! The billing routes (issue #177, ADR 0202) through the venture's own
//! composition (`billing_module`) with the real `cratefield-adapter-polar`
//! adapter over a scripted HTTP fake: one webhook upgrades an account; a
//! refund, a cancellation and a revocation put it back on free limits
//! without deleting the row; disputes flag first and only a lost one
//! downgrades; an unsigned webhook writes nothing; a duplicate delivery
//! writes nothing twice; and checkout never bills an account the caller
//! is not.

use cratefield_adapter_polar::{CustomerIds, Polar};
use cratefield_core::axum::body::{Body, Bytes};
use cratefield_core::billing::{PeriodType, Status, SubscriptionState};
use cratefield_core::{MapConfig, Ports, Statement};
use cratefield_testing::{FakeAuth, FakeHttpClient, FixedClock, TestHarness, request, request_as};
use http::{Method, StatusCode};
use keepshipping_waitlist::{DISPUTE_POLL_CRON, Plan, billing_module, entitlements, venture};
use serde_json::{Value, json};
use std::sync::Arc;
use time::macros::datetime;

/// The kit's fixed clock: 2027-01-15T08:00:00Z — the module's `now`, the
/// adapter's signature-tolerance clock and every webhook timestamp below.
const NOW: i64 = 1_800_000_000;

/// Far inside the future, so a period end never lapses mid-test.
const PERIOD_END: &str = "2028-01-15T08:00:00Z";

/// 32 raw bytes behind the `whsec_` prefix, exactly Standard Webhooks.
const RAW_KEY: &[u8] = b"billing-test-key-0123456789abcdef";
const WEBHOOK_ID: &str = "msg_test_0001";

fn at() -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(NOW).expect("the fixed epoch")
}

/// Signs `body` the way Polar does: `v1,` + base64(HMAC-SHA256 over
/// `{id}.{timestamp}.{body}`) with the decoded key.
fn sign_with(key: &[u8], id: &str, body: &str) -> String {
    use base64::Engine;
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac takes any key");
    mac.update(format!("{id}.{NOW}.{body}").as_bytes());
    let tag = mac.finalize().into_bytes();
    let tag: &[u8] = tag.as_ref();
    format!("v1,{}", base64::engine::general_purpose::STANDARD.encode(tag))
}

fn webhook_secret() -> String {
    use base64::Engine;
    format!("whsec_{}", base64::engine::general_purpose::STANDARD.encode(RAW_KEY))
}

/// A kit mounting the venture and the billing module exactly as `src/lib.rs`
/// composes them, with Polar over the scripted fake and the fake auth that
/// reads a bearer token as the account id. `patch` swaps ports under test.
fn kit(http: FakeHttpClient, patch: impl FnOnce(&mut Ports)) -> TestHarness {
    TestHarness::with_builder(
        vec![Box::new(billing_module())],
        |builder| builder.venture(venture()),
        |ports| {
            ports.auth = Some(Arc::new(FakeAuth::subjects()));
            ports.payments = Some(Arc::new(polar(http.clone(), ports.clock.clone())));
            patch(ports);
        },
    )
}

fn polar(http: FakeHttpClient, clock: Option<Arc<dyn cratefield_core::Clock>>) -> Polar {
    Polar::new(
        Arc::new(http),
        clock.unwrap_or_else(|| Arc::new(FixedClock(at()))),
        cratefield_adapter_polar::Environment::Sandbox,
        "polar_test_access_token",
        webhook_secret(),
    )
    .with_customer_ids(CustomerIds::External)
}

fn json_response(body: &str) -> http::Response<Bytes> {
    http::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Bytes::from(body.to_owned()))
        .expect("a scripted response builds")
}

/// Posts a signed delivery to `/v1/billing/webhook`; returns status and body.
async fn post_webhook(kit: &TestHarness, id: &str, body: &str) -> (StatusCode, Value) {
    use tower::ServiceExt;
    let request = webhook_request(id, sign_with(RAW_KEY, id, body), body);
    let response = kit.router.clone().oneshot(request).await.expect("the router answers");
    let status = response.status();
    let bytes = cratefield_core::axum::body::to_bytes(response.into_body(), 1_048_576)
        .await
        .expect("the body reads");
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// The same delivery, signed by someone who does not have the secret.
async fn post_forged_webhook(kit: &TestHarness, body: &str) -> (StatusCode, Value) {
    use tower::ServiceExt;
    let key = b"an-attacker-key-0123456789abcdefgh";
    let request = webhook_request(WEBHOOK_ID, sign_with(key, WEBHOOK_ID, body), body);
    let response = kit.router.clone().oneshot(request).await.expect("the router answers");
    let status = response.status();
    let bytes = cratefield_core::axum::body::to_bytes(response.into_body(), 1_048_576)
        .await
        .expect("the body reads");
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn webhook_request(id: &str, signature: String, body: &str) -> http::Request<Body> {
    http::Request::builder()
        .method(Method::POST)
        .uri("/v1/billing/webhook")
        .header("content-type", "application/json")
        .header("webhook-id", id)
        .header("webhook-timestamp", NOW.to_string())
        .header("webhook-signature", signature)
        .body(Body::from(body.to_owned()))
        .expect("the webhook request builds")
}

fn sub_webhook(kind: &str, sub: &str, account: &str) -> String {
    json!({ "type": kind, "data": {
        "id": sub, "status": "active", "product_id": "prod_annual",
        "customer_id": format!("cus_{sub}"), "cancel_at_period_end": kind == "subscription.canceled",
        "current_period_end": PERIOD_END,
        "customer": { "id": format!("cus_{sub}"), "external_id": account } } })
    .to_string()
}

fn refund_webhook(order: &str, sub: &str, status: &str) -> String {
    json!({ "type": "refund.updated", "data": {
        "id": format!("ref_{order}"), "order_id": order, "subscription_id": sub,
        "customer_id": format!("cus_{sub}"), "status": status, "reason": "customer_request",
        "amount": 15_000, "currency": "usd" } })
    .to_string()
}

fn order_webhook(order: &str, sub: &str, account: &str) -> String {
    json!({ "type": "order.paid", "data": {
        "id": order, "status": "paid", "billing_reason": "subscription_create",
        "customer_id": format!("cus_{sub}"), "subscription_id": sub,
        "total_amount": 15_000, "refunded_amount": 0, "currency": "usd",
        "customer": { "id": format!("cus_{sub}"), "external_id": account } } })
    .to_string()
}

fn dispute(id: &str, status: &str, order: &str, account: Option<&str>) -> Value {
    let mut object = json!({ "id": id, "status": status, "order_id": order, "amount": 15_000, "currency": "usd" });
    if let Some(account) = account {
        object["customer"] = json!({ "external_id": account });
    }
    object
}

fn disputes_page(items: Value) -> String {
    json!({ "items": items, "pagination": { "max_page": 1 } }).to_string()
}

/// The plan the module answers for `account` at the kit's fixed now.
fn plan(kit: &TestHarness, account: &str) -> Plan {
    pollster::block_on(billing_module().plan(&*kit.db, account, at()))
        .expect("the plan reads without a database error")
}

/// The audit trail for `account`, in order: `(kind, plan_after)` pairs.
fn audit(kit: &TestHarness, account: &str) -> Vec<(String, String)> {
    let rows = pollster::block_on(kit.db.query(&Statement::with_values(
        "SELECT kind, plan_after FROM billing_audit WHERE account_id = ? ORDER BY rowid",
        vec![account.into()],
    )))
    .expect("the audit reads");
    rows.rows
        .iter()
        .map(|row| {
            (
                row.get::<String>("kind").expect("a kind"),
                row.get::<String>("plan_after").expect("a plan"),
            )
        })
        .collect()
}

/// The expected audit trail, written compactly.
fn trail(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs.iter().map(|(kind, plan)| (kind.to_string(), plan.to_string())).collect()
}

fn count(kit: &TestHarness, sql: &str) -> i64 {
    let rows =
        pollster::block_on(kit.db.query(&Statement::new(sql.to_owned()))).expect("the count reads");
    rows.first().and_then(|row| row.get::<i64>("n")).unwrap_or(0)
}

fn disputed(kit: &TestHarness, account: &str) -> bool {
    let rows = pollster::block_on(kit.db.query(&Statement::with_values(
        "SELECT disputed FROM billing_accounts WHERE account_id = ?",
        vec![account.into()],
    )))
    .expect("the flag reads");
    rows.first().and_then(|row| row.get::<i64>("disputed")).unwrap_or(0) == 1
}

/// Runs the module's `scheduled` (the dispute poll) against the kit's own
/// database, clock and Polar adapter.
fn poll_disputes(kit: &TestHarness, http: &FakeHttpClient) {
    use cratefield_core::Module;
    let mut ports =
        Ports::with_config(Arc::new(MapConfig::from_pairs([("POLAR_ENVIRONMENT", "sandbox")])));
    ports.db = Some(kit.db.clone());
    ports.clock = Some(Arc::new(FixedClock(at())));
    ports.auth = Some(Arc::new(FakeAuth::subjects()));
    ports.payments = Some(Arc::new(polar(http.clone(), Some(Arc::new(FixedClock(at()))))));
    let context = kit.harness.module_context(&billing_module(), &ports);
    pollster::block_on(billing_module().scheduled(&context, DISPUTE_POLL_CRON))
        .expect("the dispute poll runs");
}

fn problem_slug(body: &Value) -> String {
    let uri = body["type"].as_str().expect("a problem+json `type`");
    uri.split_once("/problems/").map_or(uri, |(_, slug)| slug).to_owned()
}

#[test]
fn entitlements_read_free_or_paid() {
    let at = datetime!(2026-02-14 08:00 UTC);
    let end = datetime!(2027-02-14 08:00 UTC);
    let state = |status: Status, access_until| SubscriptionState {
        status,
        period_type: PeriodType::Normal,
        renews: true,
        access_until,
        pending_product: None,
        last_event_at: at,
        revoked: status == Status::Revoked,
    };
    assert_eq!(entitlements(None, at), Plan::Free, "no account yet");
    let active = state(Status::Active, Some(end));
    assert_eq!(entitlements(Some(&active), at), Plan::Paid);
    assert_eq!(entitlements(Some(&active), end), Plan::Free, "lapsed needs no webhook");
    for status in [Status::Revoked, Status::Expired, Status::Incomplete, Status::Paused] {
        assert_eq!(entitlements(Some(&state(status, None)), at), Plan::Free, "{status:?}");
    }
    let grace = state(Status::InGracePeriod, Some(at + time::Duration::hours(1)));
    assert_eq!(entitlements(Some(&grace), at), Plan::Paid);
    assert_eq!(entitlements(Some(&grace), at + time::Duration::hours(2)), Plan::Free);
}

#[pollster::test]
async fn one_webhook_upgrades_the_account_and_a_replay_writes_nothing_twice() {
    let kit = kit(FakeHttpClient::scripted(vec![]), |_| {});
    let body = sub_webhook("subscription.active", "sub_1", "acc_1");
    let (status, reply) = post_webhook(&kit, WEBHOOK_ID, &body).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["applied"], 1);
    assert_eq!(plan(&kit, "acc_1"), Plan::Paid);
    assert_eq!(audit(&kit, "acc_1"), trail(&[("subscription.started", "paid")]));
    assert_eq!(count(&kit, "SELECT COUNT(*) AS n FROM billing_accounts"), 1);

    let (status, reply) = post_webhook(&kit, WEBHOOK_ID, &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reply["applied"], 0, "the replay was claimed already");
    assert_eq!(audit(&kit, "acc_1").len(), 1, "one delivery, one audit row");
    assert_eq!(plan(&kit, "acc_1"), Plan::Paid);
}

#[pollster::test]
async fn a_refund_and_a_lapsed_renewal_put_the_account_back_on_free() {
    // A pending refund is a promise: only a succeeded one revokes.
    let refunded = kit(FakeHttpClient::scripted(vec![]), |_| {});
    let active = &sub_webhook("subscription.active", "sub_1", "acc_1");
    post_webhook(&refunded, "w1", active).await;
    post_webhook(&refunded, "w2", &refund_webhook("ord_1", "sub_1", "pending")).await;
    assert_eq!(plan(&refunded, "acc_1"), Plan::Paid, "only a succeeded refund revokes");
    post_webhook(&refunded, "w3", &refund_webhook("ord_1", "sub_1", "succeeded")).await;
    assert_eq!(plan(&refunded, "acc_1"), Plan::Free);
    assert_eq!(
        audit(&refunded, "acc_1"),
        trail(&[("subscription.started", "paid"), ("subscription.refunded", "free")])
    );
    // The row survives: never delete an account for non-payment.
    assert_eq!(count(&refunded, "SELECT COUNT(*) AS n FROM billing_accounts"), 1);

    // A cancellation keeps paid access to the period; a revocation ends it.
    let kit = kit(FakeHttpClient::scripted(vec![]), |_| {});
    post_webhook(&kit, "w1", active).await;
    post_webhook(&kit, "w2", &sub_webhook("subscription.canceled", "sub_1", "acc_1")).await;
    assert_eq!(plan(&kit, "acc_1"), Plan::Paid, "paid access survives to the period end");
    post_webhook(&kit, "w3", &sub_webhook("subscription.revoked", "sub_1", "acc_1")).await;
    assert_eq!(plan(&kit, "acc_1"), Plan::Free);
    assert_eq!(
        audit(&kit, "acc_1"),
        trail(&[
            ("subscription.started", "paid"),
            ("subscription.canceled", "paid"),
            ("subscription.expired", "free"),
        ])
    );
    assert_eq!(count(&kit, "SELECT COUNT(*) AS n FROM billing_accounts"), 1);
}

#[pollster::test]
async fn disputes_flag_first_and_only_a_lost_one_downgrades() {
    // Page one: open disputes on acc_1 (by customer id) and acc_2 (by order
    // only, resolved through the row `order.paid` recorded). Page two: the
    // first came back lost, the second won.
    let http = FakeHttpClient::scripted(vec![
        Ok(json_response(&disputes_page(json!([
            dispute("disp_1", "needs_response", "ord_1", Some("acc_1")),
            dispute("disp_2", "needs_response", "ord_2", None),
        ])))),
        Ok(json_response(&disputes_page(json!([
            dispute("disp_1", "lost", "ord_1", Some("acc_1")),
            dispute("disp_2", "won", "ord_2", None),
        ])))),
    ]);
    let kit = kit(http.clone(), |_| {});
    post_webhook(&kit, "w1", &sub_webhook("subscription.active", "sub_1", "acc_1")).await;
    post_webhook(&kit, "w2", &sub_webhook("subscription.active", "sub_2", "acc_2")).await;
    // The order id is what the dispute resolves by — recorded by `order.paid`.
    post_webhook(&kit, "w3", &order_webhook("ord_2", "sub_2", "acc_2")).await;
    assert_eq!(plan(&kit, "acc_1"), Plan::Paid);
    assert_eq!(plan(&kit, "acc_2"), Plan::Paid);

    poll_disputes(&kit, &http);

    // Open: the accounts are flagged, the plans untouched while the card
    // network decides (ADR 0202's flag-only policy).
    assert!(disputed(&kit, "acc_1"));
    assert_eq!(plan(&kit, "acc_1"), Plan::Paid);
    assert!(disputed(&kit, "acc_2"), "the flag is set through the order id too");
    assert_eq!(plan(&kit, "acc_2"), Plan::Paid);

    poll_disputes(&kit, &http);

    // Lost: downgrade, flag cleared. Won: plan restored, flag cleared.
    assert_eq!(plan(&kit, "acc_1"), Plan::Free);
    assert!(!disputed(&kit, "acc_1"));
    assert_eq!(
        audit(&kit, "acc_1"),
        trail(&[
            ("subscription.started", "paid"),
            ("dispute.opened", "paid"),
            ("dispute.lost", "free"),
        ])
    );
    assert_eq!(plan(&kit, "acc_2"), Plan::Paid);
    assert!(!disputed(&kit, "acc_2"), "a won dispute clears the flag it set");
    assert!(audit(&kit, "acc_2").contains(&("dispute.won".to_owned(), "paid".to_owned())));
    assert_eq!(count(&kit, "SELECT COUNT(*) AS n FROM billing_accounts"), 2);
}

#[pollster::test]
async fn a_late_order_cannot_re_grant_what_a_refund_revoked() {
    let http = FakeHttpClient::scripted(vec![]);
    let kit = kit(http, |_| {});
    post_webhook(&kit, "w1", &sub_webhook("subscription.active", "sub_1", "acc_1")).await;
    post_webhook(&kit, "w2", &refund_webhook("ord_1", "sub_1", "succeeded")).await;
    assert_eq!(plan(&kit, "acc_1"), Plan::Free);

    // The same order redelivered late, under a fresh webhook id: it records
    // the order id for dispute mapping and nothing else.
    let (status, reply) = post_webhook(&kit, "w3", &order_webhook("ord_1", "sub_1", "acc_1")).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(plan(&kit, "acc_1"), Plan::Free, "an order never moves the plan");
    assert_eq!(
        audit(&kit, "acc_1"),
        trail(&[
            ("subscription.started", "paid"),
            ("subscription.refunded", "free"),
            ("order.paid", "free"),
        ])
    );
    let row = pollster::block_on(kit.db.query(&Statement::with_values(
        "SELECT last_order_id, status FROM billing_accounts WHERE account_id = ?",
        vec!["acc_1".into()],
    )))
    .expect("the row reads");
    let row = row.first().expect("the account row survived");
    assert_eq!(row.get::<String>("last_order_id").as_deref(), Some("ord_1"));
    assert_eq!(row.get::<String>("status").as_deref(), Some("revoked"));
}

#[pollster::test]
async fn a_forged_signature_is_refused_before_anything_is_read() {
    let kit = kit(FakeHttpClient::scripted(vec![]), |_| {});
    let body = sub_webhook("subscription.active", "sub_1", "acc_1");
    let (status, reply) = post_forged_webhook(&kit, &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(problem_slug(&reply), "validation-failed");
    assert_eq!(count(&kit, "SELECT COUNT(*) AS n FROM billing_accounts"), 0);
    assert_eq!(count(&kit, "SELECT COUNT(*) AS n FROM billing_audit"), 0);
}

#[pollster::test]
async fn checkout_refuses_to_bill_an_account_the_caller_is_not() {
    // No auth port wired at all: the deployment's misconfiguration, a 503.
    let unauthed = kit(FakeHttpClient::scripted(vec![]), |ports| ports.auth = None);
    let response = request(
        &unauthed.router,
        Method::POST,
        "/v1/billing/checkout",
        Some(r#"{"interval":"annual"}"#),
    )
    .await;
    assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(problem_slug(&response.json()), "not-ready");

    // An anonymous caller: their 401. A body naming someone else's account
    // changes nothing — the account never comes from the body.
    let anon = kit(FakeHttpClient::scripted(vec![]), |_| {});
    let response = request(
        &anon.router,
        Method::POST,
        "/v1/billing/checkout",
        Some(r#"{"account_id":"victim","interval":"annual"}"#),
    )
    .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(problem_slug(&response.json()), "unauthenticated");

    // Even an authenticated caller is billed only as themselves: a body
    // naming a victim is ignored, and the session Polar sees is the
    // caller's.
    let http = FakeHttpClient::scripted(vec![Ok(json_response(
        r#"{"id":"chk_v","url":"https://polar.sh/checkout/chk_v"}"#,
    ))]);
    let kit = kit(http.clone(), |ports| {
        ports.config = Arc::new(MapConfig::from_pairs([("POLAR_PRODUCT_ANNUAL", "prod_annual")]));
    });
    let response = request_as(
        &kit.router,
        Method::POST,
        "/v1/billing/checkout",
        "acc_1",
        Some(r#"{"account_id":"victim","interval":"annual"}"#),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.json());
    let (_, url, body) = http.captured().into_iter().next().expect("Polar was called");
    assert!(body.contains("acc_1"), "the session names the verified caller: {body}");
    assert!(!body.contains("victim"), "the body's account id is ignored: {body}");
    assert!(url.contains("/v1/checkouts/"), "{url}");
}

#[pollster::test]
async fn checkout_and_portal_bill_the_verified_caller() {
    let http = FakeHttpClient::scripted(vec![
        Ok(json_response(r#"{"id":"chk_1","url":"https://polar.sh/checkout/chk_1"}"#)),
        Ok(json_response(r#"{"id":"chk_2","url":"https://polar.sh/checkout/chk_2"}"#)),
        Ok(json_response(r#"{"customer_portal_url":"https://polar.sh/portal/sess_1"}"#)),
    ]);
    let kit = kit(http.clone(), |ports| {
        ports.config = Arc::new(MapConfig::from_pairs([
            ("POLAR_PRODUCT_ANNUAL", "prod_annual"),
            ("POLAR_PRODUCT_MONTHLY", "prod_monthly"),
        ]));
    });
    let response = request_as(
        &kit.router,
        Method::POST,
        "/v1/billing/checkout",
        "acc_1",
        Some(r#"{"interval":"monthly"}"#),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.json());
    assert_eq!(response.json()["url"], "https://polar.sh/checkout/chk_1");
    assert_eq!(response.json()["interval"], "monthly");

    // An empty body asks for the annual default; the portal opens on the
    // caller's account too.
    let response =
        request_as(&kit.router, Method::POST, "/v1/billing/checkout", "acc_1", Some("{}")).await;
    assert_eq!(response.json()["interval"], "annual");
    let response = request_as(&kit.router, Method::POST, "/v1/billing/portal", "acc_1", None).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.json());
    assert_eq!(response.json()["url"], "https://polar.sh/portal/sess_1");

    let captured = http.captured();
    assert!(captured[0].1.contains("/v1/checkouts/"));
    assert!(captured[0].2.contains("prod_monthly"), "the asked plan's product");
    assert!(captured[0].2.contains("acc_1"), "the verified caller, nobody else");
    assert!(captured[1].2.contains("prod_annual"), "the annual default");
    assert!(captured[2].1.contains("/v1/customer-sessions/"), "the portal");
}
