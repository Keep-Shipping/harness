//! The join guards, exercised through the venture's own module
//! composition ([`keepshipping_waitlist::module`]): a missing or wrong
//! captcha token is refused, a rate-limit denial is a 429 with
//! `retry-after`, an unknown product is a 400 problem, and a clean join is
//! accepted (`202`) and captured as `pending` — with and without a working
//! mailer. SQLite only: the venture never touches Postgres.

use cratefield_core::{Decision, Statement};
use cratefield_testing::{
    FakeCaptcha, FakeMailer, FakeRateLimiter, MailerMode, TestHarness, request,
};
use http::{Method, StatusCode};
use keepshipping_waitlist::{SITE_ORIGINS, module, venture};
use std::sync::Arc;
use std::time::Duration;

fn join_json(email: &str, product: &str, token: &str) -> String {
    if token.is_empty() {
        return format!(r#"{{"email":"{email}","product":"{product}"}}"#);
    }
    format!(r#"{{"email":"{email}","product":"{product}","captchaToken":"{token}"}}"#)
}

async fn join(
    kit: &TestHarness,
    email: &str,
    product: &str,
    token: &str,
) -> cratefield_testing::TestResponse {
    request(&kit.router, Method::POST, "/v1/waitlist", Some(&join_json(email, product, token)))
        .await
}

/// The problem's slug: the part of `type` after `/problems/`. Since
/// cratefield-core 0.7 the `type` URI is named under the serving venture's
/// own base, so a client (and this test) matches on the slug, never on the
/// full URI.
fn problem_slug(response: &cratefield_testing::TestResponse) -> String {
    let body = response.json();
    let uri = body["type"].as_str().expect("a problem+json `type`");
    uri.split_once("/problems/").map_or(uri, |(_, slug)| slug).to_owned()
}

fn entry_status(kit: &TestHarness, email: &str) -> Option<String> {
    let stmt = Statement::with_values(
        "SELECT status FROM waitlist_entries WHERE email_normalized = ?",
        vec![email.into()],
    );
    let rows = pollster::block_on(kit.db.query(&stmt)).expect("select the entry");
    rows.first().and_then(|row| row.get::<String>("status"))
}

#[pollster::test]
async fn missing_captcha_token_is_refused() {
    // The captcha port is bound exactly as the worker binds it in
    // production — so the module must fail closed when the field is
    // absent, not wave the join through.
    let kit = TestHarness::with_ports(vec![Box::new(module())], |ports| {
        ports.captcha = Some(Arc::new(FakeCaptcha::with_tokens(["good"])));
    });
    let response = join(&kit, "nick@example.com", "keepshipping", "").await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(problem_slug(&response), "captcha-failed");
    assert_eq!(
        entry_status(&kit, "nick@example.com"),
        None,
        "a refused join must not create a row"
    );
}

#[pollster::test]
async fn wrong_captcha_token_is_refused_and_a_good_one_joins() {
    let kit = TestHarness::with_ports(vec![Box::new(module())], |ports| {
        ports.captcha = Some(Arc::new(FakeCaptcha::with_tokens(["good"])));
    });
    let bad = join(&kit, "nick@example.com", "keepshipping", "bad").await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);

    let good = join(&kit, "nick@example.com", "keepshipping", "good").await;
    assert_eq!(good.status, StatusCode::ACCEPTED);
    assert_eq!(good.json()["ok"], true);
    assert_eq!(entry_status(&kit, "nick@example.com").as_deref(), Some("pending"));
}

#[pollster::test]
async fn unknown_product_is_a_400_problem() {
    let kit = TestHarness::with_ports(vec![Box::new(module())], |ports| {
        ports.captcha = Some(Arc::new(FakeCaptcha::with_tokens(["good"])));
    });
    let response = join(&kit, "nick@example.com", "not-our-product", "good").await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(problem_slug(&response), "unknown-product");
}

#[pollster::test]
async fn rate_limit_denial_is_429_with_retry_after() {
    let deny = Decision { ok: false, retry_after: Some(Duration::from_secs(17)), quota: None };
    let kit = TestHarness::with_ports(vec![Box::new(module())], move |ports| {
        ports.rate_limiter =
            Some(Arc::new(FakeRateLimiter::scripted(vec![deny.clone()], deny.clone())));
    });
    let response = join(&kit, "nick@example.com", "keepshipping", "good").await;
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers.get("retry-after").unwrap(), "17");
}

#[pollster::test]
async fn clean_join_defers_the_confirm_mail() {
    let kit = TestHarness::with_ports(vec![Box::new(module())], |ports| {
        ports.captcha = Some(Arc::new(FakeCaptcha::with_tokens(["good"])));
    });
    let response = join(&kit, "nick@example.com", "keepshipping", "good").await;
    assert_eq!(response.status, StatusCode::ACCEPTED);
    kit.defer.drain().await;
    let sent = kit.mailer.sent();
    assert_eq!(sent.len(), 1, "exactly the join mail: {sent:?}");
    assert!(sent[0].to.contains("nick@example.com"), "{sent:?}");
}

#[pollster::test]
async fn not_configured_mailer_still_captures_the_join() {
    // The deployment before the Resend subdomain is verified: no mail can
    // flow, but the waitlist must not silently drop signups.
    let kit = TestHarness::with_ports(vec![Box::new(module())], |ports| {
        ports.captcha = Some(Arc::new(FakeCaptcha::with_tokens(["good"])));
        ports.mailer = Some(Arc::new(FakeMailer::new(MailerMode::NotConfigured)));
    });
    let response = join(&kit, "nick@example.com", "keepshipping", "good").await;
    assert_eq!(
        response.status,
        StatusCode::ACCEPTED,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    kit.defer.drain().await;
    assert!(kit.mailer.sent().is_empty());
    assert_eq!(entry_status(&kit, "nick@example.com").as_deref(), Some("pending"));
}

#[test]
fn the_venture_names_the_site_and_shares_the_origin_list() {
    let venture = venture();
    assert_eq!(venture.name, "keepshipping-waitlist");
    assert_eq!(venture.domain, "keepshipping.run");
    assert_eq!(venture.cors_origins, SITE_ORIGINS, "CORS allowlist and write guard share one list");
}
