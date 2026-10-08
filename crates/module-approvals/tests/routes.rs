//! The acceptance surface for issue #147: park a step, review it, decide it,
//! and let the decision reach the run. Every refusal the module owes a caller
//! is driven from here too, because a check nothing reaches is a check that
//! stopped working without anybody noticing.

use cratefield_core::axum::http::{Method, StatusCode};
use cratefield_core::{
    HttpClient, HttpError, MapConfig, ModuleContext, Ports, Realtime, Statement,
};
use cratefield_testing::{
    FakeAuth, FakeHttpClient, FakeRealtime, TestHarness, TestResponse as Response, request,
    request_as,
};
use ks_module_approvals::{Approvals, SUMMARY_LIMIT_BYTES};
use serde_json::Value;
use std::ops::Deref;
use std::sync::Arc;

const RUNNER_TOKEN: &str = "runner-token-0123456789abcdef";
const PUBLIC_BASE: &str = "https://approvals.test.example";
const PROPOSER: &str = "ada";
const APPROVER: &str = "grace";
const PLAN_DIGEST: &str = "bb7479d35a1954f0f67e3e7ff2316ad5c11e0a20ff3d8f67a3b31b6fdbca9e33";
const RUN: &str = "1700000000001";

/// What GitHub answers, in the order the module asks.
type Script = Vec<Result<http::Response<bytes::Bytes>, HttpError>>;

fn json_response(
    status: u16,
    body: &'static str,
) -> Result<http::Response<bytes::Bytes>, HttpError> {
    Ok(http::Response::builder()
        .status(status)
        .body(bytes::Bytes::from_static(body.as_bytes()))
        .expect("a response builds"))
}

/// GitHub saying the login is on the team, then accepting a dispatch.
fn agreed() -> Script {
    vec![json_response(200, r#"{"state":"active","role":"member"}"#), json_response(204, "")]
}

/// The harness, plus the two port handles whose recorded traffic the tests
/// assert on. The handles are shared with the router's own copies, so what a
/// handler did is what the test reads.
struct Kit {
    harness: TestHarness,
    http: Arc<FakeHttpClient>,
    realtime: Arc<FakeRealtime>,
}

impl Deref for Kit {
    type Target = TestHarness;

    fn deref(&self) -> &TestHarness {
        &self.harness
    }
}

/// The deployment this module runs under: four secrets, the prefix the review
/// links are built under, and the one organisation it hosts — spelled in a
/// different case from the repo owner, because GitHub org names are not case
/// sensitive and this list must agree. Dummy values, never real.
fn config() -> MapConfig {
    MapConfig::from_pairs([
        ("APPROVALS_RUNNER_TOKEN", RUNNER_TOKEN),
        ("APPROVALS_SIGNING_SECRET", "signing-secret-0123456789abcdef"),
        ("APPROVALS_GITHUB_TOKEN", "gh-token-0123456789abcdef"),
        ("APPROVALS_PUBLIC_BASE_URL", PUBLIC_BASE),
        ("APPROVALS_GITHUB_ORGS", "keep-shipping"),
    ])
}

/// A configured kit: a login-bearing auth port, a live room, and a GitHub that
/// answers `script`.
fn kit(script: Script) -> Kit {
    let http = Arc::new(FakeHttpClient::scripted(script));
    let realtime = Arc::new(FakeRealtime::new());
    let (http_port, realtime_port) = (Arc::clone(&http), Arc::clone(&realtime));
    let harness = TestHarness::with_ports(vec![Box::new(Approvals::new())], move |ports| {
        ports.config = Arc::new(config());
        ports.auth = Some(Arc::new(FakeAuth::subjects()));
        ports.realtime = Some(Arc::clone(&realtime_port) as Arc<dyn Realtime>);
        ports.http = Some(Arc::clone(&http_port) as Arc<dyn HttpClient>);
    });
    Kit { harness, http, realtime }
}

/// The same kit with one more configuration key, for the settings a test is
/// about.
fn kit_with(script: Script, extra: [(&str, &str); 1]) -> Kit {
    let http = Arc::new(FakeHttpClient::scripted(script));
    let realtime = Arc::new(FakeRealtime::new());
    let (http_port, realtime_port) = (Arc::clone(&http), Arc::clone(&realtime));
    let harness = TestHarness::with_ports(vec![Box::new(Approvals::new())], move |ports| {
        ports.config = Arc::new(MapConfig::from_pairs([
            ("APPROVALS_RUNNER_TOKEN", RUNNER_TOKEN),
            ("APPROVALS_GITHUB_TOKEN", "gh-token-0123456789abcdef"),
            ("APPROVALS_PUBLIC_BASE_URL", PUBLIC_BASE),
            ("APPROVALS_GITHUB_ORGS", "keep-shipping"),
            ("APPROVALS_SIGNING_SECRET", "signing-secret-0123456789abcdef"),
            extra[0],
        ]));
        ports.auth = Some(Arc::new(FakeAuth::subjects()));
        ports.realtime = Some(Arc::clone(&realtime_port) as Arc<dyn Realtime>);
        ports.http = Some(Arc::clone(&http_port) as Arc<dyn HttpClient>);
    });
    Kit { harness, http, realtime }
}

/// A `POST /requests` body with the given summary and TTL.
fn request_body(summary: &str, ttl_secs: u64) -> Value {
    serde_json::json!({
        "run_id": RUN,
        "repo": "Keep-Shipping/harness",
        "step": "apply",
        "summary": summary,
        "artifacts": [{"name": "main.tfplan", "sha256": PLAN_DIGEST}],
        "team": "keep-shipping/platform",
        "proposed_by": PROPOSER,
        "reason": "the production database is in the plan",
        "ttl_secs": ttl_secs,
    })
}

/// `/v1/approvals/requests/{ticket}[/decision]`, the one place the mount path
/// is spelled.
fn path(ticket: &str, tail: &str) -> String {
    format!("/v1/approvals/requests/{ticket}{tail}")
}

async fn park_json(kit: &Kit, body: &Value) -> Response {
    let body = body.to_string();
    request_as(&kit.router, Method::POST, "/v1/approvals/requests", RUNNER_TOKEN, Some(&body)).await
}

async fn park(kit: &Kit, summary: &str) -> Response {
    park_json(kit, &request_body(summary, 3600)).await
}

async fn read(kit: &Kit, ticket: &str) -> Value {
    request_as(&kit.router, Method::GET, &path(ticket, ""), RUNNER_TOKEN, None).await.json()
}

/// Parks one step and answers with its ticket.
async fn park_and_name(kit: &Kit) -> String {
    let created = park(kit, "1 to create").await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(created.body()));
    created.json()["ticket"].as_str().expect("a ticket").to_owned()
}

async fn decide(kit: &Kit, ticket: &str, approver: &str, decision: &str) -> Response {
    let body = serde_json::json!({"decision": decision, "comment": "looks right"}).to_string();
    request_as(&kit.router, Method::POST, &path(ticket, "/decision"), approver, Some(&body)).await
}

/// A decision posted with whatever `Content-Type` and `Origin` a browser — or
/// a `fetch` with `mode: "no-cors"` — would send. Driven by hand because the
/// kit's own helper only ever sends JSON, and it answers with the status and
/// body directly because `TestResponse` cannot be built outside the kit.
async fn raw_decide(
    kit: &Kit,
    ticket: &str,
    approver: &str,
    content_type: &str,
    origin: Option<&str>,
    body: &str,
) -> (StatusCode, Vec<u8>) {
    use cratefield_core::axum::body::{Body, to_bytes};
    use tower::ServiceExt;

    let mut builder = http::Request::builder()
        .method(Method::POST)
        .uri(path(ticket, "/decision"))
        .header("authorization", format!("Bearer {approver}"))
        .header("content-type", content_type);
    if let Some(origin) = origin {
        builder = builder.header("origin", origin);
    }
    let request = builder.body(Body::from(body.to_owned())).expect("a request builds");
    let response = kit.router.clone().oneshot(request).await.expect("the router answers");
    let (parts, body) = response.into_parts();
    (parts.status, to_bytes(body, 64 * 1024).await.expect("the body reads").to_vec())
}

async fn form_decide(
    kit: &Kit,
    ticket: &str,
    approver: &str,
    origin: Option<&str>,
) -> (StatusCode, Vec<u8>) {
    raw_decide(
        kit,
        ticket,
        approver,
        "application/x-www-form-urlencoded",
        origin,
        "decision=approve&comment=looks+right",
    )
    .await
}

/// Runs the scheduled drain once, against the same ports the router saw.
async fn drain(kit: &Kit) {
    let mut ports = Ports::with_config(Arc::new(config()));
    ports.db = Some(kit.db.clone());
    ports.clock = Some(Arc::new(kit.clock.clone()));
    ports.http = Some(Arc::clone(&kit.http) as Arc<dyn HttpClient>);
    let ctx: ModuleContext = kit.harness.harness.module_context(&*kit.modules[0], &ports);
    kit.modules[0].scheduled(&ctx, "* * * * *").await.expect("the drain succeeds");
}

/// The slug a problem body carries, from its `type` URI.
fn slug(body: &Value) -> String {
    body["type"].as_str().unwrap_or_default().rsplit('/').next().unwrap_or_default().to_owned()
}

#[pollster::test]
async fn a_team_member_approves_and_the_run_is_told() {
    let kit = kit(agreed());
    // A summary carrying the five characters an HTML text node ends on: a page
    // that rendered this raw would be a stored XSS with an approve button.
    let hostile = "<script>alert(\"x\")</script> & 'quoted' plan";

    let created = park(&kit, hostile).await;
    assert_eq!(created.status, StatusCode::CREATED);
    let created = created.json();
    let ticket = created["ticket"].as_str().expect("a ticket").to_owned();
    assert_eq!(created["review_url"], format!("{PUBLIC_BASE}{}", path(&ticket, "/review")));
    assert!(created["expires_at"].as_str().is_some_and(|stamp| stamp.ends_with('Z')));

    let pending = read(&kit, &ticket).await;
    assert_eq!(pending["state"], "pending");
    assert!(pending.get("decision").is_none());

    // The review page: escaped, and only for somebody signed in.
    let review = path(&ticket, "/review");
    let anonymous = request(&kit.router, Method::GET, &review, None).await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    assert_eq!(slug(&anonymous.json()), "unauthenticated");

    let page = request_as(&kit.router, Method::GET, &review, APPROVER, None).await;
    assert_eq!(page.status, StatusCode::OK);
    assert_eq!(
        page.headers.get("content-type").and_then(|value| value.to_str().ok()),
        Some("text/html; charset=utf-8")
    );
    let html = String::from_utf8(page.body().to_vec()).expect("the page is UTF-8");
    assert!(
        html.contains("&lt;script&gt;") && !html.contains("<script>"),
        "the summary is escaped:\n{html}"
    );
    for shown in [PLAN_DIGEST, "keep-shipping/platform", "value=\"approve\""] {
        assert!(html.contains(shown), "the page should show {shown}:\n{html}");
    }

    // The click.
    let decided = decide(&kit, &ticket, APPROVER, "approve").await;
    assert_eq!(decided.status, StatusCode::OK, "{}", String::from_utf8_lossy(decided.body()));
    let decided = decided.json();
    let signature = decided["decision"]["signature"].as_str().expect("a signature").to_owned();
    assert_eq!(signature.len(), 64, "HMAC-SHA256 as hex");

    // What the runner polls now.
    let state = read(&kit, &ticket).await;
    assert_eq!(state["state"], "approved");
    assert_eq!(state["decision"]["approver"], APPROVER);
    assert_eq!(state["decision"]["comment"], "looks right");
    assert_eq!(state["decision"]["signature"], signature.as_str());
    assert_eq!(state["artifacts"][0]["sha256"], PLAN_DIGEST);

    // The room was told, under this request's own room id.
    let broadcasts = kit.realtime.broadcasts();
    assert_eq!(broadcasts.len(), 1, "one announcement");
    assert_eq!(broadcasts[0].0, format!("approvals/{ticket}"));
    let announced: Value = serde_json::from_slice(&broadcasts[0].1).expect("JSON");
    assert_eq!(announced["decision"]["signature"], signature.as_str());

    // And the run is told by the outbox, once the drain runs.
    drain(&kit).await;
    let captured = kit.http.captured();
    assert_eq!(captured[0].0, "GET", "the membership lookup went out first");
    assert!(
        captured[0]
            .1
            .ends_with(&format!("/orgs/keep-shipping/teams/platform/memberships/{APPROVER}")),
        "{:?}",
        captured[0].1
    );
    let (method, uri, body) = &captured[captured.len() - 1];
    assert_eq!(method, "POST");
    assert_eq!(uri, "https://api.github.com/repos/Keep-Shipping/harness/dispatches");
    let dispatch: Value = serde_json::from_str(body).expect("a JSON dispatch");
    // GitHub documents only these two properties; anything else is a 422 risk.
    let mut keys: Vec<&str> =
        dispatch.as_object().expect("a JSON object").keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["client_payload", "event_type"]);
    assert_eq!(dispatch["event_type"], "keepshipping-approval");
    let payload = &dispatch["client_payload"];
    for (key, value) in [
        ("ticket", ticket.as_str()),
        ("run", RUN),
        ("repo", "Keep-Shipping/harness"),
        ("step", "apply"),
        ("decision", "approved"),
        ("approver", APPROVER),
        ("signature", signature.as_str()),
    ] {
        assert_eq!(payload[key], value, "the dispatch must carry {key}");
    }
    assert_eq!(payload["artifacts"][0]["sha256"], PLAN_DIGEST);

    // A drained outbox is empty: the work did not survive its delivery.
    let remaining =
        kit.db.query(&Statement::new("SELECT COUNT(*) AS n FROM approvals_outbox")).await;
    assert_eq!(remaining.expect("count").first().and_then(|row| row.get::<i64>("n")), Some(0));
}

#[pollster::test]
async fn a_denial_is_recorded_and_dispatched_as_a_denial() {
    let kit = kit(agreed());
    let ticket = park_and_name(&kit).await;

    assert_eq!(decide(&kit, &ticket, APPROVER, "deny").await.status, StatusCode::OK);
    let state = read(&kit, &ticket).await;
    assert_eq!(state["state"], "denied");
    assert_eq!(state["decision"]["decision"], "denied");

    drain(&kit).await;
    let captured = kit.http.captured();
    let dispatch: Value =
        serde_json::from_str(&captured[captured.len() - 1].2).expect("a JSON dispatch");
    assert_eq!(dispatch["client_payload"]["decision"], "denied");
    assert_eq!(kit.realtime.broadcasts().len(), 1);
}

#[pollster::test]
async fn nobody_but_an_active_team_member_may_decide() {
    // Each case scripts exactly what GitHub answers — including nothing at all
    // for the proposer, who is refused before any lookup happens.
    let cases = [
        ("the proposer", vec![], PROPOSER, "proposer-cannot-approve"),
        (
            "a stranger",
            vec![json_response(404, r#"{"message":"Not Found"}"#)],
            "stranger",
            "not-a-team-member",
        ),
        (
            "an invited newcomer",
            vec![json_response(200, r#"{"state":"pending"}"#)],
            "newcomer",
            "not-a-team-member",
        ),
    ];
    for (who, script, approver, expected) in cases {
        let kit = kit(script);
        let ticket = park_and_name(&kit).await;
        let refused = decide(&kit, &ticket, approver, "approve").await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "{who} was not refused");
        assert_eq!(slug(&refused.json()), expected, "{who}");
        assert_eq!(read(&kit, &ticket).await["state"], "pending", "{who} left a trace");
    }
}

#[pollster::test]
async fn an_expired_request_is_refused_and_reads_as_expired() {
    let kit = kit(vec![]);
    let ticket = park_and_name(&kit).await;

    // Expiry is the server's clock, so the only way to reach it in a test is to
    // age the stored deadline past it — a runner restating its own `expires_at`
    // is exactly what this check exists to stop.
    kit.db
        .execute(&Statement::with_values(
            "UPDATE approval_requests SET expires_at = ? WHERE ticket = ?",
            vec!["2020-01-01T00:00:00Z".into(), ticket.clone().into()],
        ))
        .await
        .expect("age the request");

    assert_eq!(read(&kit, &ticket).await["state"], "expired");
    let refused = decide(&kit, &ticket, APPROVER, "approve").await;
    assert_eq!(refused.status, StatusCode::GONE);
    assert_eq!(slug(&refused.json()), "approval-expired");
}

#[pollster::test]
async fn the_first_answer_stands() {
    let kit = kit([agreed(), vec![json_response(200, r#"{"state":"active"}"#)]].concat());
    let ticket = park_and_name(&kit).await;

    assert_eq!(decide(&kit, &ticket, APPROVER, "approve").await.status, StatusCode::OK);
    let second = decide(&kit, &ticket, "alan", "deny").await;
    assert_eq!(second.status, StatusCode::CONFLICT);
    assert_eq!(slug(&second.json()), "already-decided");
    assert_eq!(read(&kit, &ticket).await["state"], "approved");
}

#[pollster::test]
async fn the_runner_routes_need_the_deployment_token() {
    let kit = kit(vec![]);
    let body = request_body("1 to create", 3600).to_string();
    // Missing, wrong, and not-a-bearer all answer the same way.
    for bearer in [
        Option::<&str>::None,
        Some("runner-token-0123456789abcdeF"),
        Some("Basic runner"),
        Some(""),
    ] {
        let refused = match bearer {
            Some(bearer) => {
                request_as(&kit.router, Method::POST, "/v1/approvals/requests", bearer, Some(&body))
                    .await
            }
            None => request(&kit.router, Method::POST, "/v1/approvals/requests", Some(&body)).await,
        };
        assert_eq!(refused.status, StatusCode::UNAUTHORIZED, "{bearer:?} authenticated");
    }

    let unreadable =
        request_as(&kit.router, Method::GET, "/v1/approvals/requests/nope", RUNNER_TOKEN, None)
            .await;
    assert_eq!(unreadable.status, StatusCode::NOT_FOUND);
}

#[pollster::test]
async fn a_summary_over_the_hosted_ceiling_is_refused_by_name() {
    let kit = kit(vec![]);
    let refused = park(&kit, &"x".repeat(SUMMARY_LIMIT_BYTES + 1)).await;
    assert_eq!(refused.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        refused.headers.get("content-type").and_then(|value| value.to_str().ok()),
        Some("application/problem+json"),
        "the runner gets a problem, not axum's default text"
    );
    let problem = refused.json();
    assert_eq!(slug(&problem), "summary-too-large");
    // The detail and the extensions have to be enough for the runner to fix
    // this without reading the module's source.
    let detail = problem["detail"].as_str().expect("a detail");
    assert!(
        detail.contains(&SUMMARY_LIMIT_BYTES.to_string()) && detail.contains("HOSTED_BODY_LIMIT"),
        "{detail}"
    );
    assert_eq!(problem["limit"], SUMMARY_LIMIT_BYTES);
    assert_eq!(problem["size"], SUMMARY_LIMIT_BYTES + 1);

    // One byte under the ceiling is a working request.
    assert_eq!(park(&kit, &"x".repeat(SUMMARY_LIMIT_BYTES)).await.status, StatusCode::CREATED);
}

#[pollster::test]
async fn a_plan_rendered_at_the_hosted_limit_is_accepted() {
    use ks_core::plan_summary::{
        AttrValue, HOSTED_BODY_LIMIT, Limits, PlanChange, Target, summarize,
    };
    use ks_core::ports::iac::ChangeAction;

    // The coupling the module asks runners to honour, checked from this side: a
    // plan too big to render in full, rendered at `HOSTED_BODY_LIMIT`, is a
    // summary this module accepts.
    assert_eq!(SUMMARY_LIMIT_BYTES, HOSTED_BODY_LIMIT);
    let changes: Vec<PlanChange> = (0..800)
        .map(|index| PlanChange {
            address: format!("module.item[{index}].attribute"),
            actions: vec![ChangeAction::Update],
            attributes: vec![ks_core::plan_summary::AttributeChange {
                path: "value".to_owned(),
                before: AttrValue::Known("a".repeat(120)),
                after: AttrValue::Known("b".repeat(120)),
                sensitive: false,
                forces_replacement: false,
            }],
            reason: None,
        })
        .collect();
    let full = summarize(&changes);
    assert!(
        full.render(Target::Plain, &Limits::default()).len() > HOSTED_BODY_LIMIT,
        "this plan does not overflow on its own, so the test proves nothing"
    );
    let limits = Limits { max_bytes: Some(HOSTED_BODY_LIMIT), ..Limits::default() };
    let rendered = full.render(Target::Plain, &limits);
    assert!(rendered.len() <= HOSTED_BODY_LIMIT, "{} bytes", rendered.len());

    assert_eq!(park(&kit(vec![]), &rendered).await.status, StatusCode::CREATED);
}

#[pollster::test]
async fn runner_free_text_that_would_break_a_signature_or_a_url_is_refused() {
    // Every case is a shape a runner could send today and the module must not
    // accept: a newline or a comma would make two requests share one signature,
    // and a `?` or a second `/` would aim the token at another repository.
    let cases: [(&str, Value); 5] = [
        ("a newline in the step", serde_json::json!({"step": "apply\ndecision=approved"})),
        (
            "one digest written as two",
            serde_json::json!({"artifacts": [{"name": "p", "sha256": "aa,bb"}]}),
        ),
        ("a query in the team", serde_json::json!({"team": "org?x=1/slug"})),
        ("a repository we do not host", serde_json::json!({"repo": "elsewhere/harness"})),
        (
            "a team in a repository org we do not host",
            serde_json::json!({"team": "someone-else/platform"}),
        ),
    ];
    for (why, patch) in cases {
        let mut body = request_body("1 to create", 3600);
        for (key, value) in patch.as_object().expect("a patch") {
            body[key] = value.clone();
        }
        let refused = park_json(&kit(vec![]), &body).await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{why} was accepted");
        assert_eq!(slug(&refused.json()), "validation-failed", "{why}");
    }
}

#[pollster::test]
async fn a_form_decision_must_come_from_our_own_origin() {
    // The review page's form posts urlencoded, which any page on the internet
    // can make a browser send; the `Origin` is what separates the two.
    let cases = [
        (Some(PUBLIC_BASE), StatusCode::OK),
        (Some("https://evil.example"), StatusCode::FORBIDDEN),
        (Some("null"), StatusCode::FORBIDDEN),
        (None, StatusCode::FORBIDDEN),
    ];
    for (origin, expected) in cases {
        let kit = kit([agreed(), vec![json_response(204, "")]].concat());
        let ticket = park_and_name(&kit).await;
        let (status, body) = form_decide(&kit, &ticket, APPROVER, origin).await;
        assert_eq!(status, expected, "{origin:?}");
        if expected == StatusCode::FORBIDDEN {
            let problem: Value = serde_json::from_slice(&body).expect("a problem body");
            assert_eq!(slug(&problem), "cross-site-decision", "{origin:?}");
        }
    }
}

#[pollster::test]
async fn the_proposers_login_casing_does_not_help_them() {
    // GitHub logins are case-insensitive, so "Ada" parked this step.
    let kit = kit(vec![]);
    let refused = decide(&kit, &park_and_name(&kit).await, "Ada", "approve").await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(slug(&refused.json()), "proposer-cannot-approve");
}

#[pollster::test]
async fn a_github_outage_is_not_a_membership_refusal() {
    // A 502 must park the run and say so. Folding it into "not a member" would
    // tell a reviewer their team had refused them because of an outage.
    let kit = kit(vec![json_response(502, "upstream")]);
    let ticket = park_and_name(&kit).await;
    let refused = decide(&kit, &ticket, APPROVER, "approve").await;
    assert_eq!(refused.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(slug(&refused.json()), "membership-unchecked");
}

#[pollster::test]
async fn the_ttl_is_clamped_to_the_deployment_ceiling() {
    use time::format_description::well_known::Rfc3339 as RFC3339;

    let kit = kit_with(vec![], [("APPROVALS_MAX_TTL_SECS", "60")]);
    let ticket = park_and_name(&kit).await;
    let request = read(&kit, &ticket).await;
    let created =
        time::OffsetDateTime::parse(request["created_at"].as_str().unwrap(), &RFC3339).unwrap();
    let expires =
        time::OffsetDateTime::parse(request["expires_at"].as_str().unwrap(), &RFC3339).unwrap();
    // The runner asked for an hour and named a 7-day default; the deployment said 60.
    assert_eq!(expires - created, time::Duration::seconds(60));
}

#[pollster::test]
async fn a_permanently_refused_dispatch_is_dropped_rather_than_retried() {
    // GitHub answered 422, which will read the same in a minute's time. Retrying
    // for ever would park the run for ever over a payload nobody will accept.
    let kit = kit(vec![
        json_response(200, r#"{"state":"active"}"#),
        json_response(422, r#"{"message":"Validation Failed"}"#),
    ]);
    let ticket = park_and_name(&kit).await;
    assert_eq!(decide(&kit, &ticket, APPROVER, "approve").await.status, StatusCode::OK);

    drain(&kit).await;
    let remaining =
        kit.db.query(&Statement::new("SELECT COUNT(*) AS n FROM approvals_outbox")).await;
    assert_eq!(remaining.expect("count").first().and_then(|row| row.get::<i64>("n")), Some(0));
    assert_eq!(kit.http.captured().len(), 2, "one membership lookup and one dispatch, no retry");
}

#[pollster::test]
async fn only_json_and_our_own_origin_decide() {
    // `text/plain` needs no preflight, so a `fetch(..., {mode: "no-cors"})` from
    // anywhere would reach the JSON branch. It must not. And a JSON post with a
    // foreign `Origin` is a browser, so it is refused whatever the content type.
    let cases = [
        (
            "text/plain",
            Some(PUBLIC_BASE),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-media-type",
        ),
        ("text/plain", None, StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported-media-type"),
        (
            "application/json",
            Some("https://evil.example"),
            StatusCode::FORBIDDEN,
            "cross-site-decision",
        ),
        ("application/json; charset=utf-8", Some(PUBLIC_BASE), StatusCode::OK, ""),
        ("application/json", None, StatusCode::OK, ""),
    ];
    for (content_type, origin, expected, expected_slug) in cases {
        let kit = kit([agreed(), vec![json_response(204, "")]].concat());
        let ticket = park_and_name(&kit).await;
        let (status, body) =
            raw_decide(&kit, &ticket, APPROVER, content_type, origin, r#"{"decision":"approve"}"#)
                .await;
        assert_eq!(status, expected, "{content_type} from {origin:?}");
        if !expected_slug.is_empty() {
            let problem: Value = serde_json::from_slice(&body).expect("a problem body");
            assert_eq!(slug(&problem), expected_slug, "{content_type} from {origin:?}");
        }
    }
}

#[pollster::test]
async fn an_approver_that_is_not_a_login_is_refused_before_any_call() {
    // The subject id is interpolated into a GitHub URL, so a subject carrying a
    // slash must be refused before it reaches one.
    let kit = kit(agreed());
    let ticket = park_and_name(&kit).await;
    let refused = decide(&kit, &ticket, "ada/../x", "approve").await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(slug(&refused.json()), "approver-not-a-login");
    assert!(kit.http.captured().is_empty(), "nothing was asked of GitHub");
}

#[pollster::test]
async fn an_empty_signing_secret_decides_nothing() {
    // An HMAC keyed with the empty string is a signature anybody can reproduce.
    let kit = kit_with(agreed(), [("APPROVALS_SIGNING_SECRET", "")]);
    let ticket = park_and_name(&kit).await;
    let refused = decide(&kit, &ticket, APPROVER, "approve").await;
    assert_eq!(refused.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(slug(&refused.json()), "not-ready");
    assert_eq!(read(&kit, &ticket).await["state"], "pending");
    let queued = kit.db.query(&Statement::new("SELECT COUNT(*) AS n FROM approvals_outbox")).await;
    assert_eq!(queued.expect("count").first().and_then(|row| row.get::<i64>("n")), Some(0));
}
