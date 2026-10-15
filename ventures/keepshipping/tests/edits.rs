//! The edit-as-code console (issue #170) through the venture's own
//! composition ([`keepshipping_waitlist::edits_module`]) with GitHub behind
//! a scripted HTTP fake: a DNS form becomes one pull request (exactly the
//! five REST calls, one additive file, no dispatch), the CI plan callback
//! stores the plan in words, approval fires the `repository_dispatch` with
//! the plan's digest, an approval that names a stale plan is refused, a
//! plan that removes anything demands the zone typed back, signed-out
//! callers get a page rather than a stack trace, and a bad form re-renders
//! with plain-word errors.

use cratefield_core::axum::body::{Body, Bytes};
use cratefield_core::{HttpError, MapConfig, Ports, Statement};
use cratefield_testing::{FakeAuth, FakeHttpClient, TestHarness, request_as};
use http::{Method, StatusCode};
use keepshipping_waitlist::{edits_module, venture};
use serde_json::{Value, json};
use std::sync::Arc;

const RUNNER_TOKEN: &str = "runner-token-test";

/// The five GitHub answers one pull-request open consumes: the base
/// branch's head, the new branch, the file's (missing) blob, the file
/// commit, and the pull request itself.
fn github_opens_a_pull_request() -> Vec<Result<http::Response<Bytes>, HttpError>> {
    vec![
        ok_json(200, r#"{"object":{"sha":"basemainsha000000000000000000000000000"}}"#),
        ok_json(201, r#"{}"#),
        empty(404), // the edit file does not exist yet — nothing to overwrite
        ok_json(201, r#"{"content":{}}"#),
        ok_json(
            201,
            r#"{"number":7,"html_url":"https://github.com/keepshipping/infra/pull/7",
                "head":{"sha":"prheadsha00000000000000000000000000000000"}}"#,
        ),
    ]
}

fn ok_json(status: u16, body: &str) -> Result<http::Response<Bytes>, HttpError> {
    http::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Bytes::from(body.to_owned()))
        .map_err(|err| HttpError::Transport(err.to_string()))
}

fn empty(status: u16) -> Result<http::Response<Bytes>, HttpError> {
    http::Response::builder()
        .status(status)
        .body(Bytes::new())
        .map_err(|err| HttpError::Transport(err.to_string()))
}

/// A kit mounting only the edits module over the venture composition, with
/// fake auth (the bearer token is the caller's id) and the scripted fake
/// behind the module's `HttpClient` port. `patch` overrides anything —
/// including the config, for the no-token postures.
fn kit(
    responses: Vec<Result<http::Response<Bytes>, HttpError>>,
    patch: impl FnOnce(&mut Ports),
) -> (TestHarness, FakeHttpClient) {
    let http = FakeHttpClient::scripted(responses);
    let harness = TestHarness::with_builder(
        vec![Box::new(edits_module())],
        |builder| builder.venture(venture()),
        |ports| {
            ports.auth = Some(Arc::new(FakeAuth::subjects()));
            ports.http = Some(Arc::new(http.clone()));
            ports.config = Arc::new(MapConfig::from_pairs([
                ("EDITS_REPO", "keepshipping/infra"),
                ("EDITS_BASE_BRANCH", "main"),
                ("EDITS_GITHUB_TOKEN", "gh-token-test"),
                ("EDITS_RUNNER_TOKEN", RUNNER_TOKEN),
            ]));
            patch(ports);
        },
    );
    (harness, http)
}

/// Posts a form body (`a=1&b=2`) as a signed-in caller would from the
/// console; returns status, headers and the body text.
async fn post_form(
    kit: &TestHarness,
    path: &str,
    bearer: &str,
    form: &str,
) -> (StatusCode, cratefield_core::axum::http::HeaderMap, String) {
    use tower::ServiceExt;
    let request = http::Request::builder()
        .method(Method::POST)
        .uri(path)
        .header("authorization", format!("Bearer {bearer}"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form.to_owned()))
        .expect("the form request builds");
    let response = kit.router.clone().oneshot(request).await.expect("the router answers");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = cratefield_core::axum::body::to_bytes(response.into_body(), 1_048_576)
        .await
        .expect("the body reads");
    (status, headers, String::from_utf8_lossy(&bytes).into_owned())
}

/// The edit id a create redirected to.
fn created_id(headers: &cratefield_core::axum::http::HeaderMap) -> String {
    headers
        .get("location")
        .and_then(|value| value.to_str().ok())
        .and_then(|location| location.rsplit('/').next())
        .unwrap_or_default()
        .to_owned()
}

/// GET as a signed-in caller.
async fn get_as(kit: &TestHarness, path: &str, bearer: &str) -> (StatusCode, String) {
    let response = request_as(&kit.router, Method::GET, path, bearer, None).await;
    (response.status, String::from_utf8_lossy(response.body()).into_owned())
}

/// One column of the edit's row, as text (integers included).
fn edit_field(kit: &TestHarness, id: &str, column: &str) -> String {
    let rows = pollster::block_on(kit.db.query(&Statement::with_values(
        format!("SELECT CAST({column} AS TEXT) AS value FROM edits WHERE id = ?"),
        vec![id.into()],
    )))
    .expect("the edit row reads");
    rows.first().map(|row| row.get::<String>("value").unwrap_or_default()).unwrap_or_default()
}

/// Every outbox row as `(id, topic, payload)`.
fn outbox(kit: &TestHarness) -> Vec<(String, String, String)> {
    let rows = pollster::block_on(kit.db.query(&Statement::new(
        "SELECT id, topic, payload FROM edits_outbox ORDER BY rowid".to_owned(),
    )))
    .expect("the outbox reads");
    rows.rows
        .iter()
        .map(|row| {
            (
                row.get::<String>("id").unwrap_or_default(),
                row.get::<String>("topic").unwrap_or_default(),
                row.get::<String>("payload").unwrap_or_default(),
            )
        })
        .collect()
}

/// The DNS form every flow starts from.
const DNS_FORM: &str = "kind=dns&zone=example.com&name=www&rtype=A&content=192.0.2.10&ttl=1";

/// Creates one DNS edit and drains its pull request open; returns the edit
/// id. The kit must have been built with [`github_opens_a_pull_request`].
async fn a_dns_edit_underway(kit: &TestHarness) -> String {
    let (status, headers, _) = post_form(kit, "/v1/edits", "person_1", DNS_FORM).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "the form submits to a redirect");
    let id = created_id(&headers);
    assert!(id.starts_with("01"), "the id is a ULID: {id}");
    kit.defer.drain().await;
    id
}

/// The plan body the workflow posts for an additive change, and a plan that
/// removes an existing record (the red path).
fn plan_json(actions: &[&str], before_after: Value) -> String {
    json!({
        "head_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "plan": { "resource_changes": [{
            "address": "cloudflare_dns_record.www",
            "change": { "actions": actions, "before": before_after, "after": before_after },
        }]},
    })
    .to_string()
}

async fn post_plan(kit: &TestHarness, id: &str, token: &str, body: &str) -> (StatusCode, Value) {
    use tower::ServiceExt;
    let request = http::Request::builder()
        .method(Method::POST)
        .uri(format!("/v1/edits/{id}/plan"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .expect("the plan request builds");
    let response = kit.router.clone().oneshot(request).await.expect("the router answers");
    let status = response.status();
    let bytes = cratefield_core::axum::body::to_bytes(response.into_body(), 1_048_576)
        .await
        .expect("the body reads");
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

#[test]
fn a_dns_form_becomes_one_pull_request_and_nothing_else() {
    pollster::block_on(async {
        let (kit, http) = kit(github_opens_a_pull_request(), |_| {});
        let id = a_dns_edit_underway(&kit).await;

        // The pull request is the only write: exactly five REST calls, and
        // no dispatch has been fired — approval has not happened yet.
        let calls = http.captured();
        assert_eq!(calls.len(), 5, "{calls:#?}");
        assert!(calls[0].1.ends_with("/repos/keepshipping/infra/git/ref/heads/main"));
        assert!(calls[1].1.ends_with("/repos/keepshipping/infra/git/refs"));
        assert!(
            calls[2].1.contains(&format!(
                "/contents/modules%2Fexample_com%2Fedit-{}.tf",
                id.to_lowercase()
            ))
        );
        assert!(calls[4].1.ends_with("/repos/keepshipping/infra/pulls"));
        assert!(!calls.iter().any(|(_, uri, _)| uri.contains("/dispatches")));

        // The committed file decodes to exactly one additive DNS resource.
        use base64::Engine as _;
        let put: Value = serde_json::from_str(&calls[3].2).expect("the PUT body is JSON");
        let engine = base64::engine::general_purpose::STANDARD;
        let committed = String::from_utf8(
            engine
                .decode(put["content"].as_str().expect("the file content"))
                .expect("the commit is base64"),
        )
        .expect("the commit is UTF-8");
        assert_eq!(committed.matches("resource \"cloudflare_dns_record\"").count(), 1);
        assert!(committed.contains("name = \"www.example.com\""), "{committed}");
        assert!(committed.contains("content = \"192.0.2.10\""), "{committed}");
        assert!(committed.contains("zone_id = data.cloudflare_zone.ks_edit_zone.id"));

        // The row moved on: awaiting the plan, linked to pull request #7.
        assert_eq!(edit_field(&kit, &id, "status"), "awaiting");
        assert_eq!(edit_field(&kit, &id, "pr_number"), "7");
        assert_eq!(
            edit_field(&kit, &id, "pr_head_sha"),
            "prheadsha00000000000000000000000000000000"
        );

        // The page says so in words, and links the pull request.
        let (status, body) = get_as(&kit, &format!("/v1/edits/{id}"), "person_1").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Checking the plan"), "{body}");
        assert!(body.contains("Pull request #7 on GitHub"), "{body}");
        assert!(body.contains("Waiting for the plan"), "{body}");
    });
}

#[test]
fn a_plan_arrives_then_approval_fires_one_dispatch() {
    pollster::block_on(async {
        let mut responses = github_opens_a_pull_request();
        responses.push(empty(204)); // the repository_dispatch
        let (kit, http) = kit(responses, |_| {});
        let id = a_dns_edit_underway(&kit).await;

        // Nothing to approve before the plan arrives.
        let (status, _, body) =
            post_form(&kit, &format!("/v1/edits/{id}/approve"), "person_1", "").await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        // The delivered open_pr row is gone; nothing else has been queued.
        assert!(
            outbox(&kit).iter().all(|(_, topic, _)| topic != "github.repository_dispatch"),
            "{:#?}",
            outbox(&kit)
        );

        // The callback authenticates a machine, not a person.
        let plan_body = plan_json(
            &["create"],
            json!({"name":"www.example.com","content":"192.0.2.10","type":"A"}),
        );
        let (status, _) = post_plan(&kit, &id, "the-wrong-token", &plan_body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, body) = post_plan(&kit, &id, RUNNER_TOKEN, r#"{"plan":{}}"#).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(http.captured().len(), 5, "a refused callback calls GitHub never");

        // The real callback stores the plan and the body's digest.
        let (status, body) = post_plan(&kit, &id, RUNNER_TOKEN, &plan_body).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ok"], json!(true));
        assert_eq!(edit_field(&kit, &id, "status"), "planned");
        assert_eq!(edit_field(&kit, &id, "pr_head_sha"), "a".repeat(40));
        let stored_digest = edit_field(&kit, &id, "plan_sha256");
        assert_eq!(stored_digest.len(), 64);

        // The detail page reads the plan in words and offers approval,
        // carrying the plan's digest in the form.
        let (status, page) = get_as(&kit, &format!("/v1/edits/{id}"), "person_1").await;
        assert_eq!(status, StatusCode::OK);
        assert!(page.contains("Ready for approval"), "{page}");
        assert!(page.contains("1 to add"), "{page}");
        assert!(page.contains("Add the DNS record"), "{page}");
        assert!(page.contains("Approve and apply"), "{page}");
        assert!(page.contains("name=\"saw\""), "{page}");

        // Approval and its dispatch enqueue in one batch.
        let (status, _, body) = post_form(
            &kit,
            &format!("/v1/edits/{id}/approve"),
            "person_1",
            &format!("saw={stored_digest}"),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
        assert_eq!(edit_field(&kit, &id, "status"), "approved");
        assert_eq!(edit_field(&kit, &id, "approver"), "person_1");
        let queued = outbox(&kit);
        assert_eq!(queued.len(), 1, "{queued:#?}");
        assert_eq!(queued[0].0, format!("{id}:dispatch"));
        assert_eq!(queued[0].1, "github.repository_dispatch");

        // An approved edit refuses further plans: the plan is frozen.
        let (status, _) = post_plan(&kit, &id, RUNNER_TOKEN, &plan_body).await;
        assert_eq!(status, StatusCode::CONFLICT);

        // The drain delivers exactly one dispatch, carrying the digest.
        kit.defer.drain().await;
        let calls = http.captured();
        assert_eq!(calls.len(), 6, "{calls:#?}");
        assert!(calls[5].1.ends_with("/repos/keepshipping/infra/dispatches"));
        let dispatch: Value = serde_json::from_str(&calls[5].2).expect("the dispatch body");
        assert_eq!(dispatch["event_type"], json!("keepshipping-edit-approved"));
        assert_eq!(dispatch["client_payload"]["edit_id"], json!(id));
        assert_eq!(dispatch["client_payload"]["pr_number"], json!(7));
        assert_eq!(dispatch["client_payload"]["plan_sha256"], json!(stored_digest));
        assert_eq!(dispatch["client_payload"]["approver"], json!("person_1"));
        assert_eq!(dispatch["client_payload"]["zone"], json!("example.com"));
    });
}

#[test]
fn a_plan_that_removes_demands_the_zone_typed_back() {
    pollster::block_on(async {
        let mut responses = github_opens_a_pull_request();
        responses.push(empty(204)); // the repository_dispatch, after confirmation
        let (kit, http) = kit(responses, |_| {});
        let id = a_dns_edit_underway(&kit).await;

        let removal = json!({
            "head_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "plan": { "resource_changes": [{
                "address": "cloudflare_dns_record.legacy",
                "change": { "actions": ["delete"],
                    "before": {"name":"legacy.example.com","content":"192.0.2.51","type":"A"},
                    "after": null },
            }]},
        })
        .to_string();
        let (status, _) = post_plan(&kit, &id, RUNNER_TOKEN, &removal).await;
        assert_eq!(status, StatusCode::OK);
        let digest = edit_field(&kit, &id, "plan_sha256");

        // The page turns the removal red and asks for the zone's name.
        let (_, page) = get_as(&kit, &format!("/v1/edits/{id}"), "person_1").await;
        assert!(page.contains("1 to remove"), "{page}");
        assert!(page.contains("Remove the DNS record"), "{page}");
        assert!(page.contains("Removes things — check carefully"), "{page}");
        assert!(page.contains("This plan removes things."), "{page}");
        assert!(page.contains("Type the zone name to confirm"), "{page}");
        assert!(page.contains("class=\"danger\""), "{page}");

        // Approving without the typed name is refused and changes nothing.
        let (status, _, body) = post_form(
            &kit,
            &format!("/v1/edits/{id}/approve"),
            "person_1",
            &format!("saw={digest}&confirm=wrong"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.contains("Type the zone name"), "{body}");
        assert_eq!(edit_field(&kit, &id, "status"), "planned");
        assert!(outbox(&kit).is_empty(), "no dispatch was queued: {:#?}", outbox(&kit));

        // With the zone typed back, approval goes through end to end.
        let (status, _, body) = post_form(
            &kit,
            &format!("/v1/edits/{id}/approve"),
            "person_1",
            &format!("saw={digest}&confirm=example.com"),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
        assert_eq!(edit_field(&kit, &id, "status"), "approved");
        kit.defer.drain().await;
        let calls = http.captured();
        assert_eq!(calls.len(), 6, "{calls:#?}");
        assert!(calls[5].1.ends_with("/repos/keepshipping/infra/dispatches"));
    });
}

#[test]
fn an_approval_stale_against_the_plan_is_refused() {
    pollster::block_on(async {
        let mut responses = github_opens_a_pull_request();
        responses.push(empty(204)); // the repository_dispatch, after the fresh approval
        let (kit, http) = kit(responses, |_| {});
        let id = a_dns_edit_underway(&kit).await;
        let plan_body = plan_json(
            &["create"],
            json!({"name":"www.example.com","content":"192.0.2.10","type":"A"}),
        );
        let (status, _) = post_plan(&kit, &id, RUNNER_TOKEN, &plan_body).await;
        assert_eq!(status, StatusCode::OK);

        // A form built from an older page carries a digest no current plan
        // matches: refused with the page that says to look again — the plan
        // may have moved on since it was rendered.
        let (status, _, body) =
            post_form(&kit, &format!("/v1/edits/{id}/approve"), "person_1", "saw=deadbeef").await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(body.contains("The plan changed"), "{body}");
        assert_eq!(edit_field(&kit, &id, "status"), "planned");
        assert!(outbox(&kit).is_empty(), "no dispatch was queued: {:#?}", outbox(&kit));
        assert_eq!(http.captured().len(), 5, "GitHub hears nothing");

        // The digest the page itself carries approves.
        let digest = edit_field(&kit, &id, "plan_sha256");
        let (status, _, body) = post_form(
            &kit,
            &format!("/v1/edits/{id}/approve"),
            "person_1",
            &format!("saw={digest}"),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
        assert_eq!(edit_field(&kit, &id, "status"), "approved");
    });
}

#[test]
fn signed_out_callers_get_the_sign_in_page_not_a_stack_trace() {
    pollster::block_on(async {
        let (kit, _) = kit(github_opens_a_pull_request(), |_| {});
        for (status, body) in [
            get_as(&kit, "/v1/edits", "").await,
            get_as(&kit, "/v1/edits/new?kind=dns", "").await,
            get_as(&kit, "/v1/edits/some-id", "").await,
        ] {
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert!(body.contains("Sign in to continue"), "{body}");
            // The console's own sign-in, coming straight back here.
            assert!(body.contains("href=\"/console/login?next=%2Fv1%2Fedits"), "{body}");
            // No way back to a list that would only 401 too.
            assert!(!body.contains("All changes"), "{body}");
        }
        let (status, _, body) = post_form(&kit, "/v1/edits", "", DNS_FORM).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        let (status, _, body) = post_form(&kit, "/v1/edits/some-id/approve", "", "").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(outbox(&kit).len(), 0, "nothing was queued for strangers");
    });
}

#[test]
fn a_bad_form_renders_again_with_its_errors_in_words() {
    pollster::block_on(async {
        let (kit, http) = kit(vec![], |_| {});
        let (status, _, body) = post_form(
            &kit,
            "/v1/edits",
            "person_1",
            "kind=dns&zone=example.com&name=www&rtype=NS&content=not an ip&ttl=1",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.contains("Record type must be one of"), "{body}");
        assert!(body.contains("value=\"not an ip\""), "the typed content is carried back: {body}");
        assert_eq!(outbox(&kit).len(), 0, "a refused form writes nothing");
        assert!(http.captured().is_empty());

        // An unknown kind never becomes a row either.
        let (status, _, _) =
            post_form(&kit, "/v1/edits", "person_1", "kind=teleport&zone=example.com").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(outbox(&kit).len(), 0);
    });
}

#[test]
fn without_a_github_token_the_queue_waits_instead_of_failing() {
    pollster::block_on(async {
        let (kit, http) = kit(vec![], |ports| {
            ports.config = Arc::new(MapConfig::from_pairs([
                ("EDITS_REPO", "keepshipping/infra"),
                ("EDITS_BASE_BRANCH", "main"),
                ("EDITS_RUNNER_TOKEN", RUNNER_TOKEN),
                // No EDITS_GITHUB_TOKEN on purpose.
            ]));
        });
        let (status, headers, _) = post_form(&kit, "/v1/edits", "person_1", DNS_FORM).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let id = created_id(&headers);
        assert_eq!(edit_field(&kit, &id, "status"), "opening");

        // The drain has nothing it may send, so it sends nothing.
        kit.defer.drain().await;
        assert!(http.captured().is_empty(), "{:?}", http.captured());
        assert_eq!(edit_field(&kit, &id, "status"), "opening");
        // The page still tells the truth about where things stand.
        let (_, body) = get_as(&kit, &format!("/v1/edits/{id}"), "person_1").await;
        assert!(body.contains("Opening the pull request"), "{body}");
    });
}

#[test]
fn the_list_page_shows_every_change_and_its_chip() {
    pollster::block_on(async {
        let (kit, _) = kit(github_opens_a_pull_request(), |_| {});
        let (status, body) = get_as(&kit, "/v1/edits", "person_1").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("No changes yet"), "{body}");
        assert!(body.contains("Make a change"), "{body}");
        assert!(body.contains("/v1/edits/new?kind=dns"), "{body}");

        let (_, headers, _) = post_form(&kit, "/v1/edits", "person_1", DNS_FORM).await;
        let id = created_id(&headers);
        let (_, body) = get_as(&kit, "/v1/edits", "person_1").await;
        assert!(body.contains(&format!("/v1/edits/{id}")), "{body}");
        assert!(body.contains("DNS record www.example.com (A)"), "{body}");

        // An unknown kind renders the chooser rather than guessing.
        let (status, body) = get_as(&kit, "/v1/edits/new?kind=teleport", "person_1").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Make a change"), "{body}");
    });
}
