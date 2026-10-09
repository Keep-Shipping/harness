//! The standard setup console (issue #273) through the venture's own
//! composition: the checklist's first view seeds sensible defaults, every
//! route demands a verified caller, one send makes one pull request (and
//! never two), live DNS flips the chips, and the honest paths — a hostile
//! value, GitHub not connected — behave as the pages promise.

use cratefield_core::axum::body::Bytes;
use cratefield_core::{Ports, Statement};
use cratefield_testing::{FakeAuth, FakeHttpClient, TestHarness, request, request_as};
use http::{Method, StatusCode};
use keepshipping_waitlist::{GitHubPullRequests, PullRequests, Setup, venture};
use serde_json::{Value, json};
use std::sync::Arc;

const DOMAIN: &str = "example.test";
const HERE: &str = "/v1/setup/example.test";

/// The checklist with everything selected and Google's DKIM key pasted —
/// the form the page posts (`application/x-www-form-urlencoded`; the
/// handlers read the body, not the content type).
const ALL_ON: &str = "search_console=on&postmaster=on&bing=on&spf=on&dkim=on&dmarc=on\
     &mta_sts=on&tls_rpt=on\
     &spf_value=v%3Dspf1+include%3A_spf.google.com+~all\
     &dkim_selector=google\
     &dkim_key=v%3DDKIM1%3B+k%3Drsa%3B+p%3DMIIBIjANBgkq\
     &dmarc_rua=mailto%3Admarc-reports%40example.test\
     &sitemap_url=https%3A%2F%2Fexample.test%2Fsitemap.xml";

/// A kit mounting the venture and the setup module exactly as `src/lib.rs`
/// composes them — `pr` is the pull-request seam (GitHub over the scripted
/// fake, or `None` for the unconnected console) and the same scripted fake
/// answers the module's DoH lookups.
fn kit(
    pr: Option<Arc<dyn PullRequests>>,
    http: FakeHttpClient,
    patch: impl FnOnce(&mut Ports),
) -> TestHarness {
    TestHarness::with_builder(
        vec![Box::new(Setup::new(pr))],
        |builder| builder.venture(venture()),
        |ports| {
            ports.auth = Some(Arc::new(FakeAuth::subjects()));
            ports.http = Some(Arc::new(http.clone()));
            patch(ports);
        },
    )
}

fn setup_pr(http: &FakeHttpClient) -> Arc<dyn PullRequests> {
    Arc::new(GitHubPullRequests::new(
        Arc::new(http.clone()),
        "keep-shipping/infra",
        "github_pat_test",
        "main",
    ))
}

fn json_response(body: &str) -> Result<http::Response<Bytes>, cratefield_core::HttpError> {
    Ok(http::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Bytes::from(body.to_owned()))
        .expect("a scripted response builds"))
}

/// One DoH answer carrying the given TXT chunks, quoted the way Cloudflare
/// frames them.
fn doh(records: &[&str]) -> Result<http::Response<Bytes>, cratefield_core::HttpError> {
    let answers: Vec<Value> = records
        .iter()
        .map(|data| json!({"name": "x.example.test", "type": 16, "data": format!("\"{data}\"")}))
        .collect();
    json_response(&json!({ "Status": 0, "Answer": answers }).to_string())
}

/// A DoH answer for a name with no records (asked and told no).
fn no_records() -> Result<http::Response<Bytes>, cratefield_core::HttpError> {
    json_response(r#"{"Status": 0, "Answer": []}"#)
}

/// A plain-text body — the MTA-STS policy fetch.
fn text_response(body: &str) -> Result<http::Response<Bytes>, cratefield_core::HttpError> {
    Ok(http::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain")
        .body(Bytes::from(body.to_owned()))
        .expect("a scripted response builds"))
}

/// The GitHub answers one pull request takes, in the order the client
/// makes them: the base ref, the branch, the file commit, the pull request.
fn github_script() -> Vec<Result<http::Response<Bytes>, cratefield_core::HttpError>> {
    vec![
        json_response(r#"{"ref": "refs/heads/main", "object": {"sha": "abc123"}}"#),
        json_response(r#"{"ref": "refs/heads/setup/x"}"#),
        json_response(r#"{"content": {"path": "dns.tf"}}"#),
        json_response(r#"{"html_url": "https://github.com/keep-shipping/infra/pull/9"}"#),
    ]
}

/// The same four calls with the pull request itself failing: the branch
/// and file commit land, the PR answers 500.
fn github_open_fails() -> Vec<Result<http::Response<Bytes>, cratefield_core::HttpError>> {
    vec![
        json_response(r#"{"ref": "refs/heads/main", "object": {"sha": "abc123"}}"#),
        json_response(r#"{"ref": "refs/heads/setup/x"}"#),
        json_response(r#"{"content": {"path": "dns.tf"}}"#),
        Ok(http::Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Bytes::from("no"))
            .expect("a scripted response builds")),
    ]
}

/// Five DoH answers for a domain where nothing is live yet: apex, dkim,
/// dmarc, mta-sts, tls-rpt — no policy fetch, the record is absent.
fn nothing_live_script() -> Vec<Result<http::Response<Bytes>, cratefield_core::HttpError>> {
    vec![no_records(), no_records(), no_records(), no_records(), no_records()]
}

/// The chips of the status answer, by item key.
async fn chips(kit: &TestHarness) -> Vec<(String, String)> {
    let response =
        request_as(&kit.router, Method::GET, &format!("{HERE}/status"), "acc_1", None).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.json());
    response.json()["items"]
        .as_array()
        .expect("items is an array")
        .iter()
        .map(|item| {
            (
                item["key"].as_str().expect("a key").to_owned(),
                item["chip"].as_str().expect("a chip").to_owned(),
            )
        })
        .collect()
}

fn chip_of(chips: &[(String, String)], key: &str) -> String {
    chips
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, chip)| chip.clone())
        .unwrap_or_else(|| panic!("no chip for {key}"))
}

// -------------------------------------------------------------------------
// The ten

#[pollster::test]
async fn a_first_view_seeds_the_checklist() {
    // Nothing stored yet: the GET seeds the row and renders every box
    // checked with Google's defaults.
    let kit = kit(None, FakeHttpClient::scripted(nothing_live_script()), |_| {});
    let response = request_as(&kit.router, Method::GET, HERE, "acc_1", None).await;
    assert_eq!(response.status, StatusCode::OK, "{}", String::from_utf8_lossy(response.body()));
    let page = String::from_utf8(response.body().to_vec()).expect("the page is text");
    assert_eq!(page.matches("checked").count(), 8, "all eight items start on");
    assert!(page.contains("v=spf1 include:_spf.google.com ~all"));
    assert!(page.contains("dmarc-reports@example.test"));
    assert!(page.contains("https://example.test/sitemap.xml"));
    // And the row is in the database, version 1.
    let rows = pollster::block_on(kit.db.query(&Statement::with_values(
        "SELECT version, dkim_selector, dkim_key FROM setup_domains WHERE domain = ?",
        vec![DOMAIN.into()],
    )))
    .expect("the row reads");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows.first().and_then(|row| row.get::<i64>("version")), Some(1));
    assert_eq!(
        rows.first().and_then(|row| row.get::<String>("dkim_selector")),
        Some("google".to_owned())
    );
    // `dkim_key` is NULL until the operator pastes Google's key.
    assert_eq!(rows.first().and_then(|row| row.get::<Option<String>>("dkim_key")), Some(None));
}

#[pollster::test]
async fn the_index_lists_the_domains_on_file() {
    let kit = kit(None, FakeHttpClient::scripted(nothing_live_script()), |_| {});
    // An empty console: the naming box, no domains.
    let response = request_as(&kit.router, Method::GET, "/v1/setup", "acc_1", None).await;
    assert_eq!(response.status, StatusCode::OK);
    let page = String::from_utf8(response.body().to_vec()).expect("the page is text");
    assert!(page.contains("name=\"domain\""), "the new-domain box is there");
    assert!(!page.contains("/v1/setup/example.test"));
    // After a first view the domain is listed.
    request_as(&kit.router, Method::GET, HERE, "acc_1", None).await;
    let response = request_as(&kit.router, Method::GET, "/v1/setup", "acc_1", None).await;
    let page = String::from_utf8(response.body().to_vec()).expect("the page is text");
    assert!(page.contains("/v1/setup/example.test"));
}

#[pollster::test]
async fn every_route_demands_a_verified_caller() {
    let wired = kit(None, FakeHttpClient::scripted(vec![]), |_| {});
    // Anonymous on the pages: an HTML error page, not problem+json.
    for path in ["/v1/setup", HERE] {
        let response = request(&wired.router, Method::GET, path, None).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{path}");
        let content_type = response
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        assert!(content_type.starts_with("text/html"), "{path}: {content_type}");
    }
    // Anonymous on the API route: problem+json, as an API answers.
    let response = request(&wired.router, Method::GET, &format!("{HERE}/status"), None).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    let content_type = response
        .headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert!(content_type.starts_with("application/problem+json"), "{content_type}");
    let body = response.json();
    assert!(body["type"].as_str().unwrap_or_default().ends_with("/problems/unauthenticated"));
    // No auth port wired: the deployment's 503, problem+json on the API
    // route and an HTML page on the console's.
    let unwired = kit(None, FakeHttpClient::scripted(vec![]), |ports| ports.auth = None);
    let response = request_as(&unwired.router, Method::GET, "/v1/setup", "acc_1", None).await;
    assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        String::from_utf8(response.body().to_vec())
            .expect("the page is text")
            .contains("identity provider")
    );
    let response =
        request_as(&unwired.router, Method::GET, &format!("{HERE}/status"), "acc_1", None).await;
    assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
    let body = response.json();
    let uri = body["type"].as_str().expect("a problem type");
    assert!(uri.ends_with("/problems/not-ready"), "{uri}");
}

#[pollster::test]
async fn one_click_sends_exactly_one_pull_request() {
    let http = FakeHttpClient::scripted({
        let mut script = github_script();
        script.extend(nothing_live_script()); // the page GET after the redirect
        script
    });
    let kit = kit(Some(setup_pr(&http)), http.clone(), |_| {});
    let response = request_as(&kit.router, Method::POST, HERE, "acc_1", Some(ALL_ON)).await;
    assert_eq!(
        response.status,
        StatusCode::SEE_OTHER,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    let expected = format!("{HERE}?note=saved");
    assert_eq!(
        response.headers.get("location").and_then(|value| value.to_str().ok()),
        Some(expected.as_str())
    );
    // Exactly four GitHub calls: ref, branch, one file, one pull request.
    let captured = http.captured();
    assert_eq!(captured.len(), 4, "{captured:?}");
    assert!(captured[0].1.ends_with("/git/ref/heads/main"));
    assert!(captured[1].1.ends_with("/git/refs"));
    assert!(captured[1].2.contains("\"refs/heads/setup/example.test-"));
    assert!(captured[2].1.ends_with("/contents/dns.tf"));
    assert!(captured[3].1.ends_with("/pulls"));
    // The pull request carries the plain-words summary and the house
    // title; the file (base64 on the wire) carries the Terraform.
    assert!(captured[3].2.contains("Standard setup for example.test"));
    assert!(captured[3].2.contains("only Google may send email as example.test"));
    // The change is stored with its pull-request URL and its file; the
    // checklist state too.
    let rows = pollster::block_on(kit.db.query(&Statement::with_values(
        "SELECT pr_url, branch, title, files FROM setup_changes WHERE domain = ?",
        vec![DOMAIN.into()],
    )))
    .expect("the change reads");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows.first().and_then(|row| row.get::<String>("pr_url")),
        Some("https://github.com/keep-shipping/infra/pull/9".to_owned())
    );
    let files = rows.first().and_then(|row| row.get::<String>("files")).expect("files");
    assert!(files.contains("resource \\\"cloudflare_dns_record\\\""), "{files}");
    assert!(files.contains("_spf"), "{files}");
    let rows = pollster::block_on(kit.db.query(&Statement::with_values(
        "SELECT dkim_key FROM setup_domains WHERE domain = ?",
        vec![DOMAIN.into()],
    )))
    .expect("the state reads");
    assert_eq!(
        rows.first().and_then(|row| row.get::<Option<String>>("dkim_key")),
        Some(Some("v=DKIM1; k=rsa; p=MIIBIjANBgkq".to_owned()))
    );
}

#[pollster::test]
async fn resending_the_same_checklist_sends_no_second_change() {
    let http = FakeHttpClient::scripted({
        let mut script = github_script();
        script.extend(nothing_live_script());
        script
    });
    let kit = kit(Some(setup_pr(&http)), http.clone(), |_| {});
    request_as(&kit.router, Method::POST, HERE, "acc_1", Some(ALL_ON)).await;
    // The same checklist again: saved, but nothing material changed, so
    // no branch, no commit, no pull request.
    let response = request_as(&kit.router, Method::POST, HERE, "acc_1", Some(ALL_ON)).await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);
    let expected = format!("{HERE}?note=nochange");
    assert_eq!(
        response.headers.get("location").and_then(|value| value.to_str().ok()),
        Some(expected.as_str())
    );
    assert_eq!(http.captured().len(), 4, "no GitHub calls on the re-send");
    let rows = pollster::block_on(
        kit.db.query(&Statement::new("SELECT COUNT(*) AS changes FROM setup_changes".to_owned())),
    )
    .expect("the count reads");
    assert_eq!(
        rows.first().and_then(|row| row.get::<i64>("changes")),
        Some(1),
        "still the one change"
    );
}

#[pollster::test]
async fn live_dns_turns_the_chips_done() {
    // Everything live: the apex TXT carries SPF and Google's verification
    // token, the DKIM name answers, DMARC answers, the MTA-STS record is
    // live and the policy page answers, TLS-RPT answers.
    let script = vec![
        doh(&["\"v=spf1 include:_spf.google.com ~all\"", "\"google-site-verification=abc123\""]),
        doh(&["\"v=DKIM1; k=rsa; p=MIIBIjANBgkq\""]),
        doh(&["\"v=DMARC1; p=none; rua=mailto:dmarc-reports@example.test\""]),
        doh(&["\"v=STSv1; id=20240101\""]),
        text_response("version: STSv1\nmode: testing\nmx: smtp.google.com\nmax_age: 604800\n"),
        doh(&["\"v=TLSRPTv1; rua=mailto:tls-reports@example.test\""]),
    ];
    let http = FakeHttpClient::scripted(script);
    let kit = kit(None, http.clone(), |_| {});
    // The DKIM key was never pasted, so DKIM still needs the operator
    // even though a record answers.
    let response =
        request_as(&kit.router, Method::GET, &format!("{HERE}/status"), "acc_1", None).await;
    assert_eq!(response.status, StatusCode::OK);
    let body = response.json();
    assert_eq!(body["checked_at"], "2027-01-15T08:00:00Z");
    let chips: Vec<(String, String)> = body["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| {
            (
                item["key"].as_str().expect("a key").to_owned(),
                item["chip"].as_str().expect("a chip").to_owned(),
            )
        })
        .collect();
    assert_eq!(chip_of(&chips, "spf"), "done");
    assert_eq!(chip_of(&chips, "search_console"), "done", "the verification record is live");
    assert_eq!(chip_of(&chips, "dkim"), "needs-you", "no key, no done");
    assert_eq!(chip_of(&chips, "dmarc"), "done");
    assert_eq!(chip_of(&chips, "mta_sts"), "done", "record and policy both answer");
    assert_eq!(chip_of(&chips, "tls_rpt"), "done");
    assert_eq!(chip_of(&chips, "postmaster"), "needs-you");
    // Quoted DoH TXT framing was stripped, not searched through raw.
    assert!(http.captured().iter().any(|(method, uri, _)| method == "GET"
        && uri == "https://mta-sts.example.test/.well-known/mta-sts.txt"));
}

#[pollster::test]
async fn deselecting_an_item_removes_its_record_and_its_bullet() {
    let http = FakeHttpClient::scripted(github_script());
    let kit = kit(Some(setup_pr(&http)), http.clone(), |_| {});
    request_as(&kit.router, Method::GET, HERE, "acc_1", None).await; // seed
    let without_dmarc = ALL_ON.replace("dmarc=on&", "");
    let response = request_as(&kit.router, Method::POST, HERE, "acc_1", Some(&without_dmarc)).await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);
    // The change's one file has no DMARC record; the summary says so in
    // plain words.
    let rows = pollster::block_on(kit.db.query(&Statement::with_values(
        "SELECT files, summary_md FROM setup_changes WHERE domain = ?",
        vec![DOMAIN.into()],
    )))
    .expect("the change reads");
    let files = rows.first().and_then(|row| row.get::<String>("files")).expect("files");
    assert!(!files.contains("_dmarc.example.test"), "{files}");
    assert!(files.contains("_mta-sts.example.test"), "the others stay");
    let summary = rows.first().and_then(|row| row.get::<String>("summary_md")).expect("summary");
    assert!(summary.contains("Turn off DMARC"), "{summary}");
    assert!(summary.contains("Turn on SPF"));
    // And the checklist now shows the item as Off.
    let statuses = chips(&kit).await;
    assert_eq!(chip_of(&statuses, "dmarc"), "off");
}

#[pollster::test]
async fn hostile_values_cannot_break_out_of_the_page() {
    let kit = kit(None, FakeHttpClient::scripted(nothing_live_script()), |_| {});
    request_as(&kit.router, Method::GET, HERE, "acc_1", None).await; // seed
    // An SPF value that starts like a record and carries a script tag —
    // the validator takes it (it *is* an SPF record, barely), so the page
    // must escape it.
    let hostile = ALL_ON.replace(
        "spf_value=v%3Dspf1+include%3A_spf.google.com+~all",
        "spf_value=v%3Dspf1+%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    );
    let response = request_as(&kit.router, Method::POST, HERE, "acc_1", Some(&hostile)).await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);
    let response = request_as(&kit.router, Method::GET, HERE, "acc_1", None).await;
    let page = String::from_utf8(response.body().to_vec()).expect("the page is text");
    assert!(!page.contains("<script>alert(1)"), "a hostile value must never reach the page raw");
    assert!(page.contains("&quot;&gt;&lt;script&gt;"), "the value is stored and rendered escaped");
    // A domain that is not a domain is refused before anything runs.
    let response =
        request_as(&kit.router, Method::GET, "/v1/setup/Example.com", "acc_1", None).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    let invalid =
        request_as(&kit.router, Method::GET, "/v1/setup/not%20a%20domain/status", "acc_1", None)
            .await;
    assert_eq!(invalid.status, StatusCode::BAD_REQUEST);
}

#[pollster::test]
async fn an_i_did_this_click_closes_the_outside_items() {
    let script = {
        let mut script = nothing_live_script(); // the page GET after confirm
        script.extend(nothing_live_script()); // the status GET
        script
    };
    let kit = kit(None, FakeHttpClient::scripted(script), |_| {});
    request_as(&kit.router, Method::GET, HERE, "acc_1", None).await; // seed
    let response = request_as(
        &kit.router,
        Method::POST,
        &format!("{HERE}/confirmed"),
        "acc_1",
        Some("item=postmaster"),
    )
    .await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);
    assert_eq!(response.headers.get("location").and_then(|value| value.to_str().ok()), Some(HERE));
    // Postmaster is done because the operator said so; Bing still asks.
    let statuses = chips(&kit).await;
    assert_eq!(chip_of(&statuses, "postmaster"), "done");
    assert_eq!(chip_of(&statuses, "bing"), "needs-you");
    // A second click is the same fact once.
    let rows = pollster::block_on(kit.db.query(&Statement::with_values(
        "SELECT COUNT(*) AS clicks FROM setup_confirmations WHERE domain = ? AND item = ?",
        vec![DOMAIN.into(), "postmaster".into()],
    )))
    .expect("the confirmation reads");
    assert_eq!(rows.first().and_then(|row| row.get::<i64>("clicks")), Some(1));
}

#[pollster::test]
async fn without_github_the_change_is_stored_and_the_page_says_so() {
    let http = FakeHttpClient::scripted({
        let mut script = nothing_live_script(); // the page GET after the send
        script.extend(nothing_live_script()); // the status GET
        script
    });
    let kit = kit(None, http.clone(), |_| {});
    let response = request_as(&kit.router, Method::POST, HERE, "acc_1", Some(ALL_ON)).await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);
    let expected = format!("{HERE}?note=saved");
    assert_eq!(
        response.headers.get("location").and_then(|value| value.to_str().ok()),
        Some(expected.as_str())
    );
    assert!(http.captured().is_empty(), "nothing is called when GitHub is not connected");
    // The change exists, its pull-request slot honestly empty.
    let rows = pollster::block_on(kit.db.query(&Statement::with_values(
        "SELECT pr_url, summary_md FROM setup_changes WHERE domain = ?",
        vec![DOMAIN.into()],
    )))
    .expect("the change reads");
    assert_eq!(rows.len(), 1, "the change is stored");
    assert_eq!(rows.first().and_then(|row| row.get::<Option<String>>("pr_url")), Some(None));
    // And the page the redirect lands on says connecting to GitHub is
    // what is missing.
    let response =
        request_as(&kit.router, Method::GET, &format!("{HERE}?note=saved"), "acc_1", None).await;
    let page = String::from_utf8(response.body().to_vec()).expect("the page is text");
    assert!(page.contains("Connecting this console to GitHub"), "{page}");
}

#[pollster::test]
async fn a_pull_request_that_never_opened_is_retried_by_the_next_send() {
    let http = FakeHttpClient::scripted({
        let mut script = github_open_fails(); // the first send's pull request fails
        script.extend(nothing_live_script()); // the page GET that says so
        script.extend(github_script()); // the re-send's pull request opens
        script.extend(nothing_live_script()); // the page GET that shows it
        script
    });
    let kit = kit(Some(setup_pr(&http)), http.clone(), |_| {});
    // The first send: the change is stored, the pull request did not open,
    // and the redirect (and the page) say exactly that — not "connect
    // GitHub", which would be a lie while the client is wired.
    let response = request_as(&kit.router, Method::POST, HERE, "acc_1", Some(ALL_ON)).await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);
    let expected = format!("{HERE}?note=unfiled");
    assert_eq!(
        response.headers.get("location").and_then(|value| value.to_str().ok()),
        Some(expected.as_str())
    );
    let rows = pollster::block_on(kit.db.query(&Statement::with_values(
        "SELECT pr_url FROM setup_changes WHERE domain = ?",
        vec![DOMAIN.into()],
    )))
    .expect("the change reads");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows.first().and_then(|row| row.get::<Option<String>>("pr_url")), Some(None));
    let response =
        request_as(&kit.router, Method::GET, &format!("{HERE}?note=unfiled"), "acc_1", None).await;
    let page = String::from_utf8(response.body().to_vec()).expect("the page is text");
    assert!(page.contains("didn't open"), "{page}");
    // The same checklist again: instead of "no change", the console tries
    // the pull request once more — and this time it opens.
    let response = request_as(&kit.router, Method::POST, HERE, "acc_1", Some(ALL_ON)).await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);
    let expected = format!("{HERE}?note=saved");
    assert_eq!(
        response.headers.get("location").and_then(|value| value.to_str().ok()),
        Some(expected.as_str())
    );
    let github_calls =
        http.captured().iter().filter(|(_, uri, _)| uri.contains("api.github.com")).count();
    assert_eq!(github_calls, 8, "four calls failed, then four retried");
    // The retry is its own send, and it carries the pull-request URL the
    // first one never got.
    let rows = pollster::block_on(kit.db.query(&Statement::with_values(
        "SELECT pr_url FROM setup_changes WHERE domain = ?",
        vec![DOMAIN.into()],
    )))
    .expect("the changes read");
    assert_eq!(rows.len(), 2);
    assert!(
        rows.rows.iter().any(|row| matches!(
            row.get::<Option<String>>("pr_url"),
            Some(Some(url)) if url.ends_with("/pull/9")
        )),
        "the retry opened the pull request"
    );
    assert!(
        rows.rows.iter().any(|row| matches!(row.get::<Option<String>>("pr_url"), Some(None))),
        "the failed send stays on record"
    );
    let response =
        request_as(&kit.router, Method::GET, &format!("{HERE}?note=saved"), "acc_1", None).await;
    let page = String::from_utf8(response.body().to_vec()).expect("the page is text");
    assert!(page.contains("infra/pull/9"), "{page}");
}

#[pollster::test]
async fn a_broken_or_wrongly_typed_answer_is_never_a_done() {
    // A DoH body without a Status did not really answer: the check failed,
    // and the chip says so instead of claiming the record is absent.
    let script: Vec<_> = (0..5).map(|_| json_response(r#"{"Answer": []}"#)).collect();
    let wired = kit(None, FakeHttpClient::scripted(script), |_| {});
    let response =
        request_as(&wired.router, Method::GET, &format!("{HERE}/status"), "acc_1", None).await;
    assert_eq!(response.status, StatusCode::OK);
    let body = response.json();
    let spf = body["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["key"] == "spf")
        .expect("an spf row")
        .clone();
    assert_eq!(spf["chip"], "pending", "no Status is a failure, not a no");
    assert_eq!(spf["detail"], "Couldn't check just now.");
    // A CNAME carrying TXT-looking data must not pass for the record: only
    // type-16 answers count.
    let cname = json_response(
        r#"{"Status": 0, "Answer": [{"name": "x", "type": 5, "data": "\"v=spf1 include:_spf.google.com ~all\""}]}"#,
    );
    let script = vec![cname, no_records(), no_records(), no_records(), no_records()];
    let wired = kit(None, FakeHttpClient::scripted(script), |_| {});
    let statuses = chips(&wired).await;
    assert_eq!(chip_of(&statuses, "spf"), "pending", "a CNAME is not an SPF record");
}
