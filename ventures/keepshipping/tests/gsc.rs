//! The Search Console console routes (issue #274) through the venture's own
//! composition (`gsc_module`) with the real `Gsc` client over a scripted
//! HTTP fake: the page reads Google live and says what it found; the JSON
//! twin carries the same verdict for the Standard setup page to embed; the
//! change generator needs no secret at all; an anonymous caller gets the
//! 401 shell; a missing auth port or service account is the deployment's
//! honest 503. And no matter what happens, nothing that leaves this module
//! — a captured request, a page, a generated module, a signed assertion —
//! ever carries the service-account key.

use cratefield_core::axum::body::{Body, Bytes};
use cratefield_core::{HttpClient, HttpError, Ports};
use cratefield_testing::{FakeAuth, FakeHttpClient, FixedClock, TestHarness, request, request_as};
use http::{Method, StatusCode};
use keepshipping_waitlist::{Gsc, gsc_module, search_console_module, venture};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

/// The kit's fixed clock: 2027-01-15T08:00:00Z — the module's `now`, the
/// assertion's `iat`, and the `last_read_at` every live read below reports.
const NOW: i64 = 1_800_000_000;

/// The zone every request below asks about.
const ZONE: &str = "example.com";

/// A throwaway RSA-2048 key, generated once for this file with `openssl`
/// and pasted in as a fixture: it opens nothing, signs nothing real, and
/// exists only so the JWT assertions in these tests are genuinely signed
/// (the signing test below verifies one against this key's public half).
/// Its first key-body line is the substring the leak assertions look for —
/// no captured request, page or module may carry it.
const FIXTURE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
     MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC08nKTUqx5hX+V\n\
     eEODg9GdXiijHVreWYw3TqYK+NtTkJK+8OWYYGkaFI28CE7lLKmNxqZ8RY320U1x\n\
     9CBwZ3xpEnr+ISG89cnJ6GZUHx72K/4l/1L9gYP1cP9eXU04rHgKlPoy3p3oBZ5Y\n\
     yh0hVtdw30xfumKjaIUd5L3Kxpdybh56tPso65FSEGH+lxa0oyK8K5ktQ6NIkcDp\n\
     PZ5S0WD+7d4fyF9nREK5of7Qanb9bcJZgP6lWHSFo2L/0Hk6R3is1g96yWNWfJMu\n\
     pEoegF8PTEYp5INxf/uATbH1E5l88HuA+57kYWy7eaPNVpimjQSWXeXG9DTCbCa+\n\
     /TDBjlixAgMBAAECggEAFDPBcQtY8FRkUzbTKtrLy2sY1GVRoOOUkRQ5252/Nww8\n\
     Jg9VQvb4pQ3IaUbwMAwVfhvAuL03RWhG4kMkYAhdzolerALc9nDmr6E/04KJ/WgZ\n\
     /voLtPwB1KRiDpISLhKrcFsDuCw8qwv9iuI98Fv2v8Zei42Ot7nSquy/9+TGQeMz\n\
     ekD9c5kqiMqt6m2PUDk0RMYwNaN+wM18e1fwurXd9x2zkjD0ltPjccFWDXOU195Y\n\
     0V33/IB9t3FY11XTbyCAkkTh7+RyCgcaNlINib1Hyeq/z5WzcLtYpUel8XlzB+EA\n\
     KCfIslO6h4zyZKVG0iVHmz01xENN5JtSOOmw22iihQKBgQDZJUbS31rTz0Dhxgwq\n\
     7rHDzNi7RjtMYJlCkwFq4LKEmkEukDPf6shWvO/mWKKvV6RdLcWLZNXX3zQxukLb\n\
     txTnspzO6X7D5HzkxKRHKGoECbZJqfBxAPHEVcdyMNvO3ndxXP/jpE9SxHQbVquX\n\
     sqXrcD43LllK6mXXjcRJREBNYwKBgQDVUwjqTgWpiO0BUbd38FQ6GCM3DjGBZ6o3\n\
     tDsCRClnQd/HHGJnfiWQeTjfTnk5RQp7Zch87UtcGfWRUnmcXAydr4ujsZI1awgI\n\
     6SIy5pgshGUedeTr+UrROh5Le5ssAutgPPdUCOGdS+IpxJh6sVqZW7H/XVWrL2or\n\
     E9YS8JrX2wKBgE5B6/NlgbNiNyznFk2GttQtCFL97bMKAVIH7vPYxR2bBjDE0Z06\n\
     XTc9Ymwut3rf6CGYtGAXWCYzj/j3+s56ffM+4NqFNiVdPFGqONZYT1TjNyn3L+tZ\n\
     /sfWbknOJ/m3HW7iqGofNmNK39lWdAL45Gkki5eRgabJMSjtM7d//HinAoGBAIej\n\
     14xb9d+5j7GCCx15M6UIygNsw++bQbFPqSGkw4rDaQ2Kr8tMe4gkfBQJKq1Oh/60\n\
     VkmQ/JTgcLNpdKgGI4N0Jl78PpI2rxIzYqpo0yOjP0SiA+BDT94/jRnDy4Oti4pS\n\
     2ZSWXRaONI0IU0fYU1ol4sUTzLAfYutnHnxGfr53AoGAbbwqYf++BpSbykm0M6JV\n\
     YjXHCx00Fkm98vfF2bCCsQCHw/nVSC74naxPVHvtOsV4L7DAQPQ194eNE5Xp1MRs\n\
     pvsZkG79D1KVUF4wzEjihUSJZWdLLhSh+pTpTUyF00dIcrzbN6vhc8bdyL7o4T70\n\
     4Y/IF5iSXqMKmp02/KTluDk=\n\
     -----END PRIVATE KEY-----\n";

/// The key body's first line — the leak assertions' substring.
const KEY_FINGERPRINT: &str = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC08nKTUqx5hX+V";

/// The service-account JSON the fixture key sits in — the exact shape a
/// Google-issued key file has (`private_key` carrying `\n` escapes), as the
/// `GOOGLE_SERVICE_ACCOUNT_JSON` secret would hold it.
const SERVICE_ACCOUNT_JSON: &str = concat!(
    r#"{"client_email":"console-sa@keepshipping-test.iam.gserviceaccount.com","#,
    r#""private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC08nKTUqx5hX+V\n"#,
    r#"eEODg9GdXiijHVreWYw3TqYK+NtTkJK+8OWYYGkaFI28CE7lLKmNxqZ8RY320U1x\n"#,
    r#"9CBwZ3xpEnr+ISG89cnJ6GZUHx72K/4l/1L9gYP1cP9eXU04rHgKlPoy3p3oBZ5Y\n"#,
    r#"yh0hVtdw30xfumKjaIUd5L3Kxpdybh56tPso65FSEGH+lxa0oyK8K5ktQ6NIkcDp\n"#,
    r#"PZ5S0WD+7d4fyF9nREK5of7Qanb9bcJZgP6lWHSFo2L/0Hk6R3is1g96yWNWfJMu\n"#,
    r#"pEoegF8PTEYp5INxf/uATbH1E5l88HuA+57kYWy7eaPNVpimjQSWXeXG9DTCbCa+\n"#,
    r#"/TDBjlixAgMBAAECggEAFDPBcQtY8FRkUzbTKtrLy2sY1GVRoOOUkRQ5252/Nww8\n"#,
    r#"Jg9VQvb4pQ3IaUbwMAwVfhvAuL03RWhG4kMkYAhdzolerALc9nDmr6E/04KJ/WgZ\n"#,
    r#"/voLtPwB1KRiDpISLhKrcFsDuCw8qwv9iuI98Fv2v8Zei42Ot7nSquy/9+TGQeMz\n"#,
    r#"ekD9c5kqiMqt6m2PUDk0RMYwNaN+wM18e1fwurXd9x2zkjD0ltPjccFWDXOU195Y\n"#,
    r#"0V33/IB9t3FY11XTbyCAkkTh7+RyCgcaNlINib1Hyeq/z5WzcLtYpUel8XlzB+EA\n"#,
    r#"KCfIslO6h4zyZKVG0iVHmz01xENN5JtSOOmw22iihQKBgQDZJUbS31rTz0Dhxgwq\n"#,
    r#"7rHDzNi7RjtMYJlCkwFq4LKEmkEukDPf6shWvO/mWKKvV6RdLcWLZNXX3zQxukLb\n"#,
    r#"txTnspzO6X7D5HzkxKRHKGoECbZJqfBxAPHEVcdyMNvO3ndxXP/jpE9SxHQbVquX\n"#,
    r#"sqXrcD43LllK6mXXjcRJREBNYwKBgQDVUwjqTgWpiO0BUbd38FQ6GCM3DjGBZ6o3\n"#,
    r#"tDsCRClnQd/HHGJnfiWQeTjfTnk5RQp7Zch87UtcGfWRUnmcXAydr4ujsZI1awgI\n"#,
    r#"6SIy5pgshGUedeTr+UrROh5Le5ssAutgPPdUCOGdS+IpxJh6sVqZW7H/XVWrL2or\n"#,
    r#"E9YS8JrX2wKBgE5B6/NlgbNiNyznFk2GttQtCFL97bMKAVIH7vPYxR2bBjDE0Z06\n"#,
    r#"XTc9Ymwut3rf6CGYtGAXWCYzj/j3+s56ffM+4NqFNiVdPFGqONZYT1TjNyn3L+tZ\n"#,
    r#"/sfWbknOJ/m3HW7iqGofNmNK39lWdAL45Gkki5eRgabJMSjtM7d//HinAoGBAIej\n"#,
    r#"14xb9d+5j7GCCx15M6UIygNsw++bQbFPqSGkw4rDaQ2Kr8tMe4gkfBQJKq1Oh/60\n"#,
    r#"VkmQ/JTgcLNpdKgGI4N0Jl78PpI2rxIzYqpo0yOjP0SiA+BDT94/jRnDy4Oti4pS\n"#,
    r#"2ZSWXRaONI0IU0fYU1ol4sUTzLAfYutnHnxGfr53AoGAbbwqYf++BpSbykm0M6JV\n"#,
    r#"YjXHCx00Fkm98vfF2bCCsQCHw/nVSC74naxPVHvtOsV4L7DAQPQ194eNE5Xp1MRs\n"#,
    r#"pvsZkG79D1KVUF4wzEjihUSJZWdLLhSh+pTpTUyF00dIcrzbN6vhc8bdyL7o4T70\n"#,
    r#"4Y/IF5iSXqMKmp02/KTluDk=\n-----END PRIVATE KEY-----\n","#,
    r#""token_uri":"https://oauth2.googleapis.com/token"}"#,
);

fn at() -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(NOW).expect("the fixed epoch")
}

/// The kit's one status read spends these three Google answers in order:
/// the token exchange, `sites.get` saying the service account owns the
/// property, and `sitemaps.list` with the one sitemap submitted.
fn google_script() -> Vec<Result<http::Response<Bytes>, HttpError>> {
    vec![
        Ok(ok_json(
            r#"{"access_token":"ya29.test-token","expires_in":3599,"token_type":"Bearer"}"#,
        )),
        Ok(ok_json(r#"{"siteUrl":"sc-domain:example.com","permissionLevel":"siteOwner"}"#)),
        Ok(ok_json(
            json!({ "sitemap": [{
                "path": "https://example.com/sitemap.xml",
                "type": "sitemap",
                "lastSubmitted": "2027-01-14T00:00:00Z",
                "isPending": false,
                "isSitemapsIndex": false,
            }] })
            .to_string()
            .as_str(),
        )),
    ]
}

fn ok_json(body: &str) -> http::Response<Bytes> {
    http::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Bytes::from(body.to_owned()))
        .expect("a scripted response builds")
}

fn http_status(status: StatusCode) -> Result<http::Response<Bytes>, HttpError> {
    Ok(http::Response::builder()
        .status(status)
        .body(Bytes::new())
        .expect("a scripted response builds"))
}

/// A `FakeHttpClient` that also records the `Authorization` header of every
/// request it forwards — the harness fake captures `(method, uri, body)`
/// only, and "the bearer token was spent, and only on the two reads" is
/// exactly the claim this file exists to pin.
#[derive(Clone)]
struct RecordingClient {
    inner: FakeHttpClient,
    authorization: Arc<Mutex<Vec<Option<String>>>>,
}

impl RecordingClient {
    fn scripted(responses: Vec<Result<http::Response<Bytes>, HttpError>>) -> Self {
        Self {
            inner: FakeHttpClient::scripted(responses),
            authorization: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn captured(&self) -> Vec<(String, String, String)> {
        self.inner.captured()
    }

    fn bearer_values(&self) -> Vec<Option<String>> {
        self.authorization.lock().expect("uncontended").clone()
    }
}

#[async_trait::async_trait]
impl HttpClient for RecordingClient {
    async fn send(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        self.authorization.lock().expect("uncontended").push(
            request
                .headers()
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
        );
        self.inner.send(request).await
    }
}

/// A kit mounting the venture and the console module exactly as `src/lib.rs`
/// composes them, with `Gsc` over the recording fake and the fake auth that
/// reads a bearer token as the subject id. `sa` decides whether the
/// `GOOGLE_SERVICE_ACCOUNT_JSON` secret is set; `patch` swaps ports.
fn kit(http: RecordingClient, sa: Option<&str>, patch: impl FnOnce(&mut Ports)) -> TestHarness {
    TestHarness::with_builder(
        vec![Box::new(gsc_module(Gsc::new(
            Arc::new(http.clone()),
            Arc::new(FixedClock(at())),
            sa.map(str::to_owned),
        )))],
        |builder| builder.venture(venture()),
        |ports| {
            ports.auth = Some(Arc::new(FakeAuth::subjects()));
            patch(ports);
        },
    )
}

/// GETs through the router as `acc_1`, or anonymously when `bearer` is
/// `None`.
async fn get_as(
    kit: &TestHarness,
    path: &str,
    bearer: Option<&str>,
) -> cratefield_testing::TestResponse {
    match bearer {
        Some(bearer) => request_as(&kit.router, Method::GET, path, bearer, None).await,
        None => request(&kit.router, Method::GET, path, None).await,
    }
}

/// A POST of a form body with whatever response came back — the harness'
/// `TestResponse` cannot be built outside its crate, and a form post needs
/// headers the `request` helpers do not set.
struct Posted {
    status: StatusCode,
    headers: http::HeaderMap,
    body: Bytes,
}

impl Posted {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("the body is JSON")
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }
}

/// POSTs a form-encoded body to `/v1/console/search-console/module` as
/// `acc_1`, optionally asking for JSON back.
async fn post_module(kit: &TestHarness, body: &str, accept: Option<&str>) -> Posted {
    use tower::ServiceExt;
    let mut builder = http::Request::builder()
        .method(Method::POST)
        .uri("/v1/console/search-console/module")
        .header("content-type", "application/x-www-form-urlencoded")
        .header("authorization", "Bearer acc_1");
    if let Some(accept) = accept {
        builder = builder.header("accept", accept);
    }
    let request = builder.body(Body::from(body.to_owned())).expect("the request builds");
    let response = kit.router.clone().oneshot(request).await.expect("the router answers");
    let (parts, body) = response.into_parts();
    let body =
        cratefield_core::axum::body::to_bytes(body, 1_048_576).await.expect("the body reads");
    Posted { status: parts.status, headers: parts.headers, body }
}

fn page_of(response: &cratefield_testing::TestResponse) -> String {
    String::from_utf8_lossy(response.body()).into_owned()
}

/// The problem's slug: the part of `type` after `/problems/`.
fn problem_slug(body: &Value) -> String {
    let uri = body["type"].as_str().expect("a problem+json `type`");
    uri.split_once("/problems/").map_or(uri, |(_, slug)| slug).to_owned()
}

/// The form the page posts: the happy values.
fn module_form() -> String {
    "zone=example.com&owners=you%40example.com%2C+teammate%40example.com&sitemap=https%3A%2F%2Fexample.com%2Fsitemap.xml"
        .to_owned()
}

#[test]
fn the_page_reads_google_live_and_says_what_it_found() {
    let http = RecordingClient::scripted(google_script());
    let kit = kit(http.clone(), Some(SERVICE_ACCOUNT_JSON), |_| {});
    let response = pollster::block_on(get_as(
        &kit,
        "/v1/console/search-console?zone=example.com",
        Some("acc_1"),
    ));
    assert_eq!(response.status, StatusCode::OK, "{}", page_of(&response));
    assert!(
        response
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("text/html")),
        "the page is a page"
    );
    let page = page_of(&response);
    assert!(page.contains("Search Console"), "the heading: {page}");
    assert!(page.contains("example.com"), "the zone is named: {page}");
    assert!(page.contains("Verified"), "the verified chip: {page}");
    assert!(page.contains("Sitemap submitted"), "the sitemap chip: {page}");
    assert!(page.contains("Last checked 2027-01-15 08:00 UTC"), "the stamp: {page}");
    assert!(page.contains("One-time setup"), "the setup card: {page}");
    assert!(page.contains("GOOGLE_SERVICE_ACCOUNT_JSON"), "the secret is named: {page}");
    assert!(!page.contains("BEGIN PRIVATE KEY"), "no key material on the page");
    assert!(!page.contains(KEY_FINGERPRINT), "no key body on the page");

    // The order the reads went out in: token first, then sites, then
    // sitemaps — and the bearer token was spent on exactly the two reads,
    // never on the exchange itself.
    let captured = http.captured();
    assert_eq!(captured.len(), 3, "{captured:?}");
    let (method, uri, body) = captured.first().expect("the token exchange");
    assert_eq!(method, "POST", "{captured:?}");
    assert!(uri.contains("oauth2.googleapis.com/token"), "{uri}");
    assert!(
        body.starts_with(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="
        ),
        "{body}"
    );
    let (method, uri, _) = &captured[1];
    assert_eq!(method.as_str(), "GET");
    assert!(
        uri.contains("/webmasters/v3/sites/sc-domain%3Aexample.com"),
        "the property URL is percent-encoded: {uri}"
    );
    assert_eq!(captured[2].1.rsplit('/').next(), Some("sitemaps"));
    let bearers = http.bearer_values();
    assert_eq!(bearers.len(), 3, "one header per sent request: {bearers:?}");
    assert_eq!(
        bearers.first().and_then(Option::as_deref),
        None,
        "the token exchange carries no bearer yet"
    );
    assert_eq!(
        bearers[1].as_deref(),
        Some("Bearer ya29.test-token"),
        "the sites read spends the minted token"
    );
    assert_eq!(bearers[2].as_deref(), Some("Bearer ya29.test-token"), "so does the sitemaps read");

    // And nothing Google saw carries the key.
    for (_, uri, body) in &captured {
        assert!(!uri.contains(KEY_FINGERPRINT) && !body.contains(KEY_FINGERPRINT));
        assert!(!body.contains("BEGIN PRIVATE KEY"));
    }
}

#[test]
fn the_page_without_a_zone_asks_for_one() {
    let http = RecordingClient::scripted(vec![]);
    let kit = kit(http.clone(), Some(SERVICE_ACCOUNT_JSON), |_| {});
    let response = pollster::block_on(get_as(&kit, "/v1/console/search-console", Some("acc_1")));
    assert_eq!(response.status, StatusCode::OK);
    let page = page_of(&response);
    assert!(page.contains("Look up a domain"), "{page}");
    assert!(http.captured().is_empty(), "no read went out — there is nothing to read yet");
}

#[test]
fn an_anonymous_caller_is_asked_to_sign_in() {
    let http = RecordingClient::scripted(vec![]);
    let kit = kit(http, Some(SERVICE_ACCOUNT_JSON), |_| {});
    // The page answers the 401 as the shell, so the browser shows it.
    let response = pollster::block_on(request(
        &kit.router,
        Method::GET,
        "/v1/console/search-console?zone=example.com",
        None,
    ));
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    let page = page_of(&response);
    assert!(page.contains("Sign in required"), "{page}");
    assert!(
        page.contains("href=\"/console/login?next=%2Fv1%2Fconsole%2Fsearch-console\""),
        "{page}"
    );
    // The JSON twin answers the same refusal as a problem, so the Standard
    // setup page's fetch sees it as one.
    let response = pollster::block_on(request(
        &kit.router,
        Method::GET,
        "/v1/console/gsc?zone=example.com",
        None,
    ));
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(problem_slug(&response.json()), "unauthenticated");
}

#[test]
fn a_deployment_without_an_auth_port_is_not_ready() {
    let http = RecordingClient::scripted(vec![]);
    let kit = kit(http, Some(SERVICE_ACCOUNT_JSON), |ports| ports.auth = None);
    let response =
        pollster::block_on(get_as(&kit, "/v1/console/search-console?zone=example.com", None));
    assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
    let page = page_of(&response);
    assert!(page.contains("Not ready yet"), "{page}");
    assert!(page.contains("no auth port is wired"), "{page}");
}

#[test]
fn the_json_twin_reports_what_the_page_shows() {
    let http = RecordingClient::scripted(google_script());
    let kit = kit(http, Some(SERVICE_ACCOUNT_JSON), |_| {});
    let response =
        pollster::block_on(get_as(&kit, "/v1/console/gsc?zone=example.com", Some("acc_1")));
    assert_eq!(response.status, StatusCode::OK, "{}", page_of(&response));
    let body = response.json();
    assert_eq!(body["zone"], ZONE);
    assert_eq!(body["verified"], true);
    assert_eq!(body["sitemap_submitted"], true);
    assert_eq!(body["sitemap"], "https://example.com/sitemap.xml");
    assert_eq!(body["last_read_at"], "2027-01-15T08:00:00Z", "the kit clock");
}

#[test]
fn a_property_not_shared_with_the_service_account_reads_as_unverified() {
    let http = RecordingClient::scripted(vec![
        Ok(ok_json(r#"{"access_token":"ya29.test-token","token_type":"Bearer"}"#)),
        // 403: the property exists but the service account is not on it —
        // the expected not-yet state, not a failure.
        http_status(StatusCode::FORBIDDEN),
        Ok(ok_json(r#"{"sitemap":[]}"#)),
    ]);
    let kit = kit(http, Some(SERVICE_ACCOUNT_JSON), |_| {});
    let response =
        pollster::block_on(get_as(&kit, "/v1/console/gsc?zone=example.com", Some("acc_1")));
    assert_eq!(response.status, StatusCode::OK, "{}", page_of(&response));
    let body = response.json();
    assert_eq!(body["verified"], false);
    assert_eq!(body["sitemap_submitted"], false);
    assert_eq!(body["sitemap"], Value::Null);
}

#[test]
fn without_the_secret_status_reads_say_so_and_the_generator_keeps_working() {
    let http = RecordingClient::scripted(vec![]);
    let kit = kit(http, None, |_| {});

    let response = pollster::block_on(get_as(
        &kit,
        "/v1/console/search-console?zone=example.com",
        Some("acc_1"),
    ));
    assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
    let page = page_of(&response);
    assert!(page.contains("Not ready yet"), "{page}");
    assert!(page.contains("secret is missing"), "{page}");

    let response =
        pollster::block_on(get_as(&kit, "/v1/console/gsc?zone=example.com", Some("acc_1")));
    assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(problem_slug(&response.json()), "not-ready");

    // The one write needs no Google and no secret: it is pure generation.
    let response = pollster::block_on(post_module(&kit, &module_form(), None));
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert!(response.text().contains("sc-domain:"));
}

#[test]
fn the_change_payload_names_what_the_pull_request_would_contain() {
    let http = RecordingClient::scripted(vec![]);
    let kit = kit(http, None, |_| {});
    let response = pollster::block_on(post_module(&kit, &module_form(), Some("application/json")));
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let payload = response.json();
    // The payload is the sibling edit-as-code module's ingest shape —
    // `edits::propose({zone, title, summary_md, files, author})` (#170).
    assert_eq!(payload["zone"], "example.com");
    assert_eq!(payload["author"], "acc_1", "the signed-in caller is the author");
    assert!(
        payload["title"].as_str().is_some_and(|title| title.contains("example.com")),
        "{payload}"
    );
    assert_eq!(
        payload["summary_md"],
        "Add Search Console domain verification for example.com\n\n\
         Generated from the Keep Shipping console (issue #274): the \
         DNS verification token, the TXT record carrying it, the \
         sc-domain:example.com property, and the owners who share it. \
         Sitemap submission follows as a gsc.sitemap_submit step.",
        "the commit message became the markdown summary, same wording"
    );
    assert!(payload.get("commit_message").is_none(), "the old key is gone: {payload}");
    assert_eq!(payload["files"].as_array().map(Vec::len), Some(1));
    assert_eq!(payload["files"][0]["path"], "search-console/main.tf");
    let content = payload["files"][0]["content"].as_str().expect("the module text");
    assert!(content.contains("sc-domain:"), "the site_url output: {content}");
    assert!(content.contains("you@example.com"), "the owners: {content}");
    assert!(content.contains("teammate@example.com"), "both owners: {content}");
    for resource in [
        "resource \"cloudflare_dns_record\"",
        "resource \"google_site_verification_web_resource\"",
        "resource \"google_site_verification_owner\"",
    ] {
        assert!(content.contains(resource), "{resource} is in the module: {content}");
    }
    assert!(!content.contains("BEGIN PRIVATE KEY"), "no key material in the module");
}

#[test]
fn the_module_download_is_a_terraform_attachment() {
    let http = RecordingClient::scripted(vec![]);
    let kit = kit(http, None, |_| {});
    let response = pollster::block_on(post_module(&kit, &module_form(), None));
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.header("content-type"), Some("text/x-terraform"));
    assert_eq!(
        response.header("content-disposition"),
        Some("attachment; filename=\"search-console.tf\"")
    );
    let module = response.text();
    assert!(module.contains("sc-domain:"), "{module}");
    assert!(!module.contains("BEGIN PRIVATE KEY"));
}

#[test]
fn the_generator_is_deterministic_for_the_same_inputs() {
    let once = search_console_module(
        "example.com",
        &["you@example.com", "teammate@example.com"],
        Some("https://example.com/sitemap.xml"),
    );
    let again = search_console_module(
        "example.com",
        &["you@example.com", "teammate@example.com"],
        Some("https://example.com/sitemap.xml"),
    );
    assert_eq!(once, again, "the same inputs, the same bytes");

    // And the route answers with exactly that text, twice.
    let http = RecordingClient::scripted(vec![]);
    let kit = kit(http, None, |_| {});
    let first = pollster::block_on(post_module(&kit, &module_form(), Some("application/json")));
    let second = pollster::block_on(post_module(&kit, &module_form(), Some("application/json")));
    assert_eq!(first.json()["files"][0]["content"], second.json()["files"][0]["content"]);
}

#[test]
fn the_form_refuses_what_cannot_be_a_change() {
    let http = RecordingClient::scripted(vec![]);
    let kit = kit(http, None, |_| {});
    let cases: Vec<(&str, String, &str)> = vec![
        // A scheme is not a zone.
        (
            "scheme in the zone",
            "zone=https%3A%2F%2Fexample.com&owners=you%40example.com".to_owned(),
            "won't work",
        ),
        // No owners, no grant.
        ("no owners", "zone=example.com&owners=".to_owned(), "at least one owner"),
        // A sitemap must live on the zone.
        (
            "sitemap on another host",
            "zone=example.com&owners=you%40example.com&sitemap=https%3A%2F%2Fother.example%2Fsitemap.xml"
                .to_owned(),
            "must live on example.com",
        ),
    ];
    for (name, form, needle) in cases {
        let response = pollster::block_on(post_module(&kit, &form, None));
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{name}: {}", response.text());
        assert_eq!(problem_slug(&response.json()), "validation-failed", "{name}");
        assert!(
            response.json()["detail"].as_str().is_some_and(|detail| detail.contains(needle)),
            "{name}: {}",
            response.json()
        );
    }
}

#[test]
fn the_status_routes_refuse_what_cannot_be_a_zone() {
    let http = RecordingClient::scripted(google_script());
    let kit = kit(http, Some(SERVICE_ACCOUNT_JSON), |_| {});
    for path in [
        "/v1/console/gsc?zone=https%3A%2F%2Fexample.com",
        "/v1/console/gsc?zone=Example.com",
        "/v1/console/gsc?zone=example.com%2Fpath",
    ] {
        let response = pollster::block_on(get_as(&kit, path, Some("acc_1")));
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(problem_slug(&response.json()), "validation-failed", "{path}");
    }
    // And the JSON twin demands a zone outright.
    let response = pollster::block_on(get_as(&kit, "/v1/console/gsc", Some("acc_1")));
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
}

#[test]
fn the_assertion_is_signed_by_the_fixture_key_and_names_the_account() {
    // Mint one assertion through a real token exchange, then verify the
    // signature against the fixture key's public half — the same check
    // Google's token endpoint does — and read the claims back.
    use base64::Engine;
    use rsa::RsaPrivateKey;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::sha2::Sha256;
    use rsa::signature::Verifier;

    let fake = FakeHttpClient::scripted(google_script());
    let client = Gsc::new(
        Arc::new(fake.clone()),
        Arc::new(FixedClock(at())),
        Some(SERVICE_ACCOUNT_JSON.to_owned()),
    );
    let status = pollster::block_on(client.read_status(ZONE)).expect("the read answers");
    assert!(status.verified && status.sitemap_submitted);

    let (_, _, body) = fake.captured().first().expect("the token exchange went out").clone();
    let assertion = body
        .split_once("assertion=")
        .map(|(_, assertion)| assertion)
        .expect("the assertion rides the form body");
    let segments: Vec<&str> = assertion.split('.').collect();
    assert_eq!(segments.len(), 3, "header.claims.signature: {assertion}");
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let claims: Value =
        serde_json::from_slice(&engine.decode(segments[1]).expect("the claims decode"))
            .expect("the claims are JSON");
    assert_eq!(claims["iss"], "console-sa@keepshipping-test.iam.gserviceaccount.com");
    assert_eq!(claims["scope"], "https://www.googleapis.com/auth/webmasters");
    assert_eq!(claims["aud"], "https://oauth2.googleapis.com/token");
    assert_eq!(claims["iat"], NOW);
    assert_eq!(claims["exp"], NOW + 3600);
    let key = RsaPrivateKey::from_pkcs8_pem(FIXTURE_KEY_PEM).expect("the fixture key parses");
    let signing_input = format!("{}.{}", segments[0], segments[1]);
    let signature =
        Signature::try_from(engine.decode(segments[2]).expect("the signature decodes").as_slice())
            .expect("the signature parses");
    VerifyingKey::<Sha256>::new(key.into())
        .verify(signing_input.as_bytes(), &signature)
        .expect("the assertion is signed by the fixture key");
    assert!(
        !assertion.contains(KEY_FINGERPRINT),
        "the assertion carries the claims, never the key"
    );
}

#[test]
fn form_values_cannot_inject_terraform() {
    // The sitemap is free text after its host; in an `output` value an
    // unescaped `${...}` is evaluated at apply time and a `"` closes the
    // string. Both must reach the module as literal text.
    let module = search_console_module(
        "example.com",
        &["you@example.com"],
        Some("https://example.com/${file(\"/etc/passwd\")}\"x"),
    );
    // `$${` is HCL's literal `${`; only an undoubled opener interpolates.
    assert!(!module.replace("$${", "").contains("${file("), "{module}");
    assert!(module.contains("$${file(\\\"/etc/passwd\\\")}\\\"x"), "{module}");

    // An owner is one email address: anything carrying a quote, a brace
    // or a space is refused before any Terraform is written.
    let http = RecordingClient::scripted(vec![]);
    let kit = kit(http, None, |_| {});
    for owner in [
        "a%40example.com%22%5D%7D",             // a@example.com"]}
        "%24%7Bfile(%22x%22)%7D%40example.com", // ${file("x")}@example.com
        "not+an+email",
    ] {
        let form = format!("zone=example.com&owners={owner}");
        let response = pollster::block_on(post_module(&kit, &form, None));
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{owner}: {}", response.text());
        assert_eq!(problem_slug(&response.json()), "validation-failed", "{owner}");
    }
}
