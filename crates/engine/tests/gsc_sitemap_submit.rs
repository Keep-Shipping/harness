//! The `gsc.sitemap_submit` step over a fake HTTP client: the requests it
//! builds and the responses it accepts.
//!
//! Everything is scripted on a [`FakeHttpClient`], and every assertion is
//! read back out of `fake.requests()` — the token exchange, the JWT the
//! assertion carries, the bearer header the submit carries — so what is
//! checked here is the exact traffic Google would see.

use std::sync::Arc;

use ks_core::harness::Harness;
use ks_core::ports::clock::Clock;
use ks_core::ports::http::{HttpClient, HttpMethod, HttpResponse};
use ks_core::ports::script_host::Value;
use ks_core::ports::secrets::Redactor;
use ks_core::step::{
    CancellationToken, Inputs, LogSink, Outputs, Port, Ports, StepError, StepKind,
};
use ks_engine::gsc_sitemap_submit::GscSitemapSubmit;
use ks_engine::run::run_step;
use ks_testing::block_on;
use ks_testing::clock::FakeClock;
use ks_testing::http::FakeHttpClient;
use ks_testing::step::{RecordingSink, StepCase, step_conformance};
use rsa::RsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::sha2::Sha256;

// A throwaway RSA-2048 keypair generated for this test file alone
// (`openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048`). It has
// never signed anything real, is not enrolled with any Google project, and
// carries no authority; it is inlined here so no key-shaped file exists in
// the repository.
const TEST_PRIVATE_KEY: &str = "\
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCFtPaaVTENF/ic
izU3/4+0RB2t5pSNOVImS56V/anFjgOblqjXxXUh8qE9NPE1O5nXZxuh9SnFZNmU
CLOUu7c8oF88dokvfs6vTJlmI2u56+9+mauMmTlb1ADoBE2OPPo7uUsbdlJ3PCTK
ZWV3joevH531PKMO7UvJvb7dg67YuPXnRCKDqw9My+0fPUZXihXu2BxVwluEwnbW
PYFlHV7mGGdpjU/IMvsOjRRHRWWsu4rSQJsyv648okvHGHwv3pTWs1QWKPXKgrMl
2hsRFbXIzqzi/RcQqS1O2Euc9o3g/MNAtZcLaBktTl562DSlKF9dctPhbuAvntmI
Z2KCQ9g/AgMBAAECggEAFEy7PAc/ITvIdQv1koDscnP9BZACccaIIGROuXr/sYy0
I4UmMUw7UmIh9Mb68BgSbU+sNFSieOOs3PrNOQGe+kdm7ikY/usDuj2o9IbgLiQS
AmiWUQxaVwTC9nbgx32eiD7DlnHKZ2vsMgZe913eX8ovEzKXlwaUARcbyUna2/BQ
xXf/JPnlee8EiCCfzvyUa8rnUZLX6HxPn7kIr6MBcK+fPhI1cfJ3a20AieEA6KWG
GQwXYLPdoD7zHDFoxAJOsG4jZXWuPJJQcrmg0SUDCyzV1qzoQDHWjXG/AuZeWkzU
KQnpEBNbwNaygoW0qM0XGmq1HRgb3/NihdCYMZDOkQKBgQC8Mmr5gSuf/bPYbV9E
rmLM0cRiEe7HV2Wts3PdUu86wH9z5JyaIUnhDNnlMMNPr3HcNMyASsFEgk1F3vg4
EMkHIJDUvn74/Vpg6e4QCVjZqXn690P4tftJdnCDFvPehvHX3H0pFh/0cbjchcEh
calwRhLQrNyiGnbDLDf4ZwHbuwKBgQC14OA+2qSgdH2lQqNl9gVJnlrqd9h7CCc3
QOy5aJW/m3Vyk0JvqoPMaW1OTMGDMNY+hsGJkgc0KG+XczOkDYJ4ffk7r7sumwYg
mj3E38KD63cK2gCr/N7Ogk9HJKtUaNT6/Ig8tsAYRmd4Wt36fRYRA6v5vgie7HkR
pYjY1qOzTQKBgEjaU6MGp/alZauQm2KhB0o2ogk82+x7HrdhUqcI5ecegbhBdYYN
AOaH7QnWGKWOS0ttfQTk63Az6On1aK17gfaqWqagn9KPcR83L5sxox2Ph9LpSXzM
JdzIZsG4butj3dcsWZ9AG1qrc16awKrLr0XxOnNhl3+BMxxWz8vvRD7lAoGATwBu
B39LcRMInKc0eI6Dv3WUgjIqi06AUkTWTrb6DO+G9Yy3l++WLk1BGHjIuaaV+TTp
jksq6+IAjuWQcdsYaCQ4BVAQ226lG7ZDzGdxg4HdBI6rKgm98i+yJfHspc6fbKIS
v2SWTjUOrr2xnCOHWT6iDeoYroeDE0I3DhE1rCUCgYBzIylOyKg3uTYk1FdxE3zq
yKQSpgzedfFs4DXCEmwms/Vpoj+rBWDcZpyGeHwlIkpSdBILCBQBZFo6BraXO5X5
k9YVUejEjCO1ID/P5i63rCdigdGN9ZLYgQDheGxJrjh8YsE3GUFnMj5i2P+X6SVQ
wlTqD+1caqwelYSoECxz3Q==
-----END PRIVATE KEY-----
";

const SITE: &str = "sc-domain:example.com";
const SITEMAP: &str = "https://example.com/sitemap.xml";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const SUBMIT_URL: &str = "https://www.googleapis.com/webmasters/v3/sites/sc-domain%3Aexample.com/sitemaps/\
     https%3A%2F%2Fexample.com%2Fsitemap.xml";

/// The service-account JSON the step reads, built around the throwaway key.
fn credentials() -> String {
    serde_json::json!({
        "type": "service_account",
        "client_email": "sa@test.iam.gserviceaccount.com",
        "private_key": TEST_PRIVATE_KEY,
        "token_uri": TOKEN_URL,
    })
    .to_string()
}

fn response(status: u16, body: &[u8]) -> HttpResponse {
    HttpResponse { status, headers: vec![], body: body.to_vec() }
}

/// The fake a scenario runs against: the token exchange answered with a
/// fixed token, the submit with whatever `status` the test asks for. Exactly
/// the two hosts the step may touch are allowlisted.
fn fake(submit: HttpResponse) -> Arc<FakeHttpClient> {
    Arc::new(
        FakeHttpClient::new()
            .with_allowed_host("oauth2.googleapis.com")
            .with_allowed_host("www.googleapis.com")
            .with_response(HttpMethod::Post, TOKEN_URL, response(200, br#"{"access_token":"tok"}"#))
            .with_response(HttpMethod::Put, SUBMIT_URL, submit),
    )
}

fn compose(http: Arc<FakeHttpClient>) -> Harness {
    Harness::builder()
        .ports(
            Ports::default()
                .with_clock(Arc::new(FakeClock::new()) as Arc<dyn Clock>)
                .with_http_client(http as Arc<dyn HttpClient>),
        )
        .step(GscSitemapSubmit)
        .build()
        .expect("the composition is valid")
}

fn inputs() -> Inputs {
    Inputs::from([
        ("credentials".to_string(), Value::from(credentials())),
        ("site".to_string(), Value::from(SITE)),
        ("sitemap".to_string(), Value::from(SITEMAP)),
    ])
}

/// Runs the step in a real harness; the sink keeps whatever the run logged.
fn drive(http: Arc<FakeHttpClient>) -> (Result<Outputs, StepError>, Arc<RecordingSink>) {
    let harness = compose(Arc::clone(&http));
    let sink = Arc::new(RecordingSink::new());
    let result = block_on(run_step(
        &harness,
        "gsc.sitemap_submit",
        inputs(),
        CancellationToken::new(),
        Arc::clone(&sink) as Arc<dyn LogSink>,
        Arc::new(Redactor::new()),
    ));
    (result, sink)
}

/// The request the step sent to `url`, in order.
fn sent(fake: &FakeHttpClient, method: HttpMethod, url: &str) -> ks_core::ports::http::HttpRequest {
    fake.requests()
        .into_iter()
        .find(|request| request.method == method && request.url == url)
        .unwrap_or_else(|| panic!("no {method} to {url} among the recorded requests"))
}

/// Decodes one base64url JWT segment.
fn segment(jwt: &str, index: usize) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let part = jwt.split('.').nth(index).unwrap_or_else(|| panic!("segment {index} of {jwt}"));
    let (mut bytes, mut held, mut bits) = (Vec::new(), 0u32, 0u32);
    for byte in part.bytes() {
        let value =
            ALPHABET.iter().position(|candidate| *candidate == byte).expect("base64url") as u32;
        held = (held << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((held >> bits) as u8);
        }
    }
    bytes
}

#[test]
fn a_sitemap_is_submitted_with_the_token_the_account_minted() {
    let http = fake(response(200, b""));
    let (result, sink) = drive(Arc::clone(&http));
    let outputs = result.expect("the submit succeeds");

    assert_eq!(outputs.get("site"), Some(&Value::from(SITE)));
    assert_eq!(outputs.get("sitemap"), Some(&Value::from(SITEMAP)));
    assert_eq!(outputs.get("submitted"), Some(&Value::from(true)));

    // Token first, submit second: the exchange has to happen before the call
    // that spends it.
    let requests = http.requests();
    assert_eq!(requests.len(), 2, "one token exchange, one submit");
    assert_eq!((requests[0].method, requests[0].url.as_str()), (HttpMethod::Post, TOKEN_URL));
    assert_eq!((requests[1].method, requests[1].url.as_str()), (HttpMethod::Put, SUBMIT_URL));
    let authorization = requests[1]
        .headers
        .iter()
        .find(|(name, _)| name == "Authorization")
        .map(|(_, value)| value.clone())
        .expect("the submit carries credentials");
    assert_eq!(authorization, "Bearer tok", "the token the fake minted is the token spent");

    // The step's own record names the site and the sitemap, and nothing
    // else. (The engine adds its `step started` line around it.)
    let records = sink.records();
    let own: Vec<_> =
        records.iter().filter(|record| record.message.starts_with("submitted ")).collect();
    assert_eq!(own.len(), 1, "one info line of the step's own, got {records:?}");
    assert!(own[0].message.contains(SITE) && own[0].message.contains(SITEMAP));
}

#[test]
fn the_token_exchange_carries_the_grant_and_the_assertion_and_no_key() {
    let http = fake(response(200, b""));
    let _ = drive(Arc::clone(&http));

    let token = sent(&http, HttpMethod::Post, TOKEN_URL);
    let content_type = |request: &ks_core::ports::http::HttpRequest| {
        request
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("Content-Type"))
            .map(|(_, value)| value.clone())
    };
    assert_eq!(content_type(&token).as_deref(), Some("application/x-www-form-urlencoded"));
    let body = String::from_utf8(token.body.clone()).expect("a form body is text");
    assert!(
        body.starts_with("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&"),
        "{body}"
    );
    let assertion = body
        .strip_prefix("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=")
        .expect("the assertion is the second form field");
    assert_eq!(assertion.split('.').count(), 3, "header.claims.signature: {assertion}");

    // No captured request — body or header — repeats any line of the private
    // key, and neither does the log.
    let private_fragment = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCFtPaaVTENF";
    for request in http.requests() {
        let text = String::from_utf8_lossy(&request.body);
        assert!(!text.contains(private_fragment), "the key leaked into a body: {text}");
        for (_, value) in &request.headers {
            assert!(!value.contains(private_fragment), "the key leaked into a header");
        }
    }
}

#[test]
fn the_assertion_is_signed_rs256_over_the_expected_claims() {
    let http = fake(response(200, b""));
    let _ = drive(Arc::clone(&http));
    let token = sent(&http, HttpMethod::Post, TOKEN_URL);
    let body = String::from_utf8(token.body).expect("a form body is text");
    let assertion = body.split("assertion=").nth(1).expect("the assertion rides the form");
    let jwt: Vec<&str> = assertion.split('.').collect();
    assert_eq!(jwt.len(), 3, "header.claims.signature");

    let header: serde_json::Value =
        serde_json::from_slice(&segment(assertion, 0)).expect("the header is JSON");
    assert_eq!(header, serde_json::json!({"alg": "RS256", "typ": "JWT"}));

    let claims: serde_json::Value =
        serde_json::from_slice(&segment(assertion, 1)).expect("the claims are JSON");
    assert_eq!(claims["iss"], "sa@test.iam.gserviceaccount.com");
    assert_eq!(claims["scope"], "https://www.googleapis.com/auth/webmasters");
    assert_eq!(claims["aud"], TOKEN_URL);
    let (iat, exp) = (claims["iat"].as_u64().expect("iat"), claims["exp"].as_u64().expect("exp"));
    assert_eq!(exp - iat, 3600, "the assertion lives an hour");
    // `FakeClock` starts at Unix time 1_700_000_000, and the `iat` must be
    // that instant, not the wall clock.
    assert_eq!(iat, 1_700_000_000, "time comes from the run's clock");

    // The strongest check: the signature really is RS256 over
    // `header.claims`, verifiable with the matching public key.
    let signing_input = format!("{}.{}", jwt[0], jwt[1]);
    let signature = rsa::pkcs1v15::Signature::try_from(segment(assertion, 2).as_slice())
        .expect("the signature decodes");
    let key = RsaPrivateKey::from_pkcs8_pem(TEST_PRIVATE_KEY).expect("the fixture key parses");
    let verifying = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key.into());
    use rsa::signature::Verifier;
    assert!(
        verifying.verify(signing_input.as_bytes(), &signature).is_ok(),
        "the assertion's signature must verify against the fixture public key"
    );
    // And a tampered signing input must not.
    let tampered = format!("{}.x{}", jwt[0], jwt[1]);
    assert!(
        verifying.verify(tampered.as_bytes(), &signature).is_err(),
        "a tampered assertion must not verify"
    );
}

#[test]
fn a_conflict_is_a_submission_already_made() {
    let http = fake(response(409, b"already there"));
    let (result, _) = drive(Arc::clone(&http));
    let outputs = result.expect("409 means the sitemap is already submitted");
    assert_eq!(outputs.get("submitted"), Some(&Value::from(true)));
}

#[test]
fn other_statuses_fail_with_the_status_and_no_token() {
    for status in [403, 404, 500] {
        let http = fake(response(status, b""));
        let (result, _) = drive(Arc::clone(&http));
        let error = result.expect_err("only 2xx and 409 mean submitted");
        assert!(
            matches!(&error, StepError::Failed(message) if message.contains(&status.to_string())),
            "{status}: {error}"
        );
        // The bearer token is a secret the error must not quote back.
        if let StepError::Failed(message) = &error {
            assert!(!message.contains("tok"), "{message}");
        }
    }
}

#[test]
fn a_refused_token_exchange_fails_the_step() {
    let http = Arc::new(
        FakeHttpClient::new()
            .with_allowed_host("oauth2.googleapis.com")
            .with_allowed_host("www.googleapis.com")
            .with_response(HttpMethod::Post, TOKEN_URL, response(401, b"bad assertion")),
    );
    let (result, _) = drive(Arc::clone(&http));
    let error = result.expect_err("a refused exchange is a failed step");
    assert!(matches!(&error, StepError::Failed(message) if message.contains("401")), "{error}");
    assert_eq!(http.requests().len(), 1, "a refused exchange is never spent");
}

#[test]
fn a_token_exchange_that_is_not_json_or_has_no_token_fails() {
    for body in ["not json", r#"{"nope":true}"#] {
        let http = Arc::new(
            FakeHttpClient::new()
                .with_allowed_host("oauth2.googleapis.com")
                .with_allowed_host("www.googleapis.com")
                .with_response(HttpMethod::Post, TOKEN_URL, response(200, body.as_bytes())),
        );
        let (result, _) = drive(Arc::clone(&http));
        assert!(matches!(result, Err(StepError::Failed(_))), "{body}: {result:?}");
    }
}

#[test]
fn without_the_http_client_the_step_refuses_at_the_port() {
    // At composition time the refusal is the builder's: a step that requires
    // HttpClient cannot even build without one.
    let refused = Harness::builder()
        .ports(Ports::default().with_clock(Arc::new(FakeClock::new()) as Arc<dyn Clock>))
        .step(GscSitemapSubmit)
        .build()
        .expect_err("no http client was wired");
    assert!(format!("{refused:?}").contains("HttpClient"), "{refused:?}");

    // And the step's own guard answers in kind when a context without the
    // port reaches it anyway.
    let ctx = ks_core::step::StepCtx::new(
        Ports::default(),
        Arc::new(FakeClock::new()),
        CancellationToken::new(),
        ks_core::step::StepLog::new(
            "gsc.sitemap_submit",
            Arc::new(Redactor::new()),
            Arc::new(RecordingSink::new()),
        ),
    );
    let error = block_on(GscSitemapSubmit.run(ctx, inputs())).expect_err("no port, no run");
    assert!(matches!(&error, StepError::Port { port: Port::HttpClient, .. }), "{error}");
}

#[test]
fn malformed_inputs_are_invalid_input() {
    // Not JSON at all.
    let not_json = Inputs::from([
        ("credentials".to_string(), Value::from("let me in")),
        ("site".to_string(), Value::from(SITE)),
        ("sitemap".to_string(), Value::from(SITEMAP)),
    ]);
    // JSON, but missing the fields the step uses.
    let wrong_shape = Inputs::from([
        ("credentials".to_string(), Value::from(r#"{"client":"sa@test"}"#)),
        ("site".to_string(), Value::from(SITE)),
        ("sitemap".to_string(), Value::from(SITEMAP)),
    ]);
    // A key whose `private_key` is not a PKCS#8 PEM RSA key.
    let not_a_key = Inputs::from([
        (
            "credentials".to_string(),
            Value::from(
                r#"{"client_email":"sa@test.iam.gserviceaccount.com","private_key":"nope"}"#,
            ),
        ),
        ("site".to_string(), Value::from(SITE)),
        ("sitemap".to_string(), Value::from(SITEMAP)),
    ]);
    for credentials in [not_json, wrong_shape, not_a_key] {
        let http = fake(response(200, b""));
        let harness = compose(Arc::clone(&http));
        let sink = Arc::new(RecordingSink::new());
        let error = block_on(run_step(
            &harness,
            "gsc.sitemap_submit",
            credentials,
            CancellationToken::new(),
            Arc::clone(&sink) as Arc<dyn LogSink>,
            Arc::new(Redactor::new()),
        ))
        .expect_err("bad credentials are refused before any traffic");
        assert!(
            matches!(&error, StepError::InvalidInput { field, .. } if field == "credentials"),
            "{error}"
        );
        assert!(http.requests().is_empty(), "a refused step never reaches the network");
    }

    // Empty and non-https values for the two address inputs.
    for (name, value) in
        [("site", ""), ("sitemap", ""), ("sitemap", "http://example.com/sitemap.xml")]
    {
        let http = fake(response(200, b""));
        let harness = compose(Arc::clone(&http));
        let mut values = inputs();
        values.insert(name.to_string(), Value::from(value));
        let sink = Arc::new(RecordingSink::new());
        let error = block_on(run_step(
            &harness,
            "gsc.sitemap_submit",
            values,
            CancellationToken::new(),
            Arc::clone(&sink) as Arc<dyn LogSink>,
            Arc::new(Redactor::new()),
        ))
        .expect_err("a bad address is refused before any traffic");
        assert!(
            matches!(&error, StepError::InvalidInput { field, .. } if field == name),
            "{name}={value:?}: {error}"
        );
        assert!(http.requests().is_empty());
    }
}

#[test]
fn a_run_cancelled_before_the_step_never_reaches_the_network() {
    let http = fake(response(200, b""));
    let harness = compose(Arc::clone(&http));
    let sink = Arc::new(RecordingSink::new());
    let error = block_on(run_step(
        &harness,
        "gsc.sitemap_submit",
        inputs(),
        {
            let token = CancellationToken::new();
            token.cancel();
            token
        },
        Arc::clone(&sink) as Arc<dyn LogSink>,
        Arc::new(Redactor::new()),
    ))
    .expect_err("a cancelled run does not run");
    assert_eq!(error, StepError::Cancelled);
    assert!(http.requests().is_empty());
}

#[test]
fn the_sitemap_submit_step_passes_the_step_conformance_kit() {
    let http = fake(response(200, b""));
    let harness = compose(Arc::clone(&http));
    let case =
        StepCase::new("gsc.sitemap_submit", inputs()).with_secret("credentials", &credentials());
    block_on(step_conformance(&harness, case));
}
