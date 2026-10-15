//! The console sign-in (`src/signin.rs`), driven natively end to end: the
//! login redirect carries a fresh S256 PKCE challenge and `state`, the
//! callback exchanges the code with the matching verifier at a fake token
//! endpoint, the issued ES256 token passes the console's real verifier
//! (keys served by a fake JWKS endpoint), and only an allowlisted, verified
//! email gets the `ks_console` cookie. The refusals — bad state, missing or
//! tampered or expired login cookie, a failed exchange, an address off the
//! allowlist, hostile `next` values — each end without a session cookie.
//! Last, the cookie reaches the `/v1` console modules as their bearer.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cratefield_auth_client::AuthClient;
use cratefield_core::axum::body::{Body, Bytes};
use cratefield_core::{Clock, HmacSigner, HttpError};
use cratefield_testing::{FakeAuth, FakeHttpClient, FixedClock, TestHarness};
use http::{Method, Request, StatusCode};
use keepshipping_waitlist::signin::{self, Client, Keys, Refresh, Reply};
use keepshipping_waitlist::{Setup, venture};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tower::ServiceExt as _;

const ISSUER: &str = "https://auth.keepshipping.test";
const CLIENT_ID: &str = "keepshipping-console";
const ORIGIN: &str = "https://console.keepshipping.test";
const ALLOWLIST: &str = "ada@factory0.ventures, grace@factory0.ventures";
const SECRET: &str = "test-secret-0123456789abcdef-0123";
const NOW: i64 = 1_800_000_000;

const CLIENT: Client<'static> =
    Client { issuer: ISSUER, client_id: CLIENT_ID, client_secret: None };

fn clock_at(at: i64) -> Arc<dyn Clock> {
    Arc::new(FixedClock(OffsetDateTime::from_unix_timestamp(at).expect("in range")))
}

fn signer_at(at: i64) -> HmacSigner {
    HmacSigner::new(SECRET, None).expect("a long enough secret").with_clock(clock_at(at))
}

/// The sign-in keys at a moment; the signer is leaked so the keys can
/// borrow it for the whole test.
fn keys_at(at: i64) -> Keys<'static> {
    Keys::new(Box::leak(Box::new(signer_at(at))), SECRET, None).expect("keys")
}

/// The issuer's signing key: a fixed P-256 scalar, and its public JWK.
fn issuer_key() -> (SigningKey, Value) {
    let secret = p256::SecretKey::from_slice(&[7u8; 32]).expect("scalar");
    let signing = SigningKey::from(&secret);
    let point = signing.verifying_key().to_sec1_point(false);
    let sec1 = point.as_bytes();
    let jwk = json!({
        "kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig",
        "x": URL_SAFE_NO_PAD.encode(&sec1[1..33]),
        "y": URL_SAFE_NO_PAD.encode(&sec1[33..65]),
    });
    (signing, jwk)
}

/// An access token minted the way auth-core mints one.
fn access_token(email: &str, verified: bool) -> String {
    let (signing, _) = issuer_key();
    let header = json!({"alg": "ES256", "typ": "JWT", "kid": "k1"});
    let claims = json!({
        "iss": ISSUER, "sub": "user-1", "aud": CLIENT_ID, "sid": "session-1",
        "iat": NOW, "exp": NOW + 600, "email": email, "email_verified": verified,
        "amr": ["passkey"],
    });
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature: Signature = signing.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

fn json_response(status: u16, body: &str) -> Result<http::Response<Bytes>, HttpError> {
    Ok(http::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Bytes::from(body.to_owned()))
        .expect("a scripted response builds"))
}

/// The console's verifier, against a JWKS endpoint serving the issuer key.
fn verifier() -> AuthClient {
    let (_, jwk) = issuer_key();
    let jwks =
        FakeHttpClient::scripted(vec![json_response(200, &json!({ "keys": [jwk] }).to_string())]);
    AuthClient::new(Arc::new(jwks), clock_at(NOW), ISSUER, CLIENT_ID)
}

/// The auth-core token response for `token`.
fn token_endpoint(token: &str) -> FakeHttpClient {
    FakeHttpClient::scripted(vec![json_response(
        200,
        &json!({
            "access_token": token, "token_type": "Bearer", "expires_in": 600,
            "refresh_token": "rt_1",
        })
        .to_string(),
    )])
}

/// One query parameter of a URL, decoded.
fn param(url: &str, name: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    form_urlencoded::parse(query.as_bytes())
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

/// The value a `Set-Cookie` sets for `name`, if the reply sets it.
fn cookie_set(reply: &Reply, name: &str) -> Option<String> {
    reply.set_cookies.iter().find_map(|cookie| {
        let (pair, _) = cookie.split_once(';')?;
        let (key, value) = pair.split_once('=')?;
        (key == name).then(|| value.to_owned())
    })
}

/// The whole `Set-Cookie` line for `name`.
fn cookie_line<'a>(reply: &'a Reply, name: &str) -> &'a str {
    reply
        .set_cookies
        .iter()
        .find(|cookie| cookie.starts_with(&format!("{name}=")))
        .unwrap_or_else(|| panic!("no Set-Cookie for {name}: {:?}", reply.set_cookies))
}

/// A started sign-in: the authorize URL and the login cookie it set.
fn start(next: Option<&str>) -> (String, String) {
    let reply = signin::begin(&CLIENT, ORIGIN, next, &keys_at(NOW), NOW);
    assert_eq!(reply.status, 302, "{reply:?}");
    let location = reply.location.clone().expect("a redirect");
    let sealed = cookie_set(&reply, signin::LOGIN_COOKIE).expect("the login cookie");
    (location, sealed)
}

async fn callback(
    query: &str,
    cookie: Option<&str>,
    token_http: &FakeHttpClient,
    keys: &Keys<'_>,
) -> Reply {
    signin::finish(
        &CLIENT,
        ALLOWLIST,
        ORIGIN,
        Some(query),
        cookie,
        keys,
        token_http,
        &verifier(),
        NOW,
    )
    .await
}

fn login_cookie_header(sealed: &str) -> String {
    format!("other=1; {}={sealed}", signin::LOGIN_COOKIE)
}

/// Every refusal: no session cookie, the login cookie cleared.
fn assert_no_session(reply: &Reply) {
    assert!(cookie_set(reply, signin::SESSION_COOKIE).is_none(), "{reply:?}");
    assert!(cookie_line(reply, signin::LOGIN_COOKIE).contains("Max-Age=0"), "{reply:?}");
}

#[test]
fn login_redirects_to_the_issuer_with_pkce_and_a_signed_attempt() {
    let (location, _) = start(Some("/console/fleet/keepshipping-run"));
    assert!(location.starts_with(&format!("{ISSUER}/v1/auth-core/authorize?")), "{location}");
    assert_eq!(param(&location, "response_type").as_deref(), Some("code"));
    assert_eq!(param(&location, "client_id").as_deref(), Some(CLIENT_ID));
    assert_eq!(
        param(&location, "redirect_uri").as_deref(),
        Some("https://console.keepshipping.test/console/callback")
    );
    assert_eq!(param(&location, "code_challenge_method").as_deref(), Some("S256"));
    // auth-core's authorize takes no scope and no nonce.
    assert_eq!(param(&location, "scope"), None);
    assert_eq!(param(&location, "nonce"), None);
    assert_eq!(param(&location, "code_challenge").map(|c| c.len()), Some(43));
    assert_eq!(param(&location, "state").map(|s| s.len()), Some(22));

    let reply = signin::begin(&CLIENT, ORIGIN, None, &keys_at(NOW), NOW);
    let line = cookie_line(&reply, signin::LOGIN_COOKIE);
    for attribute in ["Max-Age=600", "Path=/console", "HttpOnly", "Secure", "SameSite=Lax"] {
        assert!(line.contains(attribute), "{attribute} missing: {line}");
    }
    // Fresh every time: a second attempt shares no state or challenge.
    let (again, _) = start(None);
    assert_ne!(param(&location, "state"), param(&again, "state"));
    assert_ne!(param(&location, "code_challenge"), param(&again, "code_challenge"));
    // Never over plain http, and never against a plain-http issuer.
    let plain =
        signin::begin(&CLIENT, "http://console.keepshipping.test", None, &keys_at(NOW), NOW);
    assert_eq!(plain.status, 400);
    assert!(plain.set_cookies.is_empty());
}

#[test]
fn the_happy_path_sets_the_session_cookie_and_returns_to_next() {
    pollster::block_on(async {
        let (location, sealed) = start(Some("/console/fleet/keepshipping-run"));
        let state = param(&location, "state").expect("state");
        let challenge = param(&location, "code_challenge").expect("challenge");
        let token = access_token("Ada@Factory0.Ventures", true);
        let token_http = token_endpoint(&token);

        let reply = callback(
            &format!("code=c0de&state={state}"),
            Some(&login_cookie_header(&sealed)),
            &token_http,
            &keys_at(NOW + 30),
        )
        .await;
        assert_eq!(reply.status, 303, "{reply:?}");
        assert_eq!(reply.location.as_deref(), Some("/console/fleet/keepshipping-run"));
        assert_eq!(cookie_set(&reply, signin::SESSION_COOKIE).as_deref(), Some(token.as_str()));
        let line = cookie_line(&reply, signin::SESSION_COOKIE);
        for attribute in ["Max-Age=600", "Path=/", "HttpOnly", "Secure", "SameSite=Lax"] {
            assert!(line.contains(attribute), "{attribute} missing: {line}");
        }
        assert!(!line.contains("Domain="), "host-only: {line}");
        // The refresh token rides sealed, on /console only, for the
        // issuer's 30-day sliding session.
        let sealed_refresh = cookie_set(&reply, signin::REFRESH_COOKIE).expect("refresh cookie");
        assert!(!sealed_refresh.contains("rt_1"), "sealed, not readable: {sealed_refresh}");
        let line = cookie_line(&reply, signin::REFRESH_COOKIE);
        for attribute in ["Max-Age=2592000", "Path=/console;", "HttpOnly", "Secure", "SameSite=Lax"]
        {
            assert!(line.contains(attribute), "{attribute} missing: {line}");
        }
        assert!(cookie_line(&reply, signin::LOGIN_COOKIE).contains("Max-Age=0"));

        // The exchange was auth-core's shape, with the verifier that
        // matches the challenge the browser carried to the issuer.
        let captured = token_http.captured();
        assert_eq!(captured.len(), 1);
        let (method, uri, body) = &captured[0];
        assert_eq!(method, "POST");
        assert_eq!(uri, &format!("{ISSUER}/v1/auth-core/token"));
        let form: Vec<(String, String)> = form_urlencoded::parse(body.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let field = |name: &str| form.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
        assert_eq!(field("grant_type"), Some("authorization_code"));
        assert_eq!(field("code"), Some("c0de"));
        assert_eq!(field("client_id"), Some(CLIENT_ID));
        assert_eq!(
            field("redirect_uri"),
            Some("https://console.keepshipping.test/console/callback")
        );
        assert_eq!(field("client_secret"), None, "a public client sends no secret");
        let verifier = field("code_verifier").expect("the PKCE verifier");
        assert_eq!(URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())), challenge);
    });
}

#[test]
fn a_confidential_client_sends_its_secret() {
    pollster::block_on(async {
        let client = Client { client_secret: Some("cs_test_value"), ..CLIENT };
        let reply = signin::begin(&client, ORIGIN, None, &keys_at(NOW), NOW);
        let state = param(reply.location.as_deref().expect("redirect"), "state").expect("state");
        let sealed = cookie_set(&reply, signin::LOGIN_COOKIE).expect("cookie");
        let token_http = token_endpoint(&access_token("ada@factory0.ventures", true));
        let reply = signin::finish(
            &client,
            ALLOWLIST,
            ORIGIN,
            Some(&format!("code=c&state={state}")),
            Some(&login_cookie_header(&sealed)),
            &keys_at(NOW),
            &token_http,
            &verifier(),
            NOW,
        )
        .await;
        assert_eq!(reply.status, 303, "{reply:?}");
        assert!(token_http.captured()[0].2.contains("client_secret=cs_test_value"));
    });
}

#[test]
fn a_bad_state_is_refused_before_any_exchange() {
    pollster::block_on(async {
        let (_, sealed) = start(None);
        let token_http = token_endpoint(&access_token("ada@factory0.ventures", true));
        for query in ["code=c0de&state=forged", "code=c0de", "state=&code=c0de"] {
            let reply =
                callback(query, Some(&login_cookie_header(&sealed)), &token_http, &keys_at(NOW))
                    .await;
            assert_eq!(reply.status, 400, "{query}: {reply:?}");
            assert_no_session(&reply);
        }
        assert!(token_http.captured().is_empty(), "no code was exchanged");
    });
}

#[test]
fn a_missing_tampered_or_expired_login_cookie_is_refused() {
    pollster::block_on(async {
        let (location, sealed) = start(None);
        let state = param(&location, "state").expect("state");
        let query = format!("code=c0de&state={state}");
        let token_http = token_endpoint(&access_token("ada@factory0.ventures", true));

        let missing = callback(&query, None, &token_http, &keys_at(NOW)).await;
        assert_eq!(missing.status, 400);
        assert_no_session(&missing);
        let other_cookies = callback(&query, Some("a=1; b=2"), &token_http, &keys_at(NOW)).await;
        assert_eq!(other_cookies.status, 400);

        // One byte of the signed payload changed: the MAC no longer holds.
        let (payload, mac) = sealed.split_once('.').expect("payload.mac");
        let mut bytes = payload.as_bytes().to_vec();
        bytes[3] = if bytes[3] == b'A' { b'B' } else { b'A' };
        let tampered = format!("{}.{mac}", String::from_utf8(bytes).expect("ascii"));
        let reply =
            callback(&query, Some(&login_cookie_header(&tampered)), &token_http, &keys_at(NOW))
                .await;
        assert_eq!(reply.status, 400);

        // Signed with another key (another deployment's HARNESS_SECRET).
        let other = "another-secret-0123456789abcdef-0123";
        let foreign_signer: &'static HmacSigner = Box::leak(Box::new(
            HmacSigner::new(other, None).expect("secret").with_clock(clock_at(NOW)),
        ));
        let foreign = Keys::new(foreign_signer, other, None).expect("keys");
        let reply =
            callback(&query, Some(&login_cookie_header(&sealed)), &token_http, &foreign).await;
        assert_eq!(reply.status, 400);

        // Ten minutes and a second later the attempt is over.
        let reply = callback(
            &query,
            Some(&login_cookie_header(&sealed)),
            &token_http,
            &keys_at(NOW + signin::LOGIN_TTL_SECS + 1),
        )
        .await;
        assert_eq!(reply.status, 400);
        assert_no_session(&reply);
        assert!(token_http.captured().is_empty(), "no code was exchanged");
    });
}

#[test]
fn an_issuer_error_or_a_failed_exchange_sets_no_session() {
    pollster::block_on(async {
        let (location, sealed) = start(None);
        let state = param(&location, "state").expect("state");
        let cookie = login_cookie_header(&sealed);

        // The person cancelled at the issuer.
        let token_http = token_endpoint("unused");
        let reply = callback(
            &format!("error=access_denied&state={state}"),
            Some(&cookie),
            &token_http,
            &keys_at(NOW),
        )
        .await;
        assert_eq!(reply.status, 400);
        assert_no_session(&reply);
        assert!(token_http.captured().is_empty());

        // auth-core's one refusal (a reused code, a wrong verifier, ...).
        let refused = FakeHttpClient::scripted(vec![json_response(
            400,
            r#"{"type":"auth/token-request-refused","status":400}"#,
        )]);
        let query = format!("code=c0de&state={state}");
        let reply = callback(&query, Some(&cookie), &refused, &keys_at(NOW)).await;
        assert_eq!(reply.status, 502, "{reply:?}");
        assert_no_session(&reply);
        assert_eq!(
            reply.notice.as_ref().and_then(|n| n.link.clone()).map(|(href, _)| href).as_deref(),
            Some("/console/login"),
            "a way to try again"
        );

        // The issuer unreachable, a garbled answer, a token that is not
        // the issuer's: all the same no.
        let unreachable =
            FakeHttpClient::scripted(vec![Err(HttpError::Transport("down".to_owned()))]);
        let garbled = FakeHttpClient::scripted(vec![json_response(200, "not json")]);
        let forged = token_endpoint("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.");
        for http in [unreachable, garbled, forged] {
            let reply = callback(&query, Some(&cookie), &http, &keys_at(NOW)).await;
            assert_eq!(reply.status, 502, "{reply:?}");
            assert_no_session(&reply);
        }
    });
}

#[test]
fn an_email_off_the_allowlist_or_unverified_is_403_with_no_cookie() {
    pollster::block_on(async {
        for (email, verified) in [
            ("mallory@evil.example", true),
            ("ada@factory0.ventures.evil.example", true),
            ("ada@factory0.ventures", false),
        ] {
            let (location, sealed) = start(None);
            let state = param(&location, "state").expect("state");
            let reply = callback(
                &format!("code=c0de&state={state}"),
                Some(&login_cookie_header(&sealed)),
                &token_endpoint(&access_token(email, verified)),
                &keys_at(NOW),
            )
            .await;
            assert_eq!(reply.status, 403, "{email}: {reply:?}");
            assert_no_session(&reply);
        }
    });
}

#[test]
fn next_never_leaves_the_console() {
    for hostile in [
        "https://evil.example/console",
        "//evil.example/console",
        "/\\evil.example",
        "/\t/evil.example",
        "\\/evil.example",
        "/consolex",
        "/console\n/x",
        "/v1/waitlist/admin/export.csv",
        "javascript:alert(1)",
        "",
        "console/fleet",
        "/%2F%2Fevil.example",
    ] {
        let kept = signin::safe_next(Some(hostile));
        assert!(
            kept == "/console/fleet" || hostile == "/%2F%2Fevil.example",
            "{hostile:?} became {kept:?}"
        );
    }
    // Percent-encoded slashes stay a path on this host: not a redirect out.
    assert_eq!(signin::safe_next(Some("/%2F%2Fevil.example")), "/console/fleet");
    for fine in [
        "/console",
        "/console/fleet/keepshipping-run",
        "/console/fleet?x=1",
        "/v1/edits/new?kind=dns&zone=keepshipping.run",
        "/v1/setup/example.test",
        "/v1/console/search-console?zone=example.com",
    ] {
        assert_eq!(signin::safe_next(Some(fine)), fine);
    }
    assert_eq!(signin::safe_next(None), "/console/fleet");
}

#[test]
fn a_hostile_next_lands_on_the_fleet_after_a_real_sign_in() {
    pollster::block_on(async {
        for (next, lands) in [
            ("//evil.example", "/console/fleet"),
            ("https://evil.example/", "/console/fleet"),
            ("/v1/setup/example.test", "/v1/setup/example.test"),
        ] {
            let (location, sealed) = start(Some(next));
            let state = param(&location, "state").expect("state");
            let reply = callback(
                &format!("code=c0de&state={state}"),
                Some(&login_cookie_header(&sealed)),
                &token_endpoint(&access_token("grace@factory0.ventures", true)),
                &keys_at(NOW),
            )
            .await;
            assert_eq!(reply.status, 303, "{reply:?}");
            assert_eq!(reply.location.as_deref(), Some(lands), "{next}");
        }
    });
}

#[test]
fn logout_clears_the_session_cookie_and_links_the_issuer_sign_out() {
    let reply = signin::logout(&CLIENT);
    assert_eq!(reply.status, 200);
    let line = cookie_line(&reply, signin::SESSION_COOKIE);
    assert!(line.starts_with("ks_console=;") && line.contains("Max-Age=0"), "{line}");
    assert!(line.contains("Path=/;"), "the same path it was set on: {line}");
    let link = reply.notice.and_then(|notice| notice.link).expect("issuer sign-out link");
    assert_eq!(link.0, format!("{ISSUER}/v1/auth-core/logout"));
}

#[test]
fn the_sign_in_link_carries_where_the_person_was() {
    assert_eq!(signin::login_href("/console/fleet"), "/console/login?next=%2Fconsole%2Ffleet");
    assert_eq!(
        signin::login_href("/v1/edits/new?kind=dns&zone=a"),
        "/console/login?next=%2Fv1%2Fedits%2Fnew%3Fkind%3Ddns%26zone%3Da"
    );
}

#[test]
fn the_session_cookie_becomes_the_bearer_header() {
    let mut headers = http::HeaderMap::new();
    headers.insert("cookie", "a=1; ks_console=tok.abc".parse().expect("header"));
    let credentials = signin::session_credentials(&headers);
    assert_eq!(credentials.get("authorization").expect("bearer"), "Bearer tok.abc");
    // An explicit header wins; the cookie never overrides it.
    headers.insert("authorization", "Bearer explicit".parse().expect("header"));
    let credentials = signin::session_credentials(&headers);
    assert_eq!(credentials.get("authorization").expect("bearer"), "Bearer explicit");
    // No cookie, no header.
    assert!(signin::session_credentials(&http::HeaderMap::new()).get("authorization").is_none());
}

/// The `/v1` console pages read the same cookie: the setup console, through
/// the venture's composition, names the caller from `ks_console`, and its
/// signed-out page links the console sign-in.
#[test]
fn the_setup_console_reads_the_cookie_and_links_the_sign_in() {
    pollster::block_on(async {
        let kit = TestHarness::with_builder(
            vec![Box::new(Setup::new(None))],
            |builder| builder.venture(venture()),
            |ports| {
                ports.auth = Some(Arc::new(FakeAuth::subjects()));
                ports.http = Some(Arc::new(FakeHttpClient::scripted(vec![])));
            },
        );
        let get = |cookie: Option<&str>| {
            let mut request = Request::builder().method(Method::GET).uri("/v1/setup");
            if let Some(cookie) = cookie {
                request = request.header("cookie", cookie);
            }
            kit.router.clone().oneshot(request.body(Body::empty()).expect("request"))
        };
        let signed_in = get(Some("ks_console=acc_1")).await.expect("served");
        assert_eq!(signed_in.status(), StatusCode::OK);

        let signed_out = get(None).await.expect("served");
        assert_eq!(signed_out.status(), StatusCode::UNAUTHORIZED);
        let body = cratefield_core::axum::body::to_bytes(signed_out.into_body(), usize::MAX)
            .await
            .expect("body");
        let page = String::from_utf8_lossy(&body);
        assert!(page.contains("href=\"/console/login?next=%2Fv1%2Fsetup\""), "{page}");
    });
}

/// A finished sign-in's sealed refresh cookie (holding `rt_1`).
fn signed_in() -> String {
    pollster::block_on(async {
        let (location, sealed) = start(None);
        let state = param(&location, "state").expect("state");
        let reply = callback(
            &format!("code=c0de&state={state}"),
            Some(&login_cookie_header(&sealed)),
            &token_endpoint(&access_token("ada@factory0.ventures", true)),
            &keys_at(NOW),
        )
        .await;
        cookie_set(&reply, signin::REFRESH_COOKIE).expect("refresh cookie")
    })
}

fn refresh_cookie_header(sealed: &str) -> String {
    format!("ks_console=expired; {}={sealed}", signin::REFRESH_COOKIE)
}

/// A token endpoint answering one refresh with a new pair.
fn rotating(refresh_token: &str) -> FakeHttpClient {
    FakeHttpClient::scripted(vec![json_response(
        200,
        &json!({
            "access_token": access_token("ada@factory0.ventures", true),
            "token_type": "Bearer", "expires_in": 600, "refresh_token": refresh_token,
        })
        .to_string(),
    )])
}

fn form_field(body: &str, name: &str) -> Option<String> {
    form_urlencoded::parse(body.as_bytes()).find(|(k, _)| k == name).map(|(_, v)| v.into_owned())
}

#[test]
fn an_expired_session_is_renewed_and_the_rotated_refresh_token_kept() {
    pollster::block_on(async {
        let sealed = signed_in();
        let http = rotating("rt_2");
        let renewed = signin::refresh(
            &CLIENT,
            Some(&refresh_cookie_header(&sealed)),
            &keys_at(NOW),
            &http,
            &verifier(),
            NOW,
        )
        .await;
        let Refresh::Renewed { claims, set_cookies } = renewed else {
            panic!("expected a renewal, got {renewed:?}");
        };
        assert_eq!(claims.email.as_deref(), Some("ada@factory0.ventures"));
        let (_, uri, body) = &http.captured()[0];
        assert_eq!(uri, &format!("{ISSUER}/v1/auth-core/token"));
        assert_eq!(form_field(body, "grant_type").as_deref(), Some("refresh_token"));
        assert_eq!(form_field(body, "refresh_token").as_deref(), Some("rt_1"));
        assert_eq!(form_field(body, "client_id").as_deref(), Some(CLIENT_ID));
        let reply = Reply { status: 200, location: None, notice: None, set_cookies };
        let access = cookie_line(&reply, signin::SESSION_COOKIE);
        assert!(access.contains("Max-Age=600") && access.contains("Path=/;"), "{access}");
        let rotated = cookie_set(&reply, signin::REFRESH_COOKIE).expect("a new refresh cookie");
        assert_ne!(rotated, sealed);

        // The next renewal spends the rotated token, never the spent one.
        let http = rotating("rt_3");
        let again = signin::refresh(
            &CLIENT,
            Some(&refresh_cookie_header(&rotated)),
            &keys_at(NOW),
            &http,
            &verifier(),
            NOW,
        )
        .await;
        assert!(matches!(again, Refresh::Renewed { .. }), "{again:?}");
        assert_eq!(form_field(&http.captured()[0].2, "refresh_token").as_deref(), Some("rt_2"));
    });
}

#[test]
fn a_refused_refresh_signs_out_and_an_unreachable_issuer_keeps_the_cookie() {
    pollster::block_on(async {
        let sealed = signed_in();
        let header = refresh_cookie_header(&sealed);
        let refused = FakeHttpClient::scripted(vec![json_response(
            400,
            r#"{"type":"auth/token-request-refused","status":400}"#,
        )]);
        let outcome =
            signin::refresh(&CLIENT, Some(&header), &keys_at(NOW), &refused, &verifier(), NOW)
                .await;
        let Refresh::SignedOut { set_cookies } = outcome else {
            panic!("a refusal is signed out, got {outcome:?}");
        };
        let reply = Reply { status: 401, location: None, notice: None, set_cookies };
        assert!(cookie_line(&reply, signin::SESSION_COOKIE).contains("Max-Age=0"));
        assert!(cookie_line(&reply, signin::REFRESH_COOKIE).contains("Max-Age=0"));

        // Down is not refused: the cookie stays for the next request.
        let down = FakeHttpClient::scripted(vec![Err(HttpError::Transport("down".to_owned()))]);
        let outcome =
            signin::refresh(&CLIENT, Some(&header), &keys_at(NOW), &down, &verifier(), NOW).await;
        assert!(matches!(outcome, Refresh::Unavailable), "{outcome:?}");

        // No refresh cookie: nothing to ask, nothing to clear. A cookie
        // that does not open (forged, or another deployment's key): cleared
        // without asking the issuer.
        let http = rotating("unused");
        let none =
            signin::refresh(&CLIENT, Some("a=1"), &keys_at(NOW), &http, &verifier(), NOW).await;
        assert!(matches!(none, Refresh::SignedOut { ref set_cookies } if set_cookies.is_empty()));
        let forged = refresh_cookie_header("not-a-sealed-token");
        let bad =
            signin::refresh(&CLIENT, Some(&forged), &keys_at(NOW), &http, &verifier(), NOW).await;
        assert!(matches!(bad, Refresh::SignedOut { ref set_cookies } if set_cookies.len() == 2));
        assert!(http.captured().is_empty(), "the issuer was never asked");
    });
}

#[test]
fn a_rotated_harness_secret_still_opens_the_refresh_cookie() {
    pollster::block_on(async {
        let sealed = signed_in();
        let new_secret = "rotated-secret-0123456789abcdef-0123";
        let signer: &'static HmacSigner = Box::leak(Box::new(
            HmacSigner::new(new_secret, Some(SECRET.to_owned())).expect("secret"),
        ));
        let keys = Keys::new(signer, new_secret, Some(SECRET)).expect("keys");
        let outcome = signin::refresh(
            &CLIENT,
            Some(&refresh_cookie_header(&sealed)),
            &keys,
            &rotating("rt_2"),
            &verifier(),
            NOW,
        )
        .await;
        assert!(matches!(outcome, Refresh::Renewed { .. }), "{outcome:?}");
    });
}

#[test]
fn login_with_a_live_refresh_cookie_skips_the_issuer_round_trip() {
    pollster::block_on(async {
        let sealed = signed_in();
        let header = refresh_cookie_header(&sealed);
        let reply = signin::login(
            &CLIENT,
            ALLOWLIST,
            ORIGIN,
            Some("/v1/setup/example.test"),
            Some(&header),
            &keys_at(NOW),
            &rotating("rt_2"),
            &verifier(),
            NOW,
        )
        .await;
        assert_eq!(reply.status, 303, "{reply:?}");
        assert_eq!(reply.location.as_deref(), Some("/v1/setup/example.test"));
        assert!(cookie_set(&reply, signin::SESSION_COOKIE).is_some());

        // A refused refresh falls back to the issuer, clearing the old pair.
        let refused = FakeHttpClient::scripted(vec![json_response(400, "{}")]);
        let reply = signin::login(
            &CLIENT,
            ALLOWLIST,
            ORIGIN,
            None,
            Some(&header),
            &keys_at(NOW),
            &refused,
            &verifier(),
            NOW,
        )
        .await;
        assert_eq!(reply.status, 302, "{reply:?}");
        assert!(reply.location.as_deref().unwrap_or_default().starts_with(ISSUER));
        assert!(cookie_line(&reply, signin::REFRESH_COOKIE).contains("Max-Age=0"));
        assert!(cookie_set(&reply, signin::LOGIN_COOKIE).is_some_and(|v| !v.is_empty()));
    });
}
