//! Console sign-in: the authorization-code flow (with S256 PKCE) against a
//! Cratefield auth instance, ending in the `ks_console` session cookie every
//! console page reads — the fleet view, standard setup, Search Console and
//! edit as code.
//!
//! The contract is the auth service's (`cratefield-auth-core`):
//!
//! * `GET {AUTH_ISSUER}/v1/auth-core/authorize` with `client_id`,
//!   `redirect_uri` (exact-matched against the registration),
//!   `response_type=code`, `state` and an S256 `code_challenge`; a person
//!   with no live session at the issuer signs in there first.
//! * `POST {AUTH_ISSUER}/v1/auth-core/token`, form-encoded,
//!   `grant_type=authorization_code` with `code`, `redirect_uri`,
//!   `code_verifier` and `client_id` (plus `client_secret` for a
//!   confidential client). The answer is `{access_token, token_type:
//!   "Bearer", expires_in, refresh_token}`; the access token is the ES256
//!   JWT the console's verifier already checks (`aud` = our client id), and
//!   lives [`expires_in`](cratefield_oauth_client::TokenResponse) seconds
//!   (600 today).
//! * `POST {AUTH_ISSUER}/v1/auth-core/token` with
//!   `grant_type=refresh_token`, `client_id` and `refresh_token`: a new
//!   pair. Refresh tokens rotate on every use and are single-use (reusing a
//!   spent one revokes the session), so the new one is always kept; the
//!   session slides over 30 days.
//!
//! The session is two cookies. `ks_console` is the access token, verbatim,
//! for exactly as long as it lives, on `Path=/` so the `/v1` console pages
//! read it too. `ks_console_refresh` is the refresh token, sealed
//! (XChaCha20-Poly1305 under a key derived from `HARNESS_SECRET`, so it is
//! unreadable as well as tamper-proof), on `Path=/console`: when the access
//! cookie is gone or no longer verifies, a `/console` page — or the login
//! route a `/v1` page's "Sign in" link leads to — refreshes server-side and
//! sets both again, before falling back to the 401 or the issuer.
//!
//! Everything here is a pure function or generic over the harness ports
//! (`Signer`, `HttpClient`, the `AuthClient` verifier), so
//! `tests/signin.rs` drives the whole flow natively against fakes; the
//! Workers glue in `fleet/console.rs` only turns a [`Reply`] into a
//! response.
//!
//! The transient login cookie (`ks_console_login`) carries `state`, the
//! PKCE verifier and the return path, signed with the harness key ring
//! (`HARNESS_SECRET`, the same HMAC signer that signs confirm links) under
//! its own purpose and a ten-minute expiry. It is scoped to `/console`,
//! HttpOnly, Secure and SameSite=Lax (the callback is a top-level GET from
//! the issuer, which Lax still carries).

use base64::Engine as _;
use cratefield_auth_client::{AuthClient, Claims};
use cratefield_core::axum::body::Bytes;
use cratefield_core::{HttpClient, Kid, Payload, Signer, constant_time_eq};
use cratefield_oauth_client::{
    ClientAuth, Pkce, ProviderConfig, SealContext, TokenResponse, TokenSealer, XChaChaSealer,
    authorize_url, random_state,
};
use http::{HeaderMap, header};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::fleet::email_allowed;

/// The console session cookie: the issuer's access token, verbatim.
pub const SESSION_COOKIE: &str = "ks_console";
/// The short-lived cookie that carries one sign-in attempt.
pub const LOGIN_COOKIE: &str = "ks_console_login";
/// The sealed refresh token.
pub const REFRESH_COOKIE: &str = "ks_console_refresh";
/// The refresh cookie's lifetime: the issuer's 30-day sliding session.
pub const REFRESH_TTL_SECS: i64 = 30 * 86_400;
/// The sealed refresh token's place, bound into its ciphertext.
const REFRESH_SEAL: SealContext<'static> = SealContext {
    namespace: "keepshipping-console",
    table: "session",
    row_id: "browser",
    column: "refresh_token",
};
/// How long a sign-in attempt may take, start to callback.
pub const LOGIN_TTL_SECS: i64 = 600;
/// The signer purpose of the login cookie; nothing else verifies under it.
const LOGIN_PURPOSE: &str = "keepshipping-console.login";

/// `GET` — starts a sign-in (`?next=<path>`).
pub const LOGIN_PATH: &str = "/console/login";
/// `GET` — the issuer sends the browser back here with `code` and `state`.
/// Register `https://<console host>/console/callback` with the issuer.
pub const CALLBACK_PATH: &str = "/console/callback";
/// `POST` — clears the session cookie.
pub const LOGOUT_PATH: &str = "/console/logout";
/// Where a sign-in lands when `next` is absent or refused.
pub const DEFAULT_NEXT: &str = "/console/fleet";

/// The auth service's routes under its issuer (auth-core's
/// `/.well-known/openid-configuration` names the same three).
const AUTHORIZE_ROUTE: &str = "/v1/auth-core/authorize";
const TOKEN_ROUTE: &str = "/v1/auth-core/token";
const ISSUER_LOGOUT_ROUTE: &str = "/v1/auth-core/logout";

/// The console paths a sign-in may return to. Everything else — another
/// host, a scheme-relative `//`, a backslash a browser would read as a
/// slash, control characters — lands on [`DEFAULT_NEXT`] instead.
const RETURN_PREFIXES: [&str; 4] = ["/console", "/v1/edits", "/v1/setup", "/v1/console"];

/// The console's registration at the issuer.
#[derive(Clone, Copy)]
pub struct Client<'a> {
    /// `AUTH_ISSUER`: the issuer origin (`https://auth.keepshipping.run`).
    pub issuer: &'a str,
    /// `AUTH_CLIENT_ID`: the console's client id; every token's `aud`.
    pub client_id: &'a str,
    /// `AUTH_CLIENT_SECRET`, for a confidential registration. `None` is a
    /// public client, which auth-core authenticates by PKCE alone.
    pub client_secret: Option<&'a str>,
}

impl Client<'_> {
    fn issuer(&self) -> &str {
        self.issuer.trim_end_matches('/')
    }

    fn provider(&self) -> ProviderConfig {
        ProviderConfig {
            authorize_url: format!("{}{AUTHORIZE_ROUTE}", self.issuer()),
            token_url: format!("{}{TOKEN_ROUTE}", self.issuer()),
            revoke_url: None,
            client_id: self.client_id.to_owned(),
            client_secret: self.client_secret.map(str::to_owned),
            // auth-core takes no `scope` (its tokens always carry `email`
            // and `email_verified` when the user has an address); an empty
            // list leaves the parameter off the authorize URL.
            scopes: Vec::new(),
            scope_separator: " ",
            client_auth: ClientAuth::ClientSecretPost,
        }
    }
}

/// What a sign-in route answers, without any Workers types: a redirect or a
/// notice page, plus the `Set-Cookie` values to send with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    /// `Location` on a redirect.
    pub location: Option<String>,
    /// The notice page on anything that is not a redirect.
    pub notice: Option<Notice>,
    /// One `Set-Cookie` header each.
    pub set_cookies: Vec<String>,
}

/// A notice page's words and optional link (`(href, text)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub title: String,
    pub message: String,
    pub link: Option<(String, String)>,
}

impl Reply {
    fn redirect(status: u16, location: impl Into<String>, set_cookies: Vec<String>) -> Self {
        Self { status, location: Some(location.into()), notice: None, set_cookies }
    }

    fn notice(status: u16, title: &str, message: &str, link: Option<(String, String)>) -> Self {
        Self {
            status,
            location: None,
            notice: Some(Notice { title: title.to_owned(), message: message.to_owned(), link }),
            set_cookies: Vec::new(),
        }
    }

    fn with_cookie(mut self, cookie: String) -> Self {
        self.set_cookies.push(cookie);
        self
    }
}

/// The keys `HARNESS_SECRET` (and `HARNESS_SECRET_PREVIOUS`) give the
/// sign-in: the harness signer for the login cookie, and sealers derived
/// from the same secrets for the refresh cookie — the current one seals,
/// both open, so a rotation does not sign everyone out.
pub struct Keys<'a> {
    signer: &'a dyn Signer,
    sealers: Vec<XChaChaSealer>,
}

impl<'a> Keys<'a> {
    /// `None` only if a sealer key cannot be built, which a 32-byte digest
    /// always can.
    #[must_use]
    pub fn new(signer: &'a dyn Signer, secret: &str, previous: Option<&str>) -> Option<Self> {
        // The blob names its key by id, so the id follows the secret (not
        // its position): a cookie sealed under today's current key still
        // finds it once that key has become the previous one.
        let sealer = |secret: &str| {
            let derive = |label: &[u8]| {
                let mut digest = Sha256::new();
                digest.update(label);
                digest.update(secret.as_bytes());
                digest.finalize()
            };
            let key = derive(b"keepshipping-console refresh-cookie seal v1\0");
            let id = derive(b"keepshipping-console refresh-cookie key id v1\0")[0];
            let key = base64::engine::general_purpose::STANDARD.encode(key);
            XChaChaSealer::from_base64_key(&key, id).ok()
        };
        let mut sealers = vec![sealer(secret)?];
        if let Some(previous) = previous {
            sealers.push(sealer(previous)?);
        }
        Some(Self { signer, sealers })
    }

    fn seal(&self, refresh_token: &str) -> Option<String> {
        self.sealers.first()?.seal(refresh_token, &REFRESH_SEAL).ok()
    }

    fn open(&self, sealed: &str) -> Option<String> {
        self.sealers
            .iter()
            .find_map(|sealer| sealer.open(sealed, &REFRESH_SEAL).ok())
            .map(|token| token.to_string())
    }
}

/// What the login cookie carries; signed, so none of it can be swapped.
#[derive(Serialize, Deserialize)]
struct Attempt {
    state: String,
    verifier: String,
    next: String,
}

/// `next` if it is a console path a sign-in may return to, else
/// [`DEFAULT_NEXT`]. Only a same-origin absolute path qualifies: it must
/// start with exactly one `/`, carry no backslash, whitespace or control
/// character (browsers strip or reinterpret those, turning `/\t/evil` into
/// `//evil`), and sit under one of the console prefixes on a segment
/// boundary (`/console`, `/console/…`, `/console?…` — never `/consolex`).
#[must_use]
pub fn safe_next(raw: Option<&str>) -> String {
    let Some(next) = raw else {
        return DEFAULT_NEXT.to_owned();
    };
    let shaped = next.starts_with('/')
        && !next.starts_with("//")
        && next.len() <= 1024
        && next.bytes().all(|byte| byte.is_ascii_graphic() && byte != b'\\');
    let under_console = RETURN_PREFIXES.iter().any(|prefix| {
        next.strip_prefix(prefix)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(['/', '?', '#']))
    });
    if shaped && under_console { next.to_owned() } else { DEFAULT_NEXT.to_owned() }
}

/// The "Sign in" link a signed-out console page shows: the console's own
/// login, coming back to `next` (which [`safe_next`] re-checks on use).
#[must_use]
pub fn login_href(next: &str) -> String {
    let query = form_urlencoded::Serializer::new(String::new()).append_pair("next", next).finish();
    format!("{LOGIN_PATH}?{query}")
}

/// The credentials a console request brings: an `Authorization` header
/// when a page's `fetch` sent one, otherwise the session cookie turned
/// into one, so the harness's bearer-token verifier (the `Auth` port)
/// reads both. SameSite=Lax plus the worker's origin guard on writes are
/// what keep a cookie-bearing form post safe against cross-site forgery.
#[must_use]
pub fn session_credentials(headers: &HeaderMap) -> HeaderMap {
    if headers.contains_key(header::AUTHORIZATION) {
        return headers.clone();
    }
    let cookie = headers.get(header::COOKIE).and_then(|value| value.to_str().ok());
    let token = crate::fleet::cookie_value(cookie, SESSION_COOKIE).filter(|t| !t.is_empty());
    let mut with_bearer = headers.clone();
    if let Some(token) = token
        && let Ok(value) = format!("Bearer {token}").parse()
    {
        with_bearer.insert(header::AUTHORIZATION, value);
    }
    with_bearer
}

/// `GET /console/login?next=<path>`: a fresh `state` and PKCE pair, kept
/// in the signed login cookie, and a redirect to the issuer's authorize
/// endpoint. `origin` is the console's own `https://` origin (the request
/// URL's); the issuer exact-matches `{origin}/console/callback` against
/// the registration, so a forged host can never receive a code.
#[must_use]
pub fn begin(
    client: &Client<'_>,
    origin: &str,
    next: Option<&str>,
    keys: &Keys<'_>,
    now: i64,
) -> Reply {
    if !origin.starts_with("https://") || !client.issuer().starts_with("https://") {
        return Reply::notice(
            400,
            "Sign-in needs HTTPS",
            "The console signs in only over https, against an https issuer.",
            None,
        );
    }
    let (Ok(pkce), Ok(state)) = (Pkce::new(), random_state()) else {
        tracing::error!("console sign-in: no randomness for state/PKCE");
        return Reply::notice(503, "Sign-in unavailable", RETRY_COPY, None);
    };
    let attempt = Attempt {
        state: state.clone(),
        verifier: pkce.verifier().to_owned(),
        next: safe_next(next),
    };
    let Ok(subject) = serde_json::to_string(&attempt) else {
        return Reply::notice(503, "Sign-in unavailable", RETRY_COPY, None);
    };
    let sealed = keys.signer.sign(&Payload {
        purpose: LOGIN_PURPOSE.to_owned(),
        subject,
        exp: u64::try_from(now + LOGIN_TTL_SECS).ok(),
        kid: Kid::Cur,
    });
    let redirect_uri = format!("{origin}{CALLBACK_PATH}");
    let location = authorize_url(&client.provider(), &redirect_uri, &state, Some(&pkce));
    Reply::redirect(302, location, vec![login_cookie(&sealed, LOGIN_TTL_SECS)])
}

/// `GET /console/callback?code=…&state=…`: the login cookie must verify
/// and its `state` match; the code is exchanged (with the verifier) at the
/// issuer's token endpoint; the access token must pass the console's own
/// verifier and carry a verified email on `allowlist`. Only then is
/// `ks_console` set — for exactly as long as the token lives — and the
/// browser sent to the remembered `next`. Every answer clears the login
/// cookie: an attempt is single-use whichever way it ends. Neither the
/// code nor any token is ever logged.
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is one port or one request fact; a struct would only rename them"
)]
pub async fn finish(
    client: &Client<'_>,
    allowlist: &str,
    origin: &str,
    query: Option<&str>,
    cookie_header: Option<&str>,
    keys: &Keys<'_>,
    http: &dyn HttpClient,
    verifier: &AuthClient,
    now: i64,
) -> Reply {
    finish_inner(client, allowlist, origin, query, cookie_header, keys, http, verifier, now)
        .await
        .with_cookie(login_cookie("", 0))
}

#[expect(clippy::too_many_arguments, reason = "see `finish`")]
async fn finish_inner(
    client: &Client<'_>,
    allowlist: &str,
    origin: &str,
    query: Option<&str>,
    cookie_header: Option<&str>,
    keys: &Keys<'_>,
    http: &dyn HttpClient,
    verifier: &AuthClient,
    now: i64,
) -> Reply {
    let retry = || Some((LOGIN_PATH.to_owned(), "Sign in again".to_owned()));
    let params = Params::parse(query.unwrap_or_default());
    if params.error.is_some() {
        return Reply::notice(400, "Sign-in did not finish", DECLINED_COPY, retry());
    }
    let attempt = crate::fleet::cookie_value(cookie_header, LOGIN_COOKIE)
        .and_then(|sealed| keys.signer.verify(&sealed, LOGIN_PURPOSE))
        .and_then(|payload| serde_json::from_str::<Attempt>(&payload.subject).ok());
    let Some(attempt) = attempt else {
        return Reply::notice(400, "Sign-in expired", EXPIRED_COPY, retry());
    };
    let state_ok = params
        .state
        .as_deref()
        .is_some_and(|state| constant_time_eq(state.as_bytes(), attempt.state.as_bytes()));
    let (true, Some(code)) = (state_ok, params.code.as_deref().filter(|code| !code.is_empty()))
    else {
        tracing::warn!("console sign-in: callback state did not match the login cookie");
        return Reply::notice(400, "Sign-in expired", EXPIRED_COPY, retry());
    };

    let redirect_uri = format!("{origin}{CALLBACK_PATH}");
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", &redirect_uri),
        ("code_verifier", &attempt.verifier),
    ];
    let tokens = match token_call(client, http, &form).await {
        Ok(tokens) => tokens,
        Err(reason) => {
            tracing::warn!(%reason, "console sign-in: code exchange failed");
            return Reply::notice(502, "Sign-in could not finish", EXCHANGE_COPY, retry());
        }
    };
    let claims = match verifier.verify(&tokens.access_token).await {
        Ok(claims) => claims,
        Err(error) => {
            tracing::warn!(%error, "console sign-in: issued token did not verify");
            return Reply::notice(502, "Sign-in could not finish", EXCHANGE_COPY, retry());
        }
    };
    if !allowed(&claims, allowlist) {
        return Reply::notice(403, "Not allowed", FORBIDDEN_COPY, None);
    }
    match session_cookies(keys, &tokens, &claims, None, now) {
        Some(cookies) => Reply::redirect(303, safe_next(Some(&attempt.next)), cookies),
        None => Reply::notice(502, "Sign-in could not finish", EXCHANGE_COPY, retry()),
    }
}

/// Whether verified claims name a person this console lets in: a verified
/// email on the comma-separated allowlist.
#[must_use]
pub fn allowed(claims: &Claims, allowlist: &str) -> bool {
    claims
        .email
        .as_deref()
        .filter(|_| claims.email_verified == Some(true))
        .is_some_and(|email| email_allowed(email, allowlist))
}

/// The two session cookies for a fresh pair. The access cookie lives
/// exactly as long as the token — the shorter of what the token endpoint
/// said and what the token itself says; the refresh cookie as long as the
/// issuer's sliding session. A response without a refresh token keeps
/// `previous` (auth-core always rotates; this is only the RFC's leeway).
fn session_cookies(
    keys: &Keys<'_>,
    tokens: &TokenResponse,
    claims: &Claims,
    previous: Option<&str>,
    now: i64,
) -> Option<Vec<String>> {
    let by_claim = claims.exp - now;
    let max_age = if tokens.expires_in > 0 { by_claim.min(tokens.expires_in) } else { by_claim };
    if max_age <= 0 {
        return None;
    }
    let mut cookies = vec![session_cookie(&tokens.access_token, max_age)];
    let refresh = tokens.refresh_token.as_deref().or(previous).filter(|token| !token.is_empty());
    if let Some(sealed) = refresh.and_then(|token| keys.seal(token)) {
        cookies.push(refresh_cookie(&sealed, REFRESH_TTL_SECS));
    }
    Some(cookies)
}

/// What a server-side refresh came to.
#[derive(Debug)]
pub enum Refresh {
    /// A new, verified access token; `set_cookies` stores the new pair.
    Renewed { claims: Claims, set_cookies: Vec<String> },
    /// No refresh cookie, one that does not open, or one the issuer
    /// refused: signed out. `set_cookies` clears whatever is left.
    SignedOut { set_cookies: Vec<String> },
    /// The issuer could not be asked (transport, 5xx): the refresh cookie
    /// is kept for the next request, this one is signed out.
    Unavailable,
}

/// Renews the session from the sealed refresh cookie in `cookie_header`:
/// `grant_type=refresh_token` at the issuer, the new access token through
/// the console's verifier, and both cookies set again — the rotated
/// refresh token always replacing the spent one. A refusal (auth-core
/// answers every one with a 400, a reused token having revoked the
/// session) clears both cookies.
pub async fn refresh(
    client: &Client<'_>,
    cookie_header: Option<&str>,
    keys: &Keys<'_>,
    http: &dyn HttpClient,
    verifier: &AuthClient,
    now: i64,
) -> Refresh {
    let Some(sealed) = crate::fleet::cookie_value(cookie_header, REFRESH_COOKIE)
        .filter(|sealed| !sealed.is_empty())
    else {
        return Refresh::SignedOut { set_cookies: Vec::new() };
    };
    let signed_out = || Refresh::SignedOut { set_cookies: clear_session() };
    let Some(refresh_token) = keys.open(&sealed) else {
        return signed_out();
    };
    let form = [("grant_type", "refresh_token"), ("refresh_token", refresh_token.as_str())];
    let tokens = match token_call(client, http, &form).await {
        Ok(tokens) => tokens,
        Err(TokenError::Refused(status)) => {
            tracing::info!(status, "console session: refresh refused; signed out");
            return signed_out();
        }
        Err(TokenError::Unavailable(reason)) => {
            tracing::warn!(%reason, "console session: refresh could not reach the issuer");
            return Refresh::Unavailable;
        }
    };
    let claims = match verifier.verify(&tokens.access_token).await {
        Ok(claims) => claims,
        Err(error) => {
            tracing::warn!(%error, "console session: refreshed token did not verify");
            return signed_out();
        }
    };
    match session_cookies(keys, &tokens, &claims, Some(&refresh_token), now) {
        Some(set_cookies) => Refresh::Renewed { claims, set_cookies },
        None => signed_out(),
    }
}

/// `GET /console/login?next=<path>`: a browser that still holds a refresh
/// cookie is renewed in place and sent straight to `next` (a `/v1` page's
/// "Sign in" link lands here, since only `/console` sees that cookie);
/// anyone else starts the authorization-code flow ([`begin`]).
#[expect(clippy::too_many_arguments, reason = "see `finish`")]
pub async fn login(
    client: &Client<'_>,
    allowlist: &str,
    origin: &str,
    next: Option<&str>,
    cookie_header: Option<&str>,
    keys: &Keys<'_>,
    http: &dyn HttpClient,
    verifier: &AuthClient,
    now: i64,
) -> Reply {
    let cleared = match refresh(client, cookie_header, keys, http, verifier, now).await {
        Refresh::Renewed { claims, set_cookies } if allowed(&claims, allowlist) => {
            return Reply::redirect(303, safe_next(next), set_cookies);
        }
        Refresh::Renewed { .. } => clear_session(),
        Refresh::SignedOut { set_cookies } => set_cookies,
        Refresh::Unavailable => Vec::new(),
    };
    let mut reply = begin(client, origin, next, keys, now);
    reply.set_cookies.extend(cleared);
    reply
}

/// `Set-Cookie` values that end the console session on this browser.
#[must_use]
pub fn clear_session() -> Vec<String> {
    vec![session_cookie("", 0), refresh_cookie("", 0)]
}

/// `POST /console/logout`: the session cookie goes. The issuer's own
/// session is the issuer's; the page links to its sign-out, which asks
/// before it acts.
#[must_use]
pub fn logout(client: &Client<'_>) -> Reply {
    let issuer_logout = client
        .issuer()
        .starts_with("https://")
        .then(|| (format!("{}{ISSUER_LOGOUT_ROUTE}", client.issuer()), SIGN_OUT_ISSUER.to_owned()));
    let mut reply = Reply::notice(200, "Signed out", SIGNED_OUT_COPY, issuer_logout);
    reply.set_cookies = clear_session();
    reply
}

/// Why a token call failed. `Refused` is the issuer's answer (any 4xx);
/// `Unavailable` is everything that is not an answer. Neither carries the
/// body, a code or a token, so both are fit for a log.
enum TokenError {
    Refused(u16),
    Unavailable(String),
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(status) => write!(f, "token endpoint refused ({status})"),
            Self::Unavailable(reason) => f.write_str(reason),
        }
    }
}

/// One call to auth-core's token endpoint (RFC 6749 §4.1.3 and §6):
/// form-encoded, `client_id` always in the body, `client_secret` only for
/// a confidential client.
async fn token_call(
    client: &Client<'_>,
    http: &dyn HttpClient,
    grant: &[(&str, &str)],
) -> Result<TokenResponse, TokenError> {
    let mut form = form_urlencoded::Serializer::new(String::new());
    form.extend_pairs(grant).append_pair("client_id", client.client_id);
    if let Some(secret) = client.client_secret {
        form.append_pair("client_secret", secret);
    }
    let unavailable = |reason: &str| TokenError::Unavailable(reason.to_owned());
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(client.provider().token_url)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT, "application/json")
        .body(Bytes::from(form.finish()))
        .map_err(|_| unavailable("the token request could not be built"))?;
    let response = http
        .send(request)
        .await
        .map_err(|error| TokenError::Unavailable(format!("transport: {error}")))?;
    let status = response.status();
    if status.is_client_error() {
        return Err(TokenError::Refused(status.as_u16()));
    }
    if !status.is_success() {
        return Err(TokenError::Unavailable(format!("token endpoint answered {status}")));
    }
    let tokens: TokenResponse = serde_json::from_slice(response.body())
        .map_err(|_| unavailable("the token response did not parse"))?;
    if tokens.token_type.as_deref().is_some_and(|kind| !kind.eq_ignore_ascii_case("bearer")) {
        return Err(unavailable("the token response is not a bearer token"));
    }
    if tokens.access_token.is_empty() {
        return Err(unavailable("the token response carried no access token"));
    }
    Ok(tokens)
}

/// The callback's query: `code` and `state`, or the issuer's `error`.
#[derive(Default)]
struct Params {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

impl Params {
    fn parse(query: &str) -> Self {
        let mut params = Self::default();
        for (name, value) in form_urlencoded::parse(query.as_bytes()) {
            let slot = match name.as_ref() {
                "code" => &mut params.code,
                "state" => &mut params.state,
                "error" => &mut params.error,
                _ => continue,
            };
            // A repeated parameter is ambiguous; the first one counts.
            slot.get_or_insert_with(|| value.into_owned());
        }
        params
    }
}

/// `ks_console`: the whole console's session, so `Path=/` — the setup,
/// Search Console and edit-as-code pages live under `/v1/`, not
/// `/console`. Host-only (no `Domain`), so no other host ever sees it.
fn session_cookie(token: &str, max_age: i64) -> String {
    format!("{SESSION_COOKIE}={token}; Max-Age={max_age}; Path=/; HttpOnly; Secure; SameSite=Lax")
}

/// `ks_console_refresh`: only `/console` routes refresh, so only they see it.
fn refresh_cookie(sealed: &str, max_age: i64) -> String {
    format!(
        "{REFRESH_COOKIE}={sealed}; Max-Age={max_age}; Path=/console; HttpOnly; Secure; SameSite=Lax"
    )
}

/// `ks_console_login`: only the login and callback routes need it.
fn login_cookie(sealed: &str, max_age: i64) -> String {
    format!(
        "{LOGIN_COOKIE}={sealed}; Max-Age={max_age}; Path=/console; HttpOnly; Secure; SameSite=Lax"
    )
}

const RETRY_COPY: &str = "Sign-in could not start right now. Try again shortly.";
const DECLINED_COPY: &str = "The auth service did not complete the sign-in (it was cancelled or \
     refused). Nothing was changed.";
const EXPIRED_COPY: &str = "This sign-in attempt is missing, expired or was started in another \
     browser. Start again from the console.";
const EXCHANGE_COPY: &str = "The auth service did not confirm this sign-in. Try again; if it keeps \
     happening, the console's registration at the auth service needs a look.";
const FORBIDDEN_COPY: &str = "Your account is not on this console's allowlist (CONSOLE_EMAILS), \
     or its email address is not verified. Ask an operator to add it.";
const SIGNED_OUT_COPY: &str = "You are signed out of the console on this browser.";
const SIGN_OUT_ISSUER: &str = "Also sign out of the auth service";
