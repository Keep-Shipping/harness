//! The GitHub Actions run context: the [`RunContext`] adapter for a job on a
//! runner ([#150](https://github.com/Keep-Shipping/harness/issues/150)).
//!
//! A job run by an agent is still a job: the identity is whatever the token
//! says, so [`Establishment::CiOidc`] stands either way. What the event payload
//! changes is the *kind* — a pull request opened by an account GitHub or the
//! organisation calls an agent's is an [`ActorKind::Agent`] run, since the thing
//! proposing the change is an agent even though the thing testing it is a
//! runner. A payload this run cannot read leaves the job a plain CI run.
//!
//! Where the laptop adapter answers from git config and TTY state, this one
//! answers from the variables GitHub Actions sets and from the job's own OIDC
//! ID token. To learn *who* the job is, the adapter mints a token from the
//! endpoint the runner exports — `ACTIONS_ID_TOKEN_REQUEST_URL` with the
//! bearer `ACTIONS_ID_TOKEN_REQUEST_TOKEN` — and reads its `iss` and `sub`
//! into [`Establishment::CiOidc`], the one
//! [`IdentityStrength::Strong`](ks_core::ports::run_context::IdentityStrength)
//! establishment, so the actor is [`ActorKind::Ci`].
//!
//! # This adapter does not verify the token
//!
//! The token's signature is **not** verified here — this crate carries no JWT
//! or JWKS machinery, so the three-segment token is decoded and its claims
//! taken at face value. [`Establishment::CiOidc`] and
//! [`IdentityStrength::Strong`](ks_core::ports::run_context::IdentityStrength)
//! therefore mean only *"obtained from GitHub's dedicated OIDC token
//! endpoint"*, not *"cryptographically verified"*. The endpoint is
//! authenticated by the request token, so the claims are the job's own
//! self-report, exactly as the local adapter's git config is the laptop's.
//!
//! A caller that would rest access control on this identity MUST verify the
//! token itself first — the signature against GitHub's JWKS, and the
//! `iss`/`aud`/`exp` claims — before trusting the `issuer`/`subject` below.
//! That belongs to the venture/server consuming the identity, not to the
//! runner relaying it; adding a JWKS client here is deliberately out of scope
//! for this adapter (tracked separately).
//!
//! Only [`Establishment::CiOidc`] is strong and only an [`ActorKind::Ci`]
//! actor may be strong, so a job whose workflow lacks
//! `permissions: id-token: write` cannot be described honestly: the
//! constructor refuses it ([`GithubActionsError::NotGithubActions`]) rather
//! than dressing a weak actor up as a job, and the caller falls back to the
//! local path. Every context this adapter does build has [`Capabilities::oidc`]
//! set, and speaks HTTP through the [`HttpClient`] port it is handed, whose
//! [`HttpPolicy`](ks_core::ports::http::HttpPolicy) must allow the token
//! endpoint's host (production needs a client that speaks https; the
//! plain-http [`TcpHttpClient`](crate::http_client::TcpHttpClient) is a
//! development stand-in).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ks_core::ports::BoxFuture;
use ks_core::ports::http::{HttpClient, HttpError, HttpMethod, HttpRequest};
use ks_core::ports::run_context::{
    Actor, ActorKind, Capabilities, Establishment, Event, GitInfo, NetworkScope, RunContext,
    RunContextError, Trigger, Workspace,
};
use ks_core::ports::secrets::SecretValue;

use crate::actor::{ActorBaseline, is_agent_account};

/// The documented accept header for the token endpoint: version 2.0 of the
/// response shape.
const ACCEPT: &str = "application/json; api-version=2.0";
/// The variable GitHub sets to `true` in every Actions job.
const GITHUB_ACTIONS: &str = "GITHUB_ACTIONS";
/// The job's commit SHA.
const GITHUB_SHA: &str = "GITHUB_SHA";
/// The job's ref, e.g. `refs/heads/main`.
const GITHUB_REF: &str = "GITHUB_REF";
/// The job's checked-out workspace.
const GITHUB_WORKSPACE: &str = "GITHUB_WORKSPACE";
/// What triggered the job, e.g. `push`, `pull_request`.
const GITHUB_EVENT_NAME: &str = "GITHUB_EVENT_NAME";
/// The login that started the job.
const GITHUB_ACTOR: &str = "GITHUB_ACTOR";
/// The file the runner writes the event payload to.
const GITHUB_EVENT_PATH: &str = "GITHUB_EVENT_PATH";
/// The runner's scratch directory for the job.
const RUNNER_TEMP: &str = "RUNNER_TEMP";
/// Where the runner accepts ID token requests.
const TOKEN_URL: &str = "ACTIONS_ID_TOKEN_REQUEST_URL";
/// The bearer token that authenticates those requests.
const TOKEN_REQUEST_TOKEN: &str = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";

/// The variables that describe the job; without them there is no run context.
const JOB_VARS: &[&str] = &[GITHUB_SHA, GITHUB_REF, GITHUB_WORKSPACE];
/// The variables that carry the ID token endpoint.
const TOKEN_VARS: &[&str] = &[TOKEN_URL, TOKEN_REQUEST_TOKEN];
/// The audience the adapter mints its *own* identity token with: that token is
/// read for its `iss`/`sub` claims and dropped at once, so the audience is
/// never sent anywhere else and nothing is trusted on its account.
const IDENTITY_AUDIENCE: &str = "keepshipping";

/// Why a [`GithubActionsRunContext`] could not be built. Callers treat every
/// variant alike — log it, then fall back to the local path — but the reason
/// is worth printing.
#[derive(Debug)]
pub enum GithubActionsError {
    /// Not a GitHub Actions job, or one whose environment lacks what a run
    /// context needs: `missing` names the absent variables (the job
    /// variables, or the ID token endpoint's pair when the workflow did not
    /// grant `id-token: write`).
    NotGithubActions {
        /// The absent variables, in check order.
        missing: Vec<&'static str>,
    },
    /// A GitHub Actions job with everything present, whose ID token could not
    /// be minted.
    Identity(RunContextError),
}

impl fmt::Display for GithubActionsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GithubActionsError::NotGithubActions { missing } => write!(
                f,
                "not a usable GitHub Actions run context (missing: {})",
                missing.join(", ")
            ),
            GithubActionsError::Identity(error) => {
                write!(f, "the GitHub Actions job could not mint an id token: {error}")
            }
        }
    }
}

impl std::error::Error for GithubActionsError {}

/// The runner's ID token endpoint and the credential that opens it.
struct TokenEndpoint {
    url: String,
    request_token: SecretValue,
}

impl TokenEndpoint {
    /// Mints one ID token for `audience` — the response's `value` field,
    /// still wrapped as a secret.
    async fn mint(
        &self,
        http: &dyn HttpClient,
        audience: &str,
    ) -> Result<SecretValue, RunContextError> {
        let mut request = HttpRequest::new(HttpMethod::Get, token_url(&self.url, audience));
        let authorization = self
            .request_token
            .with_bytes(|bytes| format!("Bearer {}", String::from_utf8_lossy(bytes)));
        request.headers.push(("Authorization".to_string(), authorization));
        request.headers.push(("Accept".to_string(), ACCEPT.to_string()));
        let response = http.send(request).await.map_err(transport)?;
        if response.status != 200 {
            return Err(backend(format!("the token endpoint answered {}", response.status)));
        }
        parse_token_body(&response.body)
    }
}

/// The token request URL for `audience`: it rides as a query parameter on top
/// of whatever the endpoint already carries (`&` when it has a query of its
/// own, `?` when it does not).
fn token_url(base: &str, audience: &str) -> String {
    let separator = if base.contains('?') { '&' } else { '?' };
    format!("{base}{separator}audience={}", encode_component(audience))
}

/// A [`RunContext`] for one GitHub Actions job: the CI counterpart of the
/// laptop adapter.
///
/// Its [`ActorKind::Ci`] identity and [`Establishment::CiOidc`] are built
/// from an ID token whose signature this adapter **does not verify** (see the
/// [module documentation](self)); `IdentityStrength::Strong` here means only
/// "minted via GitHub's dedicated OIDC token endpoint", never "verified". A
/// consumer that needs a verified identity must check the token against
/// GitHub's JWKS itself.
pub struct GithubActionsRunContext {
    actor: Actor,
    event: Event,
    capabilities: Capabilities,
    workspace: Workspace,
    endpoint: TokenEndpoint,
    http: Arc<dyn HttpClient>,
}

impl GithubActionsRunContext {
    /// Builds the run context from a snapshot of the job's environment and the
    /// policy-checked `http` client it should mint tokens through, under an
    /// empty baseline.
    /// The environment is passed in rather than read here, as
    /// [`LocalRunFacts`](ks_core::ports::run_context::LocalRunFacts) is: the
    /// decision stays pure and tests can script it. Returns
    /// [`GithubActionsError::NotGithubActions`] when this is not a job with an
    /// ID token endpoint — the caller's cue to use the local path — and
    /// [`GithubActionsError::Identity`] when the endpoint was there but would
    /// not hand out the identity token.
    pub async fn from_env(
        env: &BTreeMap<String, String>,
        http: Arc<dyn HttpClient>,
    ) -> Result<GithubActionsRunContext, GithubActionsError> {
        Self::from_env_with(env, http, &ActorBaseline::default()).await
    }

    /// As [`GithubActionsRunContext::from_env`], but under the organisation's
    /// `baseline` — what turns a bot-authored pull request into an
    /// [`ActorKind::Agent`] run.
    pub async fn from_env_with(
        env: &BTreeMap<String, String>,
        http: Arc<dyn HttpClient>,
        baseline: &ActorBaseline,
    ) -> Result<GithubActionsRunContext, GithubActionsError> {
        if env.get(GITHUB_ACTIONS).map(String::as_str) != Some("true") {
            return Err(GithubActionsError::NotGithubActions { missing: vec![GITHUB_ACTIONS] });
        }
        let mut missing = missing_vars(env, JOB_VARS);
        missing.extend(missing_vars(env, TOKEN_VARS));
        if !missing.is_empty() {
            return Err(GithubActionsError::NotGithubActions { missing });
        }

        let endpoint = TokenEndpoint {
            url: env[TOKEN_URL].clone(),
            request_token: SecretValue::new(env[TOKEN_REQUEST_TOKEN].clone().into_bytes()),
        };
        // Mint the job's own identity token, read its claims, drop the
        // bytes: self-reported, not signature-verified — see the module docs.
        let identity = endpoint
            .mint(http.as_ref(), IDENTITY_AUDIENCE)
            .await
            .map_err(GithubActionsError::Identity)?;
        let (issuer, subject) = claims_of(&identity).map_err(GithubActionsError::Identity)?;

        let git_ref = env[GITHUB_REF].clone();
        let root = PathBuf::from(&env[GITHUB_WORKSPACE]);
        let event_name = env.get(GITHUB_EVENT_NAME).map(String::as_str).unwrap_or_default();
        let display_name = env
            .get(GITHUB_ACTOR)
            .filter(|name| !name.is_empty())
            .cloned()
            .unwrap_or_else(|| subject.clone());
        // The runner is the runner either way: what the payload adds is who
        // proposed the work, and an agent proposing it makes the run an agent's
        // without weakening the establishment (see the module documentation).
        let established = Establishment::CiOidc { issuer, subject };
        let actor = match proposer(env) {
            Some((login, user_type))
                if is_agent_account(&login, user_type.as_deref(), baseline) =>
            {
                Actor { kind: ActorKind::Agent, established, display_name: login }
            }
            _ => Actor { kind: ActorKind::Ci, established, display_name },
        };
        Ok(GithubActionsRunContext {
            actor,
            event: Event {
                git: GitInfo { sha: env[GITHUB_SHA].clone(), git_ref: git_ref.clone() },
                trigger: trigger_of(event_name, &git_ref),
            },
            capabilities: Capabilities {
                // The constructor requires the endpoint, so `oidc` and the
                // token variables agree by construction.
                oidc: true,
                // A runner has no person attached mid-flight.
                interactive: false,
                // GitHub Actions offers every job its cache service.
                ci_cache: true,
                // A hosted runner reaches the whole internet; narrowing this
                // belongs to policy, not to the adapter.
                network: NetworkScope::Any,
                // Both environment-backed resolvers serve a job; the
                // `github-actions` one is the store behind `ci-only`
                // environments. Spelled out rather than imported from
                // `env_secrets`, which this file's two crate roots (lib and
                // bin) cannot both name.
                secret_resolvers: BTreeSet::from(["env".to_string(), "github-actions".to_string()]),
            },
            workspace: Workspace { scratch: scratch_dir(env, &root), root },
            endpoint,
            http,
        })
    }
}

/// The account that proposed the job's work, with its GitHub account type: the
/// pull request's author when the payload carries one, else the sender — the
/// account that triggered the run at all.
///
/// Best-effort by design: no `GITHUB_EVENT_PATH`, an unreadable file, or a body
/// that is not JSON is [`None`], leaving the identity on the OIDC token alone —
/// the safe direction, since an unrecognised proposer stays a plain CI run.
fn proposer(env: &BTreeMap<String, String>) -> Option<(String, Option<String>)> {
    let path = env.get(GITHUB_EVENT_PATH).filter(|path| !path.is_empty())?;
    let body = std::fs::read_to_string(path).ok()?;
    let payload: serde_json::Value = serde_json::from_str(&body).ok()?;
    let user = payload
        .get("pull_request")
        .and_then(|pull_request| pull_request.get("user"))
        .or_else(|| payload.get("sender"))?;
    let login =
        user.get("login").and_then(serde_json::Value::as_str).filter(|login| !login.is_empty())?;
    let user_type = user.get("type").and_then(serde_json::Value::as_str).map(str::to_string);
    Some((login.to_string(), user_type))
}

/// Prints the job's identity and nothing that opens a door: the endpoint URL
/// carries a signature and the request token is a credential, so both are left
/// to `..`.
impl fmt::Debug for GithubActionsRunContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GithubActionsRunContext")
            .field("actor", &self.actor)
            .field("event", &self.event)
            .field("capabilities", &self.capabilities)
            .field("workspace", &self.workspace)
            .finish_non_exhaustive()
    }
}

impl RunContext for GithubActionsRunContext {
    fn actor(&self) -> &Actor {
        &self.actor
    }

    fn event(&self) -> &Event {
        &self.event
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    fn workspace(&self) -> &Workspace {
        &self.workspace
    }

    fn oidc_token<'a>(
        &'a self,
        audience: &'a str,
    ) -> BoxFuture<'a, Result<SecretValue, RunContextError>> {
        // `capabilities().oidc` is true for every context this adapter builds,
        // so there is no `OidcUnavailable` answer to give: a failure here is
        // always the endpoint's.
        Box::pin(self.endpoint.mint(self.http.as_ref(), audience))
    }
}

/// The variables among `names` that `env` does not set to a non-empty value.
fn missing_vars(env: &BTreeMap<String, String>, names: &[&'static str]) -> Vec<&'static str> {
    names.iter().copied().filter(|name| !set(env, name)).collect()
}

/// Whether `env` sets `name` to anything at all.
fn set(env: &BTreeMap<String, String>, name: &str) -> bool {
    env.get(name).is_some_and(|value| !value.is_empty())
}

/// The scratch directory: the runner's own temp directory when it gives one,
/// else a `.ks` directory beside the checkout — never the checkout itself.
fn scratch_dir(env: &BTreeMap<String, String>, root: &Path) -> PathBuf {
    match env.get(RUNNER_TEMP).filter(|dir| !dir.is_empty()) {
        Some(dir) if Path::new(dir) != root => PathBuf::from(dir),
        _ => root.join(".ks").join("scratch"),
    }
}

/// What triggered the job, from its event name and ref.
///
/// A `push` whose ref is a tag is a [`Trigger::Tag`] — its `name` is the
/// ref's last segment, so the two agree by construction; a pull request
/// carries the number parsed from `refs/pull/<n>/merge`, falling back to a
/// plain push when GitHub names no number; the dispatch events are
/// [`Trigger::Manual`]; anything else about a commit and a ref is a push.
fn trigger_of(event_name: &str, git_ref: &str) -> Trigger {
    match event_name {
        "pull_request" | "pull_request_target" => match pull_request_number(git_ref) {
            Some(number) => Trigger::PullRequest { number },
            None => Trigger::Push,
        },
        "workflow_dispatch" | "repository_dispatch" => Trigger::Manual,
        _ => match git_ref.strip_prefix("refs/tags/") {
            Some(name) if !name.is_empty() => Trigger::Tag { name: name.to_string() },
            _ => Trigger::Push,
        },
    }
}

/// The `<n>` of `refs/pull/<n>/merge` (or `/head`), or [`None`].
fn pull_request_number(git_ref: &str) -> Option<u64> {
    git_ref.strip_prefix("refs/pull/")?.split('/').next()?.parse().ok()
}

/// The `value` field of a token response — `{"value": "<jwt>", "count": N}` —
/// as a secret. The body is never echoed: it carries the token.
fn parse_token_body(body: &[u8]) -> Result<SecretValue, RunContextError> {
    let json: serde_json::Value = serde_json::from_slice(body)
        .map_err(|_| backend("the token endpoint answered with a body that is not json"))?;
    let token = json
        .get("value")
        .and_then(serde_json::Value::as_str)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| backend("the token endpoint answered without a `value` token"))?;
    Ok(SecretValue::new(token.as_bytes().to_vec()))
}

/// The `iss` and `sub` claims of an ID token.
///
/// The payload (the middle segment) is base64url-decoded and parsed as JSON;
/// the signature is deliberately not checked — see the module documentation.
/// Every failure names the broken step and never the token.
fn claims_of(token: &SecretValue) -> Result<(String, String), RunContextError> {
    token.with_bytes(|bytes| {
        let payload = jwt_payload(bytes)?;
        let json: serde_json::Value = serde_json::from_slice(&payload)
            .map_err(|_| backend("the id token payload is not json"))?;
        Ok((claim(&json, "iss")?, claim(&json, "sub")?))
    })
}

/// The decoded payload of a three-segment `header.payload.signature` JWT.
fn jwt_payload(jwt: &[u8]) -> Result<Vec<u8>, RunContextError> {
    let text = std::str::from_utf8(jwt).map_err(|_| backend("the id token is not utf-8"))?;
    let mut segments = text.split('.');
    match (segments.next(), segments.next(), segments.next(), segments.next()) {
        (Some(_header), Some(payload), Some(_signature), None) => decode_base64url(payload)
            .ok_or_else(|| backend("the id token payload is not base64url")),
        _ => Err(backend("the id token is not a three-segment jwt")),
    }
}

/// One non-empty string claim.
fn claim(json: &serde_json::Value, name: &str) -> Result<String, RunContextError> {
    json.get(name)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| backend(format!("the id token has no {name} claim")))
}

/// Base64url (RFC 4648 §5, padding tolerated) decoding, hand-rolled like the
/// rest of this crate's wire helpers: the workspace carries no base64 crate,
/// and this is the only place one is needed.
fn decode_base64url(text: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut decoded = Vec::with_capacity(text.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for byte in text.bytes() {
        if byte == b'=' {
            continue;
        }
        let value = ALPHABET.iter().position(|digit| *digit == byte)? as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            decoded.push((buffer >> bits) as u8);
        }
    }
    Some(decoded)
}

/// Percent-encodes everything outside RFC 3986's unreserved set, byte by byte,
/// so an audience cannot change the URL's shape — a stray `&` or `#` would cut
/// the query short.
fn encode_component(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            other => {
                let _ = write!(out, "%{other:02X}");
            }
        }
    }
    out
}

/// A backend failure naming what happened, safe to print.
fn backend(message: impl Into<String>) -> RunContextError {
    RunContextError::Backend { message: message.into() }
}

/// The port's failure for a transport-level [`HttpError`].
fn transport(error: HttpError) -> RunContextError {
    backend(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_client::TcpHttpClient;
    use crate::test_server::spawn as spawn_server;
    use ks_core::ports::http::{HttpPolicy, HttpResponse};
    use ks_testing::block_on;
    use ks_testing::http::FakeHttpClient;
    use std::time::Duration;

    const ISSUER: &str = "https://token.actions.githubusercontent.com";
    const SUBJECT: &str = "repo:Keep-Shipping/harness:pull_request";
    const SHA: &str = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b";
    const TOKEN_BASE: &str = "http://token.example";

    /// Base64url encoding: the fixture-side counterpart of the adapter's
    /// decoder, so a fixture reads as the claims it carries.
    fn encode_base64url(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let mut buffer = u32::from(chunk[0]) << 16;
            if let Some(byte) = chunk.get(1) {
                buffer |= u32::from(*byte) << 8;
            }
            if let Some(byte) = chunk.get(2) {
                buffer |= u32::from(*byte);
            }
            for index in 0..chunk.len() + 1 {
                out.push(ALPHABET[((buffer >> (18 - 6 * index)) & 0x3F) as usize] as char);
            }
        }
        out
    }

    /// A synthetic — deliberately unsigned — ID token for `issuer`/`subject`,
    /// shaped like the real one: three segments, the middle a base64url JSON
    /// claims object.
    fn id_token(issuer: &str, subject: &str) -> String {
        let claims = format!(r#"{{"iss":"{issuer}","sub":"{subject}"}}"#);
        format!(
            "{header}.{payload}.not-a-real-signature",
            header = encode_base64url(br#"{"alg":"RS256","typ":"JWT"}"#),
            payload = encode_base64url(claims.as_bytes())
        )
    }

    /// The token endpoint's answer carrying `jwt`.
    fn token_body(jwt: &str) -> String {
        format!(r#"{{"value":"{jwt}","count":1}}"#)
    }

    /// The environment GitHub sets for a job with `id-token: write`, pointed
    /// at `base` for its token endpoint.
    fn job_env(base: &str) -> BTreeMap<String, String> {
        [
            (GITHUB_ACTIONS, "true"),
            (GITHUB_SHA, SHA),
            (GITHUB_REF, "refs/heads/main"),
            (GITHUB_WORKSPACE, "/home/runner/work/harness/harness"),
            (GITHUB_EVENT_NAME, "push"),
            (GITHUB_ACTOR, "octocat"),
            (RUNNER_TEMP, "/home/runner/work/_temp"),
            (TOKEN_URL, base),
            (TOKEN_REQUEST_TOKEN, "request-secret"),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
    }

    /// The audience `ks_testing`'s conformance kit asks for.
    const CONFORMANCE_AUDIENCE: &str = "conformance-audience";

    /// A fake endpoint that mints the identity token for every audience the
    /// tests ask for, except `deploy`, which answers as scripted.
    fn http_with_identity(base: &str, answer: HttpResponse) -> Arc<dyn HttpClient> {
        let mut client = FakeHttpClient::new().with_allowed_host("token.example");
        for audience in [IDENTITY_AUDIENCE, CONFORMANCE_AUDIENCE] {
            client = client.with_response(
                HttpMethod::Get,
                token_url(base, audience),
                HttpResponse {
                    status: 200,
                    headers: vec![],
                    body: token_body(&id_token(ISSUER, SUBJECT)).into_bytes(),
                },
            );
        }
        Arc::new(client.with_response(HttpMethod::Get, token_url(base, "deploy"), answer))
    }

    /// A policy-checked client that may talk to the test server's host.
    fn local_client() -> TcpHttpClient {
        TcpHttpClient::new(HttpPolicy {
            allowed_hosts: ["127.0.0.1".to_string()].into_iter().collect(),
            timeout: Duration::from_secs(5),
            max_response_bytes: 1024 * 1024,
        })
    }

    #[test]
    fn mints_the_identity_token_over_http_and_reads_its_claims() {
        let jwt = id_token(ISSUER, SUBJECT);
        let (address, captured, _) = spawn_server("200 OK", &token_body(&jwt), false);
        // An endpoint that already carries a query: the audience must be
        // appended to it, not replace it.
        let base = format!("http://{address}/token?sig=abc");
        let context =
            block_on(GithubActionsRunContext::from_env(&job_env(&base), Arc::new(local_client())))
                .expect("a job with an id token endpoint builds");

        assert_eq!(context.actor().kind, ActorKind::Ci);
        assert_eq!(
            context.actor().established,
            Establishment::CiOidc { issuer: ISSUER.to_string(), subject: SUBJECT.to_string() }
        );
        assert_eq!(context.actor().display_name, "octocat");
        assert!(!context.capabilities().interactive);
        // A minted token is the JWT itself, wrapped as a secret.
        let token = block_on(context.oidc_token("https://example.com/aud")).expect("a token");
        assert_eq!(token.with_bytes(<[u8]>::to_vec), jwt.as_bytes());
        let sent = captured.lock().expect("capture").clone();
        for line in [
            "GET /token?sig=abc&audience=keepshipping HTTP/1.1",
            "GET /token?sig=abc&audience=https%3A%2F%2Fexample.com%2Faud HTTP/1.1",
            "Authorization: Bearer request-secret",
            "Accept: application/json; api-version=2.0",
        ] {
            assert!(sent.iter().any(|seen| seen == line), "no {line:?} in {sent:?}");
        }
    }

    #[test]
    fn debug_prints_the_identity_but_never_a_credential() {
        // Sentinels, so the absence assertions below are exact.
        let jwt = id_token(ISSUER, SUBJECT);
        let signed_url = "http://token.example/id?sig=SIGNED-URL-SENTINEL";
        let request_token = "REQUEST-TOKEN-SENTINEL";
        let mut env = job_env(signed_url);
        env.insert(TOKEN_REQUEST_TOKEN.to_string(), request_token.to_string());
        let context = block_on(GithubActionsRunContext::from_env(
            &env,
            http_with_identity(
                signed_url,
                HttpResponse { status: 200, headers: vec![], body: Vec::new() },
            ),
        ))
        .expect("a job with an id token endpoint builds");

        let debug = format!("{context:?}");
        // It names who the job is...
        assert!(debug.contains(ISSUER), "{debug}");
        assert!(debug.contains(SUBJECT), "{debug}");
        // ...and carries nothing that opens the endpoint: neither the bearer
        // request token, nor the signed request URL, nor the minted JWT.
        for secret in [request_token, signed_url, "SIGNED-URL-SENTINEL", jwt.as_str()] {
            assert!(!debug.contains(secret), "debug output leaked {secret:?}: {debug}");
        }
    }

    #[test]
    fn environments_that_are_not_a_job_with_an_id_token_build_nothing() {
        let http: Arc<dyn HttpClient> = Arc::new(FakeHttpClient::new());
        let without = |names: &[&str]| {
            job_env(TOKEN_BASE)
                .into_iter()
                .filter(|(name, _)| !names.contains(&name.as_str()))
                .collect::<BTreeMap<String, String>>()
        };
        let cases: Vec<(&str, BTreeMap<String, String>, Vec<&'static str>)> = vec![
            ("a laptop with no environment at all", BTreeMap::new(), vec![GITHUB_ACTIONS]),
            (
                "GITHUB_ACTIONS set to anything but true",
                BTreeMap::from([(GITHUB_ACTIONS.to_string(), "1".to_string())]),
                vec![GITHUB_ACTIONS],
            ),
            ("a job without a ref", without(&[GITHUB_REF]), vec![GITHUB_REF]),
            ("a workflow without id-token: write", without(TOKEN_VARS), TOKEN_VARS.to_vec()),
        ];
        for (what, env, expected_missing) in cases {
            let error = block_on(GithubActionsRunContext::from_env(&env, Arc::clone(&http)))
                .expect_err(what);
            assert_eq!(
                error.to_string(),
                format!(
                    "not a usable GitHub Actions run context (missing: {})",
                    expected_missing.join(", ")
                ),
                "{what}"
            );
        }
    }

    #[test]
    fn endpoints_that_break_the_contract_are_errors_never_panics() {
        // A job whose identity token is unusable never becomes a run context.
        for (what, body) in [
            ("no iss claim", r#"{"value":"eyJhbGciOiJSUzI1NiJ9.e30.sig","count":1}"#),
            ("two segments", r#"{"value":"e30.sig","count":1}"#),
            ("not json", "the endpoint says no"),
        ] {
            let http =
                Arc::new(FakeHttpClient::new().with_allowed_host("token.example").with_response(
                    HttpMethod::Get,
                    token_url(TOKEN_BASE, IDENTITY_AUDIENCE),
                    HttpResponse { status: 200, headers: vec![], body: body.as_bytes().to_vec() },
                ));
            let error = block_on(GithubActionsRunContext::from_env(&job_env(TOKEN_BASE), http))
                .expect_err(what);
            assert!(matches!(error, GithubActionsError::Identity(_)), "{what}: {error:?}");
        }
        // Once built, a failing audience request is a backend failure whose
        // message never echoes a body that might carry a token.
        for answer in [
            HttpResponse { status: 401, headers: vec![], body: Vec::new() },
            HttpResponse { status: 200, headers: vec![], body: b"not json at all".to_vec() },
            HttpResponse { status: 200, headers: vec![], body: b"{\"count\":7}".to_vec() },
        ] {
            let http = http_with_identity(TOKEN_BASE, answer);
            let context = block_on(GithubActionsRunContext::from_env(&job_env(TOKEN_BASE), http))
                .expect("builds");
            let error = block_on(context.oidc_token("deploy")).expect_err("refused");
            let RunContextError::Backend { message } = &error else {
                panic!("expected a backend error, got {error:?}");
            };
            assert!(!message.contains("not json at all"), "never echoes the body: {message}");
            assert!(!message.contains("{\"count\":7}"), "never echoes the body: {message}");
        }
    }

    #[test]
    fn the_context_passes_the_run_context_conformance_kit() {
        let base = "http://token.example/id?x=1";
        let http = http_with_identity(
            base,
            HttpResponse {
                status: 200,
                headers: vec![],
                body: token_body(&id_token(ISSUER, SUBJECT)).into_bytes(),
            },
        );
        let context = block_on(GithubActionsRunContext::from_env(&job_env(base), http))
            .expect("a job with an id token endpoint builds");
        // The kit mints its own audience, so the fake answers it too.
        block_on(ks_testing::run_context::conformance(&context));
    }

    #[test]
    fn github_names_map_onto_the_trigger_and_workspace_they_describe() {
        assert_eq!(
            trigger_of("push", "refs/tags/v1.2.3"),
            Trigger::Tag { name: "v1.2.3".to_string() }
        );
        assert_eq!(trigger_of("push", "refs/heads/main"), Trigger::Push);
        assert_eq!(trigger_of("push", "refs/tags/"), Trigger::Push);
        assert_eq!(
            trigger_of("pull_request", "refs/pull/42/merge"),
            Trigger::PullRequest { number: 42 }
        );
        assert_eq!(trigger_of("pull_request_target", "refs/heads/main"), Trigger::Push);
        assert_eq!(trigger_of("workflow_dispatch", "refs/heads/main"), Trigger::Manual);
        assert_eq!(trigger_of("repository_dispatch", "refs/heads/main"), Trigger::Manual);
        assert_eq!(trigger_of("schedule", "refs/heads/main"), Trigger::Push);
        assert_eq!(pull_request_number("refs/pull/42/head"), Some(42));
        assert_eq!(pull_request_number("refs/heads/main"), None);

        let root = PathBuf::from("/work/repo");
        let temp = BTreeMap::from([(RUNNER_TEMP.to_string(), "/work/temp".to_string())]);
        assert_eq!(scratch_dir(&temp, &root), PathBuf::from("/work/temp"));
        // An empty or identical temp directory falls back beside the
        // checkout, so scratch never equals the root the kit guards.
        for unusable in ["", "/work/repo"] {
            let env = BTreeMap::from([(RUNNER_TEMP.to_string(), unusable.to_string())]);
            assert_eq!(scratch_dir(&env, &root), PathBuf::from("/work/repo/.ks/scratch"));
        }
    }

    #[test]
    fn the_proposer_decides_the_kind_and_never_the_establishment() {
        let base = "http://token.example/id?x=1";
        let http = http_with_identity(
            base,
            HttpResponse { status: 200, headers: vec![], body: Vec::new() },
        );
        let oidc =
            || Establishment::CiOidc { issuer: ISSUER.to_string(), subject: SUBJECT.to_string() };
        // A bot-authored pull request is an agent's run, and its display name is
        // the bot's login; a person's is not. The organisation may say a person's
        // login is an agent's too — the baseline is what says so.
        let baseline =
            ActorBaseline { agents: BTreeSet::from(["ada".to_string()]), require_human: false };
        for (fixture, baseline, kind, display_name) in [
            ("pull_request.bot.json", None, ActorKind::Agent, "keepshipping-agent[bot]"),
            ("pull_request.human.json", None, ActorKind::Ci, "octocat"),
            ("pull_request.human.json", Some(&baseline), ActorKind::Agent, "ada"),
        ] {
            let mut env = job_env(base);
            env.insert(GITHUB_EVENT_NAME.to_string(), "pull_request".to_string());
            env.insert(GITHUB_REF.to_string(), "refs/pull/412/merge".to_string());
            env.insert(
                GITHUB_EVENT_PATH.to_string(),
                format!("{}/tests/fixtures/github/{fixture}", env!("CARGO_MANIFEST_DIR")),
            );
            let context = match baseline {
                Some(baseline) => block_on(GithubActionsRunContext::from_env_with(
                    &env,
                    Arc::clone(&http),
                    baseline,
                )),
                None => block_on(GithubActionsRunContext::from_env(&env, Arc::clone(&http))),
            }
            .expect("a job with an id token endpoint builds");
            assert_eq!(context.actor().kind, kind, "{fixture}");
            assert_eq!(context.actor().display_name, display_name, "{fixture}");
            // An agent proposing the work does not weaken the token the runner
            // minted for it, and the trigger is still the one `GITHUB_REF`
            // names — not the payload's.
            assert_eq!(context.actor().established, oidc(), "{fixture}");
            assert_eq!(context.event().trigger, Trigger::PullRequest { number: 412 }, "{fixture}");
        }

        // A payload the run cannot read leaves the actor exactly as it was.
        let here = env!("CARGO_MANIFEST_DIR");
        for (what, path) in [
            ("no event path", None),
            ("a path that is not there", Some("/nonexistent/event-payload.json".to_string())),
            ("a file that is not json", Some(format!("{here}/Cargo.toml"))),
        ] {
            let mut env = job_env(base);
            if let Some(path) = path {
                env.insert(GITHUB_EVENT_PATH.to_string(), path);
            }
            let context =
                block_on(GithubActionsRunContext::from_env(&env, Arc::clone(&http))).expect(what);
            assert_eq!(context.actor().kind, ActorKind::Ci, "{what}");
            assert_eq!(context.actor().display_name, "octocat", "{what}");
        }
    }

    #[test]
    fn base64url_decoding_matches_the_wire_alphabet() {
        assert_eq!(decode_base64url(""), Some(Vec::new()));
        assert_eq!(decode_base64url("aGk"), Some(b"hi".to_vec()));
        assert_eq!(decode_base64url("aGk="), Some(b"hi".to_vec()), "padding is tolerated");
        assert_eq!(decode_base64url("-_8"), Some(vec![0xfb, 0xff]));
        assert_eq!(decode_base64url("a+b"), None, "`+` is the standard alphabet, not base64url");
        assert_eq!(decode_base64url("aGk*"), None);
        // The fixture encoder and the adapter's decoder agree on every padding
        // length, which is what the token fixtures rest on.
        for claims in [r#"{"iss":"i","sub":"s"}"#, "{}", "a", "ab"] {
            assert_eq!(
                decode_base64url(&encode_base64url(claims.as_bytes())),
                Some(claims.as_bytes().to_vec()),
                "{claims}"
            );
        }
    }
}
