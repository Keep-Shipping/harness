//! The GitLab CI run context: the [`RunContext`] adapter for a job in a GitLab
//! pipeline ([#131](https://github.com/Keep-Shipping/harness/issues/131)).
//!
//! It is the GitHub Actions adapter's parallel universe, and it answers the port
//! the same way: from the variables GitLab CI sets, plus the job's own OIDC ID
//! token, whose `iss` and `sub` become [`Establishment::CiOidc`] — the one
//! `IdentityStrength::Strong` establishment — so the actor is [`ActorKind::Ci`].
//!
//! # GitLab mints the token before the job starts
//!
//! GitHub exports an OIDC *token endpoint* and its runner mints a token per
//! audience through it, over HTTP. GitLab has no such endpoint: the job-level
//! `id_tokens:` keyword mints the JWT **in advance**, hands the job an ordinary
//! variable, and the audience is whatever the job declared — so there is no HTTP
//! client anywhere in this file. That matters for
//! [`oidc_token`](RunContext::oidc_token): GitLab lets a job declare any `aud` it
//! likes, so the token in hand is *not* automatically a token for the audience a
//! caller asks for, and handing it over regardless would be handing out a
//! credential minted for somebody else. Every request is answered by reading the
//! token's own `aud` claim and checking it names what was asked for — and a
//! claim that cannot be read fails closed, because an unexamined token is exactly
//! the thing being guarded against.
//!
//! # This adapter does not verify the token
//!
//! The token's signature is **not** verified here. GitLab signs its ID tokens with
//! RS256 and publishes the key at the instance's OIDC discovery document, but this
//! crate carries no JWT or JWKS machinery, so the three-segment token is decoded
//! and its claims taken at face value. [`Establishment::CiOidc`] and
//! `IdentityStrength::Strong` therefore mean only *"handed to this job by GitLab
//! as an `id_tokens:` variable"*, never *"cryptographically verified"*. A caller
//! that would rest access control on this identity MUST verify the token itself
//! first — the signature against GitLab's JWKS, and the `iss`/`aud`/`exp` claims
//! — before trusting the `issuer`/`subject` below. That belongs to the
//! venture/server consuming the identity, not to the runner relaying it.
//!
//! # The actor is whoever triggered the pipeline
//!
//! GitLab exposes **no** merge-request-author variable — not on a merge-request
//! pipeline, not through the token — so the nearest thing is
//! [`GITLAB_USER_LOGIN`](self), which on a *fork* merge request is the fork's own
//! contributor. Only [`Establishment::CiOidc`] is strong, so a pipeline whose
//! jobs do not declare an `id_tokens:` token cannot be described honestly: the
//! constructor refuses it ([`GitlabCiError::NotGitlabCi`]) rather than dressing a
//! weak actor up as a job, and the caller falls back to the local path.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use ks_core::ports::BoxFuture;
use ks_core::ports::run_context::{
    Actor, ActorKind, Capabilities, Establishment, Event, GitInfo, NetworkScope, Provenance,
    RunContext, RunContextError, Trigger, Workspace,
};
use ks_core::ports::secrets::SecretValue;

use crate::actor::{ActorBaseline, is_agent_account};

/// `true` in every job GitLab runs.
const GITLAB_CI: &str = "GITLAB_CI";
const CI_COMMIT_SHA: &str = "CI_COMMIT_SHA";
/// The job's checked-out project directory.
const CI_PROJECT_DIR: &str = "CI_PROJECT_DIR";
/// The job's branch or tag name — bare, e.g. `main`, never `refs/heads/main`.
const CI_COMMIT_REF_NAME: &str = "CI_COMMIT_REF_NAME";
/// The tag, on a tag pipeline and nowhere else.
const CI_COMMIT_TAG: &str = "CI_COMMIT_TAG";
/// What started the pipeline: `push`, `merge_request_event`, `schedule`, …
const CI_PIPELINE_SOURCE: &str = "CI_PIPELINE_SOURCE";
/// The project-wide number of the merge request, on an MR pipeline only.
const CI_MERGE_REQUEST_IID: &str = "CI_MERGE_REQUEST_IID";
/// The full ref an MR pipeline checks out, e.g. `refs/merge-requests/1/head`.
const CI_MERGE_REQUEST_REF_PATH: &str = "CI_MERGE_REQUEST_REF_PATH";
/// Who triggered the pipeline — or, on a manual job, who started that job. This
/// is *not* the merge request author; GitLab has no variable for that.
const GITLAB_USER_LOGIN: &str = "GITLAB_USER_LOGIN";
/// The ID token GitLab minted for this job, passed in as an ordinary variable
/// under the name the [`id_tokens:`](https://docs.gitlab.com/ci/yaml/#id_tokens)
/// keyword was asked for; the adapter and
/// [`templates/gitlab/keepshipping.yml`](../../../../templates/gitlab/keepshipping.yml)
/// agree on it.
const ID_TOKEN: &str = "KEEP_SHIPPING_ID_TOKEN";

/// The variables that describe the job; without them there is no run context.
const JOB_VARS: &[&str] = &[CI_COMMIT_SHA, CI_PROJECT_DIR, CI_COMMIT_REF_NAME];
/// The variables that carry the pre-minted ID token.
const TOKEN_VARS: &[&str] = &[ID_TOKEN];

/// Why a [`GitlabCiRunContext`] could not be built. Callers treat every variant
/// alike — log it, then fall back to the local path — but the reason is worth
/// printing.
#[derive(Debug)]
pub enum GitlabCiError {
    /// Not a GitLab CI job, or one whose environment lacks what a run context
    /// needs: `missing` names the absent variables (the job variables, or the
    /// `id_tokens:` token a job without `id_tokens:` does not carry).
    NotGitlabCi {
        /// The absent variables, in check order.
        missing: Vec<&'static str>,
    },
    /// A GitLab CI job with everything present, whose ID token could not be read:
    /// an identity cannot be established from claims nobody could parse, and
    /// inventing a weaker one would dress a CI job up as something it is not.
    Identity(RunContextError),
}

impl fmt::Display for GitlabCiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GitlabCiError::NotGitlabCi { missing } => {
                write!(f, "not a usable GitLab CI run context (missing: {})", missing.join(", "))
            }
            GitlabCiError::Identity(error) => {
                write!(f, "the GitLab CI job's id token could not be read: {error}")
            }
        }
    }
}

impl std::error::Error for GitlabCiError {}

/// A [`RunContext`] for one GitLab CI job: the CI counterpart of the laptop
/// adapter, whose identity comes from an ID token whose signature this adapter
/// **does not verify** (see the [module documentation](self)).
pub struct GitlabCiRunContext {
    actor: Actor,
    event: Event,
    capabilities: Capabilities,
    workspace: Workspace,
    token: SecretValue,
}

impl GitlabCiRunContext {
    /// Builds the run context from a snapshot of the job's environment, under an
    /// empty baseline. The environment is passed in rather than read here, so
    /// the decision stays pure and tests can script it. Returns
    /// [`GitlabCiError::NotGitlabCi`] when this is not a job carrying an ID
    /// token — the caller's cue to use the local path — and
    /// [`GitlabCiError::Identity`] when the token was there but its claims
    /// could not be read.
    pub fn from_env(env: &BTreeMap<String, String>) -> Result<GitlabCiRunContext, GitlabCiError> {
        Self::from_env_with(env, &ActorBaseline::default())
    }

    /// As [`GitlabCiRunContext::from_env`], but under the organisation's
    /// `baseline` — what turns an agent's pipeline into an [`ActorKind::Agent`]
    /// run.
    pub fn from_env_with(
        env: &BTreeMap<String, String>,
        baseline: &ActorBaseline,
    ) -> Result<GitlabCiRunContext, GitlabCiError> {
        if env.get(GITLAB_CI).map(String::as_str) != Some("true") {
            return Err(GitlabCiError::NotGitlabCi { missing: vec![GITLAB_CI] });
        }
        let mut missing = missing_vars(env, JOB_VARS);
        missing.extend(missing_vars(env, TOKEN_VARS));
        if !missing.is_empty() {
            return Err(GitlabCiError::NotGitlabCi { missing });
        }

        let token = SecretValue::new(env[ID_TOKEN].clone().into_bytes());
        // Read the job's own claims once, for the identity; the bytes are never
        // copied out of `token`. Self-reported, not signature-verified.
        let (issuer, subject) = claims_of(&token).map_err(GitlabCiError::Identity)?;

        let trigger = trigger_of(env);
        let git_ref = git_ref_of(env, &trigger);
        let root = PathBuf::from(&env[CI_PROJECT_DIR]);
        // The runner is the runner either way: what the pipeline's variables
        // add is who asked for it, and a baseline naming that account an
        // agent's makes the run an agent's without weakening the establishment.
        let login = login_of(env, &token, &subject);
        let established = Establishment::CiOidc { issuer, subject };
        let actor = if is_agent_account(&login, None, baseline) {
            Actor { kind: ActorKind::Agent, established, display_name: login }
        } else {
            Actor { kind: ActorKind::Ci, established, display_name: login }
        };
        Ok(GitlabCiRunContext {
            actor,
            // Fork merge-request detection for GitLab is not built yet (#126 covers
            // GitHub), so this adapter states the repository's own code.
            event: Event {
                git: GitInfo { sha: env[CI_COMMIT_SHA].clone(), git_ref },
                trigger,
                provenance: Provenance::Repository,
            },
            capabilities: Capabilities {
                // The constructor requires the token, so `oidc` and the token
                // variable agree by construction.
                oidc: true,
                // A runner has no person attached mid-flight.
                interactive: false,
                // GitLab's `cache:` keyword is a cache every job may use; how
                // much of it survives is the runner's business, not the
                // adapter's.
                ci_cache: true,
                // A runner reaches the whole internet; narrowing this belongs to
                // policy, not to the adapter.
                network: NetworkScope::Any,
                // GitLab's own CI/CD variables belong to the pipeline, not a
                // resolver.
                secret_resolvers: BTreeSet::new(),
            },
            workspace: Workspace { scratch: scratch_dir(&root), root },
            token,
        })
    }
}

/// Who the run is: the login that triggered the pipeline, else the token's own
/// `user_login` claim, else its `sub`. GitLab names no author, so this is the
/// trigger, never the proposer — and on a fork merge request that is the fork's
/// contributor. It is also where the agent/human split is decided, which makes
/// it a split the organisation makes rather than one GitLab reports.
fn login_of(env: &BTreeMap<String, String>, token: &SecretValue, subject: &str) -> String {
    let named = |name: &str| env.get(name).filter(|login| !login.is_empty()).cloned();
    named(GITLAB_USER_LOGIN)
        .or_else(|| string_claim(token, "user_login"))
        .unwrap_or_else(|| subject.to_string())
}

/// Prints the job's identity and nothing that opens a door: the ID token is a
/// credential, so it is left to `..`.
impl fmt::Debug for GitlabCiRunContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitlabCiRunContext")
            .field("actor", &self.actor)
            .field("event", &self.event)
            .field("capabilities", &self.capabilities)
            .field("workspace", &self.workspace)
            .finish_non_exhaustive()
    }
}

impl RunContext for GitlabCiRunContext {
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
        let result = self.token.with_bytes(|bytes| -> Result<SecretValue, RunContextError> {
            if !aud_names(&claims_json(bytes)?, audience) {
                return Err(RunContextError::OidcUnavailable { audience: audience.to_string() });
            }
            Ok(SecretValue::new(bytes.to_vec()))
        });
        Box::pin(std::future::ready(result))
    }
}

/// The variables among `names` that `env` does not set to a non-empty value.
fn missing_vars(env: &BTreeMap<String, String>, names: &[&'static str]) -> Vec<&'static str> {
    names.iter().copied().filter(|name| env.get(*name).is_none_or(String::is_empty)).collect()
}

/// The scratch directory: a `.ks` directory beside the checkout, since GitLab
/// documents no job-scoped temp directory. `join` always lengthens the path, so
/// scratch cannot be the root the conformance kit guards — the assertion stays,
/// because that invariant is the kit's and not this function's.
fn scratch_dir(root: &Path) -> PathBuf {
    let scratch = root.join(".ks").join("scratch");
    debug_assert!(scratch != root, "scratch must differ from the workspace root");
    scratch
}

/// What triggered the pipeline, from `CI_PIPELINE_SOURCE` and the variables that
/// go with it. GitLab's signals are its own, so nothing here is read out of the
/// ref the way the GitHub adapter reads `GITHUB_REF`:
///
/// | `CI_PIPELINE_SOURCE` | trigger |
/// |---|---|
/// | `merge_request_event` | [`Trigger::PullRequest`] with `CI_MERGE_REQUEST_IID` |
/// | `web`, `api`, `trigger`, `chat`, `webide`, `schedule` | [`Trigger::Manual`] |
/// | `push` with a `CI_COMMIT_TAG` | [`Trigger::Tag`], named from the tag |
/// | anything else (`push` on a branch, `external`, `parent_pipeline`, `pipeline`) | [`Trigger::Push`] |
///
/// An MR pipeline whose IID is missing or unparseable falls back to a push, as
/// the GitHub adapter does when GitHub names no number: a wrong trigger is worse
/// than a coarse one. A branch with an open merge request produces **both** a
/// `push` and a `merge_request_event` pipeline, so `merge_request_event` is
/// matched first rather than derived from the ref.
fn trigger_of(env: &BTreeMap<String, String>) -> Trigger {
    let value = |name: &str| env.get(name).map(String::as_str).unwrap_or_default();
    match value(CI_PIPELINE_SOURCE) {
        "merge_request_event" => match value(CI_MERGE_REQUEST_IID).parse::<u64>() {
            Ok(number) => Trigger::PullRequest { number },
            Err(_) => Trigger::Push,
        },
        "web" | "api" | "trigger" | "chat" | "webide" | "schedule" => Trigger::Manual,
        "push" => match env.get(CI_COMMIT_TAG).filter(|tag| !tag.is_empty()) {
            Some(tag) => Trigger::Tag { name: tag.clone() },
            None => Trigger::Push,
        },
        _ => Trigger::Push,
    }
}

/// The ref the run was triggered for, always under `refs/`. GitLab's
/// `CI_COMMIT_REF_NAME` is a bare name, so the ref is built here: `refs/tags/`
/// for a tag (which the conformance kit requires to match the [`Trigger::Tag`]
/// name exactly), `refs/heads/` for a branch. An MR pipeline checks out a
/// synthetic ref GitLab hands over whole, so that one is taken as given.
fn git_ref_of(env: &BTreeMap<String, String>, trigger: &Trigger) -> String {
    let mr_ref = env
        .get(CI_MERGE_REQUEST_REF_PATH)
        .filter(|path| path.starts_with("refs/") && !path.is_empty());
    if let Some(path) = mr_ref {
        return path.clone();
    }
    match trigger {
        Trigger::Tag { name } => format!("refs/tags/{name}"),
        _ => format!("refs/heads/{}", env[CI_COMMIT_REF_NAME]),
    }
}

/// Whether the token's `aud` claim names `audience`. The claim is a string or
/// an array of strings — both spellings are in the wild — and anything else
/// names nothing.
fn aud_names(json: &serde_json::Value, audience: &str) -> bool {
    match json.get("aud") {
        Some(serde_json::Value::String(single)) => single == audience,
        Some(serde_json::Value::Array(many)) => {
            many.iter().any(|entry| entry.as_str() == Some(audience))
        }
        _ => false,
    }
}

/// The `iss` and `sub` claims of an ID token: what makes the establishment.
fn claims_of(token: &SecretValue) -> Result<(String, String), RunContextError> {
    let json = payload_json(token)?;
    Ok((claim(&json, "iss")?, claim(&json, "sub")?))
}

/// One non-empty string claim, or [`None`] — for the claims that only sharpen an
/// identity rather than establishing it.
fn string_claim(token: &SecretValue, name: &str) -> Option<String> {
    payload_json(token).ok().and_then(|json| claim(&json, name).ok())
}

/// The token's claims as JSON, or the reason they are not readable. Every
/// failure names the broken step and never the token.
fn payload_json(token: &SecretValue) -> Result<serde_json::Value, RunContextError> {
    token.with_bytes(claims_json)
}

/// [`payload_json`] over bytes rather than a secret.
fn claims_json(jwt: &[u8]) -> Result<serde_json::Value, RunContextError> {
    let text = std::str::from_utf8(jwt).map_err(|_| backend("the id token is not utf-8"))?;
    let mut segments = text.split('.');
    let payload = match (segments.next(), segments.next(), segments.next(), segments.next()) {
        (Some(_header), Some(payload), Some(_signature), None) => payload,
        _ => return Err(backend("the id token is not a three-segment jwt")),
    };
    let decoded = decode_base64url(payload)
        .ok_or_else(|| backend("the id token payload is not base64url"))?;
    serde_json::from_slice(&decoded).map_err(|_| backend("the id token payload is not json"))
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

/// A backend failure naming what happened, safe to print.
fn backend(message: impl Into<String>) -> RunContextError {
    RunContextError::Backend { message: message.into() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ks_testing::block_on;

    const ISSUER: &str = "https://gitlab.com";
    const SUBJECT: &str = "project_path:Keep-Shipping/harness:ref_type:branch:ref:main";
    const SHA: &str = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b";
    const PROJECT_DIR: &str = "/builds/Keep-Shipping/harness";
    const LOGIN: &str = "gl-runner";
    /// The audience `ks_testing`'s conformance kit asks for.
    const CONFORMANCE_AUDIENCE: &str = "conformance-audience";

    /// One row of the trigger table: a pipeline source, the variables that come
    /// with it, the trigger that source must produce, and the ref.
    type TriggerCase = (&'static str, Vec<(&'static str, &'static str)>, Trigger, &'static str);

    /// Base64url encoding: the fixture-side counterpart of the adapter's decoder,
    /// so a fixture reads as the claims it carries.
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

    /// A synthetic — deliberately unsigned — ID token shaped like the real one:
    /// three segments, the middle a base64url JSON claims object.
    fn token_with(claims: &str) -> String {
        format!(
            "{header}.{payload}.not-a-real-signature",
            header = encode_base64url(br#"{"alg":"RS256","typ":"JWT"}"#),
            payload = encode_base64url(claims.as_bytes())
        )
    }

    /// The claims of a job's ID token: the identity, the audience the template
    /// declares, and the login GitLab records for whoever ran the job.
    fn id_token(audience: &str) -> String {
        token_with(&format!(
            r#"{{"iss":"{ISSUER}","sub":"{SUBJECT}","aud":"{audience}","user_login":"ada"}}"#
        ))
    }

    /// The environment GitLab sets for a job whose pipeline declares
    /// `id_tokens: KEEP_SHIPPING_ID_TOKEN`, on a pushed branch.
    fn job_env() -> BTreeMap<String, String> {
        [
            (GITLAB_CI, "true"),
            (CI_COMMIT_SHA, SHA),
            (CI_PROJECT_DIR, PROJECT_DIR),
            (CI_COMMIT_REF_NAME, "main"),
            (CI_PIPELINE_SOURCE, "push"),
            (GITLAB_USER_LOGIN, LOGIN),
            (ID_TOKEN, id_token(CONFORMANCE_AUDIENCE).as_str()),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
    }

    /// [`job_env`] with the ID token replaced by one carrying `claims`.
    fn with_token(claims: &str) -> BTreeMap<String, String> {
        let mut env = job_env();
        env.insert(ID_TOKEN.to_string(), token_with(claims));
        env
    }

    /// The run context a job's environment builds.
    fn build(env: &BTreeMap<String, String>) -> GitlabCiRunContext {
        GitlabCiRunContext::from_env(env).expect("a job with an id token builds")
    }

    /// The establishment every token in these fixtures establishes.
    fn established() -> Establishment {
        Establishment::CiOidc { issuer: ISSUER.to_string(), subject: SUBJECT.to_string() }
    }

    /// How a token that is not the caller's token is refused.
    fn refused(audience: &str) -> RunContextError {
        RunContextError::OidcUnavailable { audience: audience.to_string() }
    }

    #[test]
    fn a_job_s_token_mints_its_identity_and_nothing_else_opens_a_door() {
        let context = build(&job_env());

        assert_eq!(context.actor().kind, ActorKind::Ci);
        assert_eq!(context.actor().established, established());
        assert_eq!(context.actor().display_name, LOGIN);
        assert_eq!(context.event().git.sha, SHA);
        assert_eq!(context.event().git.git_ref, "refs/heads/main");
        assert_eq!(context.event().trigger, Trigger::Push);
        assert!(context.capabilities().oidc);
        assert!(!context.capabilities().interactive);
        assert!(context.capabilities().ci_cache);
        // The checkout is the workspace, and scratch is beside it, never it.
        assert_eq!(context.workspace().root, PathBuf::from(PROJECT_DIR));
        assert_eq!(context.workspace().scratch, PathBuf::from(PROJECT_DIR).join(".ks/scratch"));
        assert_ne!(context.workspace().scratch, context.workspace().root);

        // The token is handed out for the audience it was minted for, and for
        // nobody else's.
        let token = block_on(context.oidc_token(CONFORMANCE_AUDIENCE)).expect("its own aud");
        assert_eq!(token.with_bytes(<[u8]>::to_vec), id_token(CONFORMANCE_AUDIENCE).into_bytes());
        assert_eq!(
            block_on(context.oidc_token("https://vault.example")).expect_err("refused"),
            refused("https://vault.example")
        );
    }

    #[test]
    fn the_context_passes_the_run_context_conformance_kit() {
        // The kit asks for its own audience, which the token carries.
        block_on(ks_testing::run_context::conformance(&build(&job_env())));
    }

    #[test]
    fn environments_that_are_not_a_job_with_an_id_token_build_nothing() {
        let without = |names: &[&str]| {
            job_env()
                .into_iter()
                .filter(|(name, _)| !names.contains(&name.as_str()))
                .collect::<BTreeMap<_, _>>()
        };
        let cases: Vec<(&str, BTreeMap<String, String>, Vec<&'static str>)> = vec![
            ("a laptop with no environment at all", BTreeMap::new(), vec![GITLAB_CI]),
            (
                "GITLAB_CI set to anything but true",
                BTreeMap::from([(GITLAB_CI.to_string(), "1".to_string())]),
                vec![GITLAB_CI],
            ),
            ("a job without a ref name", without(&[CI_COMMIT_REF_NAME]), vec![CI_COMMIT_REF_NAME]),
            ("a pipeline without id_tokens:", without(TOKEN_VARS), TOKEN_VARS.to_vec()),
            // Check order: the job variables are named before the token.
            (
                "a job with neither",
                without(&[CI_PROJECT_DIR, ID_TOKEN]),
                vec![CI_PROJECT_DIR, ID_TOKEN],
            ),
        ];
        for (what, env, expected) in cases {
            match GitlabCiRunContext::from_env(&env) {
                Err(GitlabCiError::NotGitlabCi { missing }) => {
                    assert_eq!(missing, expected, "{what}")
                }
                other => panic!("{what}: expected NotGitlabCi, got {other:?}"),
            }
        }
        // The reason is worth printing: the caller logs it before falling back.
        assert_eq!(
            GitlabCiRunContext::from_env(&BTreeMap::new()).unwrap_err().to_string(),
            "not a usable GitLab CI run context (missing: GITLAB_CI)"
        );
    }

    #[test]
    fn a_token_that_breaks_the_contract_is_an_error_never_a_panic() {
        // A job whose identity cannot be read never becomes a run context: a
        // silently weaker actor would claim `Ci` on `LocalGitConfig` evidence.
        for (what, token) in [
            ("no iss claim", format!("e30.{}.sig", encode_base64url(b"{}"))),
            ("a payload that is not json", format!("e30.{}.sig", encode_base64url(b"nope"))),
            ("two segments", "e30.sig".to_string()),
            ("not base64url", "e30.a+b.sig".to_string()),
            ("not a jwt at all", "definitely-not-a-token".to_string()),
        ] {
            let mut env = job_env();
            env.insert(ID_TOKEN.to_string(), token);
            let error = GitlabCiRunContext::from_env(&env).expect_err(what);
            assert!(matches!(error, GitlabCiError::Identity(_)), "{what}: {error:?}");
        }
        // The fixture encoder and the decoder agree at every padding length,
        // which is what the token fixtures rest on; bytes no `str` can be are an
        // error too, not a panic.
        for claims in [r#"{"iss":"i","sub":"s"}"#, "{}", "a", "ab"] {
            assert_eq!(
                decode_base64url(&encode_base64url(claims.as_bytes())),
                Some(claims.as_bytes().to_vec()),
                "{claims}"
            );
        }
        assert!(claims_json(&[0xff, b'.', b'x', b'.', b'y']).is_err());

        // Once built — which means the payload was readable — a token whose
        // `aud` cannot be read fails closed instead of being handed over
        // unexamined. A payload that is not json at all never gets this far: the
        // constructor already refused it.
        for (what, aud) in [
            ("no aud claim at all", ""),
            ("an aud that is neither string nor array", r#","aud":42"#),
            ("an empty aud", r#","aud":"""#),
            ("an aud array naming other audiences", r#","aud":["other"]"#),
        ] {
            let context =
                build(&with_token(&format!(r#"{{"iss":"{ISSUER}","sub":"{SUBJECT}"{aud}}}"#)));
            assert_eq!(
                block_on(context.oidc_token(CONFORMANCE_AUDIENCE)).expect_err(what),
                refused(CONFORMANCE_AUDIENCE),
                "{what}"
            );
        }
        // An `aud` array that does name the caller is honoured, not refused.
        let context = build(&with_token(&format!(
            r#"{{"iss":"{ISSUER}","sub":"{SUBJECT}","aud":["other","{CONFORMANCE_AUDIENCE}"]}}"#
        )));
        assert!(block_on(context.oidc_token(CONFORMANCE_AUDIENCE)).is_ok());
    }

    #[test]
    fn pipeline_sources_map_onto_the_triggers_the_table_promises() {
        // (CI_PIPELINE_SOURCE, extra variables, trigger, git_ref)
        let mut cases: Vec<TriggerCase> = vec![
            (
                "merge_request_event",
                vec![(CI_MERGE_REQUEST_IID, "41")],
                Trigger::PullRequest { number: 41 },
                "refs/merge-requests/41/head",
            ),
            // No IID, or one that does not parse: a coarse trigger beats a wrong one.
            ("merge_request_event", vec![], Trigger::Push, "refs/heads/main"),
            (
                "merge_request_event",
                vec![(CI_MERGE_REQUEST_IID, "x")],
                Trigger::Push,
                "refs/heads/main",
            ),
            (
                "push",
                vec![(CI_COMMIT_TAG, "v1.2.3")],
                Trigger::Tag { name: "v1.2.3".to_string() },
                "refs/tags/v1.2.3",
            ),
            // A push with an empty tag variable is a branch push, not a tag.
            ("push", vec![(CI_COMMIT_TAG, "")], Trigger::Push, "refs/heads/main"),
            ("push", vec![], Trigger::Push, "refs/heads/main"),
        ];
        // Every source that is somebody asking for a pipeline is a manual
        // trigger, and every source GitLab does not explain is a plain push.
        for source in ["web", "api", "trigger", "chat", "webide", "schedule"] {
            cases.push((source, vec![], Trigger::Manual, "refs/heads/main"));
        }
        for source in ["external", "parent_pipeline", "pipeline"] {
            cases.push((source, vec![], Trigger::Push, "refs/heads/main"));
        }
        for (source, extra, expected, expected_ref) in cases {
            let mut env = job_env();
            env.insert(CI_PIPELINE_SOURCE.to_string(), source.to_string());
            for (name, value) in extra {
                env.insert(name.to_string(), value.to_string());
            }
            if matches!(expected, Trigger::PullRequest { .. }) {
                // The synthetic ref GitLab hands the job whole.
                let mr_ref = "refs/merge-requests/41/head";
                env.insert(CI_MERGE_REQUEST_REF_PATH.to_string(), mr_ref.to_string());
            }
            let context = build(&env);
            assert_eq!(context.event().trigger, expected, "{source}");
            assert_eq!(context.event().git.git_ref, expected_ref, "{source}");
            // No pipeline source changes who the actor is: GitLab names the user
            // who triggered the pipeline and nothing else.
            assert_eq!(context.actor().display_name, LOGIN, "{source}");
        }
    }

    #[test]
    fn the_actor_is_who_triggered_the_pipeline_and_the_baseline_says_if_they_are_an_agent() {
        let baseline =
            ActorBaseline { agents: BTreeSet::from(["ada".to_string()]), require_human: false };
        let mut env = job_env();
        env.remove(GITLAB_USER_LOGIN);
        // With no login in the environment the token's own `user_login` names the
        // run, and the organisation's list is the whole of the evidence.
        let agent = GitlabCiRunContext::from_env_with(&env, &baseline).expect("ada is listed");
        assert_eq!(agent.actor().kind, ActorKind::Agent);
        assert_eq!(agent.actor().display_name, "ada");
        assert_eq!(agent.actor().established, established());
        // The same pipeline under an empty baseline is a plain CI run.
        assert_eq!(build(&env).actor().kind, ActorKind::Ci);
        // With no login anywhere, the subject is the last resort — a project
        // ref, never mistaken for a person.
        let mut anonymous = env.clone();
        anonymous.insert(
            ID_TOKEN.to_string(),
            token_with(&format!(r#"{{"iss":"{ISSUER}","sub":"{SUBJECT}"}}"#)),
        );
        assert_eq!(build(&anonymous).actor().display_name, SUBJECT);
    }

    #[test]
    fn debug_prints_the_identity_but_never_the_token() {
        let debug = format!("{:?}", build(&job_env()));
        // It names who the job is...
        assert!(debug.contains(ISSUER), "{debug}");
        assert!(debug.contains(SUBJECT), "{debug}");
        // ...and carries no part of the credential that establishes it.
        for fragment in [
            id_token(CONFORMANCE_AUDIENCE).as_str(),
            "not-a-real-signature",
            "eyJhbGciOiJSUzI1NiJ9",
        ] {
            assert!(!debug.contains(fragment), "debug output leaked {fragment:?}: {debug}");
        }
    }

    #[test]
    fn the_template_declares_the_id_token_this_adapter_reads() {
        let template =
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../templates/gitlab/keepshipping.yml");
        let body =
            std::fs::read_to_string(template).expect("the gitlab template ships with the repo");
        assert!(body.contains(ID_TOKEN), "{template} must declare {ID_TOKEN}");
        assert!(body.contains("aud: keepshipping"), "{template} must mint it for keepshipping");
        assert!(body.contains("id_tokens:"), "{template} must ask for it per job");
        // The hand-off ADR 0008 asks for is a blocking manual job, on every
        // tier: a protected environment's approval is Premium/Ultimate only.
        assert!(body.contains("when: manual"), "{template} must model the approval gate");
        assert!(body.contains("allow_failure: false"), "{template}'s gate must block");
    }
}
