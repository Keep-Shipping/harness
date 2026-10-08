//! The [`RunContext`] port: who and where a run is — actor, event,
//! capabilities and workspace
//! ([#48](https://github.com/Keep-Shipping/harness/issues/48)).
//!
//! This is the one port that differs between a laptop and CI, so everything
//! that differs goes here and nowhere else. A step never reads `CI`,
//! `GITHUB_ACTIONS` or a TTY itself: it asks the port who is running it, why
//! the run was triggered, what it may do and where it may write. The local
//! adapter and the CI adapter (outside this crate) answer from their own
//! environments, so the same workflow runs unchanged in both places.
//!
//! # Identity is only as strong as its establishment
//!
//! On a laptop nothing vouches for the actor: `--as agent` is self-declared,
//! git config is whatever the user typed once, and `CI=true` in a local shell
//! is trivially spoofable. [`detect_local_actor`] therefore never returns
//! [`ActorKind::Ci`] — only an adapter that verified an OIDC token
//! ([`Establishment::CiOidc`]) may, and that is the only
//! [`IdentityStrength::Strong`] establishment. Every local establishment is
//! [`IdentityStrength::Weak`].
//!
//! # OIDC tokens are secrets
//!
//! [`RunContext::oidc_token`] mints a token for an audience and hands it out
//! as a [`SecretValue`], so it is redacted and zeroised like any other
//! secret. It fails with [`RunContextError::OidcUnavailable`] when the run
//! lacks the [`capability`](Capabilities::oidc) — a plain laptop usually
//! does.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;

use super::BoxFuture;
use super::secrets::SecretValue;

/// Environment variables that identify a known coding agent, e.g.
/// `CLAUDECODE=1`. A marker counts only when set to a non-empty value, and a
/// detected marker wins even over a declared `Human` — declarations are
/// typed by humans and forged by agents, while markers are what the agent
/// runtime sets for itself. The list is a heuristic, extended over time as
/// new agents ship new markers.
pub const KNOWN_AGENT_MARKERS: &[&str] = &[
    "CLAUDECODE",
    "CLAUDE_CODE_ENTRYPOINT",
    "CODEX_SANDBOX",
    "CURSOR_AGENT",
    "GEMINI_CLI",
    "AIDER_MODEL",
    "OPENHANDS",
];

/// Variables agents typically set to make interactive tools behave in a
/// non-interactive way — `TERM=dumb`, `PAGER=cat`, `GIT_EDITOR=true`. An
/// entry `(name, value)` matches when the environment sets `name` to
/// `value`; the empty value matches any non-empty one. Kept sorted; like
/// [`KNOWN_AGENT_MARKERS`] this is a heuristic, not proof.
pub const AGENT_TYPICAL_ENV: &[(&str, &str)] = &[
    ("GIT_EDITOR", "true"),
    ("GIT_PAGER", "cat"),
    ("NO_COLOR", ""),
    ("PAGER", "cat"),
    ("TERM", "dumb"),
];

/// Whether the environment sets `name` the way an [`AGENT_TYPICAL_ENV`]
/// entry expects: set to the expected value, or set to *any non-empty* value
/// when the entry's expected value is empty. Set-but-empty (`NO_COLOR=""`)
/// does not count — the variable is there but says nothing.
fn env_says(env: &BTreeMap<String, String>, name: &str, expected: &str) -> bool {
    env.get(name)
        .is_some_and(|actual| !actual.is_empty() && (expected.is_empty() || actual == expected))
}

/// The [`AGENT_TYPICAL_ENV`] variables the environment sets, in list order.
///
/// Evidence for [`detect_local_actor`] and for checker explanations: "this
/// run is non-interactive *and* something flattened the usual interactive
/// tools".
pub fn agent_typical_evidence(env: &BTreeMap<String, String>) -> Vec<&'static str> {
    AGENT_TYPICAL_ENV
        .iter()
        .filter(|(name, expected)| env_says(env, name, expected))
        .map(|(name, _)| *name)
        .collect()
}

/// The [`Establishment::Detected`] marker for a non-interactive run with
/// agent-typical variables: `no-tty` plus each match as `NAME=value` (or
/// `NAME` alone when any non-empty value matches), e.g. `no-tty+TERM=dumb`.
/// `None` when nothing matches — such a run is unknown, not detected.
fn detected_from_env(env: &BTreeMap<String, String>) -> Option<String> {
    let matched: Vec<String> = AGENT_TYPICAL_ENV
        .iter()
        .filter(|(name, expected)| env_says(env, name, expected))
        .map(|(name, expected)| match *expected {
            "" => (*name).to_string(),
            value => format!("{name}={value}"),
        })
        .collect();
    if matched.is_empty() {
        return None;
    }
    Some(format!("no-tty+{}", matched.join("+")))
}

/// What kind of principal a run acts as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorKind {
    /// A person ran the workflow.
    Human,
    /// A coding agent ran the workflow.
    Agent,
    /// A continuous-integration system ran the workflow. Only an adapter
    /// that verified an OIDC token may report this (see
    /// [`Establishment::CiOidc`]); a local run never is, however much its
    /// environment insists.
    Ci,
}

/// How much policy may lean on an actor's identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IdentityStrength {
    /// Best-effort: self-declared, detected from the environment or read
    /// from local config. Nothing consequential should rest on it alone.
    Weak,
    /// Verified by the adapter against a token from an identity provider
    /// ([`Establishment::CiOidc`]).
    Strong,
}

/// How the run's [`Actor`] identity was established — the part policy
/// actually trusts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Establishment {
    /// Read from local git config (`git config user.name`): what a laptop
    /// knows about a person.
    LocalGitConfig,
    /// The actor declared itself, e.g. `keepshipping run --as agent`.
    /// Declaration is not proof.
    SelfDeclared,
    /// The environment gave the actor away; `marker` names the evidence: a
    /// non-empty [`KNOWN_AGENT_MARKERS`] entry (e.g. `CLAUDECODE`), or a
    /// non-interactive run carrying [`AGENT_TYPICAL_ENV`] variables (e.g.
    /// `no-tty+TERM=dumb`).
    Detected {
        /// The environment variable, or `no-tty+…` evidence description.
        marker: String,
    },
    /// The organisation's baseline decided how to treat an unknown
    /// non-interactive local run (see
    /// [#119](https://github.com/Keep-Shipping/harness/issues/119)).
    AssumedByBaseline,
    /// The adapter verified an OIDC ID token: `issuer` is the token's `iss`,
    /// `subject` its `sub`. The only [`IdentityStrength::Strong`]
    /// establishment.
    CiOidc {
        /// The verified issuer, e.g. `https://token.actions.githubusercontent.com`.
        issuer: String,
        /// The verified subject, e.g. `repo:Keep-Shipping/harness:pull_request`.
        subject: String,
    },
}

impl Establishment {
    /// How strongly this establishment vouches for the actor.
    pub fn strength(&self) -> IdentityStrength {
        match self {
            Establishment::CiOidc { .. } => IdentityStrength::Strong,
            Establishment::LocalGitConfig
            | Establishment::SelfDeclared
            | Establishment::Detected { .. }
            | Establishment::AssumedByBaseline => IdentityStrength::Weak,
        }
    }
}

/// The principal a run acts as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    /// What the principal is.
    pub kind: ActorKind,
    /// How its identity was established.
    pub established: Establishment,
    /// A human-readable name for logs and approvals; never empty.
    pub display_name: String,
}

/// What the run is built on: the commit and the ref it was triggered for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitInfo {
    /// The full commit SHA the run checked out — 40 or 64 lowercase hex chars.
    pub sha: String,
    /// The ref the run was triggered for, e.g. `refs/heads/main`.
    pub git_ref: String,
}

/// Where the code this run is about came from.
///
/// Identity ([`Establishment`]) says *who is running*; this says *whose code
/// they are running*. A push to the default branch and a pull request from a
/// fork are both a [`ActorKind::Ci`] run with a verified identity, and they are
/// not the same amount of trust: the second runs a `ship.ks` somebody outside
/// the organisation wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Provenance {
    /// The repository's own code: a push, a tag, or a pull request whose head
    /// branch lives in the same repository as the base.
    #[default]
    Repository,
    /// A pull request whose head lives in another repository — a fork. Whoever
    /// wrote the `ship.ks`, the TypeScript script or the Dockerfile is not
    /// anybody this organisation granted anything to.
    Fork,
    /// `pull_request_target`: the workflow file comes from the base branch, but
    /// the code it checks out and runs is the pull request's. Untrusted by
    /// construction, whoever opened it and wherever the head lives — this is
    /// the event GitHub's own hardening guidance tells you not to use for
    /// untrusted code.
    Target,
}

impl Provenance {
    /// Whether a run about this code may act outside its own checkout: read a
    /// secret, mint a cloud credential, or push.
    ///
    /// Fails closed in the sense that matters — [`Provenance::Repository`] is
    /// the only answer that grants those, and it is a claim the adapter has to
    /// make affirmatively, never a default a missing value falls into.
    #[must_use]
    pub fn is_untrusted(&self) -> bool {
        match self {
            Provenance::Repository => false,
            Provenance::Fork | Provenance::Target => true,
        }
    }
}

/// Why the run is happening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trigger {
    /// A push to a branch.
    Push,
    /// A pull request was opened or updated.
    PullRequest {
        /// The pull request number.
        number: u64,
    },
    /// A tag was pushed.
    Tag {
        /// The tag name, e.g. `v1.2.3`.
        name: String,
    },
    /// Someone started the run by hand.
    Manual,
}

/// The event the run responds to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// The commit and ref this run is about.
    pub git: GitInfo,
    /// What triggered the run.
    pub trigger: Trigger,
    /// Where the code this run is about came from. See [`Provenance`].
    pub provenance: Provenance,
}

impl Event {
    /// The pull request number, when the run was triggered by one.
    pub fn pr_number(&self) -> Option<u64> {
        match self.trigger {
            Trigger::PullRequest { number } => Some(number),
            Trigger::Push | Trigger::Tag { .. } | Trigger::Manual => None,
        }
    }

    /// Whether this run is about code the organisation did not write.
    #[must_use]
    pub fn is_untrusted(&self) -> bool {
        self.provenance.is_untrusted()
    }
}

/// How far a run may reach, as the adapter observes it. The checker
/// ([#34](https://github.com/Keep-Shipping/harness/issues/34)) reads this to
/// decide what a workflow may attempt before anything runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    /// The adapter can mint OIDC tokens via [`RunContext::oidc_token`].
    pub oidc: bool,
    /// A person is attached and can approve things mid-flight.
    pub interactive: bool,
    /// The run may use the CI system's cache.
    pub ci_cache: bool,
    /// Where network access may go.
    pub network: NetworkScope,
    /// The secret resolvers available here (see [`super::secrets`]).
    pub secret_resolvers: BTreeSet<String>,
}

/// What network a run may talk to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkScope {
    /// No network access at all.
    None,
    /// Only the listed hosts.
    Hosts(BTreeSet<String>),
    /// Any host.
    Any,
}

/// Where a run's files live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workspace {
    /// The checkout the workflow runs against.
    pub root: PathBuf,
    /// A directory the run may write freely; distinct from `root`.
    pub scratch: PathBuf,
}

/// Why the [`RunContext`] port refused or failed a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunContextError {
    /// The run has no OIDC token provider for this audience — usually
    /// because [`Capabilities::oidc`] is false. The checker reports this as
    /// a configuration problem, never a crash.
    OidcUnavailable {
        /// The audience that was asked for.
        audience: String,
    },
    /// The adapter's backend failed (token endpoint down, malformed
    /// response, …).
    Backend {
        /// What went wrong, safe to print.
        message: String,
    },
}

impl fmt::Display for RunContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunContextError::OidcUnavailable { audience } => {
                write!(f, "no OIDC token provider for audience {audience:?} in this run")
            }
            RunContextError::Backend { message } => {
                write!(f, "run context backend failed: {message}")
            }
        }
    }
}

impl std::error::Error for RunContextError {}

/// The `RunContext` port: the one port that differs between a laptop and CI.
///
/// Adapters answer from their environment — the local adapter from git
/// config, TTY state and [`detect_local_actor`]; a CI adapter from its
/// provider's environment and a verified OIDC token. The answers are fixed
/// for the duration of a run, so the getters borrow: a step can hold the
/// `&Actor` for as long as it holds the context.
pub trait RunContext: Send + Sync {
    /// Who is running this.
    fn actor(&self) -> &Actor;

    /// Why this run is happening, and what it is built on.
    fn event(&self) -> &Event;

    /// What this run may do.
    fn capabilities(&self) -> &Capabilities;

    /// Where this run's files live.
    fn workspace(&self) -> &Workspace;

    /// Mints an OIDC token for `audience`, wrapped as a [`SecretValue`].
    /// Fails with [`RunContextError::OidcUnavailable`] when
    /// [`Capabilities::oidc`] is false.
    fn oidc_token<'a>(
        &'a self,
        audience: &'a str,
    ) -> BoxFuture<'a, Result<SecretValue, RunContextError>>;
}

/// What a local (laptop) run admits about itself. The local adapter
/// assembles this — a snapshot of the environment it chooses to share, TTY
/// state, git config — and [`detect_local_actor`] turns it into an [`Actor`].
/// No I/O happens here: the facts are supplied, the decision is pure.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalRunFacts {
    /// The actor kind the invocation declared, e.g. `--as agent`; `None`
    /// when the caller said nothing.
    pub declared: Option<ActorKind>,
    /// A snapshot of the process environment supplied by the adapter, never
    /// read from the real process here.
    pub env: BTreeMap<String, String>,
    /// Whether standard input is a terminal, i.e. a person is attached.
    pub stdin_is_tty: bool,
    /// `git config user.name`, when set.
    pub git_user_name: Option<String>,
}

/// How an unknown non-interactive local run is treated — no terminal, and no
/// [`AGENT_TYPICAL_ENV`] evidence either (that case is
/// [`Establishment::Detected`]). Somebody *or* something is driving, and the
/// organisation baseline decides which assumption is safer (see
/// [#119](https://github.com/Keep-Shipping/harness/issues/119)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownRunPolicy {
    /// Assume a person is driving.
    TreatAsHuman,
    /// Assume an agent is driving — the cautious default for unattended
    /// machines.
    TreatAsAgent,
}

/// Decides who is running a local workflow:
///
/// 1. A non-empty [`KNOWN_AGENT_MARKERS`] entry wins over everything — even
///    over a declared `Human` — and yields [`ActorKind::Agent`] with
///    [`Establishment::Detected`].
/// 2. A declared [`ActorKind::Agent`] yields `Agent` with
///    [`Establishment::SelfDeclared`].
/// 3. Without a TTY *and* with [`AGENT_TYPICAL_ENV`] evidence, the run is a
///    detected agent: [`ActorKind::Agent`] with [`Establishment::Detected`]
///    (marker e.g. `no-tty+TERM=dumb`), however the baseline is set.
/// 4. Without a TTY and without such evidence the run is *unknown*, so
///    `baseline` decides: [`UnknownRunPolicy::TreatAsAgent`] yields `Agent`
///    with [`Establishment::AssumedByBaseline`], otherwise `Human`.
/// 5. Anything else is [`ActorKind::Human`] with
///    [`Establishment::LocalGitConfig`].
///
/// A local run can never be [`ActorKind::Ci`]: `CI=true` in a local
/// environment is trivially spoofable, and only a CI adapter with a verified
/// OIDC subject may report it.
pub fn detect_local_actor(input: &LocalRunFacts, baseline: UnknownRunPolicy) -> Actor {
    let display_name = input.git_user_name.clone().unwrap_or_else(|| "unknown".to_string());

    // Rule 1: the environment is evidence; declarations are words.
    for marker in KNOWN_AGENT_MARKERS {
        if input.env.get(*marker).is_some_and(|value| !value.is_empty()) {
            return Actor {
                kind: ActorKind::Agent,
                established: Establishment::Detected { marker: (*marker).to_string() },
                display_name,
            };
        }
    }

    // Rule 2: taken at its word, and labelled as a word.
    if input.declared == Some(ActorKind::Agent) {
        return Actor {
            kind: ActorKind::Agent,
            established: Establishment::SelfDeclared,
            display_name,
        };
    }

    // Rule 3: a non-interactive run that also flattened the interactive
    // tools is an agent at the wheel — a detection signal, not a guess.
    // Rule 4: no terminal and no evidence — no answer, so the baseline
    // governs.
    if !input.stdin_is_tty {
        if let Some(marker) = detected_from_env(&input.env) {
            return Actor {
                kind: ActorKind::Agent,
                established: Establishment::Detected { marker },
                display_name,
            };
        }
        return match baseline {
            UnknownRunPolicy::TreatAsAgent => Actor {
                kind: ActorKind::Agent,
                established: Establishment::AssumedByBaseline,
                display_name,
            },
            UnknownRunPolicy::TreatAsHuman => Actor {
                kind: ActorKind::Human,
                established: Establishment::LocalGitConfig,
                display_name,
            },
        };
    }

    // Rule 5: an interactive run with nothing agent-shaped about it.
    Actor { kind: ActorKind::Human, established: Establishment::LocalGitConfig, display_name }
}
