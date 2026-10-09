//! Generic CI mode: any CI that can run a binary
//! ([#130](https://github.com/Keep-Shipping/harness/issues/130)).
//!
//! Where the GitHub Actions adapter answers from variables GitHub exports and
//! from the job's own OIDC token ([#150](https://github.com/Keep-Shipping/harness/issues/150)),
//! this one answers from what *any* CI system exports: Buildkite, GitLab,
//! CircleCI, Jenkins, or nothing at all but the `--ci` flag saying a CI is in
//! charge. What it reads is a marker variable per system, the commit and ref
//! each names, and the login the job ran as. What it does with them is what
//! the [`RunContext`] port holds: an [`Actor`], an [`Event`], what the run may
//! do, and where its files live.
//!
//! # This adapter proves nothing about who is running
//!
//! The port is explicit that an [`ActorKind::Ci`] actor may only be *strong*
//! when it was established [`Establishment::CiOidc`] — a token this crate
//! cannot reach, because GitLab, Buildkite, CircleCI and Jenkins each mint
//! their identity tokens at their own endpoint, in their own formats, with
//! their own audience rules. Generic mode has no token endpoint to verify
//! against, so it does not claim one: the actor is
//! [`Establishment::Detected`] when a named system's marker says so, and
//! [`Establishment::SelfDeclared`] when only `--ci` did, and in both cases
//! [`IdentityStrength::Weak`](ks_core::ports::run_context::IdentityStrength).
//!
//! Two consequences follow, and both are the point of the mode rather than a
//! defect in it:
//!
//! - A policy that requires a *strong* CI identity must not trust a generic
//!   CI run. Step kinds needing [`Capabilities::oidc`] are refused rather
//!   than half-served; ADR
//!   [0008](https://github.com/Keep-Shipping/harness/blob/main/docs/adr/0008-github-actions-first.md)
//!   commits to exactly this.
//! - This adapter deliberately does **not** pass `ks_testing`'s run-context
//!   conformance kit — a dev-dependency, so it is named here rather than
//!   linked — which requires a `Ci` actor to be established `CiOidc`.
//!   Passing it would mean lying about the identity, which is the one thing a
//!   run context must never do.
//!
//! # What it does give
//!
//! The plan, the steps and the log: a run that starts, picks its environment
//! the way a laptop would, drives its steps and reports a verdict. It does not
//! give trigger mapping onto the plan's `on:` (the run names its own event),
//! status reporting (there is no Checks API to write to), or approvals from
//! inside the job — an approval in a `--ci` run *parks* the run and the job
//! ends, which is [`docs/CLI.md`](../../docs/CLI.md)'s exit 4.
//!
//! # Nothing here is fabricated
//!
//! A CI that names no commit leaves [`GitInfo::sha`] empty; one that names no
//! ref leaves [`GitInfo::git_ref`] empty. There is no `refs/heads/main`
//! default and no made-up SHA: a run that claims to be about a commit it
//! cannot name is a run lying about what it is about, and the note printed for
//! `--ci` shows `-` where a value is missing rather than filling it in.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use ks_core::ports::BoxFuture;
use ks_core::ports::run_context::{
    Actor, ActorKind, Capabilities, Establishment, Event, GitInfo, NetworkScope, Provenance,
    RunContext, RunContextError, Trigger, Workspace,
};
use ks_core::ports::secrets::SecretValue;

use crate::resume::actor_word;

/// The branch names the operator has declared trusted, comma-separated, in a
/// run context generic mode builds.
///
/// This is the only signal generic mode has about whose code it is running, so
/// it is also the only thing that can make a generic run
/// [`Provenance::Repository`]. An absent variable, an empty one, one naming
/// nothing this run is on — all of them leave the run untrusted. Entries are
/// branch names as git knows them, `main` rather than `refs/heads/main`;
/// whitespace around an entry is trimmed and an empty entry is ignored.
const TRUSTED_BRANCHES: &str = "KEEP_SHIPPING_TRUSTED_BRANCHES";

/// Which CI system the environment says is in charge.
///
/// [`CiSystem::Generic`] is both "some CI that exports only `CI`" and "nothing
/// at all, but `--ci` was passed": a `--ci` invocation is itself the assertion,
/// so it is never [`CiSystem::Generic`] for want of evidence — only for want of
/// a system to name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CiSystem {
    /// `GITHUB_ACTIONS=true`. Generic mode reads the environment but claims no
    /// OIDC identity; the native
    /// [adapter](crate::github_actions_run_context) is the one that mints a
    /// token.
    GitHubActions,
    /// `GITLAB_CI` set.
    GitLab,
    /// `BUILDKITE` set.
    Buildkite,
    /// `CIRCLECI` set.
    CircleCi,
    /// `JENKINS_URL` set.
    Jenkins,
    /// `CI` set, or nothing set and `--ci` passed.
    Generic,
}

impl CiSystem {
    /// The name a person reads in the `--ci` note, in the parked record's `ci`
    /// key, and as the actor's display name where the CI named no login: the
    /// lowercase name of the system, and `unknown` where there is no system to
    /// name. One name for all three, so a log line and the record written from
    /// it cannot disagree about what an unnamed CI is called.
    fn name(self) -> &'static str {
        match self {
            CiSystem::GitHubActions => "github-actions",
            CiSystem::GitLab => "gitlab",
            CiSystem::Buildkite => "buildkite",
            CiSystem::CircleCi => "circleci",
            CiSystem::Jenkins => "jenkins",
            CiSystem::Generic => "unknown",
        }
    }
}

impl fmt::Display for CiSystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What the caller stated outright, which beats anything the environment
/// says. Every field is optional and the default overrides nothing, so a run
/// with no flags reads purely from the environment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Overrides {
    /// What `--actor`/`--as` declared. A declared kind other than
    /// [`ActorKind::Ci`] makes the identity self-declared, because a word on a
    /// command line is not evidence.
    pub actor: Option<ActorKind>,
    /// The name `--as agent:<name>` gave: which agent proposed this run. Like
    /// [`Overrides::actor`], it only ever renames; it never establishes.
    pub actor_name: Option<String>,
    /// `--sha`, for a CI whose variable names no commit.
    pub sha: Option<String>,
    /// `--event`, which is what a generic run has to say about itself: no
    /// native adapter maps a CI's events onto the plan's `on:` for it.
    ///
    /// A trigger that names a ref shape — a [`Trigger::Tag`]'s name — carries
    /// that ref with it, and it beats a detected one: a run told it is a tag
    /// is not on the branch the environment happens to have exported, and
    /// reporting both would say it is in two places at once.
    pub trigger: Option<Trigger>,
}

/// Every variable a CI system sets to say it is the one running, including the
/// bare `CI` all of them set. This is the list [`detect`] reads its named
/// systems off, and [`detects_a_ci`] reads to answer the question behind it.
const CI_MARKERS: &[&str] =
    &["GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "CIRCLECI", "JENKINS_URL", "CI"];

/// Whether the environment says a CI is in charge at all — one of the systems
/// [`detect`] can name, or a runner that exports only `CI`.
///
/// This is the question a caller with an adapter for GitHub and one for GitLab
/// still has to answer: with neither marker set, the environment they would
/// read is not a CI's, and neither reader's `Repository` is evidence of
/// anything but the absence of the variables that would have said otherwise.
///
/// It reads [`set`] rather than [`detect`], so it is deliberately a superset of
/// what [`detect`] names. `GITHUB_ACTIONS` is read exactly by [`detect`] — a
/// job that set it to `1` did not name itself — but is read here the way
/// [`args::detect_context`](crate::args::detect_context) reads it, as a system
/// saying it is there. The two only disagree about a misspelled marker, and the
/// disagreement runs towards calling the run a CI, which is the answer that
/// makes the caller ask [`provenance_of_env`] rather than assume trust.
pub(crate) fn detects_a_ci(env: &BTreeMap<String, String>) -> bool {
    CI_MARKERS.iter().any(|marker| set(env, marker))
}

/// How many *named* systems the environment says are in charge at once — the
/// question behind "which CI is running this?", when the answer cannot be one
/// system.
///
/// `CI` is read out of [`CI_MARKERS`] but is not counted: every real CI sets it
/// next to its own marker, so counting it would make every run on a runner say
/// two systems are in charge, and the question would never have an answer. What
/// is left is the list of systems a job can name, so the count is a question
/// about who is running rather than about whether anything is.
pub(crate) fn named_ci_systems(env: &BTreeMap<String, String>) -> usize {
    CI_MARKERS.iter().filter(|marker| **marker != "CI" && set(env, marker)).count()
}

/// The provenance generic mode's own rules give to an environment, for a caller
/// that has no run context to build — `resume`, which is handed a run id and a
/// command line rather than a CI's.
///
/// The ref is the one [`GenericCiRunContext::from_env`] would have read from
/// the same environment, with no override on top: a caller without a command
/// line has no override to apply. Both rules of [`provenance_of`] are this
/// adapter's and are applied here unchanged rather than restated — a
/// `KEEP_SHIPPING_TRUSTED_BRANCHES` that trusted a `--ci` run but not a resume
/// of it would be two answers to one question.
pub(crate) fn provenance_of_env(env: &BTreeMap<String, String>) -> Provenance {
    let git_ref = facts(detect(env), env).git_ref.unwrap_or_default();
    provenance_of(&git_ref, env.get(TRUSTED_BRANCHES).map(String::as_str))
}

/// The CI system the environment is in, from its marker variables.
///
/// Checked in order — GitHub, GitLab, Buildkite, CircleCI, Jenkins — because
/// a job may well export more than one system's leftovers, and the system
/// naming itself outright is the one whose variables describe this job. The
/// last two answers are both [`CiSystem::Generic`]: `CI` is the marker all of
/// them set, so on its own it names no system, and it decides CI-versus-local
/// for the run context
/// ([`args::detect_context`](crate::args::detect_context)) rather than which
/// system this is. A `--ci` invocation with nothing set at all is still a CI
/// asserting it is one.
pub fn detect(env: &BTreeMap<String, String>) -> CiSystem {
    if env.get("GITHUB_ACTIONS").map(String::as_str) == Some("true") {
        return CiSystem::GitHubActions;
    }
    for (marker, system) in [
        ("GITLAB_CI", CiSystem::GitLab),
        ("BUILDKITE", CiSystem::Buildkite),
        ("CIRCLECI", CiSystem::CircleCi),
        ("JENKINS_URL", CiSystem::Jenkins),
    ] {
        if set(env, marker) {
            return system;
        }
    }
    CiSystem::Generic
}

/// What one system's environment says about the job, before any override. A
/// field is `None` where that system names no such thing, which is different
/// from naming it empty.
#[derive(Debug, Default)]
struct Facts {
    sha: Option<String>,
    git_ref: Option<String>,
    trigger: Option<Trigger>,
    actor: Option<String>,
    root: Option<PathBuf>,
    temp: Option<String>,
}

/// A [`RunContext`] for a job on any CI: the generic counterpart of the laptop
/// adapter and of the
/// [GitHub Actions one](crate::github_actions_run_context::GithubActionsRunContext).
///
/// Its identity is [`IdentityStrength::Weak`](ks_core::ports::run_context::IdentityStrength)
/// and [`Capabilities::oidc`] is false, always: see the [module
/// documentation](self) for why, and for what that costs a policy.
pub struct GenericCiRunContext {
    system: CiSystem,
    actor: Actor,
    event: Event,
    capabilities: Capabilities,
    workspace: Workspace,
}

impl GenericCiRunContext {
    /// Builds the run context from a snapshot of the job's environment, the
    /// `root` the checkout lives at, and whatever the command line declared.
    ///
    /// The environment is passed in rather than read here, the way the
    /// GitHub Actions adapter takes one: the decision stays pure and a test
    /// can script it. There is no failure case — every environment answers
    /// something, because `--ci` already said a CI is in charge — so this
    /// returns a context rather than a [`Result`].
    pub fn from_env(
        env: &BTreeMap<String, String>,
        root: PathBuf,
        overrides: Overrides,
    ) -> GenericCiRunContext {
        let system = detect(env);
        let facts = facts(system, env);
        // Precedence, uniformly: what the caller stated beats what the
        // environment said, and an empty string is what neither said.
        let sha = overrides.sha.or(facts.sha).unwrap_or_default();
        let git_ref = facts.git_ref.unwrap_or_default();
        // A CI that names no event and a command line that names none either
        // is somebody starting the run by hand.
        let trigger = overrides.trigger.or(facts.trigger).unwrap_or(Trigger::Manual);
        // A tag trigger names the ref it implies, and the two cannot disagree:
        // `trigger_from_cli` already refuses to call anything a tag without the
        // name, so this states what was said rather than filling anything in.
        // A trigger that names no ref shape leaves the environment's alone.
        let git_ref = match &trigger {
            Trigger::Tag { name } => format!("refs/tags/{name}"),
            _ => git_ref,
        };
        let actor = actor_of(system, facts.actor, overrides.actor, overrides.actor_name.as_deref());
        // Read after the ref above is final: a `--event "tag v1.2.3"` run is on
        // a tag whatever the environment exported, and a tag is never trusted
        // by this adapter. Generic mode fails closed — untrusted unless the
        // operator declared the branch in `KEEP_SHIPPING_TRUSTED_BRANCHES`.
        let provenance = provenance_of(&git_ref, env.get(TRUSTED_BRANCHES).map(String::as_str));
        let root = facts.root.unwrap_or(root);
        let scratch = scratch_dir(facts.temp.as_deref(), &root);
        GenericCiRunContext {
            system,
            actor,
            // The run's own statement about whose code it is; see
            // `provenance_of` for why the answer is almost always "not the
            // repository's" here.
            event: Event { git: GitInfo { sha, git_ref }, trigger, provenance },
            capabilities: Capabilities {
                // Honest: there is no token endpoint this adapter can reach and
                // verify, so it does not claim one. `oidc_token` answers
                // `OidcUnavailable` to match, never a token.
                oidc: false,
                // A job has no person attached mid-flight.
                interactive: false,
                // A CI job may use its system's cache; which key it is, and
                // whether the system has one at all, is the job's business.
                ci_cache: true,
                // A hosted agent reaches the whole internet; narrowing this
                // belongs to policy, not to the adapter.
                network: NetworkScope::Any,
                // The CI system's own secrets belong to the CI, not to a
                // resolver this crate implements.
                secret_resolvers: BTreeSet::new(),
            },
            workspace: Workspace { scratch, root },
        }
    }

    /// Which CI system this run detected, for the log and the parked record.
    pub fn system(&self) -> CiSystem {
        self.system
    }

    /// The one line a `--ci` run says about itself before it starts: what was
    /// detected, and — the point of printing it — that none of it is verified.
    pub fn note(&self) -> String {
        format!(
            "--ci {system}: actor={actor} event={event} ref={git_ref} sha={sha} \
             (self-declared; generic mode verifies no OIDC identity)",
            system = self.system,
            actor = self.actor.display_name,
            event = trigger_word(&self.event.trigger),
            git_ref = or_dash(&self.event.git.git_ref),
            sha = or_dash(&self.event.git.sha),
        )
    }
}

/// Who is running this, and how much that is worth.
///
/// The kind is whatever the caller declared, else [`ActorKind::Ci`] — this is
/// a `--ci` run, after all. The *establishment* is the part policy trusts, so
/// it is deliberately pessimistic:
///
/// - a declared kind other than `ci` is a word on a command line:
///   [`Establishment::SelfDeclared`];
/// - otherwise a named system's marker detected the run:
///   [`Establishment::Detected`] with `ci:<system>`, naming the evidence;
/// - otherwise nothing but `--ci` did, which proves nothing:
///   [`Establishment::SelfDeclared`].
///
/// Every one of those is [`IdentityStrength::Weak`](ks_core::ports::run_context::IdentityStrength),
/// which is the whole of this adapter's claim (see the module documentation).
/// The display name is the agent `--as agent:<name>` named, else the CI's own
/// login, else the declared kind, else the system's name — never empty, which
/// [`Actor::display_name`] requires. The name goes in the same place the local
/// adapter puts it ([`actor::local`](crate::actor::local)): a run that named
/// its agent must say which one in the note, not merely that it was one.
fn actor_of(
    system: CiSystem,
    login: Option<String>,
    declared: Option<ActorKind>,
    name: Option<&str>,
) -> Actor {
    let kind = declared.unwrap_or(ActorKind::Ci);
    // A declaration of `ci` says nothing the environment does not already say,
    // so it is read as no declaration: the system still gets to be detected.
    let declared = declared.filter(|kind| *kind != ActorKind::Ci);
    let established = match (declared, system) {
        (Some(_), _) => Establishment::SelfDeclared,
        (None, CiSystem::Generic) => Establishment::SelfDeclared,
        (None, system) => Establishment::Detected { marker: format!("ci:{system}") },
    };
    let display_name = match name.filter(|name| !name.is_empty()) {
        Some(name) => name.to_string(),
        None => match declared {
            Some(kind) => actor_word(kind).to_string(),
            None => {
                login.filter(|name| !name.is_empty()).unwrap_or_else(|| system.name().to_string())
            }
        },
    };
    Actor { kind, established, display_name }
}

/// Where the code this run is about came from, from the ref and the branch
/// names the operator declared in [`TRUSTED_BRANCHES`].
///
/// Two rules, and the *default* is the point of the whole function:
///
/// 1. A run on a branch whose name appears in the declared list is
///    [`Provenance::Repository`]. The branch name is the git ref with
///    `refs/heads/` stripped, compared exactly after trimming: no prefix
///    matching, and case-sensitive, because a branch named `MAIN` is a
///    different branch from `main` and a near-miss (`main-old`) that quietly
///    matched would trust a branch nobody declared.
/// 2. Everything else — no declared list, an empty one, a list that names
///    nothing this run is on, a tag ref, a ref with no `refs/heads/` prefix at
///    all — is [`Provenance::Fork`].
///
/// **Even a run on `main` is untrusted until the operator names `main`.** That
/// is deliberate, and it is the whole of the change from the earlier state of
/// this adapter: there is no special case for the default branch, and the
/// escape hatch is the declared list, not a name this function happens to
/// recognise. An adapter that trusted `main` by default would be trusting a
/// *string* it read out of the environment, and that string is written by the
/// pipeline that is asking the question.
///
/// # Why untrusted is the default rather than merely cautious
///
/// Because generic mode is the mode an operator reaches for when they are on
/// Jenkins, Buildkite, CircleCI, a self-hosted runner, or a CI this adapter has
/// never heard of — and on those systems the variables that would identify a
/// fork do not exist. GitHub exports the two repository names
/// (`GITHUB_HEAD_REPOSITORY`, `GITHUB_BASE_REPOSITORY`) and GitLab exports the
/// two project ids; a pipeline author can supply them by hand, but then they
/// are words in a `.jenkinsfile` or a `pipeline { }` block, written by whoever
/// wrote that file, and read back by a job that file also controls. A word on a
/// command line or a variable in a build script is not evidence about *whose
/// code* is being built. Silence there is not consent.
///
/// So the trust signal here is deliberately an *assertion* rather than an
/// inference: the operator says which of their branches this adapter may treat
/// as the repository's own, and anything they did not say is untrusted. That
/// is a stronger claim than "this looks like the default branch", and it is the
/// one the [`Provenance::is_untrusted`](ks_core::ports::run_context::Provenance)
/// side of the port is built on: `PolicyGate` refuses every secret to an
/// untrusted provenance, so the cost of being wrong here is a denied secret,
/// not a leaked one. See
/// [`Provenance::is_untrusted`](ks_core::ports::run_context::Provenance::is_untrusted).
///
/// # Why a tag ref is never trusted, even by name
///
/// `refs/tags/…` is not eligible at all, whatever the declared list says. A
/// tag pipeline in generic mode can be pointed at any ref the runner can
/// fetch, and the ref's shape is the only thing this adapter can check for
/// itself — unlike GitHub's adapter, which has the event payload to say whose
/// tag it is. An operator who wants a release build trusted has to name the
/// code somewhere this adapter cannot reach around; the native adapter is that
/// place.
fn provenance_of(git_ref: &str, trusted: Option<&str>) -> Provenance {
    // Rule 1: only a branch ref is eligible, and a ref that names no branch
    // (`refs/tags/v1.2.3`, a pull-request ref, an empty ref, Jenkins' detached
    // SHA) has no name to match, so it falls to rule 2.
    let Some(branch) =
        git_ref.strip_prefix("refs/heads/").map(str::trim).filter(|name| !name.is_empty())
    else {
        return Provenance::Fork;
    };
    // Rule 1 again, read entry by entry: whitespace around a name is noise, an
    // empty entry names nothing, and `None` — no declaration at all — names
    // nothing either.
    let mut declared = trusted.unwrap_or_default().split(',').map(str::trim);
    if declared.any(|name| !name.is_empty() && name == branch) {
        return Provenance::Repository;
    }
    // Rule 2: everything else.
    Provenance::Fork
}

impl RunContext for GenericCiRunContext {
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
        // Exactly what `capabilities().oidc == false` promises. There is no
        // branch here that could answer `Ok`, which is what keeps the
        // capability honest.
        Box::pin(std::future::ready(Err(RunContextError::OidcUnavailable {
            audience: audience.to_string(),
        })))
    }
}

/// The `push` / `pr 42` / `tag v1.2.3` / `manual` a person reads.
fn trigger_word(trigger: &Trigger) -> String {
    match trigger {
        Trigger::Push => "push".to_string(),
        Trigger::PullRequest { number } => format!("pr {number}"),
        Trigger::Tag { name } => format!("tag {name}"),
        Trigger::Manual => "manual".to_string(),
    }
}

/// The value as written, or `-` where nothing wrote one: a field that is empty
/// says so on its own terms rather than being filled in with a placeholder that
/// could be mistaken for a real ref.
fn or_dash(value: &str) -> &str {
    if value.is_empty() { "-" } else { value }
}

/// The `--event "pr 42"` of a `run` command line as the port's [`Trigger`].
///
/// A pull request's number and a tag's name are the glob `--event` carries
/// (`pr 42`, `tag v1.2.3`); a glob that is not one — a branch, a `v*`
/// pattern — names no such thing, so the run falls back to [`Trigger::Push`]
/// rather than inventing a number.
pub fn trigger_from_cli(trigger: &ks_core::Trigger) -> Trigger {
    match trigger.kind {
        ks_core::TriggerKind::Push => Trigger::Push,
        ks_core::TriggerKind::Pr => match trigger.glob.as_deref().and_then(|g| g.parse().ok()) {
            Some(number) => Trigger::PullRequest { number },
            None => Trigger::Push,
        },
        ks_core::TriggerKind::Tag => match trigger.glob.as_deref() {
            Some(name) if !name.is_empty() => Trigger::Tag { name: name.to_string() },
            _ => Trigger::Push,
        },
        ks_core::TriggerKind::Manual => Trigger::Manual,
    }
}

/// What each system names about the job it is running.
///
/// A field stays [`None`] where the system names no such thing, so an
/// override can fill it and an absent one cannot be confused with an empty
/// one. `root` is the checkout the CI exports where it exports one, and
/// [`None`] — the caller's own working directory — where it does not; a CI
/// working directory is rarely where a binary was invoked from anyway.
fn facts(system: CiSystem, env: &BTreeMap<String, String>) -> Facts {
    match system {
        CiSystem::GitHubActions => Facts {
            sha: value(env, "GITHUB_SHA"),
            git_ref: value(env, "GITHUB_REF"),
            trigger: Some(github_trigger(env)),
            actor: value(env, "GITHUB_ACTOR"),
            root: path(env, "GITHUB_WORKSPACE"),
            temp: value(env, "RUNNER_TEMP"),
        },
        CiSystem::GitLab => {
            // A tag pipeline's `CI_COMMIT_REF_NAME` is the tag, so the tag
            // variable has to be read first or every release build looks like a
            // branch called `v1.2.3`.
            let tag = value(env, "CI_COMMIT_TAG");
            let branch = value(env, "CI_COMMIT_REF_NAME");
            let git_ref = match (&tag, &branch) {
                (Some(tag), _) => Some(format!("refs/tags/{tag}")),
                (None, Some(name)) => Some(format!("refs/heads/{name}")),
                (None, None) => None,
            };
            Facts {
                sha: value(env, "CI_COMMIT_SHA"),
                trigger: Some(gitlab_trigger(env)),
                git_ref,
                actor: value(env, "GITLAB_USER_LOGIN"),
                root: path(env, "CI_PROJECT_DIR"),
                // GitLab names no scratch directory; the rule below puts one
                // inside the checkout, which is the only place it can be sure of.
                temp: None,
            }
        }
        CiSystem::Buildkite => Facts {
            sha: value(env, "BUILDKITE_COMMIT"),
            git_ref: Some(buildkite_ref(env)),
            trigger: Some(buildkite_trigger(env)),
            actor: value(env, "BUILDKITE_BUILD_AUTHOR"),
            root: None,
            temp: value(env, "BUILDKITE_TEMP"),
        },
        CiSystem::CircleCi => Facts {
            sha: value(env, "CIRCLE_SHA1"),
            git_ref: Some(circleci_ref(env)),
            trigger: Some(circleci_trigger(env)),
            actor: value(env, "CIRCLE_USERNAME"),
            root: path(env, "CIRCLE_WORKING_DIRECTORY"),
            temp: value(env, "CIRCLE_TEMP"),
        },
        CiSystem::Jenkins => Facts {
            sha: value(env, "GIT_COMMIT"),
            git_ref: Some(jenkins_ref(env)),
            trigger: Some(jenkins_trigger(env)),
            actor: value(env, "BUILD_USER_ID"),
            root: None,
            temp: jenkins_temp(env),
        },
        // A bare `--ci` names nothing at all: no commit, no ref, no login and
        // no checkout, so it cannot say why the job is running. It answers
        // `manual`, which claims only that nobody's name is on it — and which
        // `--event` and `--sha` exist to correct.
        CiSystem::Generic => Facts { trigger: Some(Trigger::Manual), ..Facts::default() },
    }
}

/// GitHub's event name, with the ref saying what a `push` was a push *of* — a
/// tag ref is a tag, whatever the event was called.
///
/// The same rule the native adapter applies to the same variables, restated
/// rather than shared: that adapter answers for GitHub alone, and this one
/// must keep answering when it is the only adapter the user has.
fn github_trigger(env: &BTreeMap<String, String>) -> Trigger {
    let git_ref = env.get("GITHUB_REF").map(String::as_str).unwrap_or_default();
    match env.get("GITHUB_EVENT_NAME").map(String::as_str).unwrap_or_default() {
        "pull_request" | "pull_request_target" => {
            // A merge build checks out `refs/pull/<n>/merge`; a head build
            // `refs/pull/<n>/head`. Either way the number is in the ref.
            git_ref
                .strip_prefix("refs/pull/")
                .and_then(|rest| rest.split('/').next())
                .and_then(|number| number.parse().ok())
                .map_or_else(|| trigger_of_ref(git_ref), |number| Trigger::PullRequest { number })
        }
        // GitHub names its own events, so these are read rather than guessed: a
        // schedule and a workflow run check out a branch exactly like a push
        // does, and calling all three a push says nobody knows the difference.
        "workflow_dispatch" | "repository_dispatch" | "schedule" => Trigger::Manual,
        "push" => Trigger::Push,
        _ => trigger_of_ref(git_ref),
    }
}

/// GitLab's pipeline source, which names the event without naming a ref shape:
/// `merge_request_event` carries the merge request's own iid, and `web`,
/// `api` and `trigger` are somebody asking for the pipeline by hand.
fn gitlab_trigger(env: &BTreeMap<String, String>) -> Trigger {
    match env.get("CI_PIPELINE_SOURCE").map(String::as_str).unwrap_or_default() {
        "merge_request_event" => {
            env.get("CI_MERGE_REQUEST_IID").and_then(|iid| iid.parse().ok()).map_or_else(
                || trigger_of_ref(&gitlab_ref(env)),
                |number| Trigger::PullRequest { number },
            )
        }
        // A schedule is a pipeline GitLab started on its own, with nobody's
        // push behind it, whatever branch it checks out.
        "web" | "api" | "trigger" | "schedule" => Trigger::Manual,
        "push" => Trigger::Push,
        _ => trigger_of_ref(&gitlab_ref(env)),
    }
}

/// Buildkite's event name. `pull_request` names the pull request as `!123` —
/// Buildkite's own notation, borrowed from GitHub — and the tag and build
/// events say what the ref already says.
fn buildkite_trigger(env: &BTreeMap<String, String>) -> Trigger {
    match env.get("BUILDKITE_EVENT").map(String::as_str).unwrap_or_default() {
        "pull_request" => env
            .get("BUILDKITE_PULL_REQUEST")
            .and_then(|pr| pr.strip_prefix('!'))
            .and_then(|number| number.parse().ok())
            .map_or_else(
                || trigger_of_ref(&buildkite_ref(env)),
                |number| Trigger::PullRequest { number },
            ),
        "manual" | "api" => Trigger::Manual,
        "push" => Trigger::Push,
        _ => trigger_of_ref(&buildkite_ref(env)),
    }
}

/// CircleCI's pull request variable is the URL of the pull request, so the
/// number is its last path element; without one, a branch is not a push.
fn circleci_trigger(env: &BTreeMap<String, String>) -> Trigger {
    match env.get("CIRCLE_PULL_REQUEST").map(String::as_str).unwrap_or_default() {
        "" => trigger_of_ref(&circleci_ref(env)),
        url => url.rsplit_once("/pull/").and_then(|(_, number)| number.parse().ok()).map_or_else(
            || trigger_of_ref(&circleci_ref(env)),
            |number| Trigger::PullRequest { number },
        ),
    }
}

/// Jenkins' pull requests are builds of a change request, and `CHANGE_ID` is
/// the number of one; nothing in the environment says otherwise.
fn jenkins_trigger(env: &BTreeMap<String, String>) -> Trigger {
    env.get("CHANGE_ID")
        .and_then(|id| id.parse().ok())
        .map_or_else(|| trigger_of_ref(&jenkins_ref(env)), |number| Trigger::PullRequest { number })
}

/// A tag ref is a tag. Anything else is **not** called a push: a branch ref is
/// a branch ref, and the events that check out a branch without anybody
/// pushing to it — a schedule, a nightly build, a pipeline someone re-ran —
/// all look exactly the same from here. So a ref that names no tag is reported
/// as [`Trigger::Manual`], which is the one answer no environment contradicts.
fn trigger_of_ref(git_ref: &str) -> Trigger {
    match git_ref.strip_prefix("refs/tags/") {
        Some(name) if !name.is_empty() => Trigger::Tag { name: name.to_string() },
        _ => Trigger::Manual,
    }
}

fn gitlab_ref(env: &BTreeMap<String, String>) -> String {
    match value(env, "CI_COMMIT_TAG") {
        Some(tag) => format!("refs/tags/{tag}"),
        None => match value(env, "CI_COMMIT_REF_NAME") {
            Some(name) => format!("refs/heads/{name}"),
            None => String::new(),
        },
    }
}

fn buildkite_ref(env: &BTreeMap<String, String>) -> String {
    match value(env, "BUILDKITE_TAG") {
        Some(tag) => format!("refs/tags/{tag}"),
        None => match value(env, "BUILDKITE_BRANCH") {
            Some(branch) => format!("refs/heads/{branch}"),
            None => String::new(),
        },
    }
}

fn circleci_ref(env: &BTreeMap<String, String>) -> String {
    match value(env, "CIRCLE_TAG") {
        Some(tag) => format!("refs/tags/{tag}"),
        None => match value(env, "CIRCLE_BRANCH") {
            Some(branch) => format!("refs/heads/{branch}"),
            None => String::new(),
        },
    }
}

/// Jenkins' `GIT_BRANCH` is the local branch name, which after a checkout of a
/// remote-tracking branch reads `origin/main` — so the remote comes off, and
/// the forms the git plugin exports come off with it.
///
/// Only those forms are stripped: a branch genuinely called `origin/release`
/// is a branch, and truncating it to `release` would name a ref the job is not
/// on. A checkout under another remote (`upstream/main`) keeps its prefix.
///
/// A hex value is not a branch at all. Jenkins puts the checked-out SHA in
/// `GIT_BRANCH` when HEAD is detached — the normal shape of a tag or
/// `git checkout <sha>` build — and there is no branch ref that names a
/// commit, so nothing is returned: `refs/heads/<sha>` would be a ref the
/// environment never named and the job is not on.
fn jenkins_ref(env: &BTreeMap<String, String>) -> String {
    let name = match value(env, "GIT_TAG_NAME") {
        Some(tag) => return format!("refs/tags/{tag}"),
        None => value(env, "GIT_BRANCH").unwrap_or_default(),
    };
    if is_commit_sha(&name) {
        return String::new();
    }
    let name = name.strip_prefix("refs/remotes/").unwrap_or(&name);
    let name = name.strip_prefix("origin/").unwrap_or(name);
    // A CI that exports the full ref already names a ref: prefixing it again
    // would give `refs/heads/refs/heads/main`.
    let name = name.strip_prefix("refs/heads/").unwrap_or(name);
    if name.is_empty() { String::new() } else { format!("refs/heads/{name}") }
}

/// Whether `name` is a commit id rather than a branch name: 7 to 40 hex
/// characters, which is what an abbreviated or full SHA looks like and no
/// branch Jenkins exports is named like.
fn is_commit_sha(name: &str) -> bool {
    (7..=40).contains(&name.len())
        && name.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// Jenkins' scratch directory: the sibling directory the git plugin creates
/// beside the workspace (`$WORKSPACE@tmp`), falling back to `TMPDIR` where the
/// plugin has not.
fn jenkins_temp(env: &BTreeMap<String, String>) -> Option<String> {
    match value(env, "WORKSPACE") {
        Some(workspace) => Some(format!("{workspace}@tmp")),
        None => value(env, "TMPDIR"),
    }
}

/// The scratch directory: the system's own temp directory when it names one,
/// else a `.ks` directory inside the checkout — and never the checkout itself,
/// which a scratch directory is required to differ from.
fn scratch_dir(temp: Option<&str>, root: &Path) -> PathBuf {
    match temp.filter(|dir| !dir.is_empty()).map(Path::new) {
        Some(dir) if dir != root => dir.to_path_buf(),
        _ => root.join(".ks").join("scratch"),
    }
}

/// The variable `env` sets to a non-empty value.
fn value(env: &BTreeMap<String, String>, name: &str) -> Option<String> {
    env.get(name).filter(|value| !value.is_empty()).cloned()
}

/// The variable `env` sets to a non-empty path.
fn path(env: &BTreeMap<String, String>, name: &str) -> Option<PathBuf> {
    value(env, name).map(PathBuf::from)
}

/// Whether `env` sets `name` to something that claims a CI is there.
///
/// A variable set to a recognised false value (`false`, `0`) is a system
/// saying it is *not* one, the same rule
/// [`detect_context`](crate::args::detect_context) applies to `CI`: a system
/// should not have to unset a variable to be believed about itself.
fn set(env: &BTreeMap<String, String>, name: &str) -> bool {
    env.get(name).is_some_and(|value| {
        let value = value.trim().to_ascii_lowercase();
        !value.is_empty() && value != "false" && value != "0"
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ks_core::ports::run_context::IdentityStrength;
    use ks_testing::block_on;

    /// The environment a system exports, as a map a test can script.
    fn env(vars: &[(&str, &str)]) -> BTreeMap<String, String> {
        vars.iter().map(|(name, value)| (name.to_string(), value.to_string())).collect()
    }

    /// The context a set of variables builds, with the caller's root as given.
    fn context(vars: &[(&str, &str)]) -> GenericCiRunContext {
        GenericCiRunContext::from_env(&env(vars), PathBuf::from("/work/repo"), Overrides::default())
    }

    /// The context a set of variables builds, with overrides on top.
    fn context_with(vars: &[(&str, &str)], overrides: Overrides) -> GenericCiRunContext {
        GenericCiRunContext::from_env(&env(vars), PathBuf::from("/work/repo"), overrides)
    }

    /// One fixture per system: its marker, the variables the extraction rules
    /// below are written against, and what they must produce.
    #[test]
    fn every_system_is_detected_from_its_own_marker() {
        let cases: Vec<(CiSystem, &[(&str, &str)])> = vec![
            (CiSystem::GitHubActions, &[("GITHUB_ACTIONS", "true")]),
            (CiSystem::GitLab, &[("GITLAB_CI", "true")]),
            (CiSystem::Buildkite, &[("BUILDKITE", "true")]),
            (CiSystem::CircleCi, &[("CIRCLECI", "true")]),
            (CiSystem::Jenkins, &[("JENKINS_URL", "https://jenkins.example/")]),
            // A bare `CI` names no system...
            (CiSystem::Generic, &[("CI", "true")]),
            // ...and so does nothing at all.
            (CiSystem::Generic, &[]),
        ];
        for (system, vars) in cases {
            assert_eq!(detect(&env(vars)), system, "{vars:?}");
        }
        // Order matters when a job carries another system's leftovers: the
        // system naming itself outright is the one whose variables describe
        // this job.
        assert_eq!(
            detect(&env(&[("GITHUB_ACTIONS", "true"), ("GITLAB_CI", "true")])),
            CiSystem::GitHubActions
        );
        assert_eq!(detect(&env(&[("GITLAB_CI", "true"), ("BUILDKITE", "true")])), CiSystem::GitLab);
        // `GITHUB_ACTIONS` is read exactly, like the native adapter reads it:
        // a job that sets it to `1` is a job that did not name itself.
        assert_eq!(detect(&env(&[("GITHUB_ACTIONS", "1")])), CiSystem::Generic);
        // `CI=false` is a system saying it is not one, which leaves nothing to
        // detect — `--ci` is what makes such a run a CI run anyway.
        assert_eq!(detect(&env(&[("CI", "false")])), CiSystem::Generic);
        // A marker set to a recognised false value says the same thing, so it
        // names no system either: setting a variable to `false` is not the same
        // as setting it, and a system should not have to unset it to be
        // believed about itself.
        for marker in ["GITLAB_CI", "BUILDKITE", "CIRCLECI", "JENKINS_URL"] {
            for false_value in ["", "false", "False", "0", " 0 "] {
                assert_eq!(
                    detect(&env(&[(marker, false_value)])),
                    CiSystem::Generic,
                    "{marker}={false_value:?} is not a system saying it is one"
                );
            }
        }
        assert_eq!(CiSystem::Generic.to_string(), "unknown");
        assert_eq!(CiSystem::GitHubActions.to_string(), "github-actions");
    }

    #[test]
    fn each_system_speaks_in_its_own_variables() {
        let buildkite = context(&[
            ("BUILDKITE", "true"),
            ("BUILDKITE_COMMIT", "abc123"),
            ("BUILDKITE_BRANCH", "main"),
            ("BUILDKITE_EVENT", "push"),
            ("BUILDKITE_BUILD_AUTHOR", "ada"),
        ]);
        assert_eq!(buildkite.event().git.sha, "abc123");
        assert_eq!(buildkite.event().git.git_ref, "refs/heads/main");
        assert_eq!(buildkite.event().trigger, Trigger::Push);
        assert_eq!(buildkite.actor().display_name, "ada");
        // No checkout variable in this system's vocabulary, so the caller's own
        // working directory is the root.
        assert_eq!(buildkite.workspace().root, PathBuf::from("/work/repo"));

        let gitlab = context(&[
            ("GITLAB_CI", "true"),
            ("CI_COMMIT_SHA", "def456"),
            ("CI_COMMIT_REF_NAME", "feature/x"),
            ("CI_PIPELINE_SOURCE", "push"),
            ("GITLAB_USER_LOGIN", "grace"),
            ("CI_PROJECT_DIR", "/builds/acme/api"),
        ]);
        assert_eq!(gitlab.event().git.sha, "def456");
        assert_eq!(gitlab.event().git.git_ref, "refs/heads/feature/x");
        assert_eq!(gitlab.workspace().root, PathBuf::from("/builds/acme/api"));
        assert_eq!(gitlab.actor().display_name, "grace");

        let github = context(&[
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_SHA", "aaa"),
            ("GITHUB_REF", "refs/heads/main"),
            ("GITHUB_EVENT_NAME", "push"),
            ("GITHUB_ACTOR", "octocat"),
            ("GITHUB_WORKSPACE", "/home/runner/work/api/api"),
            ("RUNNER_TEMP", "/home/runner/work/_temp"),
        ]);
        assert_eq!(github.workspace().root, PathBuf::from("/home/runner/work/api/api"));
        assert_eq!(github.workspace().scratch, PathBuf::from("/home/runner/work/_temp"));

        let circleci = context(&[
            ("CIRCLECI", "true"),
            ("CIRCLE_SHA1", "bbb"),
            ("CIRCLE_BRANCH", "main"),
            ("CIRCLE_USERNAME", "linus"),
            ("CIRCLE_WORKING_DIRECTORY", "/home/circleci/project"),
            ("CIRCLE_TEMP", "/tmp/circleci"),
        ]);
        assert_eq!(circleci.workspace().root, PathBuf::from("/home/circleci/project"));
        assert_eq!(circleci.actor().display_name, "linus");

        let jenkins = context(&[
            ("JENKINS_URL", "https://jenkins.example/"),
            ("GIT_COMMIT", "ccc"),
            ("GIT_BRANCH", "origin/main"),
            ("BUILD_USER_ID", "hedy"),
            ("WORKSPACE", "/var/lib/jenkins/workspace/api"),
        ]);
        assert_eq!(jenkins.event().git.git_ref, "refs/heads/main");
        assert_eq!(jenkins.actor().display_name, "hedy");
        // The git plugin's `$WORKSPACE@tmp`, not the workspace itself.
        assert_eq!(
            jenkins.workspace().scratch,
            PathBuf::from("/var/lib/jenkins/workspace/api@tmp")
        );
    }

    #[test]
    fn each_system_names_its_own_trigger() {
        // GitLab's merge request pipeline: the number is the iid of the merge
        // request, which is what a URL carries.
        let merge = context(&[
            ("GITLAB_CI", "true"),
            ("CI_PIPELINE_SOURCE", "merge_request_event"),
            ("CI_MERGE_REQUEST_IID", "42"),
            ("CI_COMMIT_REF_NAME", "feature/x"),
        ]);
        assert_eq!(merge.event().trigger, Trigger::PullRequest { number: 42 });
        // A pipeline GitLab started by hand is nobody's push.
        for source in ["web", "api", "trigger"] {
            let pipeline = context(&[("GITLAB_CI", "true"), ("CI_PIPELINE_SOURCE", source)]);
            assert_eq!(pipeline.event().trigger, Trigger::Manual, "{source}");
        }

        // Buildkite writes the pull request as `!123`.
        let pull = context(&[
            ("BUILDKITE", "true"),
            ("BUILDKITE_EVENT", "pull_request"),
            ("BUILDKITE_PULL_REQUEST", "!42"),
            ("BUILDKITE_BRANCH", "feature/x"),
        ]);
        assert_eq!(pull.event().trigger, Trigger::PullRequest { number: 42 });
        for event in ["manual", "api"] {
            let build = context(&[("BUILDKITE", "true"), ("BUILDKITE_EVENT", event)]);
            assert_eq!(build.event().trigger, Trigger::Manual, "{event}");
        }

        // CircleCI names the pull request by its URL.
        let pr = context(&[
            ("CIRCLECI", "true"),
            ("CIRCLE_PULL_REQUEST", "https://github.com/acme/api/pull/42"),
        ]);
        assert_eq!(pr.event().trigger, Trigger::PullRequest { number: 42 });
        let not_a_pr = context(&[
            ("CIRCLECI", "true"),
            ("CIRCLE_PULL_REQUEST", "https://github.com/acme/api/pull/42/files"),
        ]);
        assert_eq!(
            not_a_pr.event().trigger,
            Trigger::Manual,
            "a URL that names no pull request, and a branch ref is not a push"
        );

        // GitHub's number is in the ref; a workflow dispatch is a person's.
        let merge_ref = context(&[
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_EVENT_NAME", "pull_request"),
            ("GITHUB_REF", "refs/pull/42/merge"),
        ]);
        assert_eq!(merge_ref.event().trigger, Trigger::PullRequest { number: 42 });
        let dispatch =
            context(&[("GITHUB_ACTIONS", "true"), ("GITHUB_EVENT_NAME", "workflow_dispatch")]);
        assert_eq!(dispatch.event().trigger, Trigger::Manual);

        // Jenkins' `CHANGE_ID` is the number of the change request.
        let change = context(&[("JENKINS_URL", "https://jenkins.example/"), ("CHANGE_ID", "42")]);
        assert_eq!(change.event().trigger, Trigger::PullRequest { number: 42 });
    }

    #[test]
    fn a_tag_ref_is_a_tag_wherever_the_system_puts_it() {
        /// A system, the variables that put a tag on its ref, and the tag's
        /// name — one row per place a CI system keeps a tag.
        type Case = (CiSystem, Vec<(&'static str, &'static str)>, &'static str);
        let cases: Vec<Case> = vec![
            (
                CiSystem::GitHubActions,
                vec![("GITHUB_ACTIONS", "true"), ("GITHUB_REF", "refs/tags/v1.2.3")],
                "v1.2.3",
            ),
            (
                CiSystem::GitLab,
                vec![
                    ("GITLAB_CI", "true"),
                    ("CI_COMMIT_TAG", "v1.2.3"),
                    ("CI_COMMIT_REF_NAME", "v1.2.3"),
                ],
                "v1.2.3",
            ),
            (
                CiSystem::Buildkite,
                vec![("BUILDKITE", "true"), ("BUILDKITE_TAG", "v1.2.3")],
                "v1.2.3",
            ),
            (CiSystem::CircleCi, vec![("CIRCLECI", "true"), ("CIRCLE_TAG", "v1.2.3")], "v1.2.3"),
            (
                CiSystem::Jenkins,
                vec![("JENKINS_URL", "https://jenkins.example/"), ("GIT_TAG_NAME", "v1.2.3")],
                "v1.2.3",
            ),
        ];
        for (system, vars, name) in cases {
            let context = context(&vars);
            assert_eq!(context.system(), system, "{vars:?}");
            assert_eq!(
                context.event().trigger,
                Trigger::Tag { name: name.to_string() },
                "{vars:?}"
            );
            // The tag's ref and the tag's trigger agree by construction.
            assert_eq!(context.event().git.git_ref, format!("refs/tags/{name}"), "{vars:?}");
        }
        // A GitLab tag pipeline whose ref name is the tag too must not end up
        // with `refs/heads/v1.2.3`: the tag variable is read first.
        assert_eq!(
            gitlab_ref(&env(&[("CI_COMMIT_TAG", "v9"), ("CI_COMMIT_REF_NAME", "v9")])),
            "refs/tags/v9"
        );
    }

    #[test]
    fn a_named_system_is_detected_and_a_bare_ci_is_only_declared() {
        let detected = context(&[("BUILDKITE", "true"), ("BUILDKITE_BUILD_AUTHOR", "ada")]);
        assert_eq!(detected.actor().kind, ActorKind::Ci);
        assert_eq!(
            detected.actor().established,
            Establishment::Detected { marker: "ci:buildkite".to_string() }
        );

        // `CI=true` on a laptop proves nothing, so it names no evidence.
        let bare = context(&[("CI", "true")]);
        assert_eq!(bare.actor().kind, ActorKind::Ci);
        assert_eq!(bare.actor().established, Establishment::SelfDeclared);
        assert_eq!(bare.actor().display_name, "unknown", "a run must still name its actor");

        // Nothing set at all, `--ci` passed: still a CI run.
        let nothing = context(&[]);
        assert_eq!(nothing.actor().kind, ActorKind::Ci);
        assert_eq!(nothing.actor().established, Establishment::SelfDeclared);
        assert_eq!(
            nothing.event().trigger,
            Trigger::Manual,
            "nothing said why the job is running, so nothing is claimed"
        );

        // Every establishment this adapter builds is weak — the whole claim.
        for context in [&detected, &bare] {
            assert_eq!(
                context.actor().established.strength(),
                IdentityStrength::Weak,
                "generic mode verifies no OIDC identity: {actor:?}",
                actor = context.actor()
            );
        }
    }

    #[test]
    fn a_declared_actor_beats_the_environment_and_is_labelled_a_word() {
        // A declaration other than `ci` is a word on a command line, so it is
        // self-declared even where a system was detected.
        let declared = context_with(
            &[("BUILDKITE", "true"), ("BUILDKITE_BUILD_AUTHOR", "ada")],
            Overrides { actor: Some(ActorKind::Agent), ..Overrides::default() },
        );
        assert_eq!(declared.actor().kind, ActorKind::Agent);
        assert_eq!(declared.actor().established, Establishment::SelfDeclared);
        assert_eq!(declared.actor().display_name, "agent", "what was declared is what is shown");

        // `--actor ci` says what the environment already said, so the system is
        // still detected — and its login still names the run.
        let ci = context_with(
            &[("GITLAB_CI", "true"), ("GITLAB_USER_LOGIN", "grace")],
            Overrides { actor: Some(ActorKind::Ci), ..Overrides::default() },
        );
        assert_eq!(
            ci.actor().established,
            Establishment::Detected { marker: "ci:gitlab".to_string() }
        );
        assert_eq!(ci.actor().display_name, "grace");
    }

    #[test]
    fn overrides_beat_detection_everywhere_they_reach() {
        let vars = [
            ("BUILDKITE", "true"),
            ("BUILDKITE_COMMIT", "abc123"),
            ("BUILDKITE_BRANCH", "main"),
            ("BUILDKITE_EVENT", "push"),
            ("BUILDKITE_BUILD_AUTHOR", "ada"),
        ];
        let overridden = context_with(
            &vars,
            Overrides {
                actor: Some(ActorKind::Agent),
                actor_name: Some("deployer".to_string()),
                sha: Some("deadbeef".to_string()),
                trigger: Some(Trigger::PullRequest { number: 7 }),
            },
        );
        assert_eq!(overridden.event().git.sha, "deadbeef");
        // A `pr` names no ref shape, so the environment's branch stands: an
        // override replaces what it contradicts, not everything.
        assert_eq!(overridden.event().git.git_ref, "refs/heads/main");
        assert_eq!(overridden.event().trigger, Trigger::PullRequest { number: 7 });
        assert_eq!(overridden.actor().display_name, "deployer");
        // The system is still what it detected: `--sha` says what the commit is,
        // not which CI this is.
        assert_eq!(overridden.system(), CiSystem::Buildkite);
        // And a note says so on one line.
        assert_eq!(
            overridden.note(),
            "--ci buildkite: actor=deployer event=pr 7 ref=refs/heads/main sha=deadbeef \
             (self-declared; generic mode verifies no OIDC identity)"
        );

        // A tag names its own ref, and it beats a branch the environment
        // exported: `--event "tag v1.2.3"` on a `main` build would otherwise
        // claim the run is on `refs/heads/main` and is a tag at once.
        let tag = context_with(
            &vars,
            Overrides {
                trigger: Some(Trigger::Tag { name: "v1.2.3".to_string() }),
                ..Overrides::default()
            },
        );
        assert_eq!(tag.event().trigger, Trigger::Tag { name: "v1.2.3".to_string() });
        assert_eq!(tag.event().git.git_ref, "refs/tags/v1.2.3");
    }

    #[test]
    fn a_named_agent_keeps_its_name_in_a_ci_note() {
        // `--as agent:deployer`: the name says which agent proposed the run, in
        // a CI context exactly as it does on a laptop. Reporting only `agent`
        // would drop the one word the caller wrote.
        let named = context_with(
            &[("BUILDKITE", "true"), ("BUILDKITE_BUILD_AUTHOR", "ada")],
            Overrides {
                actor: Some(ActorKind::Agent),
                actor_name: Some("deployer".to_string()),
                ..Overrides::default()
            },
        );
        assert_eq!(
            (named.actor().kind, named.actor().display_name.as_str()),
            (ActorKind::Agent, "deployer")
        );
        // The CI's login is what it is for a run nobody named an agent for.
        assert_eq!(
            context(&[("BUILDKITE", "true"), ("BUILDKITE_BUILD_AUTHOR", "ada")])
                .actor()
                .display_name,
            "ada"
        );
    }

    #[test]
    fn nothing_is_fabricated_where_the_system_names_nothing() {
        let bare = context(&[]);
        assert_eq!(bare.event().git.sha, "", "no invented sha");
        assert_eq!(bare.event().git.git_ref, "", "no invented ref");
        // Scratch is inside the checkout, and never the checkout itself.
        assert_eq!(bare.workspace().scratch, PathBuf::from("/work/repo/.ks/scratch"));
        // `-` is what the note prints for a value nothing wrote, and an event
        // nothing named is `manual` rather than a plausible `push`. The actor
        // and the `ci` key in the parked record are one name: `unknown`.
        assert_eq!(
            bare.note(),
            "--ci unknown: actor=unknown event=manual ref=- sha=- \
             (self-declared; generic mode verifies no OIDC identity)"
        );
    }

    #[test]
    fn a_detached_head_is_not_a_branch() {
        // Jenkins puts the checked-out SHA in `GIT_BRANCH` when HEAD is
        // detached — the normal shape of a tag or `git checkout <sha>` build.
        // There is no branch ref that names a commit, so none is invented.
        for sha in ["9f2c1e4b7a0d6c5e3f8a1b2c3d4e5f60718293a4", "9f2c1e4"] {
            let detached =
                context(&[("JENKINS_URL", "https://jenkins.example/"), ("GIT_BRANCH", sha)]);
            assert_eq!(detached.event().git.git_ref, "", "a commit is not refs/heads/<sha>");
            assert!(!detached.note().contains("refs/heads"), "{}", detached.note());
        }
        // A branch whose name merely looks hex-ish is still a branch: only a
        // value that is nothing *but* hex, of a length a SHA can have, is a
        // commit. The prefixes the plugin adds come off, and a full ref is not
        // prefixed a second time.
        for (branch, expected) in [
            ("main", "refs/heads/main"),
            ("origin/main", "refs/heads/main"),
            ("refs/remotes/origin/main", "refs/heads/main"),
            ("refs/heads/main", "refs/heads/main"),
            ("a1b2c3", "refs/heads/a1b2c3"),
            ("deadbeef-release", "refs/heads/deadbeef-release"),
        ] {
            assert_eq!(jenkins_ref(&env(&[("GIT_BRANCH", branch)])), expected, "{branch}");
        }
        // A tag still wins: a tag build names its tag outright.
        assert_eq!(
            jenkins_ref(&env(&[("GIT_BRANCH", "9f2c1e4b"), ("GIT_TAG_NAME", "v1.2.3")])),
            "refs/tags/v1.2.3"
        );
    }

    #[test]
    fn a_ref_that_names_no_tag_is_not_called_a_push() {
        // A schedule checks out a branch like any other build, so the ref says
        // nothing about why. `manual` claims only that nobody's name is on it.
        for (system, vars) in [
            (
                CiSystem::GitHubActions,
                &[
                    ("GITHUB_ACTIONS", "true"),
                    ("GITHUB_REF", "refs/heads/main"),
                    ("GITHUB_EVENT_NAME", "schedule"),
                ][..],
            ),
            (
                CiSystem::GitLab,
                &[
                    ("GITLAB_CI", "true"),
                    ("CI_PIPELINE_SOURCE", "schedule"),
                    ("CI_COMMIT_REF_NAME", "main"),
                ][..],
            ),
        ] {
            let context = context(vars);
            assert_eq!(context.system(), system, "{vars:?}");
            assert_eq!(context.event().trigger, Trigger::Manual, "{vars:?}");
            assert!(!context.note().contains("event=push"), "{}", context.note());
        }
        // A system that says `push` says so, and is believed: it is the bare
        // ref that cannot. And a tag is still read as a tag by the same rule.
        let push = context(&[
            ("BUILDKITE", "true"),
            ("BUILDKITE_EVENT", "push"),
            ("BUILDKITE_BRANCH", "main"),
        ]);
        assert_eq!(push.event().trigger, Trigger::Push);
        assert_eq!(trigger_of_ref("refs/heads/main"), Trigger::Manual);
        assert_eq!(trigger_of_ref(""), Trigger::Manual);
        assert_eq!(trigger_of_ref("refs/tags/v1.2.3"), Trigger::Tag { name: "v1.2.3".to_string() });
    }

    #[test]
    fn a_scratch_directory_is_never_the_checkout() {
        let root = PathBuf::from("/work/repo");
        // The system names a temp directory that is the checkout: unusable.
        for temp in [None, Some(""), Some("/work/repo")] {
            assert_eq!(
                scratch_dir(temp, &root),
                PathBuf::from("/work/repo/.ks/scratch"),
                "temp {temp:?}"
            );
        }
        assert_eq!(
            scratch_dir(Some("/work/temp"), &root),
            PathBuf::from("/work/temp"),
            "a real temp directory is used as it is"
        );
        // A system that names no scratch at all gets the rule's answer.
        let gitlab = context(&[("GITLAB_CI", "true"), ("CI_PROJECT_DIR", "/builds/api")]);
        assert_eq!(gitlab.workspace().scratch, PathBuf::from("/builds/api/.ks/scratch"));
    }

    #[test]
    fn an_actor_always_has_a_name() {
        for vars in [
            vec![("BUILDKITE", "true")],
            vec![("BUILDKITE", "true"), ("BUILDKITE_BUILD_AUTHOR", "")],
            vec![("JENKINS_URL", "https://jenkins.example/")],
            vec![("CI", "true")],
            vec![],
        ] {
            let context = context(&vars);
            assert!(!context.actor().display_name.is_empty(), "{vars:?}");
        }
        // Jenkins' `TMPDIR` is the scratch fallback where the git plugin names
        // no workspace.
        let no_workspace =
            context(&[("JENKINS_URL", "https://jenkins.example/"), ("TMPDIR", "/tmp")]);
        assert_eq!(no_workspace.workspace().scratch, PathBuf::from("/tmp"));
    }

    #[test]
    fn generic_mode_never_mints_a_token_and_says_so_in_its_capabilities() {
        let context = context(&[("BUILDKITE", "true"), ("BUILDKITE_BUILD_AUTHOR", "ada")]);
        assert!(!context.capabilities().oidc, "there is no endpoint to verify against");
        assert!(!context.capabilities().interactive, "nobody is at the keyboard");
        assert!(context.capabilities().ci_cache);
        assert_eq!(context.capabilities().network, NetworkScope::Any);
        assert!(context.capabilities().secret_resolvers.is_empty(), "no resolvers exist");

        // The two agree: the capability is false, so the token is refused with
        // the error that says so. This future is ready immediately, so it needs
        // no executor.
        let refused = block_on(context.oidc_token("https://example.com/aud"))
            .expect_err("no token endpoint, so no token");
        assert_eq!(
            refused,
            RunContextError::OidcUnavailable { audience: "https://example.com/aud".to_string() }
        );
    }

    #[test]
    fn a_command_line_event_says_what_the_run_thought_it_was() {
        let trigger = |text: &str| trigger_from_cli(&crate::parse_event(text).expect("an event"));
        assert_eq!(trigger("push"), Trigger::Push);
        assert_eq!(trigger("push main"), Trigger::Push, "a branch names no number");
        assert_eq!(trigger("pr 42"), Trigger::PullRequest { number: 42 });
        assert_eq!(trigger("pr"), Trigger::Push, "no number, no pull request");
        assert_eq!(trigger("pr main"), Trigger::Push, "a branch is not a number");
        assert_eq!(trigger("tag v1.2.3"), Trigger::Tag { name: "v1.2.3".to_string() });
        assert_eq!(trigger("tag"), Trigger::Push, "no name, no tag");
        assert_eq!(trigger("manual"), Trigger::Manual);
    }

    /// Every way the declared list and a ref can disagree, and what each one
    /// must answer. One table so the policy reads as a whole: a run is trusted
    /// only where a row says so.
    #[test]
    fn generic_mode_trusts_only_a_declared_branch() {
        type Case = (&'static str, Option<&'static str>, Provenance, &'static str);
        let cases: Vec<Case> = vec![
            // The declared branch is trusted.
            ("refs/heads/main", Some("main"), Provenance::Repository, "declared"),
            // ...including among others, and with whitespace around each entry.
            (
                "refs/heads/main",
                Some("nightly , main ,release"),
                Provenance::Repository,
                "declared among others",
            ),
            (
                "refs/heads/release",
                Some(" main , release "),
                Provenance::Repository,
                "whitespace is trimmed",
            ),
            // The branch is not in the list: nothing says it is the
            // repository's own code.
            ("refs/heads/feature/x", Some("main"), Provenance::Fork, "not declared"),
            // Nothing was declared at all — not even an empty list, which is
            // a declaration of nothing.
            ("refs/heads/main", None, Provenance::Fork, "no list"),
            ("refs/heads/main", Some(""), Provenance::Fork, "empty list"),
            ("refs/heads/main", Some(" , ,, "), Provenance::Fork, "list of empty entries"),
            // A near miss is not a match: `main-old` shares a prefix with
            // `main` and is a different branch, and comparison is exact.
            ("refs/heads/main-old", Some("main"), Provenance::Fork, "prefix is not equality"),
            (
                "refs/heads/main-old",
                Some("main-old"),
                Provenance::Repository,
                "the near-miss is declared in its own right",
            ),
            // Case-sensitive: `MAIN` is not `main`.
            ("refs/heads/MAIN", Some("main"), Provenance::Fork, "case matters"),
            // A tag is never trusted here, by its own name or anything else:
            // the ref shape is the only thing this adapter can check.
            ("refs/tags/v1.2.3", Some("v1.2.3"), Provenance::Fork, "a tag is not a branch"),
            (
                "refs/tags/v1.2.3",
                Some("v1.2.3, main"),
                Provenance::Fork,
                "a tag is not a branch even when the list names it",
            ),
            // Nor is a ref that names no branch at all.
            ("", Some("main"), Provenance::Fork, "no ref, no branch"),
            ("refs/pull/42/merge", Some("main"), Provenance::Fork, "a pull-request ref"),
            ("refs/heads/", Some(""), Provenance::Fork, "a branch ref naming no branch"),
            ("main", Some("main"), Provenance::Fork, "a bare name is not a ref"),
        ];
        for (git_ref, trusted, expected, why) in cases {
            assert_eq!(provenance_of(git_ref, trusted), expected, "{git_ref:?} {trusted:?}: {why}");
        }
        // The whole of the point, stated once more where a reader cannot miss
        // it: the untrusted answers are the ones `is_untrusted` acts on.
        assert!(provenance_of("refs/heads/main", None).is_untrusted());
        assert!(!provenance_of("refs/heads/main", Some("main")).is_untrusted());
    }

    #[test]
    fn every_system_fails_closed_until_an_operator_declares_a_branch() {
        // A run that looks exactly like a GitHub Actions push to `main`, built
        // by the adapter that cannot see a fork marker, is untrusted anyway.
        let github = &[
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_REF", "refs/heads/main"),
            ("GITHUB_EVENT_NAME", "push"),
        ][..];
        assert_eq!(context(github).event().provenance, Provenance::Fork);
        assert_eq!(
            context_with(
                &[
                    ("GITHUB_ACTIONS", "true"),
                    ("GITHUB_REF", "refs/heads/main"),
                    (TRUSTED_BRANCHES, "main")
                ],
                Overrides::default()
            )
            .event()
            .provenance,
            Provenance::Repository,
            "the operator naming the branch is the whole signal"
        );
        // The same policy on every system generic mode speaks for, each on the
        // branch its own variables name. This is a per-adapter policy, not a
        // GitHub-only one: on Jenkins, Buildkite, CircleCI and GitLab the fork
        // markers are equally absent, and a self-hosted runner in `CI` alone
        // names nothing whatsoever.
        /// A system, the variables that put it on a branch, and whether that
        /// branch has a name this adapter can match a declaration against.
        type System = (CiSystem, Vec<(&'static str, &'static str)>, bool);
        let systems: Vec<System> = vec![
            (
                CiSystem::GitHubActions,
                vec![("GITHUB_ACTIONS", "true"), ("GITHUB_REF", "refs/heads/main")],
                true,
            ),
            (CiSystem::GitLab, vec![("GITLAB_CI", "true"), ("CI_COMMIT_REF_NAME", "main")], true),
            (CiSystem::Buildkite, vec![("BUILDKITE", "true"), ("BUILDKITE_BRANCH", "main")], true),
            (CiSystem::CircleCi, vec![("CIRCLECI", "true"), ("CIRCLE_BRANCH", "main")], true),
            (
                CiSystem::Jenkins,
                vec![("JENKINS_URL", "https://jenkins.example/"), ("GIT_BRANCH", "origin/main")],
                true,
            ),
            // A bare `CI` names no ref at all, so there is no branch for the
            // declaration to match: this row stays untrusted whatever the
            // operator declares, which is rule 2 as much as rule 1 is.
            (CiSystem::Generic, vec![("CI", "true")], false),
        ];
        for (system, vars, names_a_branch) in systems {
            let run = context(&vars);
            assert_eq!(run.system(), system, "{vars:?}");
            assert_eq!(
                run.event().provenance,
                Provenance::Fork,
                "{vars:?}: generic mode reads no fork marker, so nothing is trusted"
            );
            // Declaring the branch is all it takes, on every system that names
            // one.
            let mut declared = vars.clone();
            declared.push((TRUSTED_BRANCHES, "main"));
            assert_eq!(
                context(&declared).event().provenance,
                if names_a_branch { Provenance::Repository } else { Provenance::Fork },
                "{declared:?}"
            );
        }
        // A tag declared through `--event` is still a tag, and a tag ref is
        // never trusted by this adapter — which is why the provenance is read
        // after the final ref, not before it.
        let tag = context_with(
            &[
                ("BUILDKITE", "true"),
                ("BUILDKITE_BRANCH", "main"),
                (TRUSTED_BRANCHES, "main, v1.2.3"),
            ],
            Overrides {
                trigger: Some(Trigger::Tag { name: "v1.2.3".to_string() }),
                ..Overrides::default()
            },
        );
        assert_eq!(tag.event().git.git_ref, "refs/tags/v1.2.3");
        assert_eq!(tag.event().provenance, Provenance::Fork, "a tag ref is not a branch");
    }
}
