//! Enforcing policy: before the run, at every step boundary, and at secret resolution
//! ([#103](https://github.com/Keep-Shipping/harness/issues/103),
//! [ADR 0012](https://github.com/Keep-Shipping/harness/blob/main/docs/adr/0012-policy-authority.md)).
//!
//! ADR 0012's problem is that a workflow file is a file a coding agent can write, so a `policy:`
//! block is a claim, not a control. This module is the control: it decides every step against the
//! org's [`Baseline`] **intersected with** the file's own `never:` rules, in three places, because
//! a check in only one of them is a check someone can route around.
//!
//! - [`PolicyGate::preflight`] decides the whole run before it starts: a step certain to hit a
//!   `never` refuses the run rather than the step, and the steps that will need an approval are
//!   reported so an operator hears about a prompt before it happens.
//! - [`PolicyGate::run_gated`] re-decides at each step boundary from the **prepared** inputs — a
//!   plan whose changes include destroys is a different question than the plan the preflight read
//!   — and writes the refusal or the request to the run log.
//! - [`PolicyGate::secrets_port`] gives a run a `Secrets` port that refuses what policy refuses
//!   for it — whichever actor is acting — so a step reaching for a secret the run may not read is
//!   stopped at the port.
//!
//! None of this is inside `StepKind::run`: [`run_gated`](PolicyGate::run_gated) is the only path
//! that reaches it, and it has already decided, from the action class the step's own `action()`
//! reports, before the step's code runs. A step is handed the ports it declared and nothing else.
//!
//! **Provenance** ([`PolicyGate::with_provenance`]) is the fourth question `decide` asks, and it is
//! asked before either policy is read: a run about a `ship.ks` somebody outside the organisation
//! wrote is refused `apply`, `deploy`, `destroy` and secrets even where the baseline grants them
//! and even where that same `ship.ks` writes `can: apply`. This is where the workflow-YAML-only
//! defence stops being enough ([#126](https://github.com/Keep-Shipping/harness/issues/126)).
//!
//! **The vocabulary.** An action is decided as the verb [`ActionKind::as_str`] names (`"build"`,
//! `"apply"`, `"destroy"`) against the environment the action acts on, or [`ANY_OBJECT`] when it
//! names none — so a rule can bind `deploy` in `prod` without the gate inventing an environment
//! the step did not say. [`ActionKind::ReadSecrets`] is the exception: it is the `read` of
//! `secrets`, the pair [`Baseline::conservative`] names.

use std::fmt;
use std::sync::Arc;

use ks_core::Policy;
use ks_core::harness::Harness;
use ks_core::ids::StepId;
use ks_core::ports::BoxFuture;
use ks_core::ports::policy::{ANY_OBJECT, Baseline, Disposition};
use ks_core::ports::run_context::{ActorKind, Provenance};
use ks_core::ports::secrets::{
    Redactor, ResolverInfo, SecretRef, SecretValue, Secrets, SecretsError,
};
use ks_core::step::{
    ActionClass, ActionKind, CancellationToken, Inputs, LogSink, Outputs, Ports, StepError,
    StepKind,
};

use crate::journal::Journal;
use crate::run;

/// The object a secret read is decided under, in the baseline vocabulary.
const SECRETS_OBJECT: &str = "secrets";

/// What the run log calls the channel an approval came through when the caller has not named one.
/// The gate asks; the [`Journal::approval_granted`] that records who approved is the caller's,
/// because the caller is the one holding the `ApprovalChannel`.
const APPROVAL_CHANNEL: &str = "policy";

/// What the effective policy says about one action: what it may do, and the rule that says so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub disposition: Disposition,
    /// Which policy said so, in a form an operator can read and a run log can carry.
    pub rule: String,
}

/// What one gated step did.
#[derive(Debug, Clone, PartialEq)]
pub enum GatedRun {
    /// Policy refused it: `run` was never called.
    Refused(String),
    /// It needs an approval nobody has given: `run` was never called.
    WaitingForApproval,
    /// It ran. The `Result` is the step's own, exactly as [`run::run_step`] returns it.
    Ran(Result<Outputs, StepError>),
}

/// One step as the preflight sees it: its name, the action class it will report, and whether the
/// run has to resolve secrets for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightStep {
    /// The step's name, as the refusal names it.
    pub step: String,
    pub action: ActionClass,
    /// Whether resolving a secret for this step is part of what it does — which, under a policy
    /// that refuses `read secrets`, refuses the step itself.
    pub needs_secrets: bool,
    /// Whether the action class is the file's own word about the step rather than this
    /// crate's classification of it — the `action:` under a script step
    /// ([#89](https://github.com/Keep-Shipping/harness/issues/89)). In a fork's `ship.ks` that
    /// word is the fork's: `action: build` buys the one bucket a run about somebody else's code
    /// is still allowed, and nothing behind it is evidence of what the script body does.
    pub declared: bool,
}

impl PreflightStep {
    /// A step that does not reach a secret store, classed by this crate.
    pub fn new(step: impl Into<String>, action: ActionClass) -> PreflightStep {
        PreflightStep { step: step.into(), action, needs_secrets: false, declared: false }
    }

    /// A script step, classed by the `action:` its file declares rather than by the catalog.
    pub fn declared(step: impl Into<String>, action: ActionClass) -> PreflightStep {
        PreflightStep { step: step.into(), action, needs_secrets: false, declared: true }
    }
}

/// A step that will stop and ask when the run reaches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeedsApproval {
    pub step: String,
    /// Why it is a question.
    pub rule: String,
}

/// A run that will not start, and the rule that stopped it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    /// The step whose action class hit the refusal.
    pub step: String,
    pub rule: String,
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "step {:?} is refused by policy: {}", self.step, self.rule)
    }
}

impl std::error::Error for Refused {}

/// The per-step bundle [`PolicyGate::run_gated`] needs: what the step runs against, and where what
/// happens to it is written.
pub struct GateCtx<'a> {
    pub harness: &'a Harness,
    /// Where refusals and approval requests are recorded.
    pub journal: &'a Journal,
    pub cancel: CancellationToken,
    pub log: Arc<dyn LogSink>,
    /// Scrubs every line before it reaches `log`.
    pub redactor: Arc<Redactor>,
}

/// The effective policy for one run: who is acting, where their code came from, the org's
/// baseline, and the workflow file's own `never:` rules.
///
/// A `&` to both policies rather than a copy: the baseline is read from a `PolicyStore` and the
/// file's rules from a `ship.ks`, and this gate decides nothing itself.
pub struct PolicyGate<'a> {
    actor: ActorKind,
    provenance: Provenance,
    baseline: &'a Baseline,
    file: &'a Policy,
}

impl<'a> PolicyGate<'a> {
    /// Gates `actor` under `baseline` and the file's `policy:` rules. The baseline is the authority
    /// and the file's rules can only narrow it.
    ///
    /// The run is gated as [`Provenance::Repository`] — the question is not asked here. That is the
    /// one answer that grants nothing extra, so a caller that has not classified its run gets
    /// today's behaviour and not a hole: [`Provenance::Repository`] means only "this code is ours",
    /// and the adapter is the thing that knows. Every run about somebody else's code has to say so
    /// through [`with_provenance`](PolicyGate::with_provenance), which is a builder rather than a
    /// fourth argument so that the call sites already gating production runs keep compiling while
    /// the classifications land.
    pub fn new(actor: ActorKind, baseline: &'a Baseline, file: &'a Policy) -> PolicyGate<'a> {
        PolicyGate { actor, provenance: Provenance::default(), baseline, file }
    }

    /// Gates runs about code the organisation did not write.
    ///
    /// A fork pull request's `ship.ks` — and the TypeScript script and Dockerfile it names — are
    /// the run's inputs, so a run about one may check, build and plan and may do nothing that
    /// reaches past its own checkout: no `apply`, no `deploy`, no `destroy`, no secrets. The refusal
    /// is [`Disposition::Never`] rather than [`Disposition::Ask`] because the human an `Ask` would
    /// wait for is the thing that is missing: nobody in this run can be shown a diff and asked
    /// whether it may apply, and an `Ask` a fork PR parks forever is an approval nobody ever reads.
    #[must_use]
    pub fn with_provenance(mut self, provenance: Provenance) -> Self {
        self.provenance = provenance;
        self
    }

    /// What the effective policy says about one action.
    ///
    /// Provenance is read **first**, before the file's `never:` rules and before the baseline: when
    /// the code under the run is not the organisation's, the file's rules are themselves attacker
    /// input, so a `can: apply` in a fork's `ship.ks` must not widen anything, and a baseline that
    /// lets CI apply must not make a fork's apply legal.
    ///
    /// The file's `never:` rules are then read **first and unconditionally** among the two
    /// policies: a rule a `ship.ks` declares is a refusal whatever the baseline said, including when
    /// the baseline said [`Disposition::Allow`]. A workflow file may narrow the org's policy and
    /// never widen it, and an agent that can add a `can:` line to its own file must not thereby
    /// escape the baseline that refused it.
    ///
    /// The two answers are then combined by hand rather than compared. Neither [`Ord`] nor `.max()`
    /// is the tool: the derive orders least- to most-restrictive for readability, and
    /// `max(Ask, Allow) == Allow` is a fail-open a reader cannot see in the call.
    #[must_use]
    pub fn decide(&self, action: &ActionClass) -> Decision {
        let (verb, object) = self.target(action);
        if let Some(refused) = self.refuse_untrusted(action, &verb, &object) {
            return refused;
        }
        if self.file.forbids(self.actor, &verb, &object) {
            let rule = format!(
                "ship.ks: {subject} may never {verb} on {object}",
                subject = subject(self.actor)
            );
            return Decision { disposition: Disposition::Never, rule };
        }
        let disposition = self.baseline.decide(self.actor, &verb, &object);
        let (saying, policy) = match disposition {
            Disposition::Allow => ("may", ""),
            Disposition::Ask => ("must be approved to", ""),
            Disposition::Never => ("may never", "baseline: "),
        };
        let rule =
            format!("{policy}{subject} {saying} {verb} on {object}", subject = subject(self.actor));
        Decision { disposition, rule }
    }

    fn decide_secrets(&self) -> Decision {
        self.decide(&ActionClass::new(ActionKind::ReadSecrets))
    }

    /// Decides the whole run before anything starts, refusing the run — not one step of it — when a
    /// step's own action class is [`Disposition::Never`], or when the step needs secrets and
    /// reading them is [`Disposition::Never`] for this actor. An agent-reachable step under
    /// `never: read secrets` is a step that cannot run, and finding that out at the boundary is one
    /// refusal and one confusing prompt later. Anything [`Disposition::Ask`] is reported as a
    /// [`NeedsApproval`] rather than refused, because a question has an answer.
    pub fn preflight(&self, steps: &[PreflightStep]) -> Result<Vec<NeedsApproval>, Refused> {
        let secrets = self.decide_secrets();
        let mut asks = Vec::new();
        for step in steps {
            // A script step has no catalog name, so the only thing the file says about what its
            // body does is the `action:` it typed — and in a fork's file that is the fork's own
            // word about itself. `action_allows_untrusted` leaves `build`, `plan` and `other`
            // standing for a run about somebody else's code, which is right for a catalog step
            // (this crate classified it) and not for one the fork wrote: `action: build` is the
            // way to ask for the allowed bucket in words, and there is nothing behind the word
            // to check. An action `decide` already refuses is left to `decide`, which names the
            // action rather than the trick. This is read here rather than in
            // [`decide`](PolicyGate::decide) because it is a fact about the file, not about the
            // action class, and `decide` is handed a class alone.
            if step.declared
                && self.provenance.is_untrusted()
                && action_allows_untrusted(step.action.kind)
            {
                let rule = format!(
                    "provenance: {subject} may not act on a script step's own `action:`",
                    subject = untrusted(self.provenance)
                );
                return Err(Refused { step: step.step.clone(), rule });
            }
            let decision = self.decide(&step.action);
            if decision.disposition == Disposition::Never {
                return Err(Refused { step: step.step.clone(), rule: decision.rule });
            }
            // A step that needs secrets is decided by the rule about secrets — refused by it, and
            // named as the step that needs them rather than as whichever step came first.
            let rule = match (step.needs_secrets, secrets.disposition) {
                (true, Disposition::Never) => {
                    return Err(Refused { step: step.step.clone(), rule: secrets.rule.clone() });
                }
                (true, Disposition::Ask) => secrets.rule.clone(),
                _ if decision.disposition == Disposition::Ask => decision.rule,
                _ => continue,
            };
            asks.push(NeedsApproval { step: step.step.clone(), rule });
        }
        Ok(asks)
    }

    /// Gates one step and, only where the gate allows it, runs it.
    ///
    /// The action class is computed from the **prepared** inputs — the ones this run resolved, with
    /// the outputs of the steps before it — which is the whole reason the check is here and not
    /// only in the preflight. `run` is not called for a refused or unapproved step.
    ///
    /// The `Err` is what [`run::run_step`] itself returns before a step starts: the run was
    /// cancelled, the step is unknown, or its inputs do not match the schema. Policy outcomes are
    /// [`GatedRun`] values, because they are not failures of the run's plumbing.
    pub async fn run_gated(
        &self,
        ctx: &GateCtx<'_>,
        name: &str,
        inputs: Inputs,
        approved: bool,
    ) -> Result<GatedRun, StepError> {
        let step = ctx
            .harness
            .step(name)
            .cloned()
            .ok_or_else(|| StepError::UnknownStep(name.to_string()))?;
        if ctx.cancel.is_cancelled() {
            return Err(StepError::Cancelled);
        }
        let inputs = ctx.harness.prepare_inputs(step.as_ref(), inputs)?;

        // An `Ask` that has been approved proceeds; an approval is the caller's to hold. The
        // refusal and the request are recorded, and neither hands the step anything.
        let decision = self.decide(&step.action(&inputs));
        let outcome = match (decision.disposition, approved) {
            (Disposition::Allow, _) | (Disposition::Ask, true) => None,
            (Disposition::Ask, false) => {
                ctx.journal
                    .approval_requested(name, APPROVAL_CHANNEL, Vec::new())
                    .await
                    .map_err(log_failure)?;
                Some(GatedRun::WaitingForApproval)
            }
            (Disposition::Never, _) => {
                ctx.journal
                    .policy_refused(Some(name), &decision.rule)
                    .await
                    .map_err(log_failure)?;
                Some(GatedRun::Refused(decision.rule))
            }
        };
        if let Some(outcome) = outcome {
            return Ok(outcome);
        }

        let outputs = run::execute_with_ports(
            ctx.harness,
            name,
            step.as_ref(),
            inputs,
            ctx.cancel.clone(),
            Arc::clone(&ctx.log),
            Arc::clone(&ctx.redactor),
            self.ports_for(ctx.harness, step.as_ref()),
            ctx.journal.run_facts(),
        )
        .await;
        Ok(GatedRun::Ran(outputs))
    }

    /// The ports one step is handed: what it declared, with the `Secrets` port under this policy.
    /// Building them here is what lets the gate wrap the resolver without the step ever seeing the
    /// unwrapped one.
    fn ports_for(&self, harness: &Harness, step: &dyn StepKind) -> Ports {
        let ports = run::declared_ports(harness, step);
        let gated = ports.secrets().map(|inner| self.secrets_port(Arc::clone(inner)));
        match gated {
            Some(secrets) => ports.with_secrets(secrets),
            None => ports,
        }
    }

    /// The `Secrets` port to hand a step under this policy.
    ///
    /// Whenever this gate's read-secrets decision for the run's actor is
    /// [`Disposition::Never`], the step is handed the run's resolver wrapped in `PolicySecrets`,
    /// so the refusal holds at the port however the step asks for the value. The actor kind does not
    /// come into it: this is the same question [`preflight`](PolicyGate::preflight) asks, and a
    /// gate whose port and whose boundary disagree about who is refused is a gate that is refused
    /// for whoever the looser one lets through.
    ///
    /// The same holds for the run's provenance, because `decide_secrets` is
    /// [`decide`](PolicyGate::decide) and the fork refusal is in there: a run about a fork's code
    /// is wrapped in `PolicySecrets` even under a baseline that allows the read, and the step gets
    /// the error rather than the value.
    ///
    /// Where policy does *not* refuse secrets the resolver passes through: a port cannot ask, and an
    /// empty answer to "which may this actor read" would be a refusal the policy never wrote. Where
    /// it only asks, the question is put at the step boundary instead, because a port cannot ask
    /// and does not pretend to.
    #[must_use]
    pub fn secrets_port(&self, inner: Arc<dyn Secrets>) -> Arc<dyn Secrets> {
        if self.decide_secrets().disposition != Disposition::Never {
            return inner;
        }
        Arc::new(PolicySecrets { inner, actor: self.actor })
    }

    /// The refusal a run about code somebody else wrote gets for any action that reaches past its
    /// own checkout, or `None` when the run is the organisation's own or the action is one that
    /// stays inside it.
    ///
    /// This sits in [`decide`](PolicyGate::decide) rather than in the preflight or the boundary or
    /// the port because `decide` is the one place all four already ask the same question — putting
    /// it here is what makes a fork's apply refused at the preflight, refused again at the boundary
    /// if a caller skipped the preflight, refused in the rule string a run log carries, and refused
    /// at the `Secrets` port, with no second rule to keep in step with the first.
    fn refuse_untrusted(&self, action: &ActionClass, verb: &str, object: &str) -> Option<Decision> {
        if !self.provenance.is_untrusted() || action_allows_untrusted(action.kind) {
            return None;
        }
        let rule = format!(
            "provenance: {subject} may never {verb} on {object}",
            subject = untrusted(self.provenance)
        );
        Some(Decision { disposition: Disposition::Never, rule })
    }

    /// The verb and object `action` is decided under, in the baseline's vocabulary:
    /// [`ActionKind::ReadSecrets`] is the `read` of `secrets`, because that is the pair the
    /// conservative default refuses; the rest keep [`ActionKind::as_str`] as the verb.
    fn target(&self, action: &ActionClass) -> (String, String) {
        match action.kind {
            ActionKind::ReadSecrets => ("read".to_string(), SECRETS_OBJECT.to_string()),
            other => (
                other.as_str().to_string(),
                action.env.clone().unwrap_or_else(|| ANY_OBJECT.to_string()),
            ),
        }
    }
}

/// The run's resolver, with the policy's refusal in front of it.
///
/// [`ActorGatedSecrets`](ks_core::ports::secrets::ActorGatedSecrets) is the same gate over an
/// allowlist, and takes the resolver **by value**: it cannot wrap the `Arc<dyn Secrets>` a
/// composition hands out, and an allowlist is the wrong shape for a refusal covering every
/// reference.
struct PolicySecrets {
    inner: Arc<dyn Secrets>,
    actor: ActorKind,
}

impl Secrets for PolicySecrets {
    fn resolve<'a>(
        &'a self,
        reference: &'a SecretRef,
        _for_step: &'a StepId,
    ) -> BoxFuture<'a, Result<SecretValue, SecretsError>> {
        Box::pin(std::future::ready(Err(SecretsError::ForbiddenForActor {
            reference: reference.clone(),
            actor: subject(self.actor).to_string(),
        })))
    }

    fn describe(&self) -> ResolverInfo {
        self.inner.describe()
    }
}

/// A journal that will not take the record fails the step: the run log is the evidence a refusal
/// happened, so losing it is not a warning.
fn log_failure(error: ks_core::ports::run_log::RunLogError) -> StepError {
    StepError::Failed(format!("the run log refused a policy record: {error}"))
}

/// How a rule's subject reads in a message a human reads.
fn subject(actor: ActorKind) -> &'static str {
    match actor {
        ActorKind::Human => "humans",
        ActorKind::Agent => "agents",
        ActorKind::Ci => "CI",
    }
}

/// How a run's provenance reads in a message a human reads — and the string has to say which of
/// the two untrusted cases it is, because `pull_request_target` and a fork pull request are
/// different events and an operator reading a run log cannot tell them apart from "CI".
fn untrusted(provenance: Provenance) -> &'static str {
    match provenance {
        Provenance::Repository => "the repository's own code",
        Provenance::Fork => "a fork pull request",
        Provenance::Target => "a pull_request_target run",
    }
}

/// What a run about code the organisation did not write may still do.
///
/// Build, plan and `Other` stay: they read the checkout the run already has, produce an artefact
/// the run already had the right to produce, and change nothing outside. Everything that reaches —
/// `apply`, `deploy`, `destroy` and reading a secret — is refused.
fn action_allows_untrusted(kind: ActionKind) -> bool {
    matches!(kind, ActionKind::Build | ActionKind::Plan | ActionKind::Other)
}
