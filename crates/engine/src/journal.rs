//! Writing a run's transitions to the [`RunLog`] port
//! ([#46](https://github.com/Keep-Shipping/harness/issues/46)).
//!
//! This is the engine's only writer of the run log, and it does one thing: every transition emits
//! exactly one [`RunEvent`], redacted before the append — so the adapter is handed an event that is
//! already scrubbed, and cannot leak a secret however it stores it. Every method fails closed: a
//! log that will not take an entry fails the transition rather than dropping it, because a run
//! whose log has a hole in it is not a run you can prove anything about.
//!
//! [`step`](Journal::step) is the additive wrapper over [`run_step`], whose signature is untouched
//! so callers that do not journal keep using it.

use std::sync::Arc;
use std::time::Duration;

use ks_core::harness::Harness;
use ks_core::ids::RunId;
use ks_core::ports::run_log::{RunEvent, RunLog, RunLogError};
use ks_core::ports::secrets::Redactor;
use ks_core::step::{CancellationToken, Inputs, LogSink, Outputs, StepError};

use crate::credentials::StepCredentials;
use crate::run::run_step;

/// Writes one run's transitions to a [`RunLog`]. Holds the run's id, the log, and the redactor
/// every event is scrubbed with — the same one the run's secrets were registered with, so no value
/// is ever registered twice.
#[derive(Clone)]
pub struct Journal {
    log: Arc<dyn RunLog>,
    redactor: Arc<Redactor>,
    run: RunId,
}

impl Journal {
    /// Journals `run` into `log`, scrubbing every event through `redactor`.
    pub fn new(log: Arc<dyn RunLog>, redactor: Arc<Redactor>, run: RunId) -> Journal {
        Journal { log, redactor, run }
    }

    /// The run being journaled.
    pub fn run_id(&self) -> &RunId {
        &self.run
    }

    /// Scrubs `event` and appends it: the single funnel every transition below goes through, so
    /// redaction cannot be forgotten on one path.
    async fn emit(&self, event: RunEvent) -> Result<(), RunLogError> {
        self.log.append(&self.run, event.redacted(&self.redactor)).await
    }

    pub async fn run_started(
        &self,
        file_hash: &str,
        event: &str,
        actor: &str,
        is_agent: bool,
    ) -> Result<(), RunLogError> {
        let e = RunEvent::RunStarted {
            file_hash: file_hash.into(),
            event: event.into(),
            actor: actor.into(),
            is_agent,
        };
        self.emit(e).await
    }

    pub async fn approval_requested(
        &self,
        step: &str,
        channel: &str,
        artifacts: Vec<String>,
    ) -> Result<(), RunLogError> {
        let e =
            RunEvent::ApprovalRequested { step: step.into(), channel: channel.into(), artifacts };
        self.emit(e).await
    }

    pub async fn approval_granted(
        &self,
        step: &str,
        approver: &str,
        channel: &str,
        artifacts: Vec<String>,
    ) -> Result<(), RunLogError> {
        let e = RunEvent::ApprovalGranted {
            step: step.into(),
            approver: approver.into(),
            channel: channel.into(),
            artifacts,
        };
        self.emit(e).await
    }

    pub async fn approval_denied(
        &self,
        step: &str,
        approver: &str,
        channel: &str,
        artifacts: Vec<String>,
    ) -> Result<(), RunLogError> {
        let e = RunEvent::ApprovalDenied {
            step: step.into(),
            approver: approver.into(),
            channel: channel.into(),
            artifacts,
        };
        self.emit(e).await
    }

    /// Records a decision model's answer: the model, its answer and confidence, the probabilities
    /// it reported, the threshold, and what the run did with it.
    #[allow(clippy::too_many_arguments)] // the event's fields, one for one
    pub async fn decide_answered(
        &self,
        step: &str,
        model: &str,
        answer: &str,
        confidence: f64,
        probabilities: Vec<(String, f64)>,
        threshold: f64,
        outcome: &str,
    ) -> Result<(), RunLogError> {
        let e = RunEvent::DecideAnswered {
            step: step.into(),
            model: model.into(),
            answer: answer.into(),
            confidence,
            probabilities,
            threshold,
            outcome: outcome.into(),
        };
        self.emit(e).await
    }

    /// Records which credentials a step ran with: the cloud, the role it
    /// federated into (`None` when it assumed nothing) and how it got them.
    /// The token is not an argument and cannot become one.
    pub async fn credentials_resolved(
        &self,
        step: &str,
        credentials: &StepCredentials,
    ) -> Result<(), RunLogError> {
        self.emit(RunEvent::CredentialsResolved {
            step: step.into(),
            cloud: credentials.cloud().into(),
            role: credentials.role().map(str::to_string),
            via: credentials.via().into(),
        })
        .await
    }

    /// Records that an attestation was pushed against an image: the digest of
    /// the image it describes, the predicate the attestation carries, and the
    /// digest of the pushed envelope.
    pub async fn attestation_attached(
        &self,
        step: &str,
        subject: &str,
        predicate_type: &str,
        attestation: &str,
    ) -> Result<(), RunLogError> {
        let e = RunEvent::AttestationAttached {
            step: step.into(),
            subject: subject.into(),
            predicate_type: predicate_type.into(),
            attestation: attestation.into(),
        };
        self.emit(e).await
    }

    /// Records that a policy rule refused the run; `step` is `None` before any step ran.
    pub async fn policy_refused(&self, step: Option<&str>, rule: &str) -> Result<(), RunLogError> {
        let e = RunEvent::PolicyRefused { step: step.map(str::to_string), rule: rule.into() };
        self.emit(e).await
    }

    /// Records that an approved plan could not be applied as approved and the run stopped to ask
    /// again: `cause` (`"state"` or `"drift"`), the digest of the plan the approval was for, and
    /// the digest of the fresh plan now in front of approvers with whether the two change sets
    /// differ. `replanned` and `differs` are `None` when the run stopped before it had a fresh
    /// plan to compare — the re-plan itself failed — so a stop is always recorded.
    pub async fn plan_stale(
        &self,
        step: &str,
        cause: &str,
        approved: &str,
        replanned: Option<&str>,
        differs: Option<bool>,
    ) -> Result<(), RunLogError> {
        let e = RunEvent::PlanStale {
            step: step.into(),
            cause: cause.into(),
            approved: approved.into(),
            replanned: replanned.map(str::to_string),
            differs,
        };
        self.emit(e).await
    }

    pub async fn run_finished(
        &self,
        status: &str,
        shipped: Vec<String>,
    ) -> Result<(), RunLogError> {
        self.emit(RunEvent::RunFinished { status: status.into(), shipped }).await
    }

    /// Runs `name` through [`run_step`], bracketing it in `step.started` and `step.finished` — in
    /// that order, whatever the step does. The finished event carries the *names* of the outputs,
    /// sorted (`Outputs` is a `BTreeMap`, so its keys already are), the duration from the
    /// harness's [`Clock`](ks_core::ports::clock::Clock), and the error's message when it failed.
    /// Output *values* never go near the log. Fails closed: a log that refuses an entry fails the
    /// step, before it runs or after it ran, as [`StepError::Failed`], whose message names the log.
    pub async fn step(
        &self,
        harness: &Harness,
        name: &str,
        inputs: Inputs,
        cancel: CancellationToken,
        log: Arc<dyn LogSink>,
    ) -> Result<Outputs, StepError> {
        self.emit(RunEvent::StepStarted { step: name.into() }).await.map_err(log_failure)?;
        let started = harness.clock().now();
        let outcome =
            run_step(harness, name, inputs, cancel, log, Arc::clone(&self.redactor)).await;
        // The Clock port guarantees time never moves backwards within a run, so this subtraction
        // cannot fail; a zero duration is the honest floor anyway.
        let elapsed = harness.clock().now().duration_since(started).unwrap_or(Duration::ZERO);
        let duration_ms = || u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        let event = match &outcome {
            Ok(outputs) => RunEvent::StepFinished {
                step: name.into(),
                ok: true,
                outputs: outputs.keys().cloned().collect(),
                duration_ms: duration_ms(),
                error: None,
            },
            Err(error) => RunEvent::StepFinished {
                step: name.into(),
                ok: false,
                outputs: Vec::new(),
                duration_ms: duration_ms(),
                error: Some(error.to_string()),
            },
        };
        self.emit(event).await.map_err(log_failure)?;
        outcome
    }
}

/// The log's own error as a step failure — the message says so, because the step did not fail.
fn log_failure(error: RunLogError) -> StepError {
    StepError::Failed(error.to_string())
}
