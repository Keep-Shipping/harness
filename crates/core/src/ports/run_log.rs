//! The [`RunLog`] port: the append-only record of what a run did
//! ([#46](https://github.com/Keep-Shipping/harness/issues/46)). Every engine transition emits
//! exactly one [`RunEvent`], in order, and there is a way to append an entry and none to update or
//! delete one — a run's log is a fact, not a mutable view.
//!
//! **Secret values never reach the port.** Redaction happens upstream, in `ks_engine::journal`,
//! which scrubs each event through the run's [`Redactor`] *before* appending. **Raw plan values
//! never reach it either**: only addresses, actions and counts, output *names* without their
//! values, artifact hashes, and a decision model's answer. Hash-chaining and timestamps are the
//! adapter's, so an event carries no clock of its own.
//!
//! Unlike every other port here the run log is *not* step-visible: the engine writes it, not a step.
//! So it is not in the `Port` enum, a step cannot hold it, and `STEP_API` does not move.

use std::fmt;

use super::BoxFuture;
use crate::ids::RunId;
use crate::ports::secrets::Redactor;

/// One entry in a run's log: a transition the engine made, as plain data. `#[non_exhaustive]`: a
/// new transition may be added, so matchers outside this crate carry a wildcard arm.
/// [`kind`](RunEvent::kind) is the stable dotted name a wire format keys on.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum RunEvent {
    /// The run began: the file, the trigger, who runs it, and whether it is an agent.
    RunStarted { file_hash: String, event: String, actor: String, is_agent: bool },
    /// A step is about to run.
    StepStarted { step: String },
    /// A step finished. `outputs` carries *names* only; `error` is the redacted reason.
    StepFinished {
        step: String,
        ok: bool,
        outputs: Vec<String>,
        duration_ms: u64,
        error: Option<String>,
    },
    /// An approval was asked for and is pending. `artifacts` are hashes.
    ApprovalRequested { step: String, channel: String, artifacts: Vec<String> },
    /// An approval was granted.
    ApprovalGranted { step: String, approver: String, channel: String, artifacts: Vec<String> },
    /// An approval was denied.
    ApprovalDenied { step: String, approver: String, channel: String, artifacts: Vec<String> },
    /// A decision model answered, with its probabilities and what the run did with it.
    DecideAnswered {
        step: String,
        model: String,
        answer: String,
        confidence: f64,
        probabilities: Vec<(String, f64)>,
        threshold: f64,
        outcome: String,
    },
    /// A policy rule refused the run; `step` is `None` before any step ran.
    PolicyRefused { step: Option<String>, rule: String },
    /// The run ended, with the digests of what it shipped.
    RunFinished { status: String, shipped: Vec<String> },
}

impl RunEvent {
    /// The event's dotted name, stable across versions.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            RunEvent::RunStarted { .. } => "run.started",
            RunEvent::StepStarted { .. } => "step.started",
            RunEvent::StepFinished { .. } => "step.finished",
            RunEvent::ApprovalRequested { .. } => "approval.requested",
            RunEvent::ApprovalGranted { .. } => "approval.granted",
            RunEvent::ApprovalDenied { .. } => "approval.denied",
            RunEvent::DecideAnswered { .. } => "decide.answered",
            RunEvent::PolicyRefused { .. } => "policy.refused",
            RunEvent::RunFinished { .. } => "run.finished",
        }
    }

    /// The same event with every string it carries scrubbed through `r`. The engine calls this
    /// before appending, so a secret cannot reach an adapter however that adapter stores what it is
    /// given. Names that happen to equal a secret are scrubbed too — the price of the rule being
    /// checkable in one place rather than field by field.
    #[must_use]
    pub fn redacted(self, r: &Redactor) -> Self {
        let mut event = self;
        let list = |items: &mut Vec<String>| {
            *items = items.iter().map(|item| r.redact(item)).collect();
        };
        // Spelled per variant, never or-patterned: an or-pattern binds only the fields every arm
        // shares, which is how `approver` came to be unscrubbed the first time this was written.
        match &mut event {
            RunEvent::RunStarted { file_hash, event: trigger, actor, .. } => {
                *file_hash = r.redact(file_hash);
                *trigger = r.redact(trigger);
                *actor = r.redact(actor);
            }
            RunEvent::StepStarted { step } => *step = r.redact(step),
            RunEvent::StepFinished { step, outputs, error, .. } => {
                *step = r.redact(step);
                list(outputs);
                *error = error.as_deref().map(|message| r.redact(message));
            }
            RunEvent::ApprovalRequested { step, channel, artifacts } => {
                *step = r.redact(step);
                *channel = r.redact(channel);
                list(artifacts);
            }
            RunEvent::ApprovalGranted { step, approver, channel, artifacts }
            | RunEvent::ApprovalDenied { step, approver, channel, artifacts } => {
                *step = r.redact(step);
                *approver = r.redact(approver);
                *channel = r.redact(channel);
                list(artifacts);
            }
            RunEvent::DecideAnswered { step, model, answer, probabilities, outcome, .. } => {
                *step = r.redact(step);
                *model = r.redact(model);
                *answer = r.redact(answer);
                *outcome = r.redact(outcome);
                *probabilities =
                    probabilities.iter().map(|(label, p)| (r.redact(label), *p)).collect();
            }
            RunEvent::PolicyRefused { step, rule } => {
                *step = step.as_deref().map(|name| r.redact(name));
                *rule = r.redact(rule);
            }
            RunEvent::RunFinished { status, shipped } => {
                *status = r.redact(status);
                list(shipped);
            }
        }
        event
    }
}

/// Why an entry did not make it into the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunLogError {
    /// The adapter could not write it: a full disk, a closed file, a backend that refused. Safe to
    /// print — never the entry's contents.
    Backend { message: String },
}

impl fmt::Display for RunLogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunLogError::Backend { message } => write!(f, "run log append failed: {message}"),
        }
    }
}

impl std::error::Error for RunLogError {}

/// The `RunLog` port: an append-only stream of a run's [`RunEvent`]s. Deliberately no update, no
/// delete and no read — a port that could rewrite an entry would make the log a claim rather than a
/// record. A failed append is a real failure, not a warning: the engine fails closed on it (see
/// `ks_engine::journal`).
pub trait RunLog: Send + Sync {
    /// Appends `event` to `run`'s log.
    fn append<'a>(
        &'a self,
        run: &'a RunId,
        event: RunEvent,
    ) -> BoxFuture<'a, Result<(), RunLogError>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::secrets::SecretValue;

    /// Every variant, built with every string field set to the secret, against the kind it must report:
    /// the dotted name a wire format keys on, and that no string survives redaction — in any
    /// variant, in any field.
    #[test]
    fn every_variant_has_its_kind_and_survives_no_string() {
        const SECRET: &str = "s3cr3t";
        let mut r = Redactor::new();
        r.register(&SecretValue::new(SECRET.as_bytes().to_vec()));
        let s = || SECRET.to_string();
        let hashes = || vec![s()];
        for (kind, event) in [
            (
                "run.started",
                RunEvent::RunStarted { file_hash: s(), event: s(), actor: s(), is_agent: true },
            ),
            ("step.started", RunEvent::StepStarted { step: s() }),
            (
                "step.finished",
                RunEvent::StepFinished {
                    step: s(),
                    ok: false,
                    outputs: vec![s()],
                    duration_ms: 0,
                    error: Some(s()),
                },
            ),
            (
                "approval.requested",
                RunEvent::ApprovalRequested { step: s(), channel: s(), artifacts: hashes() },
            ),
            (
                "approval.granted",
                RunEvent::ApprovalGranted {
                    step: s(),
                    approver: s(),
                    channel: s(),
                    artifacts: hashes(),
                },
            ),
            (
                "approval.denied",
                RunEvent::ApprovalDenied {
                    step: s(),
                    approver: s(),
                    channel: s(),
                    artifacts: hashes(),
                },
            ),
            (
                "decide.answered",
                RunEvent::DecideAnswered {
                    step: s(),
                    model: s(),
                    answer: s(),
                    confidence: 0.5,
                    probabilities: vec![(s(), 0.5)],
                    threshold: 0.5,
                    outcome: s(),
                },
            ),
            ("policy.refused", RunEvent::PolicyRefused { step: Some(s()), rule: s() }),
            ("run.finished", RunEvent::RunFinished { status: s(), shipped: hashes() }),
        ] {
            assert_eq!(event.kind(), kind);
            let shown = format!("{:?}", event.redacted(&r));
            assert!(!shown.contains(SECRET), "a field of {kind} survived redaction: {shown}");
        }
    }
}
