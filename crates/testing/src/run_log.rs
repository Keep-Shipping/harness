//! Fake for the [`RunLog`] port ([#46](https://github.com/Keep-Shipping/harness/issues/46)): it
//! keeps every entry, in order, so "this transition emitted exactly one event" is an
//! assertion rather than a hope — the same job [`RecordingSink`] does for a step's log lines.
//! Plus the conformance kit every adapter must pass.
//!
//! [`RecordingSink`]: crate::step::RecordingSink

use std::fmt;
use std::sync::Mutex;

use ks_core::ids::RunId;
use ks_core::ports::BoxFuture;
use ks_core::ports::run_log::{RunEvent, RunLog, RunLogError};
use ks_core::ports::secrets::{Redactor, SecretValue};

/// A [`RunLog`] that keeps every `(run, event)` it is handed, in order.
///
/// `Send + Sync`, so an `Arc<RecordingRunLog>` is the `Arc<dyn RunLog>` the engine journals
/// through. `Debug` prints the entry count, never an entry: a run's log must not become a way
/// to print one.
///
/// ```
/// use std::sync::Arc;
/// use ks_core::ids::RunId;
/// use ks_core::ports::run_log::{RunEvent, RunLog};
/// use ks_testing::{block_on, run_log::RecordingRunLog};
///
/// let log = Arc::new(RecordingRunLog::new());
/// let run = RunId::from_parts(0, 0);
/// block_on(log.append(&run, RunEvent::StepStarted { step: "build".to_string() })).unwrap();
///
/// assert_eq!(log.events().len(), 1);
/// assert_eq!(format!("{log:?}"), "RecordingRunLog { entries: 1 }");
/// ```
#[derive(Default)]
pub struct RecordingRunLog {
    entries: Mutex<Vec<(RunId, RunEvent)>>,
}

impl RecordingRunLog {
    /// Creates an empty log.
    pub fn new() -> RecordingRunLog {
        RecordingRunLog::default()
    }

    /// Every event so far, in order, across all runs.
    #[must_use]
    pub fn events(&self) -> Vec<RunEvent> {
        self.entries
            .lock()
            .expect("recording run log poisoned")
            .iter()
            .map(|(_, e)| e.clone())
            .collect()
    }

    /// Every `(run, event)` pair so far, in order.
    #[must_use]
    pub fn entries(&self) -> Vec<(RunId, RunEvent)> {
        self.entries.lock().expect("recording run log poisoned").clone()
    }
}

impl RunLog for RecordingRunLog {
    fn append<'a>(
        &'a self,
        run: &'a RunId,
        event: RunEvent,
    ) -> BoxFuture<'a, Result<(), RunLogError>> {
        Box::pin(async move {
            self.entries.lock().expect("recording run log poisoned").push((run.clone(), event));
            Ok(())
        })
    }
}

impl fmt::Debug for RecordingRunLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.entries.lock().expect("recording run log poisoned").len();
        f.debug_struct("RecordingRunLog").field("entries", &count).finish()
    }
}

/// A [`RunLog`] that refuses every entry: what a full disk, a closed file or a refused backend
/// looks like from the engine. Asserted on in `tests/run_log.rs` rather than by the kit, which
/// has only the adapter it is handed to judge.
pub struct RefusingRunLog {
    /// What the adapter says went wrong. It is the only thing it ever says.
    pub message: String,
}

impl RunLog for RefusingRunLog {
    fn append<'a>(
        &'a self,
        _run: &'a RunId,
        _event: RunEvent,
    ) -> BoxFuture<'a, Result<(), RunLogError>> {
        let message = self.message.clone();
        Box::pin(async move { Err(RunLogError::Backend { message }) })
    }
}

/// One of each [`RunEvent`] variant, in the order a run meets them.
///
/// `#[non_exhaustive]` guarantees only that a match outside `ks-core` may carry a wildcard arm — it
/// does not make anyone extend this list, and nothing fails to compile when a variant is added
/// elsewhere. So extending it is owned, by hand, by whoever adds a variant to [`RunEvent`], along
/// with the wire form that stores it: an adapter's mapping refuses an event it has no form for,
/// which is the right way to fail but shows up at runtime, not at build time.
fn every_variant() -> Vec<RunEvent> {
    let hashes = || vec!["sha256:aa".to_string()];
    vec![
        RunEvent::RunStarted {
            file_hash: "sha256:f".to_string(),
            event: "push".to_string(),
            actor: "ada".to_string(),
            is_agent: false,
        },
        RunEvent::StepStarted { step: "build".to_string() },
        RunEvent::StepFinished {
            step: "build".to_string(),
            ok: true,
            outputs: vec!["digest".to_string()],
            duration_ms: 250,
            error: None,
        },
        RunEvent::ApprovalRequested {
            step: "apply-infra".to_string(),
            channel: "tty".to_string(),
            artifacts: hashes(),
        },
        RunEvent::ApprovalGranted {
            step: "apply-infra".to_string(),
            approver: "ada".to_string(),
            channel: "tty".to_string(),
            artifacts: hashes(),
        },
        RunEvent::ApprovalDenied {
            step: "apply-infra".to_string(),
            approver: "ada".to_string(),
            channel: "tty".to_string(),
            artifacts: hashes(),
        },
        RunEvent::DecideAnswered {
            step: "apply-infra".to_string(),
            model: "model".to_string(),
            answer: "yes".to_string(),
            confidence: 0.9,
            probabilities: vec![("yes".to_string(), 0.9)],
            threshold: 0.5,
            outcome: "proceed".to_string(),
        },
        RunEvent::PolicyRefused {
            step: Some("apply-infra".to_string()),
            rule: "no-prod".to_string(),
        },
        RunEvent::RunFinished { status: "ok".to_string(), shipped: hashes() },
    ]
}

/// The `RunLog` conformance kit: the fake here and the local
/// `.keepshipping/runs/<id>.jsonl` one must both pass it — the second by
/// `the_jsonl_adapter_passes_the_conformance_kit` in `crates/cli/src/run_log.rs`, which builds the
/// real adapter and runs this against it.
///
/// The port is one method wide, so this is deliberately a short kit. It walks what an append
/// surface can be held to: **every variant appends** and none is refused for being the shape it
/// is; **a redacted event appends**, so an adapter never has to understand
/// [`RunEvent::redacted`] to store one; **appends are additive** — the same entry appended again
/// and again is accepted every time, because a log that refuses a repeat is deduplicating, and a
/// log that quietly overwrites is not append-only; and **two runs are independent**, so one run's
/// log cannot be the reason another's entry is lost.
///
/// Three properties a reader might look for are **not** here, and pretending otherwise would be
/// the worse error. *What a failing adapter does* — whether it reports every refused append or
/// only the first, and whether it passes the backend's own words along — belongs to that adapter
/// and is covered by that adapter's own tests, because the engine may only fail a run on a
/// refused append if the adapter reports it; the kit cannot see it, holding only the adapter it
/// was handed, and a refusing fake of its own would just assert the kit against itself. (The
/// engine's half — that it fails closed — is asserted in `crates/engine/tests/journal.rs`.)
/// *What the adapter stored* is not checkable through a port with no read: that the event arrives
/// scrubbed is asserted against the recording fake in `ks-testing`'s `tests/run_log.rs`, where the
/// stored value is in reach. *Ordering and the hash chain* belong to the adapter — the chain is
/// the CLI adapter's, verified by `crates/cli/src/run_log.rs`'s `verify` — and the engine's half of
/// ordering is asserted consumer-side in `crates/engine/tests/journal.rs`.
pub async fn conformance(log: &dyn RunLog) {
    let run = RunId::from_parts(1_700_000_000_000, 1);
    let other = RunId::from_parts(1_700_000_000_000, 2);
    let append = async |run: &RunId, event: RunEvent| match log.append(run, event.clone()).await {
        Ok(()) => {}
        Err(error) => {
            panic!("run_log conformance: {} must append: {error}", event.kind())
        }
    };

    // ---- every variant, and every variant twice: shape is not a reason to refuse ----
    for event in every_variant() {
        append(&run, event.clone()).await;
        append(&run, event).await;
    }

    // ---- a redacted event is an ordinary entry ----
    const SECRET: &str = "s3cr3t-token";
    let mut redactor = Redactor::new();
    redactor.register(&SecretValue::new(SECRET.as_bytes().to_vec()));
    let redacted = RunEvent::StepFinished {
        step: "apply-infra".to_string(),
        ok: false,
        outputs: vec![SECRET.to_string()],
        duration_ms: 0,
        error: Some(SECRET.to_string()),
    }
    .redacted(&redactor);
    assert_eq!(
        redacted.kind(),
        "step.finished",
        "redaction changes an event's contents, never its kind: a wire format keys on the kind"
    );
    let shown = format!("{redacted:?}");
    assert!(
        shown.contains("***") && !shown.contains(SECRET),
        "the event is scrubbed before it is appended, so the kit hands the adapter that, not the \
         raw step output: {shown}"
    );
    append(&run, redacted).await;

    // ---- appends are additive: a repeat is another entry, not a replacement ----
    let repeated = RunEvent::StepStarted { step: "build".to_string() };
    for round in 0..4 {
        assert!(
            log.append(&run, repeated.clone()).await.is_ok(),
            "run_log conformance: the same entry appended {round} times must land every time — \
             an adapter that refuses or dedups a repeat is not append-only"
        );
    }

    // ---- one run's log is never the reason another's entry is lost ----
    append(
        &other,
        RunEvent::RunStarted {
            file_hash: "sha256:f".to_string(),
            event: "local".to_string(),
            actor: "ada".to_string(),
            is_agent: false,
        },
    )
    .await;
    append(&other, RunEvent::RunFinished { status: "ok".to_string(), shipped: Vec::new() }).await;
    append(&run, RunEvent::RunFinished { status: "ok".to_string(), shipped: Vec::new() }).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_on;

    /// Pins the list against its names, so adding a variant here is a deliberate edit to a
    /// nine-line expectation rather than an accident.
    ///
    /// What it cannot do is notice a variant added to `RunEvent` and not added here: nothing
    /// outside `ks-core` can enumerate the enum, so a tenth variant is caught by whoever adds it —
    /// `every_variant_is_built_and_is_named` naming it, and
    /// `the_jsonl_adapter_passes_the_conformance_kit` in `crates/cli/src/run_log.rs` then holding
    /// the adapter to a wire form for it.
    #[test]
    fn every_variant_is_built_and_is_named() {
        let kinds: Vec<&str> = every_variant().iter().map(RunEvent::kind).collect();
        assert_eq!(
            kinds,
            [
                "run.started",
                "step.started",
                "step.finished",
                "approval.requested",
                "approval.granted",
                "approval.denied",
                "decide.answered",
                "policy.refused",
                "run.finished",
            ]
        );
    }

    #[test]
    fn the_fake_passes_conformance() {
        block_on(conformance(&RecordingRunLog::new()));
    }

    /// The kit runs against `&dyn`, not against the concrete fake: the engine holds ports that
    /// way, so an adapter written to the suite has to be able to pass it that way too.
    #[test]
    fn the_fake_passes_conformance_through_the_dyn_trait() {
        let log = RecordingRunLog::new();
        let dynamic: &dyn RunLog = &log;
        block_on(conformance(dynamic));
    }
}
