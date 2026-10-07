//! Behaviour of the `RunLog` fake: what it records, in what order, per run, and
//! what it prints — plus the conformance kit, run against the fake through the
//! `dyn` trait.
//!
//! What a fake cannot be asked is covered elsewhere on purpose. The engine's half
//! of the ordering contract — one event per transition, a step bracketed by
//! `step.started` and `step.finished` — is asserted consumer-side in
//! `crates/engine/tests/journal.rs`, and the hash chain is the CLI adapter's,
//! verified by `verify` in `crates/cli/src/run_log.rs`.

use ks_core::ids::RunId;
use ks_core::ports::run_log::{RunEvent, RunLog, RunLogError};
use ks_core::ports::secrets::{Redactor, SecretValue};
use ks_testing::block_on;
use ks_testing::run_log::{RecordingRunLog, RefusingRunLog, conformance as run_log_conformance};

fn run(seed: u128) -> RunId {
    RunId::from_parts(1_700_000_000_000, seed)
}

fn started(step: &str) -> RunEvent {
    RunEvent::StepStarted { step: step.to_string() }
}

fn finished(step: &str) -> RunEvent {
    RunEvent::StepFinished {
        step: step.to_string(),
        ok: true,
        outputs: vec!["digest".to_string()],
        duration_ms: 250,
        error: None,
    }
}

/// Dyn-compatibility: the engine holds ports as `&dyn`.
fn _port_is_dyn_compatible(_log: &dyn RunLog) {}

#[test]
fn the_run_log_port_is_send_sync_and_dyn_compatible() {
    fn assert_send_sync<T: ?Sized + Send + Sync>() {}
    assert_send_sync::<dyn RunLog>();
    let _ = _port_is_dyn_compatible as fn(&dyn RunLog);
}

#[test]
fn the_fake_passes_its_conformance_kit_through_the_dyn_trait() {
    let log = RecordingRunLog::new();
    let dynamic: &dyn RunLog = &log;
    block_on(run_log_conformance(dynamic));
}

/// Failure propagation is the adapter's own property, not the kit's — the kit is handed one
/// adapter and can only judge that. Here the refusing fake is judged directly: the engine fails
/// a run on a refused append and may only do that if the refusal is reported every time, in the
/// backend's own words, and never as a silent success.
#[test]
fn a_failing_adapter_reports_every_append_as_its_own_backend_error() {
    const REFUSAL: &str = "no space left on device";
    let refusing = RefusingRunLog { message: REFUSAL.to_string() };
    let run = run(6);

    for attempt in 1..=3 {
        match block_on(refusing.append(&run, started("build"))) {
            Err(RunLogError::Backend { message }) => assert_eq!(
                message, REFUSAL,
                "the adapter's own words reach the caller on attempt {attempt}, not a substitute"
            ),
            other => panic!(
                "attempt {attempt}: a refused append must be an error, or the run would carry on \
                 as if it were journalled: got {other:?}"
            ),
        }
    }
}

#[test]
fn a_fresh_fake_records_nothing() {
    let log = RecordingRunLog::new();
    assert_eq!(log.events(), Vec::<RunEvent>::new());
    assert_eq!(log.entries(), Vec::new());
    assert_eq!(format!("{log:?}"), "RecordingRunLog { entries: 0 }");
}

/// The fake's own promise: it keeps what it was handed, in the order it was handed it, so a
/// test can assert on position rather than on membership. (The engine's ordering contract —
/// which event follows which — is `crates/engine/tests/journal.rs`'s, not this file's.)
#[test]
fn the_fake_keeps_what_it_was_handed_in_order() {
    let log = RecordingRunLog::new();
    let run = run(1);
    block_on(log.append(&run, started("build"))).expect("append");
    block_on(log.append(&run, finished("build"))).expect("append");
    block_on(log.append(&run, started("ship"))).expect("append");

    let kinds: Vec<&str> = log.events().iter().map(RunEvent::kind).collect();
    assert_eq!(kinds, ["step.started", "step.finished", "step.started"]);
    assert_eq!(
        log.entries().iter().map(|(run, _)| run.clone()).collect::<Vec<_>>(),
        vec![run.clone(), run.clone(), run],
        "every entry remembers which run it belongs to"
    );
    assert_eq!(format!("{log:?}"), "RecordingRunLog { entries: 3 }");
}

/// Two runs into one fake: neither can see the other's entries, and neither write is
/// the other's undoing.
#[test]
fn each_run_keeps_its_own_entries() {
    let log = RecordingRunLog::new();
    let first = run(2);
    let second = run(3);
    block_on(log.append(&first, started("build"))).expect("append");
    block_on(log.append(&first, finished("build"))).expect("append");
    block_on(log.append(&second, started("ship"))).expect("append");

    assert_eq!(log.entries().iter().filter(|(run, _)| *run == first).count(), 2);
    assert_eq!(log.entries().iter().filter(|(run, _)| *run == second).count(), 1);
}

/// A secret the redactor holds never reaches the fake: the journal scrubs the event
/// *before* the append, and the fake stores exactly what it was handed. This is the
/// half of the redaction contract the conformance kit cannot see, because the port has
/// no read — here the stored value is in reach.
#[test]
fn a_redacted_event_is_stored_redacted() {
    const SECRET: &str = "s3cr3t-token";
    let mut redactor = Redactor::new();
    redactor.register(&SecretValue::new(SECRET.as_bytes().to_vec()));
    let log = RecordingRunLog::new();
    let run = run(4);

    let event = RunEvent::StepFinished {
        step: "apply-infra".to_string(),
        ok: false,
        outputs: vec![SECRET.to_string()],
        duration_ms: 0,
        error: Some(format!("registry refused: {SECRET}")),
    };
    block_on(log.append(&run, event.clone())).expect("append");
    assert_eq!(
        log.events(),
        vec![event.clone()],
        "an unredacted event is stored as it is handed: the fake is not the thing that scrubs"
    );

    block_on(log.append(&run, event.redacted(&redactor))).expect("append");
    let stored = format!("{:?}", log.events()[1]);
    assert!(
        stored.contains("***") && !stored.contains(SECRET),
        "the event the adapter received must be the scrubbed one: {stored}"
    );
}

/// `Debug` is a count, never an entry: a run's log must not become a way to print one.
#[test]
fn debug_prints_the_entry_count_and_never_an_entry() {
    let log = RecordingRunLog::new();
    let run = run(5);
    let event = RunEvent::ApprovalGranted {
        step: "apply-infra".to_string(),
        approver: "ada".to_string(),
        channel: "tty".to_string(),
        artifacts: vec!["sha256:aa".to_string()],
    };
    block_on(log.append(&run, event)).expect("append");

    let shown = format!("{log:?}");
    assert_eq!(shown, "RecordingRunLog { entries: 1 }");
    assert!(!shown.contains("ada"), "an entry leaked into Debug: {shown}");
}
