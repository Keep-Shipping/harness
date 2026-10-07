//! Behaviour of the `RunLog` fake: a real hash chain, sealing, failure, and
//! tampering that `verify` actually catches — plus the conformance kit, run
//! against the fake through the `dyn` trait.

use ks_core::ids::RunId;
use ks_core::ports::run_log::{LogEvent, RunLog, RunLogError, Seq};
use ks_testing::block_on;
use ks_testing::run_log::{FakeRunLog, conformance as run_log_conformance};

fn run(seed: u128) -> RunId {
    RunId::from_parts(1_700_000_000_000, seed)
}

fn event(kind: &str, detail: &str) -> LogEvent {
    LogEvent {
        kind: kind.to_string(),
        at: std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(1_700_000_000_123),
        step: None,
        detail: detail.to_string(),
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
    let log = FakeRunLog::new();
    let dynamic: &dyn RunLog = &log;
    block_on(run_log_conformance(dynamic));
}

#[test]
fn a_fresh_fake_has_no_seeded_state() {
    let log = FakeRunLog::new();
    let run = run(1);
    assert_eq!(log.entries(&run), Vec::new());
    assert_eq!(log.appended(&run), 0);
    assert_eq!(block_on(log.read(&run)).expect("read"), Vec::new());
    let report = block_on(log.verify(&run)).expect("verify");
    assert!(report.is_intact() && report.entries == 0 && report.head.is_none(), "{report:?}");
    assert!(!log.is_sealed());
}

#[test]
fn appends_are_numbered_from_one_and_keep_their_order() {
    let log = FakeRunLog::new();
    let run = run(2);
    assert_eq!(
        block_on(log.append(&run, event("run.started", "from ci"))).expect("append"),
        Seq::FIRST
    );
    assert_eq!(
        block_on(log.append(&run, event("step.started", "build"))).expect("append"),
        Seq::new(2)
    );
    assert_eq!(
        block_on(log.append(&run, event("step.succeeded", "build ok"))).expect("append"),
        Seq::new(3)
    );
    assert_eq!(log.appended(&run), 3);
    let kinds: Vec<String> = log.entries(&run).into_iter().map(|entry| entry.event.kind).collect();
    assert_eq!(kinds, vec!["run.started", "step.started", "step.succeeded"]);
}

#[test]
fn the_chain_links_every_entry_to_the_one_before_it() {
    let log = FakeRunLog::new();
    let run = run(3);
    block_on(log.append(&run, event("run.started", "from ci"))).expect("append");
    block_on(log.append(&run, event("step.started", "build"))).expect("append");

    let entries = log.entries(&run);
    assert_eq!(entries[0].prev, None, "the first entry of a chain links to nothing");
    assert_eq!(entries[1].prev, Some(entries[0].hash.clone()));
    for entry in &entries {
        assert_eq!(entry.hash.algorithm(), "sha256");
    }
    // Distinct entries produce distinct hashes, so the chain is not a constant.
    assert_ne!(entries[0].hash, entries[1].hash);
    assert_eq!(block_on(log.verify(&run)).expect("verify").head, Some(entries[1].hash.clone()));
}

#[test]
fn tampering_is_detected_at_the_edited_entry() {
    let log = FakeRunLog::new();
    let run = run(4);
    block_on(log.append(&run, event("run.started", "from ci"))).expect("append");
    block_on(log.append(&run, event("approval.granted", "by dana"))).expect("append");
    block_on(log.append(&run, event("step.started", "build"))).expect("append");
    assert!(block_on(log.verify(&run)).expect("verify").is_intact());

    assert!(log.tamper(2), "the middle entry exists to be edited");
    let report = block_on(log.verify(&run)).expect("verify");
    assert!(!report.is_intact(), "an edited entry must not verify");
    assert_eq!(report.broken_at, Some(Seq::new(2)));
    // Reading is not judging: the damaged entries are still returned.
    assert_eq!(block_on(log.read(&run)).expect("read").len(), 3);
}

#[test]
fn a_sealed_fake_refuses_appends_and_names_the_run() {
    let log = FakeRunLog::new();
    let run = run(5);
    block_on(log.append(&run, event("run.started", "from ci"))).expect("append");

    let sealed = FakeRunLog::new().sealed();
    assert!(sealed.is_sealed());
    match block_on(sealed.append(&run, event("run.finished", "ok"))) {
        Err(RunLogError::Sealed { run: named }) => assert_eq!(named, run),
        other => panic!("a sealed log must refuse appends, got {other:?}"),
    }
    // The entry appended before sealing is still readable.
    assert_eq!(log.entries(&run).len(), 1);
}

#[test]
fn a_failing_fake_fails_all_three_methods() {
    let log = FakeRunLog::new().failing("disk full");
    let run = run(6);
    let backend = RunLogError::Backend { message: "disk full".to_string() };
    assert_eq!(block_on(log.append(&run, event("run.started", "from ci"))), Err(backend.clone()));
    assert_eq!(block_on(log.read(&run)), Err(backend.clone()));
    assert_eq!(block_on(log.verify(&run)), Err(backend));
}

#[test]
fn each_run_keeps_its_own_chain() {
    let log = FakeRunLog::new();
    let first = run(7);
    let second = run(8);
    block_on(log.append(&first, event("run.started", "ci"))).expect("append");
    block_on(log.append(&first, event("step.started", "build"))).expect("append");
    block_on(log.append(&second, event("run.started", "local"))).expect("append");

    assert_eq!(log.appended(&first), 2);
    assert_eq!(log.appended(&second), 1);
    // The second run's chain starts over, and is intact on its own.
    assert_eq!(log.entries(&second)[0].seq, Seq::FIRST);
    assert!(block_on(log.verify(&second)).expect("verify").is_intact());
}
