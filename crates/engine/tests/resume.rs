//! Park and resume across jobs: a run writes its plan and state to a
//! `StateStore` and exits at an approval; a *fresh* process — fresh store,
//! harness and working directory — fetches the plan back byte-identical,
//! applies it and finishes ([#42](https://github.com/Keep-Shipping/harness/issues/42)).
//!
//! The refusals matter as much as the happy path: a `ship.ks` edited between
//! park and resume, and a plan blob swapped in the store, must stop the run
//! rather than apply something the approver never saw.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ks_core::harness::Harness;
use ks_core::ids::RunId;
use ks_core::ports::BoxFuture;
use ks_core::ports::iac::SavedPlan;
use ks_core::ports::script_host::{Value, ValueType};
use ks_core::ports::secrets::Redactor;
use ks_core::ports::state_store::{Sensitivity, StateError, StateStore};
use ks_core::step::{
    ActionClass, ActionKind, CancellationToken, Field, Inputs, LogRecord, LogSink, Outputs, Port,
    Ports, StepCtx, StepError, StepKind, StepSchema, TypeRef, Version,
};
use ks_engine::run::run_step;
use ks_engine::state::{
    CompletedStep, LocalStateStore, PlanRef, ResumeError, RunState, fetch_plan, park, plan_key,
    resume, save_plan, sha256_hex,
};
use ks_testing::clock::FakeClock;
use ks_testing::iac::FakeIacTool;
use ks_testing::secrets::FakeSecrets;
use ks_testing::state_store::{MemoryStateStore, conformance};

/// The `ship.ks` both jobs read — the binding the parked record carries.
const SHIP_KS: &[u8] =
    b"steps:\n  plan: sample.plan\n  approval: sample.approve\n  apply: sample.apply\n";

/// The plan bytes — deterministic, so job 2's fetch compares byte for byte.
const PLAN_BYTES: &[u8] = b"# tofu plan\nresource \"null_resource\" \"app\" {}\n";

const PLAN_STEP: &str = "sample.plan";
const APPROVAL: &str = "sample.approve";
const APPLY_STEP: &str = "sample.apply";

/// The run id both jobs use; a parked run is resumed by its id.
fn run_id() -> RunId {
    RunId::from_parts(1_700_000_000_000, 42)
}

/// A clean directory under `CARGO_TARGET_TMPDIR`, so a rerun leaks nothing.
fn work_dir(label: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(label);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the work directory can be created");
    dir
}

/// A composition over `ks-testing` fakes. Job 1 and job 2 each build their own.
fn harness() -> Harness {
    Harness::builder()
        .ports(
            Ports::default()
                .with_clock(Arc::new(FakeClock::new()))
                .with_secrets(Arc::new(FakeSecrets::new()))
                .with_iac_tool(Arc::new(FakeIacTool::new())),
        )
        .step_arc(Arc::new(PlanStep))
        .step_arc(Arc::new(ApplyStep))
        .build()
        .expect("the fixture composition is valid")
}

/// Runs `name` with `inputs` through the engine, discarding the log.
fn drive(harness: &Harness, name: &str, inputs: Inputs) -> Result<Outputs, StepError> {
    ks_testing::block_on(run_step(
        harness,
        name,
        inputs,
        CancellationToken::new(),
        Arc::new(NoLog) as Arc<dyn LogSink>,
        Arc::new(Redactor::new()),
    ))
}

struct NoLog;

impl LogSink for NoLog {
    fn record(&self, _record: LogRecord) {}
}

/// Job 1 in full: plan, save the bytes, park at the approval — apply never runs,
/// the approval is not there yet. Everything job 1 held (its `Harness`, store
/// handle, plan file) goes out of scope on return; only
/// `.keepshipping/runs/<id>/` survives.
fn park_a_run(job1: &Path, store: &dyn StateStore) -> (RunId, PlanRef) {
    let mut inputs = Inputs::new();
    inputs.insert("dir".to_string(), Value::from(job1.display().to_string()));
    let outputs = drive(&harness(), PLAN_STEP, inputs).expect("the plan step runs");
    let written =
        std::fs::read(out_text(&outputs, "plan_path")).expect("the plan step wrote a file");
    assert_eq!(written, PLAN_BYTES, "job 1's plan file holds the planned bytes");

    let run = run_id();
    let plan = ks_testing::block_on(save_plan(store, &run, PLAN_STEP, &written))
        .expect("the plan is stored");
    assert_eq!(
        plan.sha256,
        out_text(&outputs, "sha256"),
        "the step and the store agree on the digest"
    );

    let mut state = RunState::new(run.clone(), SHIP_KS, "push").with_context("repo", "acme/web");
    state.record(CompletedStep {
        name: PLAN_STEP.to_string(),
        outputs: BTreeMap::from([("sha256".to_string(), plan.sha256.clone())]),
        plans: vec![plan.clone()],
    });
    state.park_at(APPROVAL).expect("the run parks at the approval");
    ks_testing::block_on(park(store, &state)).expect("the state is parked");
    (run, plan)
}

/// Writes the plan bytes into `dir` and reports their digest — a stand-in for
/// `tofu plan -out=…`.
struct PlanStep;

impl StepKind for PlanStep {
    fn name(&self) -> &'static str {
        PLAN_STEP
    }

    fn version(&self) -> Version {
        Version::new(1, 0, 0)
    }

    fn schema(&self) -> StepSchema {
        StepSchema {
            doc: "Writes a plan file into `dir` and reports its digest.",
            inputs: vec![Field::new("dir", TypeRef::Builtin(ValueType::String), "where to write")],
            outputs: vec![
                Field::new("plan_path", TypeRef::Builtin(ValueType::String), "the plan written"),
                Field::new("sha256", TypeRef::Builtin(ValueType::String), "the plan's digest"),
            ],
        }
    }

    fn requires(&self) -> &'static [Port] {
        &[]
    }

    fn optional(&self) -> &'static [Port] {
        &[]
    }

    fn action(&self, _inputs: &Inputs) -> ActionClass {
        ActionClass::new(ActionKind::Other)
    }

    fn run(&self, _ctx: StepCtx, inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>> {
        Box::pin(async move {
            let path = Path::new(text(&inputs, "dir")).join("plan.tfplan");
            write_file(&path, PLAN_BYTES)?;
            Ok(outputs(&[
                ("plan_path", path.display().to_string()),
                ("sha256", sha256_hex(PLAN_BYTES)),
            ]))
        })
    }
}

/// Re-hashes the plan at `plan_path` and applies it if it still digests to
/// `expected_sha256` — the "you cannot apply what you did not plan" rule the
/// real `IacTool::apply` holds.
struct ApplyStep;

impl StepKind for ApplyStep {
    fn name(&self) -> &'static str {
        APPLY_STEP
    }

    fn version(&self) -> Version {
        Version::new(1, 0, 0)
    }

    fn schema(&self) -> StepSchema {
        StepSchema {
            doc: "Applies the plan at `plan_path` after re-hashing it.",
            inputs: vec![
                Field::new("plan_path", TypeRef::Builtin(ValueType::String), "the plan to apply"),
                Field::new(
                    "expected_sha256",
                    TypeRef::Builtin(ValueType::String),
                    "the digest the plan must still hash to",
                ),
            ],
            outputs: vec![
                Field::new("sha256", TypeRef::Builtin(ValueType::String), "the digest applied"),
                Field::new("bytes", TypeRef::Builtin(ValueType::String), "the plan's contents"),
            ],
        }
    }

    fn requires(&self) -> &'static [Port] {
        &[]
    }

    fn optional(&self) -> &'static [Port] {
        &[]
    }

    fn action(&self, _inputs: &Inputs) -> ActionClass {
        ActionClass::new(ActionKind::Deploy)
    }

    fn run(&self, _ctx: StepCtx, inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>> {
        Box::pin(async move {
            let path = PathBuf::from(text(&inputs, "plan_path"));
            let expected = text(&inputs, "expected_sha256");
            let bytes = read_file(&path)?;
            let actual = sha256_hex(&bytes);
            if actual != expected {
                return Err(StepError::Port {
                    port: Port::IacTool,
                    message: format!(
                        "plan no longer matches its digest: expected {expected}, found {actual}"
                    ),
                });
            }
            Ok(outputs(&[
                ("sha256", actual),
                ("bytes", String::from_utf8_lossy(&bytes).into_owned()),
            ]))
        })
    }
}

/// The string input under `name`.
fn text<'a>(inputs: &'a Inputs, name: &str) -> &'a str {
    match inputs.get(name) {
        Some(Value::String(text)) => text,
        _ => "",
    }
}

/// The string output under `name`.
fn out_text(outputs: &Outputs, name: &str) -> String {
    match outputs.get(name) {
        Some(Value::String(text)) => text.clone(),
        other => panic!("{name} should be a string output, got {other:?}"),
    }
}

/// A step's declared outputs, from name/value pairs.
fn outputs(pairs: &[(&str, String)]) -> Outputs {
    pairs.iter().map(|(name, value)| ((*name).to_string(), Value::from(value.clone()))).collect()
}

/// Runs a filesystem operation against `path`, reporting failures as the port
/// error the fake steps raise.
fn io<T>(path: &Path, operation: impl FnOnce(&Path) -> std::io::Result<T>) -> Result<T, StepError> {
    operation(path).map_err(|error| StepError::Port {
        port: Port::IacTool,
        message: format!("{}: {error}", path.display()),
    })
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), StepError> {
    io(path, |path| std::fs::write(path, bytes))
}

fn read_file(path: &Path) -> Result<Vec<u8>, StepError> {
    io(path, |path| std::fs::read(path))
}

/// A clean `root` with job directories already made, and job 1 parked in it.
fn parked(label: &str) -> (PathBuf, RunId, PlanRef) {
    let root = work_dir(label);
    let job1 = root.join("job1");
    std::fs::create_dir_all(&job1).expect("job 1's directory");
    let (run, plan) = {
        let store = LocalStateStore::new(&root);
        park_a_run(&job1, &store)
    };
    (root, run, plan)
}

#[test]
fn a_run_parked_at_approval_is_finished_by_a_second_job() {
    let (root, run, plan) = parked("ks-resume-e2e");
    let job2 = root.join("job2");
    std::fs::create_dir_all(&job2).expect("job 2's directory");

    // ---- job 2: a fresh process over what job 1 left on disk ---------------
    let store = LocalStateStore::new(&root);
    let mut state = ks_testing::block_on(resume(&store, &run, SHIP_KS)).expect("the run resumes");
    assert_eq!(state.next.as_deref(), Some(APPROVAL), "parked at the approval");
    assert_eq!(state.event, "push");
    assert_eq!(state.context.get("repo").map(String::as_str), Some("acme/web"));
    assert_eq!(state.plans_for(PLAN_STEP), vec![&plan], "the record points at the parked plan");

    state.approve(APPROVAL, "ada").expect("the run is waiting on exactly this step");
    assert_eq!(state.approvals[0].by, "ada");

    let dest = job2.join("plan.tfplan");
    let saved: SavedPlan =
        ks_testing::block_on(fetch_plan(&store, &run, &plan, &dest)).expect("the plan fetches");
    assert_eq!(saved.sha256(), plan.sha256, "the fetched plan carries the parked digest");
    assert_eq!(read_file(&dest).expect("the fetched plan"), PLAN_BYTES, "job 2 got the same bytes");

    let mut inputs = Inputs::new();
    inputs.insert("plan_path".to_string(), Value::from(dest.display().to_string()));
    inputs.insert("expected_sha256".to_string(), Value::from(saved.sha256()));
    let applied = drive(&harness(), APPLY_STEP, inputs).expect("the apply step runs");
    assert_eq!(out_text(&applied, "sha256"), sha256_hex(PLAN_BYTES));
    assert_eq!(out_text(&applied, "bytes"), String::from_utf8_lossy(PLAN_BYTES));

    state.record(CompletedStep {
        name: APPLY_STEP.to_string(),
        outputs: BTreeMap::from([("sha256".to_string(), sha256_hex(PLAN_BYTES))]),
        plans: Vec::new(),
    });
    ks_testing::block_on(park(&store, &state)).expect("the final state parks");

    // A third job sees the run finished, with both steps recorded.
    let finished =
        ks_testing::block_on(resume(&store, &run, SHIP_KS)).expect("the finished run still loads");
    assert_eq!(finished.next, None);
    assert_eq!(finished.completed.len(), 2);
    assert_eq!(finished.completed[1].name, APPLY_STEP);
}

#[test]
fn a_ship_ks_edited_between_park_and_resume_is_refused() {
    let (root, run, _plan) = parked("ks-resume-changed-file");
    let edited = b"steps:\n  plan: sample.plan\n  # a new step\n";
    let error = ks_testing::block_on(resume(&LocalStateStore::new(&root), &run, edited))
        .expect_err("moved");

    match &error {
        ResumeError::FileChanged { expected, actual, .. } => {
            assert_eq!(expected, &sha256_hex(SHIP_KS), "the digest recorded when it parked");
            assert_eq!(actual, &sha256_hex(edited));
        }
        other => panic!("an edited ship.ks must be FileChanged, got {other:?}"),
    }
    let message = error.to_string();
    for fragment in ["ship.ks changed", run.as_str(), "start a new run"] {
        assert!(message.contains(fragment), "{fragment} missing from {message}");
    }
}

#[test]
fn a_plan_blob_swapped_in_the_store_is_refused() {
    let (root, run, plan) = parked("ks-resume-tampered-plan");
    let dest = root.join("job2").join("plan.tfplan");
    let store = LocalStateStore::new(&root);

    // Something between the jobs rewrote the blob in place. Content-addressing
    // does not stop a writer with filesystem access; the hash check does.
    let swapped = b"# a different plan\n";
    let blob = store.run_dir(&run).join(plan_key(&plan.sha256));
    write_file(&blob, swapped).expect("the blob can be overwritten");

    let error = ks_testing::block_on(fetch_plan(&store, &run, &plan, &dest)).expect_err("swapped");
    match &error {
        ResumeError::Decode { expected: Some(expected), actual: Some(actual), .. } => {
            assert_eq!(expected, &plan.sha256);
            assert_eq!(actual, &sha256_hex(swapped));
            assert!(error.to_string().contains("refusing to apply it"), "{error}");
        }
        other => panic!("a swapped blob must report both digests, got {other:?}"),
    }
    assert!(!dest.exists(), "a refused fetch must leave no plan file for an apply to pick up");

    // Gone entirely is a different refusal: nothing to check, so plan again.
    std::fs::remove_file(&blob).expect("the blob goes");
    let error = ks_testing::block_on(fetch_plan(&store, &run, &plan, &dest)).expect_err("gone");
    assert!(error.to_string().contains("run the plan step again"), "{error}");
}

#[test]
fn a_corrupt_or_unknown_version_state_record_is_refused_clearly() {
    let (root, run, _plan) = parked("ks-resume-corrupt-state");
    let store = LocalStateStore::new(&root);

    for (record, expected) in
        [(&b"{not json"[..], "not valid JSON"), (b"{\"version\":99}", "version 99")]
    {
        ks_testing::block_on(store.put(&run, "state.json", record, Sensitivity::Plain))
            .expect("the bad record writes");
        let error = ks_testing::block_on(resume(&store, &run, SHIP_KS)).expect_err("unreadable");
        assert!(matches!(error, ResumeError::Decode { .. }), "{error:?}");
        assert!(error.to_string().contains(expected), "{error}");
        assert!(error.to_string().contains("start a new run"), "{error}");
    }

    // And a run that never parked at all.
    let store = LocalStateStore::new(work_dir("ks-resume-never"));
    let error = ks_testing::block_on(resume(&store, &run, SHIP_KS)).expect_err("nothing parked");
    assert!(matches!(error, ResumeError::NotFound { .. }), "{error:?}");
    assert!(error.to_string().contains("nothing to resume"), "{error}");
}

#[test]
fn both_state_stores_pass_the_conformance_kit() {
    ks_testing::block_on(conformance(&MemoryStateStore::new()));
    let root = work_dir("ks-resume-conformance");
    let store = LocalStateStore::new(&root);
    ks_testing::block_on(conformance(&store));

    // And the local store outlives its handle: a fresh one reads what the
    // previous one wrote, which is what makes a resume a new process at all.
    let run = run_id();
    let record = b"{\"version\":1}";
    ks_testing::block_on(store.put(&run, "state.json", record, Sensitivity::Plain))
        .expect("the write lands");
    let reopened = LocalStateStore::new(&root);
    assert_eq!(
        ks_testing::block_on(reopened.get(&run, "state.json")).expect("the read lands"),
        Some(record.to_vec())
    );
    assert!(reopened.run_dir(&run).ends_with(Path::new(".keepshipping/runs").join(run.as_str())));
}

/// The parked run really is a run's state on disk: after job 1 exits, a fresh
/// `LocalStateStore` over the same directory lists what job 1 left, classifies
/// the plan as the issue does, and refuses to un-classify it. Without the
/// recorded sensitivity surviving the process, a resume could write plain bytes
/// over a plan that was declared secret — the ratchet would hold only for as
/// long as the handle did.
#[test]
fn a_parked_runs_classification_survives_the_process_that_recorded_it() {
    let (root, run, plan) = parked("ks-resume-sensitivity");

    // Job 2: a new store, a new process, the same directory.
    let store = LocalStateStore::new(&root);
    let listed = ks_testing::block_on(store.list(&run)).expect("the run lists");
    let keys: Vec<&str> = listed.iter().map(|summary| summary.key.as_str()).collect();
    assert_eq!(
        keys,
        [plan_key(&plan.sha256).as_str(), "state.json"],
        "both blobs are listed, sorted"
    );

    let plan_summary =
        listed.iter().find(|s| s.key == plan_key(&plan.sha256)).expect("the plan is listed");
    assert_eq!(plan_summary.sensitivity, Sensitivity::Secretish, "a saved plan is secretish (#55)");
    assert_eq!(
        plan_summary.len,
        PLAN_BYTES.len(),
        "the summary is metadata, and still counts the bytes"
    );
    assert_eq!(
        listed.iter().find(|s| s.key == "state.json").expect("the record is listed").sensitivity,
        Sensitivity::Plain,
        "the parked record is plain"
    );

    // The ratchet, in a process that never made the original write.
    let downgraded = ks_testing::block_on(store.put(
        &run,
        &plan_key(&plan.sha256),
        PLAN_BYTES,
        Sensitivity::Plain,
    ))
    .expect_err("a secretish key cannot be written plain");
    assert!(matches!(downgraded, StateError::Downgrade { .. }), "{downgraded:?}");
    assert_eq!(
        ks_testing::block_on(store.get(&run, &plan_key(&plan.sha256))).expect("the read lands"),
        Some(PLAN_BYTES.to_vec()),
        "the refused write left the plan alone"
    );

    // And a second run in the same root is a separate run, which is what
    // `delete_run` has to be careful about.
    let neighbour = RunId::from_parts(1_700_000_000_000, 43);
    ks_testing::block_on(store.put(&neighbour, "state.json", b"{}", Sensitivity::Plain))
        .expect("the neighbour's record lands");
    ks_testing::block_on(store.delete_run(&run)).expect("the finished run is cleaned up");
    assert_eq!(ks_testing::block_on(store.list(&run)).expect("list"), Vec::new());
    assert_eq!(
        ks_testing::block_on(store.list(&neighbour)).expect("list").len(),
        1,
        "cleaning up one run left the other alone"
    );
    assert!(
        !store.run_dir(&run).exists(),
        "the run's directory, its sidecars and its blobs go together"
    );
}

/// What the local store puts on disk, which the conformance kit cannot see: one
/// blob per key, one sidecar per key beside it holding nothing but the
/// classification, and no name in a listing that `get` would refuse.
#[test]
fn a_run_directory_holds_one_sidecar_per_key_beside_its_blob() {
    let (root, run, plan) = parked("ks-resume-sidecars");
    let store = LocalStateStore::new(&root);
    let dir = store.run_dir(&run);
    let plan_key = plan_key(&plan.sha256);

    assert_eq!(
        std::fs::read_to_string(dir.join(format!(".{plan_key}.sensitivity"))).expect("its sidecar"),
        "secretish",
        "the plan's classification is the only thing its sidecar holds"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join(".state.json.sensitivity")).expect("its sidecar"),
        "plain",
        "the parked record's sidecar says plain, in the same spelling the port uses"
    );

    // Files someone else dropped in here are not blobs. `get` refuses their
    // names, so a listing that reported them would advertise keys the store will
    // not answer for.
    std::fs::write(dir.join("README"), b"notes").expect("a stray file lands");
    std::fs::write(dir.join("State.json"), b"{}").expect("another one does too");
    let listed = ks_testing::block_on(store.list(&run)).expect("the run lists");
    let keys: Vec<&str> = listed.iter().map(|summary| summary.key.as_str()).collect();
    assert_eq!(keys, [plan_key.as_str(), "state.json"], "only the keys `get` accepts");
    assert!(
        matches!(
            ks_testing::block_on(store.get(&run, "README")),
            Err(StateError::InvalidKey { .. })
        ),
        "a name `put` refuses must not be listed as though it were a key"
    );
}

/// The blind spot a whole-index rewrite had: two jobs writing *different* keys
/// of the same run at the same time. Each writer only ever touches its own
/// key's files, so what either of them records survives the other.
#[test]
fn concurrent_writers_of_different_keys_all_keep_their_classification() {
    let root = work_dir("ks-resume-concurrent-keys");
    let run = run_id();
    // Threads, because a resume really is a second process: `LocalStateStore` is
    // `Clone + Send + Sync`, and nothing here serialises the two.
    std::thread::scope(|scope| {
        for round in 0..8u8 {
            let store = LocalStateStore::new(&root);
            let run = run.clone();
            scope.spawn(move || {
                let key = format!("plan-{round:02x}");
                ks_testing::block_on(store.put(&run, &key, b"a plan", Sensitivity::Secretish))
                    .expect("each key lands");
            });
        }
    });

    let listed = ks_testing::block_on(LocalStateStore::new(&root).list(&run)).expect("list");
    assert_eq!(
        listed.len(),
        8,
        "every writer's blob is there: {:?}",
        listed.iter().map(|s| &s.key).collect::<Vec<_>>()
    );
    for summary in &listed {
        assert_eq!(
            summary.sensitivity,
            Sensitivity::Secretish,
            "{} lost its classification to a writer working on another key",
            summary.key
        );
    }
}
