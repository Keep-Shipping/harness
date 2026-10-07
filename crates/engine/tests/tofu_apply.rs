//! `tofu.apply` applies exactly the plan a human approved, or nothing at all
//! ([#66](https://github.com/Keep-Shipping/harness/issues/66)).
//!
//! The refusals are the point: a plan file edited after the approval, or a
//! digest no approval ever bound, must stop the run *before* anything is
//! created — which is why the tamper test watches a real file on disk and a
//! real [`IacTool`] that re-hashes it, as the port contract requires.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ks_core::harness::Harness;
use ks_core::ports::BoxFuture;
use ks_core::ports::iac::{
    ApplyResult, Backend, ChangeAction, IacError, IacKind, IacTool, OutputValue, Outputs, PlanJson,
    ResourceChange, SavedPlan, ToolInfo,
};
use ks_core::ports::script_host::Value;
use ks_core::ports::secrets::Redactor;
use ks_core::step::{
    ActionClass, ActionKind, CancellationToken, Inputs, LogSink, Outputs as StepOutputs, Ports,
    StepError, StepKind,
};
use ks_engine::run::run_step;
use ks_engine::state::sha256_hex;
use ks_testing::block_on;
use ks_testing::clock::FakeClock;
use ks_testing::iac::FakeIacTool;
use ks_testing::step::{RecordingSink, StepCase, step_conformance};

/// The plan bytes `plan` writes, and what a swap after approval replaces them
/// with: the tamper must be visible in the file's digest, nothing subtler.
const APPROVED_PLAN: &[u8] = b"# saved plan\nresource \"null_resource\" \"app\" {}\n";
const SWAPPED_PLAN: &[u8] = b"# saved plan\nresource \"null_resource\" \"other\" {}\n";

/// The root module directory the outputs are read from.
const DIR: &str = "/ws/infra";

/// A clean directory under `CARGO_TARGET_TMPDIR`, so a rerun leaks nothing.
fn work_dir(label: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(label);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the work directory can be created");
    dir
}

/// An [`IacTool`] over a real plan file on disk, holding the port contract
/// where it belongs: `apply` re-hashes the file and refuses a mismatch before
/// it applies anything. It records every apply that actually ran, so a test can
/// assert nothing was created — not merely that the step said so.
struct DiskIac {
    applied: Mutex<Vec<String>>,
    outputs: Result<Outputs, IacError>,
}

impl DiskIac {
    /// A tool with no outputs to read.
    fn new() -> DiskIac {
        DiskIac { applied: Mutex::new(Vec::new()), outputs: Ok(Outputs::new()) }
    }

    /// A tool whose `outputs` read fails `error`, for the case where the apply
    /// already happened.
    fn failing_outputs(error: IacError) -> DiskIac {
        DiskIac { applied: Mutex::new(Vec::new()), outputs: Err(error) }
    }

    /// The digests this tool actually applied, oldest first.
    fn applied(&self) -> Vec<String> {
        self.applied.lock().expect("the apply log").clone()
    }
}

impl IacTool for DiskIac {
    fn plan<'a>(
        &'a self,
        _dir: &'a Path,
        _vars: &'a BTreeMap<String, String>,
        _backend: &'a Backend,
    ) -> BoxFuture<'a, Result<SavedPlan, IacError>> {
        Box::pin(std::future::ready(Err(IacError::Tool {
            message: "planning is not what this test exercises".to_string(),
            exit_code: None,
        })))
    }

    fn show<'a>(&'a self, _plan: &'a SavedPlan) -> BoxFuture<'a, Result<PlanJson, IacError>> {
        Box::pin(std::future::ready(Ok(PlanJson::default())))
    }

    fn apply<'a>(&'a self, plan: &'a SavedPlan) -> BoxFuture<'a, Result<ApplyResult, IacError>> {
        let result = (|| {
            let bytes = std::fs::read(plan.path())
                .map_err(|error| IacError::Tool { message: error.to_string(), exit_code: None })?;
            let actual = sha256_hex(&bytes);
            if actual != plan.sha256() {
                return Err(IacError::PlanTampered { expected: plan.sha256().to_string(), actual });
            }
            self.applied.lock().expect("the apply log").push(plan.sha256().to_string());
            Ok(ApplyResult { added: 2, changed: 1, destroyed: 0 })
        })();
        Box::pin(std::future::ready(result))
    }

    fn outputs<'a>(&'a self, _dir: &'a Path) -> BoxFuture<'a, Result<Outputs, IacError>> {
        Box::pin(std::future::ready(self.outputs.clone()))
    }

    fn tool(&self) -> ToolInfo {
        ToolInfo { kind: IacKind::OpenTofu, version: "disk-iac-test".to_string() }
    }
}

/// The harness `tofu.apply` runs under, over `tool`.
fn harness_with<T: IacTool + 'static>(tool: &Arc<T>) -> Harness {
    Harness::builder()
        .ports(
            Ports::default()
                .with_clock(Arc::new(FakeClock::new()))
                .with_iac_tool(Arc::clone(tool) as Arc<dyn IacTool>),
        )
        .step(ks_engine::tofu_apply::TofuApply)
        .build()
        .expect("the composition is valid")
}

/// The `plan` input for a file at `path` approved at `sha256`.
fn plan_input(path: &Path, sha256: &str) -> Inputs {
    let mut file = BTreeMap::new();
    file.insert("path".to_string(), Value::from(path.display().to_string()));
    file.insert("sha256".to_string(), Value::from(sha256));
    file.insert("dir".to_string(), Value::from(DIR));
    let mut inputs = Inputs::new();
    inputs.insert("plan".to_string(), Value::Map(file));
    inputs
}

/// Runs `tofu.apply` against `harness`, logging into a fresh sink.
async fn apply(
    harness: &Harness,
    inputs: Inputs,
) -> Result<(StepOutputs, Arc<RecordingSink>), StepError> {
    let sink = Arc::new(RecordingSink::default());
    let outputs = run_step(
        harness,
        "tofu.apply",
        inputs,
        CancellationToken::new(),
        Arc::clone(&sink) as Arc<dyn LogSink>,
        Arc::new(Redactor::new()),
    )
    .await?;
    Ok((outputs, sink))
}

/// The port refuses a file edited after the approval, and applies the same file
/// untouched — the two halves of the contract, on one real file on disk.
#[test]
fn only_the_approved_plan_file_applies() {
    let dir = work_dir("ks-tofu-apply-tamper");
    let path = dir.join("approved.tfplan");
    std::fs::write(&path, APPROVED_PLAN).expect("the plan file is written");
    let approved = sha256_hex(APPROVED_PLAN);
    let swapped = sha256_hex(SWAPPED_PLAN);
    let tool = Arc::new(DiskIac::new());
    let harness = harness_with(&tool);

    // Someone edits the plan file between the approval and the apply.
    std::fs::write(&path, SWAPPED_PLAN).expect("the swap lands");
    let error = block_on(apply(&harness, plan_input(&path, &approved)))
        .expect_err("the file on disk is no longer the approved one");
    let message = error.to_string();
    assert!(
        message.contains(&approved) && message.contains(&swapped),
        "the refusal names both digests, so the difference is visible: {message}",
    );
    assert!(message.contains("nothing was applied"), "{message}");
    assert!(
        tool.applied().is_empty(),
        "the port refused before applying anything, so nothing was created: {:?}",
        tool.applied(),
    );

    // Put the approved bytes back: now the same input applies.
    std::fs::write(&path, APPROVED_PLAN).expect("the restore lands");
    let outputs = block_on(apply(&harness, plan_input(&path, &approved)))
        .expect("the approved file still digests to the approved digest")
        .0;
    assert_eq!(outputs.get("applied"), Some(&Value::Number(3.0)));
    assert_eq!(tool.applied(), vec![approved], "exactly the approved file was applied");
}

/// The site fixture's plan: +2 ~1 -0, applied. Creating and destroying
/// infrastructure is an `apply` action, which is what policy demands an
/// approval for and what the run loop refuses to retry.
#[test]
fn the_site_fixture_plan_reports_three_resources_and_the_root_outputs() {
    assert_eq!(
        ks_engine::tofu_apply::TofuApply.action(&Inputs::new()),
        ActionClass::new(ActionKind::Apply),
        "applying infrastructure needs an approval and must never be retried",
    );
    let tool = Arc::new(
        FakeIacTool::new()
            .with_plan(vec![
                ResourceChange {
                    address: "null_resource.web".to_string(),
                    actions: vec![ChangeAction::Create],
                },
                ResourceChange {
                    address: "null_resource.db".to_string(),
                    actions: vec![ChangeAction::Create],
                },
                ResourceChange {
                    address: "null_resource.cache".to_string(),
                    actions: vec![ChangeAction::Update],
                },
            ])
            .with_output("url", "\"https://example.test\"", false)
            .with_output("replicas", "3", false)
            .with_output("db_password", "\"hunter2\"", true),
    );
    let harness = harness_with(&tool);
    let saved = block_on(tool.plan(Path::new(DIR), &BTreeMap::new(), &Backend::new("local")))
        .expect("the fake's plan is scripted");

    let (outputs, sink) = block_on(apply(&harness, plan_input(saved.path(), saved.sha256())))
        .expect("a plan applies");

    assert_eq!(outputs.get("applied"), Some(&Value::Number(3.0)), "+2 ~1 -0 is 3 resources");
    let logged = sink.records();
    let summary =
        logged.iter().find(|record| record.message == "3 resources").unwrap_or_else(|| {
            panic!("the run reports the apply the way `tofu` prints it: {logged:?}")
        });
    assert_eq!(
        summary
            .fields
            .iter()
            .find(|(name, _)| name == "sensitive_outputs")
            .map(|(_, value)| value.as_str()),
        Some("1"),
        "the apply records how many sensitive outputs it withheld",
    );

    let Some(Value::Map(out)) = outputs.get("out") else {
        panic!("`out` is a map, got {:?}", outputs.get("out"));
    };
    assert_eq!(out.get("url"), Some(&Value::from("https://example.test")));
    assert_eq!(out.get("replicas"), Some(&Value::Number(3.0)));
    assert!(!out.contains_key("db_password"), "a sensitive output must not be returned: {out:?}",);
    assert!(
        !logged.iter().any(|record| record.message.contains("hunter2")
            || record.fields.iter().any(|(_, value)| value.contains("hunter2"))),
        "the sensitive value is nowhere in the log: {logged:?}",
    );
}

/// A digest no approval ever bound never reaches the tool as a plan of its own.
#[test]
fn a_digest_no_approval_bound_is_refused() {
    let tool = Arc::new(FakeIacTool::new());
    let harness = harness_with(&tool);
    let unbound = "0".repeat(64);

    let error =
        block_on(apply(&harness, plan_input(Path::new("/ws/infra/approved.tfplan"), &unbound)))
            .expect_err("the approval never bound this digest");
    assert!(error.to_string().contains("nothing was applied"), "{error}");
}

/// An apply that worked but whose outputs could not be read must not read as a
/// refusal: the human it reaches has to know not to apply the plan again.
#[test]
fn unreadable_outputs_after_a_successful_apply_say_so() {
    let dir = work_dir("ks-tofu-apply-outputs");
    let path = dir.join("approved.tfplan");
    std::fs::write(&path, APPROVED_PLAN).expect("the plan file is written");
    let approved = sha256_hex(APPROVED_PLAN);
    let tool = Arc::new(DiskIac::failing_outputs(IacError::Tool {
        message: "the state backend is unreachable".to_string(),
        exit_code: Some(1),
    }));
    let harness = harness_with(&tool);

    let error = block_on(apply(&harness, plan_input(&path, &approved)))
        .expect_err("the outputs read failed");
    let message = error.to_string();
    assert!(message.contains("3 resources"), "the apply did happen: {message}");
    assert!(message.contains("do not apply it again"), "{message}");
    assert!(
        !message.contains("backend is unreachable"),
        "the tool's own output never reaches the log: {message}",
    );
    assert_eq!(tool.applied(), vec![approved], "the plan really was applied");
}

#[test]
fn the_apply_step_passes_the_step_conformance_kit() {
    let dir = work_dir("ks-tofu-apply-conformance");
    let path = dir.join("approved.tfplan");
    std::fs::write(&path, APPROVED_PLAN).expect("the plan file is written");
    let approved = sha256_hex(APPROVED_PLAN);
    let mut outputs = Outputs::new();
    outputs.insert(
        "url".to_string(),
        OutputValue { value: "\"https://example.test\"".to_string(), sensitive: false },
    );
    let tool = Arc::new(DiskIac { applied: Mutex::new(Vec::new()), outputs: Ok(outputs) });
    let harness = harness_with(&tool);

    block_on(step_conformance(&harness, StepCase::new("tofu.apply", plan_input(&path, &approved))));
}
