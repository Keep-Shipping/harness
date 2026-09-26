//! Behaviour of the `IacTool` fake: scripted plan/show/apply, the stale-plan
//! and tamper invariants, and the conformance kit.

use std::collections::BTreeMap;
use std::path::Path;

use ks_core::ports::iac::{
    Backend, ChangeAction, IacError, IacKind, IacTool, ResourceChange, SavedPlan,
};
use ks_testing::block_on;
use ks_testing::iac::{FakeIacTool, IacCall, conformance as iac_conformance};

/// One create, one update, one no-op — a plan with a bit of everything.
fn mixed_changes() -> Vec<ResourceChange> {
    vec![
        ResourceChange {
            address: "aws_subnet.app".to_string(),
            actions: vec![ChangeAction::Create],
        },
        ResourceChange {
            address: "aws_instance.web".to_string(),
            actions: vec![ChangeAction::Update],
        },
        ResourceChange {
            address: "data.aws_ami.base".to_string(),
            actions: vec![ChangeAction::NoOp],
        },
    ]
}

fn local_backend() -> Backend {
    Backend::new("local")
}

#[test]
fn the_fake_plans_shows_and_applies_scripted_changes() {
    let dir = Path::new("/ws/infra");
    let tool = FakeIacTool::new().with_plan(mixed_changes());

    let plan =
        block_on(tool.plan(dir, &BTreeMap::new(), &local_backend())).expect("the plan is scripted");
    // The SavedPlan is self-describing: a fake path plus the digest of what
    // was "written".
    assert!(plan.sha256().len() == 64, "{}", plan.sha256());
    assert!(plan.path().to_string_lossy().contains("fake-iac"), "{:?}", plan.path());

    let shown = block_on(tool.show(&plan)).expect("the saved plan parses");
    assert_eq!(shown.changes.len(), 3);
    assert!(!shown.is_empty());
    assert_eq!((shown.creates(), shown.updates(), shown.destroys()), (1, 1, 0));

    let applied = block_on(tool.apply(&plan)).expect("the fresh plan applies");
    assert_eq!((applied.added, applied.changed, applied.destroyed), (1, 1, 0));

    let digest = plan.sha256().to_string();
    assert_eq!(
        tool.calls(),
        vec![
            IacCall::Plan,
            IacCall::Show { sha256: digest.clone() },
            IacCall::Apply { sha256: digest }
        ]
    );
}

#[test]
fn a_plan_made_before_a_state_change_is_stale() {
    let dir = Path::new("/ws/infra");
    let tool = FakeIacTool::new().with_plan(mixed_changes());
    let plan = block_on(tool.plan(dir, &BTreeMap::new(), &local_backend())).unwrap();

    // Out-of-band drift: someone applied elsewhere. The old plan must not
    // apply, and apply must stop rather than push through (#67).
    tool.drift();
    assert!(
        matches!(block_on(tool.apply(&plan)), Err(IacError::StalePlan)),
        "a plan older than the state must be stale"
    );

    // The way back is a fresh plan, which applies — and is itself stale once
    // it has been applied.
    let fresh = block_on(tool.plan(dir, &BTreeMap::new(), &local_backend()))
        .expect("replanning after drift");
    assert_ne!(fresh.sha256(), plan.sha256(), "the fresh plan is a different file");
    assert!(block_on(tool.apply(&fresh)).is_ok());
    assert!(matches!(block_on(tool.apply(&fresh)), Err(IacError::StalePlan)));
}

#[test]
fn a_swapped_plan_file_is_tampered() {
    let dir = Path::new("/ws/infra");
    let tool = FakeIacTool::new().with_plan(mixed_changes());
    let plan = block_on(tool.plan(dir, &BTreeMap::new(), &local_backend())).unwrap();

    // Same path, different digest: the file was swapped after `plan`.
    let forged = SavedPlan::new(plan.path().to_path_buf(), "b".repeat(64))
        .expect("64 hex digits is a well-formed digest");
    match block_on(tool.show(&forged)) {
        Err(IacError::PlanTampered { expected, actual }) => {
            assert_eq!(expected, "b".repeat(64));
            assert!(!actual.is_empty(), "{actual}");
        }
        other => panic!("show of a forged plan must be PlanTampered, got {other:?}"),
    }
    match block_on(tool.apply(&forged)) {
        Err(IacError::PlanTampered { expected, .. }) => assert_eq!(expected, "b".repeat(64)),
        other => panic!("apply of a forged plan must be PlanTampered, got {other:?}"),
    }

    // And a digest that is not 64 hex digits never even becomes a SavedPlan.
    assert!(matches!(
        SavedPlan::new(plan.path().to_path_buf(), "nope"),
        Err(IacError::InvalidDigest { .. })
    ));
}

#[test]
fn the_fake_reports_its_tool_and_outputs() {
    let tool = FakeIacTool::new()
        .with_tool(IacKind::Terraform, "1.9.8-fake")
        .with_output("subnet_id", "\"subnet-123\"", false)
        .with_output("db_password", "\"hunter2\"", true);

    let info = tool.tool();
    assert_eq!((info.kind, info.version.as_str()), (IacKind::Terraform, "1.9.8-fake"));

    let outputs = block_on(tool.outputs(Path::new("/ws/infra"))).expect("outputs are scripted");
    assert_eq!(outputs["subnet_id"].value, "\"subnet-123\"");
    assert!(!outputs["subnet_id"].sensitive);
    assert!(outputs["db_password"].sensitive);
}

#[test]
fn the_fake_passes_conformance_and_is_dyn_compatible() {
    let tool = FakeIacTool::new().with_plan(mixed_changes());
    block_on(iac_conformance(&tool, Path::new("/ws/conformance")));

    fn assert_send_sync<T: ?Sized + Send + Sync>() {}
    assert_send_sync::<dyn IacTool>();
    let dynamic: &dyn IacTool = &tool;
    assert_eq!(dynamic.tool().kind, IacKind::OpenTofu);
}
