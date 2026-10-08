//! `rollback:` in a site file, all the way to the executor
//! ([#78](https://github.com/Keep-Shipping/harness/issues/78)).
//!
//! The policy used to stop at the checker: `check` accepted `rollback: manual`
//! and dropped it, so the file promised a human would be asked and the run
//! rolled back on its own anyway. These tests walk the whole path a value now
//! travels — parse tree, [`ks_core::workflow::Step`], [`Plan`], and the
//! executor's own [`PlannedStep`] — and then run the plan, so what is proven is
//! the behaviour, not the field.

use std::sync::Mutex;

use ks_core::ports::BoxFuture;
use ks_core::step::{ActionKind, CancellationToken, Rollback, RollbackPolicy, RollbackStatus};
use ks_core::{Catalog, CheckOptions, Checked, check_with};
use ks_engine::exec::{Attempt, ExecOptions, PlannedStep, RunLog, StepRunner, StepStatus, execute};
use ks_engine::plan::{Plan, PlanCtx};
use ks_testing::block_on;
use ks_testing::clock::FakeClock;

/// A deploy step whose `rollback:` is named by the file that goes around it.
fn site(policy: Option<&str>) -> String {
    let rollback = match policy {
        Some(policy) => format!("\n    rollback: {policy}"),
        None => String::new(),
    };
    format!(
        "\
name: api
steps:
  build:   oci.image
    from:   ./Dockerfile
  deploy:  k8s.rollout{rollback}
    image:  build.digest
"
    )
}

/// Checks `src`, refusing a file the checker would not take: these tests are
/// about what survives checking, not about what checking accepts.
fn checked(src: &str) -> Checked {
    let catalog = Catalog::builtin();
    let checked = check_with(&ks_lang::parse(src), &CheckOptions::new(&catalog));
    assert!(checked.diagnostics.is_empty(), "{src}:\n{:#?}", checked.diagnostics);
    checked
}

/// The plan `src` gives for the `default` environment, which is all a site file
/// is asked for before it is run.
fn plan(src: &str) -> Plan {
    let checked = checked(src);
    Plan::new(&checked.workflow, &PlanCtx { env: "default".into(), event: None })
}

#[test]
fn a_steps_rollback_policy_survives_the_parse_and_reaches_the_executors_step() {
    for (written, expected) in [
        (Some("auto"), RollbackPolicy::Auto),
        (Some("manual"), RollbackPolicy::Manual),
        (Some("none"), RollbackPolicy::None),
        // A step that says nothing gets the default, which is `auto`.
        (None, RollbackPolicy::Auto),
    ] {
        let src = site(written);
        let checked = checked(&src);

        // The workflow carries it...
        assert_eq!(
            checked.workflow.step("deploy").expect("declared").rollback,
            expected,
            "workflow::Step, from {written:?}"
        );
        // ...the plan carries it...
        let plan = plan(&src);
        assert_eq!(
            plan.step(2).expect("second in plan order").rollback,
            expected,
            "plan::PlannedStep, from {written:?}"
        );
        // ...and the executor's own step is what finally reads it.
        let steps = plan.to_exec_steps(|_| ActionKind::Deploy);
        let deploy = steps.iter().find(|s| s.id == "deploy").expect("the deploy step");
        assert_eq!(deploy.rollback, expected, "exec::PlannedStep, from {written:?}");
    }
}

/// A runner whose deploy never comes up healthy, recording every rollback it
/// is asked for. The count is the point: `manual` is not "roll back quietly",
/// it is "do not ask at all".
struct FailingDeploy {
    rollbacks: Mutex<Vec<String>>,
}

impl StepRunner for FailingDeploy {
    fn run<'a>(
        &'a self,
        step: &'a PlannedStep,
        _attempt: u32,
        _cancel: &'a CancellationToken,
    ) -> BoxFuture<'a, Attempt> {
        // Only the deploy fails: a build that failed would skip the deploy
        // before the policy was ever read, which would prove nothing.
        let outcome = match step.action {
            ActionKind::Deploy => Attempt::Failed(format!("{} did not come up healthy", step.id)),
            _ => Attempt::Succeeded,
        };
        Box::pin(async move { outcome })
    }

    fn rollback<'a>(&'a self, step: &'a PlannedStep) -> BoxFuture<'a, Result<Rollback, String>> {
        self.rollbacks.lock().expect("rollbacks poisoned").push(step.id.clone());
        Box::pin(async { Ok(Rollback::reverted_to("previous")) })
    }
}

/// Plans `src` and runs it, handing back the run log and the ids the runner was
/// asked to roll back.
fn run(src: &str) -> (RunLog, Vec<String>) {
    let steps = plan(src).to_exec_steps(|step| match step.name.as_str() {
        "deploy" => ActionKind::Deploy,
        _ => ActionKind::Build,
    });
    let runner = FailingDeploy { rollbacks: Mutex::new(Vec::new()) };
    let clock = FakeClock::new();
    let cancel = CancellationToken::new();
    let log = block_on(execute(&steps, &runner, &clock, &cancel, ExecOptions::default()))
        .expect("the plan is valid");
    let rollbacks = runner.rollbacks.lock().expect("rollbacks poisoned").clone();
    (log, rollbacks)
}

/// `manual` asks a human: no rollback is attempted, the step's record says one
/// is outstanding, and the run still stops on the failure.
#[test]
fn a_manual_policy_waits_for_a_human_instead_of_rolling_back() {
    let (log, rollbacks) = run(&site(Some("manual")));

    assert!(rollbacks.is_empty(), "a human's job, not the runner's: {rollbacks:?}");
    let deploy = log.step("deploy").expect("the deploy ran");
    assert_eq!(deploy.status, StepStatus::Failed, "the run still stops on the failure");
    let rollback = deploy.rollback.as_ref().expect("a manual rollback is recorded, not absent");
    assert_eq!(rollback.status(), RollbackStatus::Pending);
    assert_eq!(
        rollback.reverted_to_version(),
        None,
        "nothing changed, so there is no version to have gone back to"
    );
}

/// `auto` is the contrast: the same failing deploy, the same plan, and the
/// runner is asked — and answers with the version it went back to.
#[test]
fn an_auto_policy_does_ask_the_runner_to_roll_back() {
    let (log, rollbacks) = run(&site(Some("auto")));

    assert_eq!(rollbacks, ["deploy"]);
    let deploy = log.step("deploy").expect("the deploy ran");
    let rollback = deploy.rollback.as_ref().expect("an automatic rollback happened");
    assert_eq!(rollback.status(), RollbackStatus::Reverted);
    assert_eq!(rollback.reverted_to_version(), Some("previous"));
}

/// `none` is for a step that creates infrastructure: a failed deploy must not
/// tear down what the apply already moved.
#[test]
fn a_none_policy_leaves_the_failed_deploy_alone() {
    let (log, rollbacks) = run(&site(Some("none")));

    assert!(rollbacks.is_empty(), "infrastructure is not undone: {rollbacks:?}");
    assert_eq!(log.step("deploy").expect("the deploy ran").rollback, None);
}

/// A step that says nothing is `auto`, so a plan built without the key behaves
/// exactly as it did before `rollback:` existed.
#[test]
fn a_step_that_says_nothing_still_rolls_back_on_its_own() {
    let (log, rollbacks) = run(&site(None));

    assert_eq!(rollbacks, ["deploy"]);
    assert_eq!(
        log.step("deploy").and_then(|record| record.rollback.as_ref()).map(|r| r.status()),
        Some(RollbackStatus::Reverted)
    );
}
