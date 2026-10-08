//! The plan guard: an approved plan is applied, or the run stops and asks again
//! ([#67](https://github.com/Keep-Shipping/harness/issues/67)).
//!
//! The two ways the world moves are kept apart on purpose, because only one of them the tool can
//! see. A *state* change ([`FakeIacTool::drift`]) bumps the serial and the tool refuses the saved
//! plan with [`IacError::StalePlan`] — always caught, recheck or not. *Out-of-band drift* changes
//! what a fresh plan says without moving the serial, so the tool would happily apply the old plan;
//! only `recheck` catches it. Every test asserts on which [`IacCall`]s were made, so "applied the
//! approved plan" can never quietly mean "applied some other plan".

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ks_core::Env;
use ks_core::ids::RunId;
use ks_core::ports::BoxFuture;
use ks_core::ports::iac::{
    ApplyResult, Backend, ChangeAction, IacError, IacTool, Outputs, PlanJson, ResourceChange,
    SavedPlan, ToolInfo,
};
use ks_core::ports::run_log::{RunEvent, RunLog, RunLogError};
use ks_core::ports::secrets::Redactor;
use ks_core::ports::state_store::StateStore;
use ks_engine::journal::Journal;
use ks_engine::plan_guard::{
    GuardError, Guarded, Reapproval, StaleCause, Workspace, apply_approved, diff, recheck_default,
    resolve_recheck,
};
use ks_engine::state::{RunState, plan_key, save_plan};
use ks_testing::block_on;
use ks_testing::iac::{FakeIacTool, IacCall};
use ks_testing::run_log::RecordingRunLog;
use ks_testing::state_store::MemoryStateStore;

/// The change set every test starts from: one subnet to create.
fn create(address: &str) -> ResourceChange {
    ResourceChange { address: address.into(), actions: vec![ChangeAction::Create] }
}

fn plan(changes: Vec<ResourceChange>) -> PlanJson {
    PlanJson { changes }
}

fn change(address: &str, actions: Vec<ChangeAction>) -> ResourceChange {
    ResourceChange { address: address.into(), actions }
}

/// The world a run applies: a scripted tool, a journal over a recording log, and the approved plan
/// with the change set it was reviewed against. `fresh` is what the *next* `plan` will say — the
/// drifted world — so the tests only differ in what they do to the world and what they ask of the
/// guard.
struct World {
    tool: Arc<FakeIacTool>,
    journal: Journal,
    log: Arc<RecordingRunLog>,
    approved: SavedPlan,
    approved_changes: PlanJson,
    /// Whether the re-plan after a stale refusal should fail.
    replan_fails: bool,
}

impl World {
    /// The workspace every plan is taken against.
    fn workspace() -> Workspace<'static> {
        static VARS: std::sync::OnceLock<BTreeMap<String, String>> = std::sync::OnceLock::new();
        static BACKEND: std::sync::OnceLock<Backend> = std::sync::OnceLock::new();
        Workspace {
            dir: Path::new("/ws/infra"),
            vars: VARS.get_or_init(BTreeMap::new),
            backend: BACKEND.get_or_init(|| Backend::new("local")),
        }
    }

    /// A world whose *next* plan says `fresh` — empty means "the same thing again". Both plans
    /// are scripted before the approved one is issued, because the fake hands them out in order.
    fn new(fresh: Vec<ResourceChange>) -> World {
        let approved_changes = vec![create("aws_subnet.app")];
        let tool = FakeIacTool::new().with_plan(approved_changes.clone());
        let tool = if fresh.is_empty() { tool } else { tool.with_plan(fresh) };
        let log = Arc::new(RecordingRunLog::new());
        let journal = Journal::new(
            Arc::clone(&log) as Arc<dyn RunLog>,
            Arc::new(Redactor::new()),
            RunId::from_parts(7, 1),
        );
        let workspace = World::workspace();
        let approved =
            block_on(tool.plan(workspace.dir, workspace.vars, workspace.backend)).unwrap();
        let shown = block_on(tool.show(&approved)).unwrap();
        assert_eq!(shown, PlanJson { changes: approved_changes });
        World {
            tool: Arc::new(tool),
            journal,
            log,
            approved,
            approved_changes: shown,
            replan_fails: false,
        }
    }

    /// The same world, but planning again after a stale refusal fails — the case where there is no
    /// fresh plan to hand the approvers.
    fn with_failing_replan() -> World {
        World { replan_fails: true, ..World::new(vec![]) }
    }

    /// Moves the state, which is what the tool itself can see.
    fn state_moves(&self) {
        self.tool.drift();
    }

    /// The tool the guard drives: the fake, or a wrapper whose second `plan` call fails — the
    /// backend went away between the stale refusal and the re-plan.
    fn guard_tool(&self) -> Arc<dyn IacTool> {
        if self.replan_fails {
            Arc::new(FailingReplan::new(Arc::clone(&self.tool), 0))
        } else {
            Arc::clone(&self.tool) as Arc<dyn IacTool>
        }
    }

    /// Runs the guard against this world, for the tests that expect it to reach a verdict.
    fn apply(&self, recheck: bool) -> Guarded {
        block_on(apply_approved(
            &*self.guard_tool(),
            &self.journal,
            "infra.apply",
            World::workspace(),
            &self.approved,
            &self.approved_changes,
            recheck,
        ))
        .expect("the guard reaches a verdict")
    }

    /// The digests of every plan passed to `apply`, in call order.
    fn applied(&self) -> Vec<String> {
        self.tool
            .calls()
            .into_iter()
            .filter_map(|call| match call {
                IacCall::Apply { sha256 } => Some(sha256),
                _ => None,
            })
            .collect()
    }

    fn plans(&self) -> usize {
        self.tool.calls().iter().filter(|c| matches!(c, IacCall::Plan)).count()
    }

    fn applies(&self) -> usize {
        self.tool.calls().iter().filter(|c| matches!(c, IacCall::Apply { .. })).count()
    }

    /// The single `plan.stale` event this stop recorded.
    fn stale(&self) -> RunEvent {
        assert_eq!(self.log.events().len(), 1, "one stop, one event");
        self.log.events()[0].clone()
    }

    /// The stop's event as `(cause, differs)`, the two fields the tests read most.
    fn stale_cause(&self) -> (String, Option<bool>) {
        let RunEvent::PlanStale { cause, differs, .. } = self.stale() else {
            panic!("expected plan.stale")
        };
        (cause, differs)
    }

    /// The `Reapproval` the guard returned, or a panic naming what came back instead.
    fn reapproved(outcome: Guarded) -> Reapproval {
        match outcome {
            Guarded::Reapprove(reapproval) => reapproval,
            Guarded::Applied(result) => {
                panic!("expected a re-approval, but the plan applied: {result:?}")
            }
        }
    }
}

/// A [`FakeIacTool`] whose next `plans_left` `plan` calls fail, so a re-plan can be made to break
/// where the fake cannot. Everything else — including the recorded calls — is the inner fake's, so
/// the assertions below still read against one call log.
struct FailingReplan {
    inner: Arc<FakeIacTool>,
    plans_left: AtomicUsize,
}

impl FailingReplan {
    fn new(inner: Arc<FakeIacTool>, plans_left: usize) -> FailingReplan {
        FailingReplan { inner, plans_left: AtomicUsize::new(plans_left) }
    }
}

impl IacTool for FailingReplan {
    fn plan<'a>(
        &'a self,
        dir: &'a Path,
        vars: &'a BTreeMap<String, String>,
        backend: &'a Backend,
    ) -> BoxFuture<'a, Result<SavedPlan, IacError>> {
        if self.plans_left.load(Ordering::SeqCst) > 0 {
            self.plans_left.fetch_sub(1, Ordering::SeqCst);
            self.inner.plan(dir, vars, backend)
        } else {
            Box::pin(std::future::ready(Err(IacError::Tool {
                message: "the backend went away".to_string(),
                exit_code: Some(1),
            })))
        }
    }
    fn show<'a>(&'a self, plan: &'a SavedPlan) -> BoxFuture<'a, Result<PlanJson, IacError>> {
        self.inner.show(plan)
    }
    fn apply<'a>(&'a self, plan: &'a SavedPlan) -> BoxFuture<'a, Result<ApplyResult, IacError>> {
        self.inner.apply(plan)
    }
    fn outputs<'a>(&'a self, dir: &'a Path) -> BoxFuture<'a, Result<Outputs, IacError>> {
        self.inner.outputs(dir)
    }
    fn tool(&self) -> ToolInfo {
        self.inner.tool()
    }
}

/// A state change between plan and apply: the tool refuses the saved plan with
/// [`IacError::StalePlan`], the guard stops, re-plans and asks again — even though the re-plan
/// says exactly what was approved, because the old approval is bound to the old plan's sha256 and
/// cannot release this file.
#[test]
fn a_state_change_between_plan_and_apply_stops_and_asks_again() {
    let world = World::new(vec![]);
    world.state_moves();

    let reapproval = World::reapproved(world.apply(false));
    assert_eq!(reapproval.cause, StaleCause::State);
    assert!(reapproval.diff.is_empty(), "the re-plan says the same thing: {:?}", reapproval.diff);
    assert_ne!(
        reapproval.plan.sha256(),
        world.approved.sha256(),
        "a different plan file, so a different digest the old approval cannot release"
    );

    // The approved plan was applied, and only it; the fresh plan never was.
    assert_eq!(world.applied(), [world.approved.sha256().to_string()]);
    assert_eq!(world.plans(), 2, "planned again after the stale refusal");
    assert_eq!(world.applies(), 1);

    // And the run log says why, naming both digests.
    let RunEvent::PlanStale { step, cause, approved, replanned, differs } = world.stale() else {
        panic!("expected plan.stale")
    };
    assert_eq!((step.as_str(), cause.as_str()), ("infra.apply", "state"));
    assert_eq!(approved, world.approved.sha256());
    assert_eq!(replanned.as_deref(), Some(reapproval.plan.sha256()));
    assert_eq!(differs, Some(false), "the change set matched; the file did not");
}

/// A stale plan whose re-plan *does* differ — a resource the state change brought along, an
/// action that became an update. The difference is reported to the approver and still licenses no
/// apply.
#[test]
fn a_state_change_whose_re_plan_differs_reports_the_difference() {
    let world = World::new(vec![
        change("aws_subnet.app", vec![ChangeAction::Update]),
        create("aws_instance.web"),
    ]);
    world.state_moves();

    let reapproval = World::reapproved(world.apply(false));
    assert_eq!(reapproval.cause, StaleCause::State);
    assert_eq!(reapproval.diff.added, ["aws_instance.web"]);
    assert_eq!(reapproval.diff.changed[0].before, [ChangeAction::Create]);
    assert_eq!(reapproval.diff.changed[0].after, [ChangeAction::Update]);
    assert_eq!(
        world.applied(),
        [world.approved.sha256().to_string()],
        "the fresh plan was applied"
    );
    assert_eq!(
        world.stale_cause(),
        ("state".to_string(), Some(true)),
        "the approver is told the change set moved"
    );
}

/// Out-of-band drift: nobody touched the state, so the tool's own stale check will not fire — but
/// a fresh plan no longer says what was approved. With `recheck` the guard catches it, and stops
/// before `apply` is reached at all.
#[test]
fn out_of_band_drift_is_caught_by_recheck_before_anything_is_applied() {
    let world = World::new(vec![create("aws_subnet.app"), create("aws_instance.web")]);

    let reapproval = World::reapproved(world.apply(true));
    assert_eq!(reapproval.cause, StaleCause::Drift);
    assert_eq!(reapproval.diff.added, ["aws_instance.web"]);
    assert_eq!(reapproval.changes.creates(), 2, "the fresh plan is what approvers now see");
    assert_eq!(world.plans(), 2);
    assert_eq!(world.applies(), 0, "apply must not be reached at all");

    assert_eq!(
        world.stale_cause(),
        ("drift".to_string(), Some(true)),
        "the approver is told why and what changed"
    );
}

/// The same world with `recheck` off: the tool sees a current state and a matching digest, so it
/// applies the approved plan. This is the gap `docs/STALE_PLANS.md` names — the plan applied is the
/// one a human reviewed, but it was reviewed against a world that has moved.
#[test]
fn out_of_band_drift_applies_the_approved_plan_when_recheck_is_off() {
    let world = World::new(vec![create("aws_subnet.app"), create("aws_instance.web")]);

    let Guarded::Applied(result) = world.apply(false) else {
        panic!("with recheck off this applies")
    };
    assert_eq!(result.added, 1, "only the approved change set was applied");
    assert_eq!(
        world.applied(),
        [world.approved.sha256().to_string()],
        "and it was the approved plan"
    );
    assert!(world.log.events().is_empty(), "nothing stale was found, so nothing was logged");
}

/// With `recheck` on and no difference, the guard applies the *approved* plan — never the fresh one
/// it just took — and says nothing about staleness.
#[test]
fn recheck_that_finds_no_difference_applies_the_approved_plan() {
    let world = World::new(vec![]);

    let Guarded::Applied(result) = world.apply(true) else {
        panic!("nothing changed, so this applies")
    };
    assert_eq!(result.added, 1);
    assert_eq!(
        world.applied(),
        [world.approved.sha256().to_string()],
        "the fresh plan was applied instead"
    );
    assert_eq!(world.plans(), 2, "the recheck planned once");
    assert_eq!(world.applies(), 1);
    assert!(world.log.events().is_empty(), "an unchanged recheck is not an event");
}

/// Asking again means the run parks at the approval with the *fresh* plan saved under its own
/// digest, so the digest the old approval names releases nothing. The stored bytes are keyed by
/// `reapproval.plan`'s digest, not by a digest of the test's own choosing: had the guard handed
/// back the approved plan, the fetch below would miss and this would fail.
#[test]
fn the_fresh_plan_is_parked_for_a_new_approval_the_old_one_cannot_release() {
    let world = World::new(vec![]);
    world.state_moves();
    let reapproval = World::reapproved(world.apply(false));

    let store = MemoryStateStore::new();
    let run = RunId::from_parts(7, 2);
    let bytes = b"# tofu plan\nresource \"null_resource\" \"app\" {}\n";
    let fresh = &reapproval.plan;
    block_on(store.put(&run, &plan_key(fresh.sha256()), bytes)).expect("the fresh plan is stored");

    let mut state = RunState::new(run.clone(), b"steps:\n  apply: tofu.apply\n", "push");
    state.park_at("infra.approve").expect("the run parks at the approval");
    assert_eq!(state.next.as_deref(), Some("infra.approve"), "the run is waiting again");

    // The approver reads back the plan the guard named, and it is not the approved one.
    assert_ne!(fresh.sha256(), world.approved.sha256(), "a new plan file, so a new digest");
    let fetched =
        block_on(store.get(&run, &plan_key(fresh.sha256()))).expect("the plan bytes are there");
    assert_eq!(fetched.as_deref(), Some(bytes.as_slice()));

    // And a record of what was approved points at the old digest, which releases nothing.
    let old =
        block_on(save_plan(&store, &run, "infra.apply", b"# the approved plan\n")).expect("stored");
    assert_ne!(old.sha256, fresh.sha256(), "the old approval names the old digest");
}

/// A stale plan whose re-plan *fails*: the guard cannot put a new plan in front of approvers, so
/// it has nothing to re-ask about. It still records the stop — with no `replanned` and no
/// verdict — and propagates the tool's own error.
#[test]
fn a_re_plan_that_fails_is_still_recorded_and_the_error_propagates() {
    let world = World::with_failing_replan();
    world.state_moves();

    let error = block_on(apply_approved(
        &*world.guard_tool(),
        &world.journal,
        "infra.apply",
        World::workspace(),
        &world.approved,
        &world.approved_changes,
        false,
    ))
    .expect_err("there is no fresh plan to ask about");
    assert!(matches!(&error, GuardError::Plan(IacError::Tool { .. })), "{error:?}");
    assert!(error.to_string().contains("the backend went away"), "{error}");

    // The stop is on the record anyway — that is the point of recording it first.
    let RunEvent::PlanStale { cause, approved, replanned, differs, .. } = world.stale() else {
        panic!("expected plan.stale")
    };
    assert_eq!(cause, "state");
    assert_eq!(approved, world.approved.sha256());
    assert_eq!(replanned, None, "there was no fresh plan to name");
    assert_eq!(differs, None, "so there was nothing to compare");
    assert_eq!(world.applies(), 1, "the approved apply was attempted, then nothing more");
}

/// The log write is the only record of why a run stopped, so a log that refuses the entry fails
/// the guard closed: nothing is applied and no re-approval is implied.
#[test]
fn a_log_that_refuses_the_event_stops_the_guard_closed() {
    /// A [`RunLog`] that refuses every entry.
    struct Refusing;
    impl RunLog for Refusing {
        fn append<'a>(
            &'a self,
            _run: &'a RunId,
            _event: RunEvent,
        ) -> BoxFuture<'a, Result<(), RunLogError>> {
            Box::pin(async { Err(RunLogError::Backend { message: "no space left".into() }) })
        }
    }

    let mut world = World::new(vec![]);
    world.journal = Journal::new(
        Arc::new(Refusing) as Arc<dyn RunLog>,
        Arc::new(Redactor::new()),
        RunId::from_parts(7, 3),
    );
    world.state_moves();

    let error = block_on(apply_approved(
        &*world.guard_tool(),
        &world.journal,
        "infra.apply",
        World::workspace(),
        &world.approved,
        &world.approved_changes,
        false,
    ))
    .expect_err("the guard fails closed");
    assert!(matches!(error, GuardError::Log(_)), "{error:?}");
    assert!(error.to_string().contains("no space left"), "{error}");
    assert_eq!(world.applies(), 1, "the approved apply was attempted, then nothing more");
}

/// An apply that fails for any other reason is the tool's own error, verbatim — the guard does not
/// turn a refused backend, or a swapped plan file, into a re-approval.
#[test]
fn an_apply_that_fails_for_another_reason_propagates_the_tools_error() {
    let world = World::new(vec![]);
    // A digest the fake never issued: the plan file was swapped after planning.
    let approved =
        SavedPlan::new("/ws/infra/plan.tfplan", "0".repeat(64)).expect("a well-formed digest");

    let error = block_on(apply_approved(
        &*world.guard_tool(),
        &world.journal,
        "infra.apply",
        World::workspace(),
        &approved,
        &PlanJson::default(),
        false,
    ))
    .expect_err("apply fails");
    assert!(matches!(&error, GuardError::Apply(IacError::PlanTampered { .. })), "{error:?}");
    assert!(world.log.events().is_empty(), "a tampered plan is not a stale one");
}

/// `diff` is the whole of "differs": a no-op is not a change, an address that appears or vanishes
/// is, and so is one whose actions are not the same list — including its *order*, which is why a
/// replace and a create-before-destroy are different plans for one address.
#[test]
fn a_change_set_differs_by_address_and_by_action_and_by_nothing_else() {
    let no_op = change("data.aws_ami.base", vec![ChangeAction::NoOp]);
    let same = plan(vec![create("aws_subnet.app")]);
    assert!(diff(&same, &same).is_empty());
    assert!(diff(&same, &plan(vec![create("aws_subnet.app"), no_op.clone()])).is_empty());

    let reordered = diff(
        &plan(vec![change("a", vec![ChangeAction::Delete, ChangeAction::Create])]),
        &plan(vec![change("a", vec![ChangeAction::Create, ChangeAction::Delete])]),
    );
    assert_eq!(reordered.changed.len(), 1, "the order is significant");

    let difference = diff(
        &plan(vec![
            create("keep"),
            create("gone"),
            change("moved", vec![ChangeAction::Delete, ChangeAction::Create]),
            no_op.clone(),
        ]),
        &plan(vec![
            create("keep"),
            create("new"),
            change("moved", vec![ChangeAction::Update]),
            no_op,
        ]),
    );
    assert!(!difference.is_empty());
    assert_eq!(difference.added, ["new"]);
    assert_eq!(difference.removed, ["gone"]);
    assert_eq!(difference.changed.len(), 1);
    assert_eq!(difference.changed[0].address, "moved");
    assert_eq!(difference.changed[0].before, [ChangeAction::Delete, ChangeAction::Create]);
    assert_eq!(difference.changed[0].after, [ChangeAction::Update]);
    // A `Read` is an action like any other: a data source nobody read before is new work.
    assert_eq!(
        diff(
            &same,
            &plan(vec![create("aws_subnet.app"), change("data.x", vec![ChangeAction::Read])])
        )
        .added,
        ["data.x"]
    );
}

/// `recheck` is on in a `ci-only` environment — where a stop costs a re-run, not a human — and off
/// everywhere else. An explicit value from the workflow wins either way. The causes name
/// themselves, so the run log reads as prose.
#[test]
fn recheck_follows_the_environment_unless_the_workflow_says_otherwise() {
    // An `Env` built for the test; the checker is the only other thing that builds one, and it
    // fills the same fields.
    let env = |name: &str, ci_only| Env {
        name: name.to_string(),
        span: ks_lang::Span::default(),
        triggers: Vec::new(),
        ci_only,
        secrets: None,
        approvers: Vec::new(),
        vars: Vec::new(),
    };
    let (ci, prod) = (env("ci", true), env("prod", false));

    assert!(recheck_default(&ci), "a ci-only environment rechecks");
    assert!(!recheck_default(&prod));
    assert!(resolve_recheck(Some(true), &prod), "an explicit on wins in a normal environment");
    assert!(!resolve_recheck(Some(false), &ci), "an explicit off wins in a ci-only environment");
    assert!(resolve_recheck(None, &ci));
    assert!(!resolve_recheck(None, &prod));

    assert_eq!(StaleCause::State.as_str(), "state");
    assert_eq!(StaleCause::Drift.as_str(), "drift");
}
