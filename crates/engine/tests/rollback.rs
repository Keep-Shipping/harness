//! The deploy conformance scenario through the public API: a reference deploy step passes it, four
//! deliberately-broken ones prove it can fail, a fifth shows the boundary — the one lie a run log
//! cannot catch, which the target's own record of what it was told does — and the steps that are
//! *not* deploys are never rolled back at all.
//!
//! The scenario is [`ks_engine::rollback::deploy_conformance`] — the *fails health → rolls back →
//! reports* story
//! ([#78](https://github.com/Keep-Shipping/harness/issues/78)). It lives in `ks-engine` rather than
//! in `ks-testing` because the rollback it exercises happens in the executor; its module docs say
//! so at length. Here it is only called.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ks_core::ids::RunId;
use ks_core::ports::BoxFuture;
use ks_core::ports::clock::Clock;
use ks_core::ports::cluster::{Cluster, Manifest, Revision};
use ks_core::ports::health::Health;
use ks_core::ports::run_log::{RunEvent, RunLog as RunLogPort};
use ks_core::ports::script_host::{Value, ValueType};
use ks_core::ports::secrets::Redactor;
use ks_core::step::{
    ActionClass, ActionKind, CancellationToken, Field, Inputs, Outputs, Port, Rollback,
    RollbackPolicy, StepCtx, StepError, StepKind, StepSchema, TypeRef, Version,
};
use ks_engine::exec::{Attempt, ExecOptions, PlannedStep, RunLog, StepRunner, StepStatus, execute};
use ks_engine::journal::Journal;
use ks_engine::rollback::{Beat, DeployCase, RecordedRun, deploy_conformance};
use ks_testing::block_on;
use ks_testing::clock::FakeClock;
use ks_testing::cluster::{ClusterCall, FakeCluster};

/// The workload every deploy step here applies.
const WORKLOAD: &str = "Deployment/api";
/// The revision traffic was on before this deploy, and the one its rollback reaches.
const GOOD_REVISION: u32 = 41;
/// The version the deploy under test put on the target, and the one that failed.
const FAILED_VERSION: &str = "42";
/// How many times the reference step polls its target before it calls the gate failed.
///
/// A real step waits for as long as its `wait:` budget says; the fake only moves when something
/// asks it to, so the budget here is a poll count — and without one, a target that never settles
/// hangs the test instead of failing it, which is the one thing a conformance kit must never do.
const HEALTH_POLLS: usize = 8;

/// The version a rollback of the reference step reports, as the target names it. One source with
/// [`GOOD_REVISION`]: a case that named a version its target never reaches would be rejected for a
/// reason that has nothing to do with the contract.
fn good_version() -> String {
    Revision::new(GOOD_REVISION).to_string()
}

/// The scenario [`Rollout`] is proven against.
fn case() -> DeployCase {
    DeployCase::new("deploy", Rollout::NAME, good_version())
}

/// The reference deploy step: rolls an image out to a cluster and waits for it to come up.
///
/// It is declared here rather than in `steps.rs` because there is no deploy step kind in the engine
/// yet — this file is where the first one proves the contract, and where the sibling that adds
/// `vm.deploy` will call the same scenario. What the scenario drives is the [`StepRunner`] below,
/// which is the other half of a step: the declaration says what the step is, the runner does it.
struct Rollout;

impl Rollout {
    /// The step's registered name, and the kind the scenario's plan carries.
    const NAME: &'static str = "k8s.rollout";
}

impl StepKind for Rollout {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn version(&self) -> Version {
        Version::new(1, 0, 0)
    }

    fn schema(&self) -> StepSchema {
        StepSchema {
            doc: "Rolls an image out to a cluster and waits for it to become healthy.",
            inputs: vec![
                Field::new("image", TypeRef::Builtin(ValueType::String), "the image to roll out"),
                Field::new("wait", TypeRef::Builtin(ValueType::String), "how long to wait for it")
                    .with_default(Value::from("5m")),
            ],
            outputs: vec![Field::new(
                "revision",
                TypeRef::Builtin(ValueType::String),
                "the revision traffic is on",
            )],
        }
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::Cluster]
    }

    fn action(&self, _inputs: &Inputs) -> ActionClass {
        ActionClass::new(ActionKind::Deploy).in_env("prod")
    }

    fn run(&self, _ctx: StepCtx, _inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>> {
        // The conformance story runs through the executor, so nothing calls this: the step is
        // declared above and driven by `DeployRunner`. It refuses rather than pretending to deploy
        // to a cluster it was never given.
        Box::pin(std::future::ready(Err(StepError::Failed(format!(
            "{} is driven through the executor; see DeployRunner",
            Self::NAME
        )))))
    }
}

/// The one clause a [`DeployRunner`] breaks, or [`Flaw::None`] for the reference step.
///
/// Each is a thing a deploy step could plausibly get wrong on its own, and the scenario has to
/// catch every one of them — a kit that only ever passes proves nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flaw {
    /// Correct: wait for the target to settle, report what it reached.
    None,
    /// Reads any state that is not a hard failure as a deploy that landed — so a target that has
    /// said *nothing at all* passes. This is the silence-is-not-health bug.
    SilenceIsHealth,
    /// Goes back for real, then reports the version it *meant* to reach rather than the one the
    /// target reached.
    IntendedVersion,
    /// Goes back for real, then reports a rollback that reached nothing, so the run log cannot say
    /// where traffic is.
    SwallowedVersion,
    /// Reads health once and gives up on that one reading — which abandons a rollout that is still
    /// progressing, and never sees one that is already healthy.
    OnePoll,
    /// Reports a revert it never performed: the target is left on the version that failed.
    ClaimedRevert,
}

/// The deploy step under test: it applies the workload, waits for it, and on a rollback asks the
/// cluster for the revision traffic was on.
///
/// The `asked` list is shared with the test so it can see *which* runs asked the target to change
/// anything at all — the half of the rollback contract the scenario cannot see from the run log,
/// because a `manual` rollback that quietly changed the target would look identical from outside.
struct DeployRunner {
    cluster: Arc<FakeCluster>,
    beat: Beat,
    flaw: Flaw,
    asked: Arc<Mutex<Vec<Beat>>>,
}

impl DeployRunner {
    /// The runner the scenario drives, wired to a target whose health is the case's script for the
    /// beat it is playing and which retains the revision a rollback reaches.
    fn deployer(
        flaw: Flaw,
        asked: Arc<Mutex<Vec<Beat>>>,
    ) -> impl Fn(&DeployCase, Beat) -> DeployRunner {
        DeployRunner::watched_deployer(flaw, asked, Arc::default())
    }

    /// The same deployer, but hands every target it builds to `targets` as well, so a test can read
    /// back what the target itself was asked to do — the evidence the run log can never carry.
    fn watched_deployer(
        flaw: Flaw,
        asked: Arc<Mutex<Vec<Beat>>>,
        targets: Arc<Mutex<Vec<Arc<FakeCluster>>>>,
    ) -> impl Fn(&DeployCase, Beat) -> DeployRunner {
        move |case, beat| {
            let cluster = Arc::new(
                FakeCluster::new()
                    .with_health_script(case.health(beat))
                    .with_rollback_revision(Revision::new(GOOD_REVISION)),
            );
            targets.lock().expect("targets").push(Arc::clone(&cluster));
            DeployRunner { cluster, beat, flaw, asked: Arc::clone(&asked) }
        }
    }

    fn manifest() -> Manifest {
        Manifest::new(WORKLOAD, b"kind: Deployment").expect("the test manifest is not empty")
    }
}

impl StepRunner for DeployRunner {
    fn run<'a>(
        &'a self,
        _step: &'a PlannedStep,
        _attempt: u32,
        _cancel: &'a CancellationToken,
    ) -> BoxFuture<'a, Attempt> {
        let cluster = &self.cluster;
        let flaw = self.flaw;
        Box::pin(async move {
            if let Err(error) = cluster.apply(&[DeployRunner::manifest()]).await {
                return Attempt::Failed(error.to_string());
            }
            let mut last = Health::NoData;
            for poll in 0..HEALTH_POLLS {
                let report = match cluster.health(WORKLOAD).await {
                    Ok(report) => report,
                    Err(error) => return Attempt::Failed(error.to_string()),
                };
                last = report.state();
                let why = match report.reason() {
                    Some(reason) => reason.to_string(),
                    None => last.to_string(),
                };
                match flaw {
                    Flaw::SilenceIsHealth if !matches!(last, Health::Failed) => {
                        // Anything short of a hard failure is treated as up, so a target that has
                        // said nothing at all passes the gate.
                        return Attempt::Succeeded;
                    }
                    Flaw::OnePoll => {
                        // One reading is the whole gate, whatever it said.
                        return Attempt::Failed(format!(
                            "gave up on {WORKLOAD} after {poll} polls"
                        ));
                    }
                    _ => {}
                }
                if report.satisfies(Health::Healthy) {
                    return Attempt::Succeeded;
                }
                // Settled and not healthy: no amount of waiting will move it, so stop here rather
                // than burn the rest of the budget.
                if last.is_settled() {
                    return Attempt::Failed(format!("{last}: {why}"));
                }
            }
            Attempt::Failed(format!("{WORKLOAD} was still {last} after {HEALTH_POLLS} polls"))
        })
    }

    fn rollback<'a>(&'a self, _step: &'a PlannedStep) -> BoxFuture<'a, Result<Rollback, String>> {
        self.asked.lock().expect("asked").push(self.beat);
        let cluster = &self.cluster;
        let flaw = self.flaw;
        Box::pin(async move {
            // Every other flaw goes back for real and then misreports what came back, so it cannot
            // be caught for a rollback that also went wrong. This one never asks the target at all:
            // it states a revision the target was never told about.
            if flaw == Flaw::ClaimedRevert {
                return Ok(Rollback::reverted_to(good_version()));
            }
            // The rollback itself is the same whatever the step later *says* about it, so a step
            // that misreports one cannot be caught for a rollback that also went wrong.
            let rollout = cluster
                .rollback(WORKLOAD, Revision::new(GOOD_REVISION))
                .await
                .map_err(|error| error.to_string())?;
            Ok(match flaw {
                Flaw::IntendedVersion => Rollback::reverted_to(FAILED_VERSION),
                Flaw::SwallowedVersion => Rollback::pending(),
                _ => Rollback::reverted_to(rollout.revision().to_string()),
            })
        })
    }
}

/// Runs the scenario against `flaw` and returns the message of the panic it produced, along with
/// the beats on which the target was asked to change anything.
fn rejection(flaw: Flaw, clock: &dyn Clock) -> (String, Vec<Beat>) {
    let case = case();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let deployer = DeployRunner::deployer(flaw, Arc::clone(&asked));
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        block_on(deploy_conformance(&case, clock, deployer));
    }));
    let payload =
        caught.expect_err("the scenario must reject a deploy step that breaks its contract");
    let message = payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|text| (*text).to_string()))
        .expect("a conformance panic carries a string message");
    let asked = asked.lock().expect("asked").clone();
    (message, asked)
}

/// Runs the scenario against `flaw` and returns whether it rejected the step, along with every call
/// the target itself received.
///
/// The scenario reads a run log and nothing else, so for a flaw about *what the target was told*
/// this is the only evidence there is: the fake records the calls it received, so a claim the run
/// log cannot contradict still shows up here as a call that never arrived.
fn rejection_as_the_target_sees_it(
    flaw: Flaw,
    clock: &dyn Clock,
) -> (Option<String>, Vec<ClusterCall>) {
    let case = case();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let targets = Arc::new(Mutex::new(Vec::new()));
    let deployer = DeployRunner::watched_deployer(flaw, asked, Arc::clone(&targets));
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        block_on(deploy_conformance(&case, clock, deployer));
    }));
    let message = caught.err().map(|payload| {
        payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|text| (*text).to_string()))
            .expect("a conformance panic carries a string message")
    });
    let calls = targets.lock().expect("targets").iter().flat_map(|target| target.calls()).collect();
    (message, calls)
}

#[test]
fn a_deploy_that_fails_its_health_gate_is_rolled_back_and_reported() {
    let clock = FakeClock::new();
    let case = case();
    let asked = Arc::new(Mutex::new(Vec::new()));

    block_on(deploy_conformance(
        &case,
        &clock,
        DeployRunner::deployer(Flaw::None, Arc::clone(&asked)),
    ));

    // The declaration and the executor agree about what this step is: a deploy is what the
    // rollback machinery keys on, so a step kind that did not declare one would never be rolled
    // back whatever it did.
    assert_eq!(Rollout.action(&Inputs::new()).kind, ActionKind::Deploy);
    assert_eq!(Rollout.name(), Rollout::NAME);
    // Four runs: the failing one under each policy, then the landing one. Only the failing one
    // under `auto` reached the target — `manual` changes nothing and `none` never begins, which is
    // the part of the contract a run log alone cannot show.
    assert_eq!(*asked.lock().expect("asked"), vec![Beat::Unhealthy]);
}

#[test]
fn a_step_that_reads_silence_as_health_is_rejected() {
    let (message, asked) = rejection(Flaw::SilenceIsHealth, &FakeClock::new());

    assert!(
        message.contains("must not leave step \"deploy\" recorded as Succeeded"),
        "a target that said nothing must not leave a successful deploy behind, got {message:?}"
    );
    // It never even got as far as a rollback: it believed the deploy had landed.
    assert!(asked.is_empty(), "a step that passed the gate must not roll anything back");
}

#[test]
fn a_step_that_reports_the_version_it_intended_to_revert_to_is_rejected() {
    let (message, asked) = rejection(Flaw::IntendedVersion, &FakeClock::new());

    assert!(
        message.contains("never the version the step meant to reach"),
        "the run log must carry where traffic went, not where the step meant to send it, got \
         {message:?}"
    );
    assert!(
        message.contains(good_version().as_str()),
        "the message names the version the target actually reached, got {message:?}"
    );
    assert_eq!(asked, vec![Beat::Unhealthy], "the rollback itself did happen");
}

#[test]
fn a_step_that_goes_back_and_then_says_nothing_is_rejected() {
    let (message, asked) = rejection(Flaw::SwallowedVersion, &FakeClock::new());

    assert!(
        message.contains("is reverted, not"),
        "a rollback the target carried out must not be reported as pending, got {message:?}"
    );
    assert_eq!(asked, vec![Beat::Unhealthy], "the rollback itself did happen");
}

#[test]
fn a_step_that_fails_a_target_that_landed_gets_its_deploy_rolled_back() {
    let (message, asked) = rejection(Flaw::OnePoll, &FakeClock::new());

    assert!(
        message.contains("a target that reported Healthy must leave step"),
        "a deploy that landed must not be failed and undone, got {message:?}"
    );
    // The shape of that bug, in one line: the target was asked to go back on the *landing* run.
    assert_eq!(
        asked,
        vec![Beat::Unhealthy, Beat::Healthy],
        "the second ask is the landed deploy being rolled back"
    );
}

/// A runner that answers one scripted attempt per step id and counts rollbacks — enough for the
/// steps that are not deploys, where the only question is what the executor does with them.
struct Static {
    scripted: HashMap<String, Attempt>,
    rollbacks: Mutex<Vec<String>>,
}

impl Static {
    fn new() -> Static {
        Static { scripted: HashMap::new(), rollbacks: Mutex::new(Vec::new()) }
    }

    fn with(mut self, id: &str, attempt: Attempt) -> Static {
        self.scripted.insert(id.to_string(), attempt);
        self
    }

    fn rollbacks(&self) -> Vec<String> {
        self.rollbacks.lock().expect("rollbacks").clone()
    }
}

impl StepRunner for Static {
    fn run<'a>(
        &'a self,
        step: &'a PlannedStep,
        _attempt: u32,
        _cancel: &'a CancellationToken,
    ) -> BoxFuture<'a, Attempt> {
        let scripted = self.scripted.get(&step.id).cloned().unwrap_or(Attempt::Succeeded);
        Box::pin(std::future::ready(scripted))
    }

    fn rollback<'a>(&'a self, step: &'a PlannedStep) -> BoxFuture<'a, Result<Rollback, String>> {
        self.rollbacks.lock().expect("rollbacks").push(step.id.clone());
        Box::pin(std::future::ready(Ok(Rollback::reverted_to(good_version()))))
    }
}

/// Runs a plan against `runner` and journals every rollback it recorded, the way a production
/// caller will — the same pairing [`deploy_conformance`] does.
fn play(
    steps: &[PlannedStep],
    runner: &dyn StepRunner,
    clock: &dyn Clock,
) -> (RunLog, Vec<RunEvent>) {
    let cancel = CancellationToken::new();
    let log = block_on(execute(steps, runner, clock, &cancel, ExecOptions::default()))
        .expect("the plan is valid");

    let recorded = Arc::new(RecordedRun::new());
    let journal = Journal::new(
        Arc::clone(&recorded) as Arc<dyn RunLogPort>,
        Arc::new(Redactor::new()),
        RunId::from_parts(0, 1),
    );
    for record in &log.steps {
        let policy = steps.iter().find(|step| step.id == record.id).map(|step| step.rollback);
        if let (Some(rollback), Some(policy)) = (&record.rollback, policy) {
            block_on(journal.step_rolled_back(&record.id, policy, rollback))
                .expect("the log accepts");
        }
    }
    (log, recorded.events())
}

#[test]
fn a_build_that_fails_is_never_rolled_back() {
    let clock = FakeClock::new();
    let runner = Static::new().with("build", Attempt::Failed("no image".to_string()));
    let steps = vec![PlannedStep::new("build", "oci.image", ActionKind::Build)];

    let (log, events) = play(&steps, &runner, &clock);

    // A build changes nothing a rollback could reach, so there is nothing to revert — and nothing
    // to wait on either.
    assert_eq!(log.step("build").expect("a record").status, StepStatus::Failed);
    assert_eq!(log.step("build").expect("a record").rollback, None);
    assert!(runner.rollbacks().is_empty(), "the target was never asked");
    assert!(events.is_empty(), "and the run log carries no rollback event: {events:?}");
}

#[test]
fn a_tofu_apply_that_fails_is_never_rolled_back() {
    let clock = FakeClock::new();
    let runner = Static::new().with("apply", Attempt::Failed("no quota".to_string()));
    let steps = vec![PlannedStep::new("apply", "tofu.apply", ActionKind::Apply)];

    let (log, events) = play(&steps, &runner, &clock);

    assert_eq!(log.step("apply").expect("a record").status, StepStatus::Failed);
    assert_eq!(
        log.step("apply").expect("a record").rollback,
        None,
        "an apply that did not land is not a deploy, so it is not rolled back"
    );
    assert!(runner.rollbacks().is_empty(), "the target was never asked");
    assert!(events.is_empty(), "and the run log carries no rollback event: {events:?}");
}

#[test]
fn a_deploy_that_fails_after_a_tofu_apply_does_not_roll_back_the_infrastructure() {
    let clock = FakeClock::new();
    let runner = Static::new()
        .with("apply", Attempt::Succeeded)
        .with("deploy", Attempt::Failed("no capacity".to_string()));
    let steps = vec![
        PlannedStep::new("apply", "tofu.apply", ActionKind::Apply),
        PlannedStep::new("deploy", Rollout::NAME, ActionKind::Deploy)
            .rollback(RollbackPolicy::Auto),
    ];

    let (log, events) = play(&steps, &runner, &clock);

    assert_eq!(log.step("apply").expect("a record").status, StepStatus::Succeeded);
    assert_eq!(
        log.step("apply").expect("a record").rollback,
        None,
        "the apply succeeded: there is nothing about it to undo"
    );
    assert_eq!(log.step("deploy").expect("a record").status, StepStatus::Failed);
    assert_eq!(
        runner.rollbacks(),
        vec!["deploy".to_string()],
        "only the deploy is rolled back — the apply already moved the world, and tearing it down \
         again would destroy whatever the next deploy expects to find"
    );
    // And the run log says which step went back, so a reader is never left guessing whether the
    // infrastructure came down with it.
    assert_eq!(events.len(), 1, "one rollback, one event: {events:?}");
    let RunEvent::StepRolledBack { step, policy, status, reverted_to, .. } = &events[0] else {
        panic!("expected a step.rolled-back event, got {events:?}");
    };
    assert_eq!((step.as_str(), policy.as_str(), status.as_str()), ("deploy", "auto", "reverted"));
    assert_eq!(reverted_to.as_deref(), Some(good_version().as_str()));
}

#[test]
fn a_step_that_reports_a_revert_it_never_performed_is_caught_by_the_target_not_the_run_log() {
    let (message, calls) = rejection_as_the_target_sees_it(Flaw::ClaimedRevert, &FakeClock::new());

    // The scenario reads a run log and a run log cannot tell this one from a real revert: the step
    // records `reverted` to the right version, so every clause in `deploy_conformance` is satisfied.
    // A run log says what a step *claims* happened; only the target knows what it was told.
    assert!(
        message.is_none(),
        "the run log alone cannot catch a revert that never happened, but the scenario did reject \
         this step: {:?}",
        message,
    );

    // And what the target was actually asked is the thing that gives it away: this step reports a
    // revert to a revision it never sent, so the cluster's own record of what it was told carries
    // no rollback at all. A target that was asked would have one — which is why the `Flaw::None`
    // runner's rejection messages are read against `asked`, and this flaw against the calls.
    assert!(
        !calls.iter().any(|call| matches!(call, ClusterCall::Rollback { .. })),
        "a step that claims a revert must have asked the target to perform one, but the target \
         recorded no rollback across every run: {calls:?}",
    );
}
