//! The deploy conformance scenario: the *fails health → rolls back → reports* story every deploy
//! step must tell ([#78](https://github.com/Keep-Shipping/harness/issues/78)).
//!
//! One health vocabulary ([`Health`]) and one rollback vocabulary ([`RollbackPolicy`]) are only
//! one answer if every target gives the *same* answer. A cluster rollout, a shell deploy and a
//! function publish each have their own idea
//! of what "up" means and of what a rollback can reach, and nothing in the vocabulary stops one of
//! them from answering differently. So the vocabulary is checked from the outside, by a scenario
//! that drives a deploy step through the real executor and reads the run log that comes out.
//!
//! # Why it lives here and not in the kit
//!
//! `ks_testing::step` holds the other conformance kits, and a deploy step's scenario belongs beside
//! it in spirit — but a rollback is performed by [`StepRunner::rollback`], which lives in the
//! executor, and `ks-testing` deliberately depends on `ks-core` alone so that a conformance kit
//! never depends on the engine it tests. A scenario that has to exercise a real rollback therefore
//! cannot live there. It lives here, next to the executor it drives, and every deploy step's own
//! tests call it.
//!
//! # What it proves, and what it cannot
//!
//! The scenario asserts on the [`RunLog`] the executor produces and on the events a [`Journal`]
//! writes, which is the only evidence a reader of a run ever gets. It cannot see inside a target:
//! that a `manual` rollback really left the cluster alone, or that an `auto` rollback asked the
//! right revision, is the adapter's promise, checked by that adapter's own port kit — though a step
//! under test can see it for itself, since the scenario hands it a fresh runner per run. What the
//! scenario pins is the half that every step could otherwise get wrong on its own — treating
//! silence as health, and reporting a version the target never reached.
//!
//! The third of that family it deliberately does **not** pin, and the boundary is worth stating
//! plainly: a step whose `rollback` returns `reverted` *without ever asking the target* writes a
//! run log that is byte-for-byte the one an honest step writes. A run log records what a step
//! *claims* happened, so no assertion over it can tell the two apart. Catching that is the step's
//! own job — its tests hold a target that records what it was told — which is exactly why
//! [`deploy_conformance`] takes `target` as a closure the caller builds, rather than a target it
//! owns.
//!
//! # Panics
//!
//! It panics on violation rather than returning a `Result`, as the rest of the conformance kits do:
//! a conformance run is a test, and the message naming the broken contract is the whole output.

use std::fmt;
use std::sync::{Arc, Mutex};

use ks_core::ids::RunId;
use ks_core::ports::BoxFuture;
use ks_core::ports::clock::Clock;
use ks_core::ports::health::Health;
use ks_core::ports::run_log::{RunEvent, RunLog as RunLogPort, RunLogError};
use ks_core::ports::secrets::Redactor;
use ks_core::step::{ActionKind, CancellationToken, Rollback, RollbackPolicy, RollbackStatus};

use crate::exec::{
    ExecOptions, PlannedStep, RunLog, RunStatus, StepRecord, StepRunner, StepStatus, execute,
};
use crate::journal::Journal;

/// Which half of the story a run is playing: a target that never comes up, or one that does.
///
/// The step under test is handed this so its tests can hand it the right
/// [`health`](DeployCase::health) script — the *behaviour* is the same either way, only what the
/// target reports differs. A step that reads the beat and answers differently is exactly the thing
/// this scenario exists to catch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Beat {
    /// The target never reports [`Health::Healthy`], so the deploy fails its health gate.
    Unhealthy,
    /// The target settles on [`Health::Healthy`], so the deploy lands.
    Healthy,
}

/// One deploy step's conformance scenario: what the step is called, what its target reports, and
/// where a rollback of it ends up.
///
/// Build one with [`DeployCase::new`], then override the scripted health if the step's own tests
/// want a specific transition ([`with_never_healthy`](DeployCase::with_never_healthy),
/// [`with_landing_health`](DeployCase::with_landing_health)).
///
/// The defaults are the load-bearing ones: a target that reports [`Health::NoData`] forever, and a
/// target that walks [`Health::Progressing`] to [`Health::Healthy`]. Silence is the interesting
/// case — it is what a newly-created workload, an endpoint unreachable behind a load balancer and a
/// probe that never ran all look like, and a step that reads it as success reports a deploy that
/// served nothing.
///
/// `Debug` prints names and states, never a version value's surroundings, so a failure can be
/// pasted into a bug report as it stands.
#[derive(Clone)]
pub struct DeployCase {
    id: String,
    kind: &'static str,
    never_healthy: Vec<Health>,
    landing: Vec<Health>,
    good_version: String,
}

impl DeployCase {
    /// Describes the deploy step named `id`, of kind `kind`, whose target went back to
    /// `good_version` when it was rolled back.
    ///
    /// `good_version` is what a reader of the run log is owed — the version traffic actually went
    /// back to — so it is required here rather than defaulted: a scenario with no version to
    /// compare against would prove nothing about the half of the contract that matters most.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        kind: &'static str,
        good_version: impl Into<String>,
    ) -> DeployCase {
        DeployCase {
            id: id.into(),
            kind,
            never_healthy: vec![Health::NoData],
            landing: vec![Health::Progressing, Health::Healthy],
            good_version: good_version.into(),
        }
    }

    /// The states the target reports on the [`Beat::Unhealthy`] half, in order; the last repeats.
    #[must_use]
    pub fn with_never_healthy(self, states: impl IntoIterator<Item = Health>) -> DeployCase {
        DeployCase { never_healthy: states.into_iter().collect(), ..self }
    }

    /// The states a landing target walks through, in order; the last repeats.
    #[must_use]
    pub fn with_landing_health(self, states: impl IntoIterator<Item = Health>) -> DeployCase {
        DeployCase { landing: states.into_iter().collect(), ..self }
    }

    /// The step id the plan carries.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The step kind the plan carries, e.g. `"k8s.rollout"`.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        self.kind
    }

    /// The version a rollback of this step must report: where the target says traffic went.
    #[must_use]
    pub fn good_version(&self) -> &str {
        &self.good_version
    }

    /// What the target reports on this `beat`. A step's own tests hand this straight to their fake:
    /// `FakeCluster::with_health_script` and its equivalents take exactly this iterator.
    #[must_use]
    pub fn health(&self, beat: Beat) -> Vec<Health> {
        match beat {
            Beat::Unhealthy => self.never_healthy.clone(),
            Beat::Healthy => self.landing.clone(),
        }
    }

    /// The one-step plan the scenario runs: always a [`Deploy`](ActionKind::Deploy), because a
    /// step that is not a deploy has nothing to roll back and nothing here would apply to it.
    ///
    /// `policy` is the [`RollbackPolicy`] under test; the scenario runs the step under all three.
    #[must_use]
    pub fn step(&self, policy: RollbackPolicy) -> PlannedStep {
        PlannedStep::new(&self.id, self.kind, ActionKind::Deploy).rollback(policy)
    }
}

impl fmt::Debug for DeployCase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeployCase")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("never_healthy", &self.never_healthy)
            .field("landing", &self.landing)
            .field("good_version", &self.good_version)
            .finish()
    }
}

/// A [`RunLog`] that keeps every event it is handed, in order.
///
/// The scenario needs to read what the run log carries, so it needs a log it can read back; there
/// is no such port, and appending is the only thing a port can do — so the kit brings its own.
/// `ks-testing` has one too and cannot be used from here: it is a dev-dependency, and this module
/// is the library a step's own tests link against.
///
/// `Debug` prints the entry count only, so a run's log never becomes a way to print one.
#[derive(Default)]
pub struct RecordedRun {
    events: Mutex<Vec<RunEvent>>,
}

impl RecordedRun {
    /// Creates an empty log.
    #[must_use]
    pub fn new() -> RecordedRun {
        RecordedRun::default()
    }

    /// Every event so far, in the order it arrived.
    #[must_use]
    pub fn events(&self) -> Vec<RunEvent> {
        self.events.lock().expect("recorded run poisoned").clone()
    }
}

impl RunLogPort for RecordedRun {
    fn append<'a>(
        &'a self,
        _run: &'a RunId,
        event: RunEvent,
    ) -> BoxFuture<'a, Result<(), RunLogError>> {
        self.events.lock().expect("recorded run poisoned").push(event);
        Box::pin(std::future::ready(Ok(())))
    }
}

impl fmt::Debug for RecordedRun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.events.lock().expect("recorded run poisoned").len();
        f.debug_struct("RecordedRun").field("events", &count).finish()
    }
}

/// The deploy conformance scenario. Panics, with a message naming the broken contract, when the
/// deploy step under test violates one of:
///
/// - a deploy whose target never reports [`Health::Healthy`] is **not** recorded as succeeded, and
///   carries a reason — [`Health::NoData`] is not health, and a step that reads silence as success
///   reports a deploy that served nothing;
/// - under [`RollbackPolicy::Auto`] it is recorded as `reverted`, carrying the version its target
///   says traffic went back to — the one the case names, never the version the step meant to reach;
/// - under [`RollbackPolicy::Manual`] nothing is changed and the step records a `pending` rollback
///   with no version, because nothing was reached;
/// - under [`RollbackPolicy::None`] nothing is recorded at all — not a pending rollback, which would
///   claim a rollback is outstanding when none was ever begun;
/// - every recorded rollback reaches the run log as exactly one
///   [`step.rolled-back`](RunEvent::StepRolledBack) event carrying the policy, the status and that
///   version — and a policy that records nothing writes no event;
/// - a deploy whose target *does* report [`Health::Healthy`] is recorded as succeeded, records no
///   rollback and writes no event: a deploy that landed is not undone;
/// - asking for a human does not turn a failed deploy into a successful run.
///
/// `target` builds the step under test for one beat, wired to a target whose
/// [`health`](DeployCase::health) is the case's script for that beat. It is a closure rather than a
/// runner because each of the four runs needs its own target: a target that has already answered
/// these polls has a rollout in progress, and reusing it would prove nothing about the next policy.
///
/// `clock` is the [`Clock`] the executor reads; the step under test is not handed it, exactly as in
/// a real run, so a step that polls its target is wired to its own clock by its own tests.
///
/// ```
/// use std::sync::Arc;
///
/// use ks_core::ports::BoxFuture;
/// use ks_core::step::{CancellationToken, Rollback};
/// use ks_engine::exec::{Attempt, PlannedStep, StepRunner};
/// use ks_engine::rollback::{Beat, DeployCase, deploy_conformance};
/// use ks_testing::clock::FakeClock;
///
/// /// The smallest deploy step that could be proved: it fails its health gate, and its rollback
/// /// says where the target went.
/// struct Deploys(Beat);
///
/// impl StepRunner for Deploys {
///     fn run<'a>(
///         &'a self,
///         _step: &'a PlannedStep,
///         _attempt: u32,
///         _cancel: &'a CancellationToken,
///     ) -> BoxFuture<'a, Attempt> {
///         let landed = self.0 == Beat::Healthy;
///         Box::pin(std::future::ready(match landed {
///             true => Attempt::Succeeded,
///             false => Attempt::Failed("never became healthy".to_string()),
///         }))
///     }
///
///     fn rollback<'a>(
///         &'a self,
///         _step: &'a PlannedStep,
///     ) -> BoxFuture<'a, Result<Rollback, String>> {
///         Box::pin(std::future::ready(Ok(Rollback::reverted_to("api-41"))))
///     }
/// }
///
/// let clock = FakeClock::new();
/// let case = DeployCase::new("deploy", "k8s.rollout", "api-41");
///
/// ks_testing::block_on(deploy_conformance(&case, &clock, |_, beat| Deploys(beat)));
/// ```
pub async fn deploy_conformance<R, F>(case: &DeployCase, clock: &dyn Clock, target: F)
where
    R: StepRunner,
    F: Fn(&DeployCase, Beat) -> R,
{
    assert!(
        !case.good_version.is_empty(),
        "deploy conformance: the case must name the version a rollback reaches, or it proves \
         nothing about where traffic went"
    );
    assert!(
        !case.never_healthy.contains(&Health::Healthy),
        "deploy conformance: the {:?} beat's script reaches Healthy, so it is not a failing \
         health gate at all",
        Beat::Unhealthy,
    );

    for policy in [RollbackPolicy::Auto, RollbackPolicy::Manual, RollbackPolicy::None] {
        let runner = target(case, Beat::Unhealthy);
        let (log, recorded) = play(case, policy, &runner, clock).await;
        let record = record_of(&log, case.id());
        assert!(
            matches!(record.status, StepStatus::Failed | StepStatus::TimedOut),
            "deploy conformance: a target that never reported Healthy must not leave step {:?} \
             recorded as {:?} under {policy}",
            case.id(),
            record.status,
        );
        assert!(
            record.reason.is_some(),
            "deploy conformance: step {:?} failed its health gate with nothing to say why",
            case.id(),
        );
        assert_eq!(
            log.status,
            RunStatus::Failed,
            "deploy conformance: a deploy that did not land must fail the run under {policy}, even \
             where the rollback is waiting on a human",
        );

        match policy {
            RollbackPolicy::Auto => {
                let rollback = rollback_of(record, case.id(), policy);
                assert_eq!(
                    rollback.status(),
                    RollbackStatus::Reverted,
                    "deploy conformance: an auto rollback the target carried out is reverted, not \
                     pending and not failed",
                );
                assert_eq!(
                    rollback.reverted_to_version(),
                    Some(case.good_version()),
                    "deploy conformance: an auto rollback must report the version its target says \
                     traffic went back to ({:?}), never the version the step meant to reach",
                    case.good_version(),
                );
            }
            RollbackPolicy::Manual => {
                let rollback = rollback_of(record, case.id(), policy);
                assert_eq!(
                    rollback.status(),
                    RollbackStatus::Pending,
                    "deploy conformance: a manual rollback changes nothing and waits for a human, \
                     so it is recorded as pending",
                );
                assert_eq!(
                    rollback.reverted_to_version(),
                    None,
                    "deploy conformance: a manual rollback reached no version, so none may be \
                     reported — least of all the version that just failed",
                );
                assert_eq!(
                    rollback.reason(),
                    None,
                    "deploy conformance: a pending rollback has no failure to explain",
                );
            }
            RollbackPolicy::None => assert!(
                record.rollback.is_none(),
                "deploy conformance: a none rollback neither happens nor waits, so it records \
                 nothing at all — got {:?}",
                record.rollback,
            ),
        }

        // The last beat of the story: the outcome has to reach the run log, in its own event,
        // carrying the version traffic went back to. A rollback nobody can read is a rollback the
        // operator finds out about from the outage.
        let events = recorded.events();
        let expected = match record.rollback.as_ref() {
            None => Vec::new(),
            Some(rollback) => vec![(
                case.id().to_string(),
                policy.as_str().to_string(),
                rollback.status().as_str().to_string(),
                rollback.reverted_to_version().map(str::to_string),
                rollback.reason().map(str::to_string),
            )],
        };
        let written = events.iter().map(rolled_back).collect::<Vec<_>>();
        assert_eq!(
            written, expected,
            "deploy conformance: every rollback a step records must reach the run log as exactly \
             one step.rolled-back event carrying the policy, the status and the version traffic \
             went back to, under {policy}",
        );
    }

    let runner = target(case, Beat::Healthy);
    let (log, recorded) = play(case, RollbackPolicy::Auto, &runner, clock).await;
    let record = record_of(&log, case.id());
    assert_eq!(
        record.status,
        StepStatus::Succeeded,
        "deploy conformance: a target that reported Healthy must leave step {:?} recorded as \
         succeeded, not failed and rolled back",
        case.id(),
    );
    assert_eq!(record.reason, None, "deploy conformance: a landed deploy has nothing to explain");
    assert!(
        record.rollback.is_none(),
        "deploy conformance: a deploy that landed is not rolled back, whatever its policy says",
    );
    assert_eq!(
        log.status,
        RunStatus::Succeeded,
        "deploy conformance: a deploy that landed succeeds the run"
    );
    assert!(
        recorded.events().is_empty(),
        "deploy conformance: a deploy that landed rolls nothing back, so the run log must carry \
         no step.rolled-back event — got {:?}",
        recorded.events(),
    );
}

/// Runs the one-step plan and journals what came out, the way a production caller will.
///
/// `execute` has no journal to hand — it returns a [`RunLog`] and nothing writes to the run log
/// port yet — so this is where the two meet, and where the mapping is proved rather than asserted
/// at a wiring point that does not exist.
async fn play<R: StepRunner>(
    case: &DeployCase,
    policy: RollbackPolicy,
    runner: &R,
    clock: &dyn Clock,
) -> (RunLog, Arc<RecordedRun>) {
    let steps = [case.step(policy)];
    let log = execute(&steps, runner, clock, &CancellationToken::new(), ExecOptions::default())
        .await
        .unwrap_or_else(|error| {
            panic!("deploy conformance: the scenario's own plan is valid: {error}")
        });

    let recorded = Arc::new(RecordedRun::new());
    let journal = Journal::new(
        Arc::clone(&recorded) as Arc<dyn RunLogPort>,
        Arc::new(Redactor::new()),
        RunId::from_parts(0, 1),
    );
    for step_record in &log.steps {
        if let Some(rollback) = &step_record.rollback {
            journal.step_rolled_back(&step_record.id, policy, rollback).await.unwrap_or_else(
                |error| {
                    panic!("deploy conformance: the run log must accept a rollback event: {error}")
                },
            );
        }
    }
    (log, recorded)
}

/// The step's record, or the panic that says the executor dropped it.
fn record_of<'a>(log: &'a RunLog, id: &str) -> &'a StepRecord {
    log.step(id).unwrap_or_else(|| panic!("deploy conformance: no record for step {id:?}"))
}

/// The record's rollback, or the panic that says it never recorded one.
fn rollback_of(record: &StepRecord, id: &str, policy: RollbackPolicy) -> Rollback {
    record.rollback.clone().unwrap_or_else(|| {
        panic!("deploy conformance: step {id:?} recorded no rollback at all under {policy}")
    })
}

/// One [`RunEvent::StepRolledBack`] as the plain tuple the scenario compares — the event's own
/// `Debug` would work, but a tuple says which field is wrong in the message.
fn rolled_back(event: &RunEvent) -> (String, String, String, Option<String>, Option<String>) {
    match event {
        RunEvent::StepRolledBack { step, policy, status, reverted_to, reason } => {
            (step.clone(), policy.clone(), status.clone(), reverted_to.clone(), reason.clone())
        }
        other => panic!("deploy conformance: expected a step.rolled-back event, got {other:?}"),
    }
}
