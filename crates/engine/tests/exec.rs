//! The executor, end to end on `FakeClock`: every step scripted, so timeouts, cancellation,
//! retries, skipping and rollback are all instant and their costs are exact clock arithmetic.

use std::collections::HashMap;
use std::future::{Future, poll_fn};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Duration, SystemTime};

use ks_core::ports::BoxFuture;
use ks_core::ports::clock::Clock;
use ks_core::step::{ActionKind, CancellationToken};
use ks_engine::exec::{
    Attempt, CANCEL_POLL, ExecError, ExecOptions, PlannedStep, Retry, RunLog, RunStatus,
    StepRunner, StepStatus, default_timeout, execute,
};
use ks_testing::{block_on, clock::FakeClock};

const MINUTE: Duration = Duration::from_secs(60);

/// What a scripted step does when it is run.
#[derive(Clone)]
enum Behaviour {
    Succeed,
    Fail(&'static str),
    /// Burns `by` on the fake clock — the step's own work — then succeeds.
    Slow(Duration),
    /// Never returns and never looks at its token: the executor must time it out.
    Hang,
    /// Cancels the run's token, then never returns: a step that will not stop.
    CancelThenHang,
    /// Cancels the run's token, then waits for the executor to cancel the attempt's token
    /// before giving up — what a process with a `SIGTERM` handler does.
    CancelSafe,
    Waiting,
    Refused(&'static str),
}

/// A runner whose every step is scripted, counting calls and rollbacks. `StepRunner` is
/// `Send + Sync`, so the state is behind a mutex; `block_on` never moves between threads.
struct Scripted {
    clock: Arc<FakeClock>,
    cancel: CancellationToken,
    /// What each step does on its first run, its second, and so on; the last entry repeats.
    script: Mutex<HashMap<String, Vec<Behaviour>>>,
    /// How many times each step was run.
    calls: Mutex<HashMap<String, u32>>,
    rollbacks: Mutex<Vec<String>>,
    rollback_fails: bool,
}

impl Scripted {
    fn new(clock: Arc<FakeClock>, cancel: CancellationToken) -> Scripted {
        Scripted {
            clock,
            cancel,
            script: Mutex::new(HashMap::new()),
            calls: Mutex::new(HashMap::new()),
            rollbacks: Mutex::new(Vec::new()),
            rollback_fails: false,
        }
    }

    /// How many times the executor ran `id`. Zero means it never started.
    fn calls(&self, id: &str) -> u32 {
        self.calls.lock().expect("calls").get(id).copied().unwrap_or(0)
    }

    fn rollbacks(&self) -> Vec<String> {
        self.rollbacks.lock().expect("rollbacks").clone()
    }

    /// The nth run's behaviour, counting from 1.
    fn next(&self, id: &str) -> Behaviour {
        let mut calls = self.calls.lock().expect("calls");
        let nth = calls.entry(id.to_string()).or_default();
        let behaviour = {
            let script = self.script.lock().expect("script");
            let queue = script.get(id).unwrap_or_else(|| panic!("nothing scripted for {id:?}"));
            match queue.get(*nth as usize).or_else(|| queue.last()) {
                Some(behaviour) => behaviour.clone(),
                None => panic!("{id:?} has no behaviour scripted"),
            }
        };
        *nth += 1;
        behaviour
    }
}

impl StepRunner for Scripted {
    fn run<'a>(
        &'a self,
        step: &'a PlannedStep,
        _attempt: u32,
        cancel: &'a CancellationToken,
    ) -> BoxFuture<'a, Attempt> {
        let behaviour = self.next(&step.id);
        let clock = Arc::clone(&self.clock);
        let run = self.cancel.clone();
        Box::pin(async move {
            match behaviour {
                Behaviour::Succeed => Attempt::Succeeded,
                Behaviour::Fail(why) => Attempt::Failed(why.to_string()),
                Behaviour::Slow(by) => {
                    block_on(clock.sleep(by));
                    Attempt::Succeeded
                }
                Behaviour::Hang => std::future::pending().await,
                Behaviour::CancelThenHang => {
                    run.cancel();
                    std::future::pending().await
                }
                Behaviour::CancelSafe => {
                    run.cancel();
                    poll_fn(|_| match cancel.is_cancelled() {
                        true => Poll::Ready(Attempt::Cancelled),
                        false => Poll::Pending,
                    })
                    .await
                }
                Behaviour::Waiting => Attempt::WaitingForApproval,
                Behaviour::Refused(rule) => Attempt::PolicyRefused(rule.to_string()),
            }
        })
    }

    fn rollback<'a>(&'a self, step: &'a PlannedStep) -> BoxFuture<'a, Result<(), String>> {
        let fails = self.rollback_fails;
        self.rollbacks.lock().expect("rollbacks").push(step.id.clone());
        Box::pin(async move {
            match fails {
                true => Err(format!("no credentials for {}", step.id)),
                false => Ok(()),
            }
        })
    }
}

/// The harness: one clock, one run token and one scripted runner, shared by everything a test
/// drives at once — a step burning time, a step cancelling the run, the executor's own timers.
struct Run {
    clock: Arc<FakeClock>,
    cancel: CancellationToken,
    runner: Scripted,
}

impl Run {
    fn new() -> Run {
        let clock = Arc::new(FakeClock::new());
        let cancel = CancellationToken::new();
        let runner = Scripted::new(Arc::clone(&clock), cancel.clone());
        Run { clock, cancel, runner }
    }

    fn script(self, id: &str, behaviours: &[Behaviour]) -> Run {
        self.runner.script.lock().expect("script").insert(id.to_string(), behaviours.to_vec());
        self
    }

    /// Rollback reports a failure, as a rollback that could not reach the environment would.
    fn failing_rollback(mut self) -> Run {
        self.runner.rollback_fails = true;
        self
    }

    fn execute(&self, steps: &[PlannedStep], options: ExecOptions) -> Result<RunLog, ExecError> {
        block_on(execute(steps, &self.runner, &*self.clock, &self.cancel, options))
    }

    fn ok(&self, steps: &[PlannedStep]) -> RunLog {
        self.execute(steps, ExecOptions::default()).expect("the plan is valid")
    }
}

fn step(id: &str, action: ActionKind) -> PlannedStep {
    PlannedStep::new(id, "test.step", action)
}

fn status(log: &RunLog, id: &str) -> StepStatus {
    log.step(id).unwrap_or_else(|| panic!("no record for {id:?}")).status
}

fn reason(log: &RunLog, id: &str) -> String {
    log.step(id).and_then(|record| record.reason.clone()).unwrap_or_default()
}

#[test]
fn a_step_that_overruns_its_own_timeout_is_timed_out_and_its_dependants_skipped() {
    let run = Run::new()
        .script("plan", &[Behaviour::Slow(20 * MINUTE)])
        .script("ship", &[Behaviour::Succeed]);
    let steps = vec![
        step("plan", ActionKind::Plan).timeout(5 * MINUTE),
        step("apply", ActionKind::Apply).needs(["plan"]),
        step("ship", ActionKind::Other),
    ];

    let log = run.ok(&steps);

    assert_eq!(status(&log, "plan"), StepStatus::TimedOut);
    assert_eq!(reason(&log, "plan"), "timed out after 300s");
    assert_eq!(status(&log, "apply"), StepStatus::Skipped);
    assert_eq!(reason(&log, "apply"), "plan did not succeed");
    // The unrelated branch still ran.
    assert_eq!(status(&log, "ship"), StepStatus::Succeeded);
    assert_eq!(log.status, RunStatus::Failed);
    assert_eq!(log.exit_code(), 1);
    assert_eq!(run.runner.calls("apply"), 0);
}

#[test]
fn a_step_with_no_timeout_gets_the_default_for_its_action() {
    let run = Run::new().script("read", &[Behaviour::Hang]);
    let steps = vec![step("read", ActionKind::ReadSecrets)];

    let log = run.ok(&steps);

    assert_eq!(status(&log, "read"), StepStatus::TimedOut);
    assert_eq!(reason(&log, "read"), "timed out after 60s");
}

#[test]
fn a_step_that_will_not_stop_is_timed_out_and_dropped_after_the_grace_period() {
    let run = Run::new().script("build", &[Behaviour::Hang]);
    let steps = vec![step("build", ActionKind::Build)];

    let log = run.ok(&steps);

    assert_eq!(status(&log, "build"), StepStatus::TimedOut);
    assert_eq!(log.step("build").expect("a record").attempts, 1);
    // The deadline was walked in CANCEL_POLL slices — so a step that never yields still lets
    // the executor re-read the run's token every second — and no sleep overshoots it. The grace
    // after it is one more.
    let budget = default_timeout(ActionKind::Build);
    let ticks = run.clock.sleeps().iter().filter(|s| **s == CANCEL_POLL).count();
    assert_eq!(ticks as u64 * CANCEL_POLL.as_secs(), budget.as_secs());
    assert_eq!(run.clock.elapsed_since_start(), budget + ExecOptions::default().grace);
}

#[test]
fn the_run_timeout_stops_scheduling_and_fails_the_run() {
    let run = Run::new().script("build", &[Behaviour::Hang]).script("ship", &[Behaviour::Succeed]);
    let steps =
        vec![step("build", ActionKind::Build), step("ship", ActionKind::Deploy).needs(["build"])];
    let options = ExecOptions { run_timeout: 5 * MINUTE, ..ExecOptions::default() };

    let log = run.execute(&steps, options).expect("the plan is valid");

    assert_eq!(status(&log, "build"), StepStatus::TimedOut);
    assert_eq!(reason(&log, "build"), "run timed out");
    assert_eq!(status(&log, "ship"), StepStatus::Cancelled);
    assert_eq!(reason(&log, "ship"), "run timed out");
    assert_eq!(run.runner.calls("ship"), 0);
    // A run out of time failed. It was not cancelled — nothing asked it to stop, and the steps
    // the timeout left behind do not make it look as though it was.
    assert_eq!(log.status, RunStatus::Failed);
    assert_eq!(log.exit_code(), 1);
}

#[test]
fn a_cancelled_step_that_gives_up_leaves_the_rest_of_the_run_cancelled() {
    let run =
        Run::new().script("build", &[Behaviour::CancelSafe]).script("ship", &[Behaviour::Succeed]);
    let steps = vec![
        step("build", ActionKind::Build),
        step("ship", ActionKind::Deploy).needs(["build"]),
        step("after", ActionKind::Other),
    ];

    let log = run.ok(&steps);

    assert_eq!(status(&log, "build"), StepStatus::Cancelled);
    // Cancellation is checked before the dependency check, so everything unstarted is
    // cancelled rather than skipped — it will not run either way.
    assert_eq!(status(&log, "ship"), StepStatus::Cancelled);
    assert_eq!(status(&log, "after"), StepStatus::Cancelled);
    assert_eq!(log.status, RunStatus::Cancelled);
    assert_eq!(log.exit_code(), 130);
    assert_eq!(run.runner.calls("after"), 0, "nothing runs after a cancellation");
    // It gave up as soon as it was told to: no grace was spent waiting for it.
    assert_eq!(run.clock.elapsed_since_start(), Duration::ZERO);
}

#[test]
fn a_cancelled_step_that_ignores_its_token_is_dropped_after_the_grace_period() {
    let run = Run::new().script("build", &[Behaviour::CancelThenHang]);
    let steps = vec![step("build", ActionKind::Build)];

    let log = run.ok(&steps);

    assert_eq!(status(&log, "build"), StepStatus::Cancelled);
    assert_eq!(run.clock.elapsed_since_start(), ExecOptions::default().grace, "the grace, no more");
}

#[test]
fn a_run_cancelled_before_the_first_step_runs_nothing() {
    let run = Run::new().script("build", &[Behaviour::Succeed]);
    run.cancel.cancel();
    let steps = vec![step("build", ActionKind::Build), step("ship", ActionKind::Deploy)];

    let log = run.ok(&steps);

    assert_eq!(status(&log, "build"), StepStatus::Cancelled);
    assert_eq!(status(&log, "ship"), StepStatus::Cancelled);
    assert_eq!(reason(&log, "ship"), "cancelled");
    assert_eq!(run.runner.calls("build"), 0);
    assert_eq!(log.exit_code(), 130);
}

#[test]
fn a_retry_gets_the_whole_timeout_again() {
    let backoff = Duration::from_secs(5);
    let run = Run::new().script("build", &[Behaviour::Fail("flaky"), Behaviour::Succeed]);
    let steps = vec![
        step("build", ActionKind::Build)
            .timeout(Duration::from_secs(10))
            .idempotent()
            .retry(Retry::new(1, backoff)),
    ];

    let log = run.ok(&steps);

    // The first attempt's deadline has long passed when the second one starts; a retry is a
    // fresh run of the step, not the remainder of what the last one left.
    assert_eq!(status(&log, "build"), StepStatus::Succeeded);
    assert_eq!(log.step("build").expect("a record").attempts, 2);
    assert_eq!(run.runner.calls("build"), 2);
    assert_eq!(run.clock.sleeps(), vec![backoff], "the backoff, and nothing else");
}

#[test]
fn a_failed_step_is_retried_and_the_backoffs_are_recorded() {
    let backoff = Duration::from_secs(5);
    let run = Run::new().script(
        "build",
        &[Behaviour::Fail("registry 503"), Behaviour::Fail("registry 503"), Behaviour::Succeed],
    );
    let steps = vec![
        step("build", ActionKind::Build)
            .timeout(Duration::from_secs(30))
            .idempotent()
            .retry(Retry::new(2, backoff)),
    ];

    let log = run.ok(&steps);

    assert_eq!(status(&log, "build"), StepStatus::Succeeded);
    assert_eq!(log.step("build").expect("a record").attempts, 3);
    // The clock is the run's record: two waits, and nothing else. A step that returns without
    // suspending never arms a deadline timer.
    assert_eq!(run.clock.sleeps(), vec![backoff, backoff]);
}

#[test]
fn a_step_that_cannot_safely_be_run_twice_is_run_once() {
    let retry = Retry::new(3, Duration::from_secs(1));
    // Each of these declares three retries; none of them is retried even so.
    let unsafe_to_retry = [
        step("push", ActionKind::Other).retry(retry), // not idempotent
        PlannedStep::new("apply", "tofu.apply", ActionKind::Other).idempotent().retry(retry),
        PlannedStep::new("roll", "ship.ks.apply", ActionKind::Apply).idempotent().retry(retry),
        PlannedStep::new("down", "ship.ks.destroy", ActionKind::Destroy).idempotent().retry(retry),
    ];

    for step in unsafe_to_retry {
        let id = step.id.clone();
        let run = Run::new().script(&id, &[Behaviour::Fail("boom"), Behaviour::Succeed]);
        let log = run.ok(&[step]);
        assert_eq!(status(&log, &id), StepStatus::Failed, "{id} is not retried");
        assert_eq!(run.runner.calls(&id), 1, "{id} runs once");
    }

    // A rebuild with the declarations above is retried, so the rule is not "never".
    let run = Run::new().script("build", &[Behaviour::Fail("boom"), Behaviour::Succeed]);
    let log = run.ok(&[step("build", ActionKind::Build).idempotent().retry(retry)]);
    assert_eq!(status(&log, "build"), StepStatus::Succeeded);
}

#[test]
fn a_refusal_is_not_retried() {
    let run =
        Run::new().script("apply", &[Behaviour::Refused("needs an approval"), Behaviour::Succeed]);
    let steps = vec![
        step("apply", ActionKind::Other).idempotent().retry(Retry::new(3, Duration::from_secs(1))),
    ];

    let log = run.ok(&steps);

    assert_eq!(status(&log, "apply"), StepStatus::PolicyRefused);
    assert_eq!(reason(&log, "apply"), "needs an approval");
    assert_eq!(run.runner.calls("apply"), 1);
    assert_eq!(log.exit_code(), 5);
}

#[test]
fn a_failure_skips_its_dependants_transitively_and_nothing_else() {
    let run = Run::new()
        .script("build", &[Behaviour::Fail("no image")])
        .script("push", &[Behaviour::Succeed])
        .script("deploy", &[Behaviour::Succeed])
        .script("audit", &[Behaviour::Succeed]);
    let steps = vec![
        step("build", ActionKind::Build),
        step("push", ActionKind::Build).needs(["build"]),
        step("deploy", ActionKind::Deploy).needs(["push"]),
        step("audit", ActionKind::Other),
    ];

    let log = run.ok(&steps);

    assert_eq!(status(&log, "build"), StepStatus::Failed);
    assert_eq!(status(&log, "push"), StepStatus::Skipped);
    assert_eq!(status(&log, "deploy"), StepStatus::Skipped);
    assert_eq!(reason(&log, "deploy"), "push did not succeed");
    assert_eq!(status(&log, "audit"), StepStatus::Succeeded);
    assert_eq!(run.runner.calls("deploy"), 0, "a dependant never starts");
}

#[test]
fn fail_fast_skips_the_branch_that_would_have_run() {
    let run = Run::new()
        .script("build", &[Behaviour::Fail("no image")])
        .script("audit", &[Behaviour::Succeed]);
    let steps = vec![step("build", ActionKind::Build), step("audit", ActionKind::Other)];
    let options = ExecOptions { fail_fast: true, ..ExecOptions::default() };

    let log = run.execute(&steps, options).expect("the plan is valid");

    assert_eq!(status(&log, "audit"), StepStatus::Skipped);
    assert_eq!(reason(&log, "audit"), "fail-fast");
    assert_eq!(run.runner.calls("audit"), 0);
    assert_eq!(log.status, RunStatus::Failed);
}

#[test]
fn only_a_deploy_that_did_not_land_is_rolled_back() {
    for (behaviour, rolled_back) in [
        (Behaviour::Fail("no capacity"), true),
        (Behaviour::Slow(20 * MINUTE), true),
        (Behaviour::Succeed, false),
    ] {
        let run = Run::new()
            .script("deploy", &[behaviour])
            .script("build", &[Behaviour::Fail("no image")]);
        let steps = vec![
            step("deploy", ActionKind::Deploy).timeout(5 * MINUTE),
            step("build", ActionKind::Build),
        ];

        let log = run.ok(&steps);

        let record = log.step("deploy").expect("a record");
        match rolled_back {
            true => {
                assert_eq!(record.rollback, Some(Ok(())), "a deploy that did not land rolls back");
                assert_eq!(run.runner.rollbacks(), vec!["deploy"]);
            }
            false => assert_eq!(record.rollback, None, "a deploy that landed is not rolled back"),
        }
        assert_eq!(log.step("build").expect("a record").rollback, None, "only a deploy rolls back");
    }
}

#[test]
fn a_rollback_that_could_not_finish_is_reported_on_the_step() {
    let run = Run::new().script("deploy", &[Behaviour::Fail("no capacity")]).failing_rollback();
    let steps = vec![step("deploy", ActionKind::Deploy)];

    let log = run.ok(&steps);

    assert_eq!(
        log.step("deploy").expect("a record").rollback,
        Some(Err("no credentials for deploy".to_string()))
    );
}

#[test]
fn a_step_waiting_for_an_approval_is_not_a_failure() {
    let run =
        Run::new().script("deploy", &[Behaviour::Waiting]).script("notify", &[Behaviour::Succeed]);
    let steps = vec![
        step("deploy", ActionKind::Deploy),
        step("notify", ActionKind::Other).needs(["deploy"]),
    ];

    let log = run.ok(&steps);

    assert_eq!(status(&log, "deploy"), StepStatus::WaitingForApproval);
    assert_eq!(status(&log, "notify"), StepStatus::Skipped);
    assert_eq!(log.status, RunStatus::WaitingForApproval);
    assert_eq!(log.exit_code(), 4, "waiting is not failing: nothing broke, nothing was refused");
}

#[test]
fn a_cancelled_run_outranks_every_other_outcome() {
    let run = Run::new()
        .script("build", &[Behaviour::Fail("no image")])
        .script("audit", &[Behaviour::CancelSafe]);
    let steps = vec![step("build", ActionKind::Build), step("audit", ActionKind::Other)];

    let log = run.ok(&steps);

    assert_eq!(status(&log, "build"), StepStatus::Failed);
    assert_eq!(status(&log, "audit"), StepStatus::Cancelled);
    assert_eq!(log.status, RunStatus::Cancelled);
    assert_eq!(log.exit_code(), 130);
}

#[test]
fn an_invalid_plan_is_rejected_before_anything_runs() {
    let run = Run::new().script("a", &[Behaviour::Succeed]);
    let unknown = vec![step("a", ActionKind::Other).needs(["ghost"])];
    let forward = vec![step("a", ActionKind::Other).needs(["b"]), step("b", ActionKind::Other)];
    let duplicate =
        vec![step("a", ActionKind::Other), PlannedStep::new("a", "test.step", ActionKind::Other)];

    assert_eq!(
        run.execute(&unknown, ExecOptions::default()),
        Err(ExecError::UnknownNeed { step: "a".to_string(), needs: "ghost".to_string() })
    );
    assert_eq!(
        run.execute(&forward, ExecOptions::default()),
        Err(ExecError::ForwardNeed { step: "a".to_string(), needs: "b".to_string() })
    );
    assert_eq!(
        run.execute(&duplicate, ExecOptions::default()),
        Err(ExecError::DuplicateId { id: "a".to_string() })
    );
    assert_eq!(run.runner.calls("a"), 0, "a plan the executor refuses runs nothing");
    assert!(run.clock.sleeps().is_empty(), "and does not touch the clock");
}

/// The tables in docs/CLI.md are the contract; this keeps them from drifting away from the code.
#[test]
fn the_documented_exit_codes_and_deadlines_are_the_ones_in_force() {
    let cli = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/CLI.md"));

    for status in [
        RunStatus::Succeeded,
        RunStatus::Failed,
        RunStatus::Cancelled,
        RunStatus::WaitingForApproval,
        RunStatus::PolicyRefused,
    ] {
        let documented = cli.lines().filter(|line| line.starts_with('|')).any(|line| {
            line.contains(&format!("| {} |", status.exit_code())) && line.contains(status.as_str())
        });
        assert!(
            documented,
            "docs/CLI.md has no exit-code row for `{}` ({})",
            status.as_str(),
            status.exit_code()
        );
    }

    // `| `build` | 30m |` and its six siblings: the default timeout for each action.
    let deadlines: HashMap<&str, Duration> = cli
        .lines()
        .filter_map(|line| {
            let (name, rest) = line.trim().strip_prefix("| `")?.split_once("` | ")?;
            Some((name, minutes(rest.split('|').next()?.trim())))
        })
        .collect();
    let actions = [
        ActionKind::Build,
        ActionKind::Plan,
        ActionKind::Apply,
        ActionKind::Deploy,
        ActionKind::Destroy,
        ActionKind::ReadSecrets,
        ActionKind::Other,
    ];
    assert_eq!(deadlines.len(), actions.len(), "docs/CLI.md documents one timeout per action");
    for action in actions {
        assert_eq!(
            deadlines.get(action.as_str()),
            Some(&default_timeout(action)),
            "docs/CLI.md has the wrong default timeout for {}",
            action.as_str()
        );
    }
}

/// `30m` in a table cell: seconds, minutes or hours, to the `Duration` it means.
fn minutes(cell: &str) -> Duration {
    let split = cell.find(|c: char| !c.is_ascii_digit()).unwrap_or(cell.len());
    let (number, unit) = cell.split_at(split);
    let number: u64 = number.parse().expect("a duration in the table");
    match unit.trim() {
        "s" => Duration::from_secs(number),
        "m" => Duration::from_secs(number * 60),
        "h" => Duration::from_secs(number * 60 * 60),
        other => panic!("{other:?} is not a duration this table uses"),
    }
}

/// A clock whose every sleep is pending once and ready on the next poll — so each slice costs
/// two polls — and which counts the timers that exist right now. A `Pending` poll with no live
/// timer is the executor having parked with nothing left to wake it: `block_on` spins straight
/// past that, a real executor hangs on it forever.
struct Stingy {
    elapsed: Mutex<Duration>,
    live: Arc<AtomicUsize>,
}

/// One sleep's existence, from the call that created it to the future being dropped.
struct Held(Arc<AtomicUsize>);

impl Drop for Held {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Clock for Stingy {
    fn now(&self) -> SystemTime {
        FakeClock::default_start() + *self.elapsed.lock().expect("clock")
    }

    fn sleep<'a>(&'a self, by: Duration) -> BoxFuture<'a, ()> {
        self.live.fetch_add(1, Ordering::SeqCst);
        let held = Held(Arc::clone(&self.live));
        let elapsed = &self.elapsed;
        Box::pin(async move {
            let _held = held;
            let mut first = true;
            poll_fn(move |cx| {
                if std::mem::replace(&mut first, false) {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                *elapsed.lock().expect("clock") += by;
                Poll::Ready(())
            })
            .await;
        })
    }
}

#[test]
fn a_step_that_never_yields_still_leaves_a_live_timer_behind() {
    let clock = Arc::new(Stingy {
        elapsed: Mutex::new(Duration::ZERO),
        live: Arc::new(AtomicUsize::new(0)),
    });
    let cancel = CancellationToken::new();
    let runner = Scripted::new(Arc::new(FakeClock::new()), cancel.clone());
    runner.script.lock().expect("script").insert("build".to_string(), vec![Behaviour::Hang]);
    let steps = vec![step("build", ActionKind::Build)];

    let mut run = Box::pin(execute(&steps, &runner, &*clock, &cancel, ExecOptions::default()));
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);

    for slice in 1..=8u64 {
        assert!(run.as_mut().poll(&mut cx).is_pending(), "the step hangs, so every poll parks");
        assert!(
            clock.live.load(Ordering::SeqCst) > 0,
            "slice {slice} returned Pending with no live timer: nothing left to wake the task"
        );
    }
}
