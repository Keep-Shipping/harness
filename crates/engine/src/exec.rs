//! Running a planned run: timeouts, cancellation, retries, and what one step's outcome means for
//! everything downstream ([#41](https://github.com/Keep-Shipping/harness/issues/41)). Steps arrive
//! already ordered — ordering and parallelism belong to the planner
//! ([#40](https://github.com/Keep-Shipping/harness/issues/40)) — and every deadline, backoff and
//! timestamp is read from the [`Clock`] port, so a run's timing is a list of sleeps on
//! `ks-testing`'s `FakeClock`. What any of this means to an operator is in `docs/CLI.md`.
//!
//! Cancellation and timeouts are cooperative: a step that never yields cannot be interrupted
//! until it returns, and is then recorded as having overrun its deadline.

use std::collections::BTreeSet;
use std::fmt;
use std::future::poll_fn;
use std::task::Poll;
use std::time::{Duration, SystemTime};

use ks_core::ports::BoxFuture;
use ks_core::ports::clock::Clock;
use ks_core::step::{ActionKind, CancellationToken};

/// A step failed or ran out of time: exit 1, the code `check` has always used.
pub const EXIT_FAILED: u8 = 1;
/// The run stopped at an approval nobody gave: exit 10. A state, not a
/// failure — the run is parked, and an agent should report it rather than
/// retry. Shares its number with the CLI's `WAITING`.
pub const EXIT_WAITING_FOR_APPROVAL: u8 = 10;
/// Policy refused the run: exit 12. Shares its number with the CLI's
/// `REFUSED`.
pub const EXIT_POLICY_REFUSED: u8 = 12;
/// The run was cancelled (Ctrl-C, a cancelled CI job): 128 + `SIGINT`, as a shell reports it.
pub const EXIT_CANCELLED: u8 = 130;

/// How long the executor waits before looking at a step again.
///
/// A [`CancellationToken`] is a flag with no waker — nothing wakes the executor when the user
/// presses Ctrl-C. Re-arming the deadline timer in slices this long is what brings it back into
/// its poll loop to read the flag; the last slice is short enough that the timer never overshoots
/// the deadline.
pub const CANCEL_POLL: Duration = Duration::from_secs(1);

/// GitHub Actions' per-job cap: the default [`ExecOptions::run_timeout`].
const DEFAULT_RUN_TIMEOUT: Duration = Duration::from_secs(6 * 60 * 60);
/// How long a cancelled or timed-out step may keep running before it is dropped.
const DEFAULT_GRACE: Duration = Duration::from_secs(30);
/// Year 9999. Where a duration absurd enough to overflow `SystemTime` lands instead of a panic —
/// a bad number in a file must not read as an internal error.
const FAR_FUTURE: Duration = Duration::from_secs(253_402_300_799);

/// The step kind that mutates infrastructure through OpenTofu, and so is never retried
/// automatically: re-applying is not idempotent the way a rebuild is, and half an apply is worse
/// than none.
const TOFU_APPLY_KIND: &str = "tofu.apply";

/// How long a step of this action may run when the plan does not say otherwise. Generous enough
/// for a slow `tofu apply`, tight enough for reading a secret.
pub fn default_timeout(action: ActionKind) -> Duration {
    match action {
        ActionKind::Build => Duration::from_secs(30 * 60),
        ActionKind::Plan => Duration::from_secs(15 * 60),
        ActionKind::Apply => Duration::from_secs(60 * 60),
        ActionKind::Deploy => Duration::from_secs(30 * 60),
        ActionKind::Destroy => Duration::from_secs(60 * 60),
        ActionKind::ReadSecrets => Duration::from_secs(60),
        ActionKind::Other => Duration::from_secs(10 * 60),
    }
}

/// What one run of one step did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attempt {
    /// It did the thing.
    Succeeded,
    /// It failed, with the reason to show the operator.
    Failed(String),
    /// It stopped because the run was cancelled.
    Cancelled,
    /// It needs an approval that has not been given.
    WaitingForApproval,
    /// Policy refused it, with the rule that did.
    PolicyRefused(String),
}

/// Retries a step may take: `attempts` *extra* runs after the first, `backoff` fixed between
/// them. Only honoured for an idempotent step that is not `tofu.apply`, `Apply` or `Destroy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retry {
    pub attempts: u32,
    pub backoff: Duration,
}

impl Retry {
    /// `Retry::new(2, Duration::from_secs(5))` — up to three runs, five seconds apart.
    pub fn new(attempts: u32, backoff: Duration) -> Retry {
        Retry { attempts, backoff }
    }
}

/// One step of a plan, as the planner handed it over: identity, kind, what has to be done
/// first, and how long it may take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedStep {
    /// Unique within the run; what `needs` refers to.
    pub id: String,
    /// The step kind, e.g. `"tofu.apply"`. Only the name is read, for the retry rule.
    pub kind: String,
    /// What kind of thing it does: picks the default timeout and the rollback rule.
    pub action: ActionKind,
    /// Ids of steps that must have succeeded first. Each names an *earlier* step.
    pub needs: Vec<String>,
    /// This step's own cap, overriding the per-action default; the run's remaining time caps it
    /// either way. Each attempt gets the whole budget again.
    pub timeout: Option<Duration>,
    /// Retries, if this step takes them.
    pub retry: Option<Retry>,
    /// Whether running it twice is the same as running it once. Without this, a step runs once
    /// whatever it declares.
    pub idempotent: bool,
}

impl PlannedStep {
    /// A step with no needs, no cap and no retries.
    pub fn new(id: impl Into<String>, kind: impl Into<String>, action: ActionKind) -> PlannedStep {
        PlannedStep {
            id: id.into(),
            kind: kind.into(),
            action,
            needs: Vec::new(),
            timeout: None,
            retry: None,
            idempotent: false,
        }
    }

    pub fn needs<I, S>(mut self, needs: I) -> PlannedStep
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.needs = needs.into_iter().map(Into::into).collect();
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> PlannedStep {
        self.timeout = Some(timeout);
        self
    }

    pub fn retry(mut self, retry: Retry) -> PlannedStep {
        self.retry = Some(retry);
        self
    }

    pub fn idempotent(mut self) -> PlannedStep {
        self.idempotent = true;
        self
    }
}

/// How the run as a whole behaves. The default is the everyday run: every step gets its chance,
/// the whole thing gets six hours, and a step told to stop gets thirty seconds to notice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecOptions {
    /// After the first failure, stop: every unstarted step is skipped rather than run.
    pub fail_fast: bool,
    /// The cap on the whole run, six hours by default (GitHub's per-job cap).
    pub run_timeout: Duration,
    /// How long a cancelled or timed-out step keeps running before it is dropped.
    pub grace: Duration,
}

impl Default for ExecOptions {
    fn default() -> ExecOptions {
        ExecOptions { fail_fast: false, run_timeout: DEFAULT_RUN_TIMEOUT, grace: DEFAULT_GRACE }
    }
}

/// What one step is, once it is over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepStatus {
    Succeeded,
    Failed,
    /// It ran out of time and was dropped.
    TimedOut,
    /// The run was cancelled while it ran, or before it started.
    Cancelled,
    /// Something it needs did not succeed, so it never ran.
    Skipped,
    /// It stopped for an approval nobody has given.
    WaitingForApproval,
    /// Policy refused it.
    PolicyRefused,
}

impl StepStatus {
    /// Whether the step did not do its thing — the states that make dependants skip and, with
    /// `fail_fast`, the rest of the run too.
    fn is_failure(self) -> bool {
        matches!(self, StepStatus::Failed | StepStatus::TimedOut | StepStatus::PolicyRefused)
    }
}

/// The run's outcome, from the steps'. A skipped step does not speak for the run: its blocker
/// already did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunStatus {
    Succeeded,
    Failed,
    Cancelled,
    WaitingForApproval,
    PolicyRefused,
}

impl RunStatus {
    /// The exit code for this outcome: 0, [`EXIT_FAILED`], [`EXIT_CANCELLED`],
    /// [`EXIT_WAITING_FOR_APPROVAL`] or [`EXIT_POLICY_REFUSED`].
    pub fn exit_code(self) -> u8 {
        match self {
            RunStatus::Succeeded => 0,
            RunStatus::Failed => EXIT_FAILED,
            RunStatus::Cancelled => EXIT_CANCELLED,
            RunStatus::WaitingForApproval => EXIT_WAITING_FOR_APPROVAL,
            RunStatus::PolicyRefused => EXIT_POLICY_REFUSED,
        }
    }

    /// How the outcome is named in a run log and in `docs/CLI.md`.
    pub fn as_str(self) -> &'static str {
        match self {
            RunStatus::Succeeded => "succeeded",
            RunStatus::Failed => "failed",
            RunStatus::Cancelled => "cancelled",
            RunStatus::WaitingForApproval => "waiting_for_approval",
            RunStatus::PolicyRefused => "policy_refused",
        }
    }

    /// Precedence: a cancelled run is cancelled whatever else happened, and a run that failed is
    /// not still waiting for anything.
    fn rank(self) -> u8 {
        match self {
            RunStatus::Succeeded => 0,
            RunStatus::WaitingForApproval => 1,
            RunStatus::PolicyRefused => 2,
            RunStatus::Failed => 3,
            RunStatus::Cancelled => 4,
        }
    }

    fn merge(self, other: RunStatus) -> RunStatus {
        if other.rank() > self.rank() { other } else { self }
    }

    /// How one step speaks for the run. A skipped step has nothing to say.
    fn of_step(status: StepStatus) -> Option<RunStatus> {
        match status {
            StepStatus::Succeeded => Some(RunStatus::Succeeded),
            StepStatus::Failed | StepStatus::TimedOut => Some(RunStatus::Failed),
            StepStatus::Cancelled => Some(RunStatus::Cancelled),
            StepStatus::WaitingForApproval => Some(RunStatus::WaitingForApproval),
            StepStatus::PolicyRefused => Some(RunStatus::PolicyRefused),
            StepStatus::Skipped => None,
        }
    }
}

/// What a run left behind: one record per planned step, in plan order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunLog {
    pub status: RunStatus,
    pub steps: Vec<StepRecord>,
}

impl RunLog {
    /// The process exit code for this run.
    pub fn exit_code(&self) -> u8 {
        self.status.exit_code()
    }

    /// The record for `id`, if the plan had one.
    pub fn step(&self, id: &str) -> Option<&StepRecord> {
        self.steps.iter().find(|record| record.id == id)
    }
}

/// One step's outcome, with the timings that came off the [`Clock`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepRecord {
    pub id: String,
    pub status: StepStatus,
    /// How many times the step ran, retries included.
    pub attempts: u32,
    /// When the first attempt started; absent for a step that never ran.
    pub started: Option<SystemTime>,
    /// When the step was over — its last attempt ending, or the run giving up on it.
    pub finished: Option<SystemTime>,
    /// Why it ended that way: the failure text, or what skipped it.
    pub reason: Option<String>,
    /// Set only for a `Deploy` that failed or timed out: what rollback said.
    pub rollback: Option<Result<(), String>>,
}

/// A plan the executor will not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    /// Two steps share an id, so `needs` cannot say which one it meant.
    DuplicateId { id: String },
    /// A `needs` entry names no step in the plan.
    UnknownNeed { step: String, needs: String },
    /// A `needs` entry names a step that comes later. Ordering is the planner's job; the
    /// executor only checks that it was done.
    ForwardNeed { step: String, needs: String },
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecError::DuplicateId { id } => write!(f, "two steps are both called {id:?}"),
            ExecError::UnknownNeed { step, needs } => {
                write!(f, "step {step:?} needs {needs:?}, which no step in this run has")
            }
            ExecError::ForwardNeed { step, needs } => {
                write!(f, "step {step:?} needs {needs:?}, which comes after it")
            }
        }
    }
}

impl std::error::Error for ExecError {}

/// Runs a step. The executor owns timing, ordering and everything afterwards; a runner owns only
/// the step itself.
pub trait StepRunner: Send + Sync {
    /// Runs `step` once. `attempt` counts from 1. `cancel` is this attempt's token: the executor
    /// cancels it when the step overruns or the run is cancelled, and a runner that watches it
    /// gets to unwind. Ignoring it means being dropped — which is what happens to a child process
    /// that will not stop.
    fn run<'a>(
        &'a self,
        step: &'a PlannedStep,
        attempt: u32,
        cancel: &'a CancellationToken,
    ) -> BoxFuture<'a, Attempt>;

    /// Undoes a `Deploy` that failed or timed out. The default does nothing: rollback needs an
    /// environment to talk to, which lands with the adapters
    /// ([#78](https://github.com/Keep-Shipping/harness/issues/78)).
    fn rollback<'a>(&'a self, _step: &'a PlannedStep) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async { Ok(()) })
    }
}

/// Runs `steps` in order against `runner`, timing everything off `clock` and stopping early on
/// `cancel`.
///
/// The plan is checked first: a bad one returns [`ExecError`] having run nothing. Otherwise the
/// result is a [`RunLog`] — a run that fails still returns, with the failure in it. Only a plan
/// the executor refuses is an `Err`.
pub async fn execute<'a>(
    steps: &'a [PlannedStep],
    runner: &'a dyn StepRunner,
    clock: &'a dyn Clock,
    cancel: &'a CancellationToken,
    options: ExecOptions,
) -> Result<RunLog, ExecError> {
    check_plan(steps)?;
    let run_deadline = at(clock.now(), options.run_timeout);
    let mut records: Vec<Option<StepRecord>> = vec![None; steps.len()];

    let mut out_of_time = false;
    let mut index = 0;
    while index < steps.len() {
        let step = &steps[index];
        // Cancellation and the run deadline both stop scheduling, before the step starts.
        if cancel.is_cancelled() {
            rest(steps, &mut records, index, StepStatus::Cancelled, "cancelled");
            break;
        }
        if clock.now() >= run_deadline {
            out_of_time = true;
            rest(steps, &mut records, index, StepStatus::Cancelled, "run timed out");
            break;
        }
        if options.fail_fast && records[..index].iter().flatten().any(|r| r.status.is_failure()) {
            rest(steps, &mut records, index, StepStatus::Skipped, "fail-fast");
            break;
        }
        records[index] = match blocked_by(steps, &records, index) {
            Some(blocker) => {
                Some(skipped(&step.id, StepStatus::Skipped, &format!("{blocker} did not succeed")))
            }
            None => Some(run_one(step, runner, clock, cancel, run_deadline, options.grace).await),
        };
        index += 1;
    }

    // The caller's token is the authority on whether the run was cancelled; the run's own
    // deadline failing is one failure among the rest, which a later cancellation outranks.
    let mut status = match cancel.is_cancelled() {
        true => RunStatus::Cancelled,
        false => RunStatus::Succeeded,
    };
    if out_of_time {
        status = status.merge(RunStatus::Failed);
    }
    let finished: Vec<StepRecord> = records.into_iter().flatten().collect();
    for record in &finished {
        // A step that never ran says nothing about the run: whether it was skipped, or the run
        // stopped before reaching it, is a fact about whatever stopped it.
        if record.started.is_none() {
            continue;
        }
        if let Some(outcome) = RunStatus::of_step(record.status) {
            status = status.merge(outcome);
        }
    }
    Ok(RunLog { status, steps: finished })
}

/// Rejects a plan the executor cannot honour, before a single step runs.
fn check_plan(steps: &[PlannedStep]) -> Result<(), ExecError> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for step in steps {
        if !seen.insert(&step.id) {
            return Err(ExecError::DuplicateId { id: step.id.clone() });
        }
        for need in &step.needs {
            if seen.contains(need.as_str()) {
                continue;
            }
            return Err(if steps.iter().any(|other| &other.id == need) {
                ExecError::ForwardNeed { step: step.id.clone(), needs: need.clone() }
            } else {
                ExecError::UnknownNeed { step: step.id.clone(), needs: need.clone() }
            });
        }
    }
    Ok(())
}

/// The first thing this step needs that did not succeed, if any. Every earlier step has a record
/// by the time this is asked.
fn blocked_by(
    steps: &[PlannedStep],
    records: &[Option<StepRecord>],
    index: usize,
) -> Option<String> {
    steps[index].needs.iter().find_map(|need| {
        let earlier = steps.iter().take(index).position(|step| &step.id == need)?;
        let blocked = records[earlier].as_ref()?.status != StepStatus::Succeeded;
        blocked.then(|| need.clone())
    })
}

/// Records every step from `index` on as having gone that way, without ever starting.
fn rest(
    steps: &[PlannedStep],
    records: &mut [Option<StepRecord>],
    index: usize,
    status: StepStatus,
    why: &str,
) {
    for (record, step) in records[index..].iter_mut().zip(&steps[index..]) {
        *record = Some(skipped(&step.id, status, why));
    }
}

/// A step that never ran.
fn skipped(id: &str, status: StepStatus, why: &str) -> StepRecord {
    StepRecord {
        id: id.to_string(),
        status,
        attempts: 0,
        started: None,
        finished: None,
        reason: Some(why.to_string()),
        rollback: None,
    }
}

/// Whether this step may be retried at all: it has to ask, and it has to be safe to run twice.
/// `tofu.apply`, `Apply` and `Destroy` are never retried, whatever the plan declares —
/// re-running them can leave infrastructure half-changed.
fn retriable(step: &PlannedStep) -> bool {
    step.retry.is_some()
        && step.idempotent
        && step.kind != TOFU_APPLY_KIND
        && !matches!(step.action, ActionKind::Apply | ActionKind::Destroy)
}

/// `now + by`, landing in the far future rather than panicking when the duration is absurd.
fn at(now: SystemTime, by: Duration) -> SystemTime {
    now.checked_add(by).unwrap_or_else(|| SystemTime::UNIX_EPOCH + FAR_FUTURE)
}

/// The stopwatch one attempt runs against: its deadline — this attempt's budget from where it
/// starts, capped by the run's — the reason to record when it expires, and the grace after it.
struct Limit {
    deadline: SystemTime,
    timed_out: String,
    grace: Duration,
}

/// Runs one step to its end, retries and all.
async fn run_one(
    step: &PlannedStep,
    runner: &dyn StepRunner,
    clock: &dyn Clock,
    cancel: &CancellationToken,
    run_deadline: SystemTime,
    grace: Duration,
) -> StepRecord {
    let (extra, backoff) = match step.retry.filter(|_| retriable(step)) {
        Some(retry) => (retry.attempts, retry.backoff),
        None => (0, Duration::ZERO),
    };

    let started = clock.now();
    let mut attempts: u32 = 0;
    let (status, reason) = loop {
        attempts = attempts.saturating_add(1);
        // Each attempt gets the whole budget again: a retry is a fresh run of the step, not the
        // remainder of what the last one left.
        let budget = step.timeout.unwrap_or_else(|| default_timeout(step.action));
        let step_deadline = at(clock.now(), budget);
        let limit = Limit {
            deadline: step_deadline.min(run_deadline),
            timed_out: if step_deadline >= run_deadline {
                "run timed out".to_string()
            } else {
                format!("timed out after {budget:?}")
            },
            grace,
        };

        let (status, reason) = match drive(runner, step, attempts, clock, cancel, &limit).await {
            Ok(Attempt::Succeeded) => (StepStatus::Succeeded, None),
            Ok(Attempt::Failed(why)) => (StepStatus::Failed, Some(why)),
            Ok(Attempt::Cancelled) => (StepStatus::Cancelled, Some("cancelled".to_string())),
            Ok(Attempt::WaitingForApproval) => (StepStatus::WaitingForApproval, None),
            Ok(Attempt::PolicyRefused(why)) => (StepStatus::PolicyRefused, Some(why)),
            Err(stopped) => (stopped.status, Some(stopped.reason)),
        };
        let again =
            matches!(status, StepStatus::Failed | StepStatus::TimedOut) && attempts <= extra;
        if !again {
            break (status, reason);
        }
        // A backoff is still a place to honour Ctrl-C: checked before and after the wait.
        if cancel.is_cancelled() {
            break (StepStatus::Cancelled, Some("cancelled during backoff".to_string()));
        }
        if at(clock.now(), backoff) >= run_deadline {
            break (status, reason);
        }
        clock.sleep(backoff).await;
        if cancel.is_cancelled() {
            break (StepStatus::Cancelled, Some("cancelled during backoff".to_string()));
        }
    };

    // A deploy that did not land gets rolled back, whatever else the run does next.
    let lost = matches!(status, StepStatus::Failed | StepStatus::TimedOut);
    let rollback = match step.action == ActionKind::Deploy && lost {
        true => Some(runner.rollback(step).await),
        false => None,
    };

    StepRecord {
        id: step.id.clone(),
        status,
        attempts,
        started: Some(started),
        finished: Some(clock.now()),
        reason,
        rollback,
    }
}

/// How one attempt ended when the executor had to take the step away from the runner.
struct Stopped {
    status: StepStatus,
    reason: String,
}

/// Runs one attempt: the step against its deadline, then — if the deadline or a cancellation
/// wins — the same step against the grace period, after telling it to stop.
async fn drive(
    runner: &dyn StepRunner,
    step: &PlannedStep,
    attempt: u32,
    clock: &dyn Clock,
    cancel: &CancellationToken,
    limit: &Limit,
) -> Result<Attempt, Stopped> {
    let token = CancellationToken::new();
    let mut work = runner.run(step, attempt, &token);
    let mut timer = None;
    let cancelled = || Stopped { status: StepStatus::Cancelled, reason: "cancelled".to_string() };
    let expired = || Stopped { status: StepStatus::TimedOut, reason: limit.timed_out.clone() };
    let outcome = poll_fn(|cx| {
        // The step goes first: where both are ready on one poll, the work wins.
        if let Poll::Ready(result) = work.as_mut().poll(cx) {
            return Poll::Ready(Ok(result));
        }
        if cancel.is_cancelled() {
            return Poll::Ready(Err(cancelled()));
        }
        // The timer wakes the executor in slices, so a step parked on nothing still gets the
        // run's cancellation read; the last slice ends on the deadline itself. A slice that
        // fires short of it is replaced here, in this same poll: returning `Pending` with no
        // live timer would leave the task with nothing to wake it, and the waker the dropped
        // one registered would only ever wake a future nobody is waiting on.
        loop {
            let arm = timer.get_or_insert_with(|| {
                clock.sleep(remaining(clock, limit.deadline).min(CANCEL_POLL))
            });
            if arm.as_mut().poll(cx).is_pending() {
                return Poll::Pending; // a live timer, with its waker registered
            }
            if clock.now() >= limit.deadline {
                return Poll::Ready(Err(expired()));
            }
            timer = None;
        }
    })
    .await;
    match outcome {
        // The step came back having run past its deadline without ever yielding to the timer,
        // which is what a step that never suspends does.
        Ok(_) if clock.now() > limit.deadline => Err(expired()),
        Ok(result) => Ok(result),
        Err(stopped) => {
            // The grace period: a runner that watches the token gets to unwind; one that does
            // not is dropped once the grace is up.
            token.cancel();
            drop(until(clock, limit.grace, work).await);
            Err(stopped)
        }
    }
}

/// How long is left until `deadline`, never negative.
fn remaining(clock: &dyn Clock, deadline: SystemTime) -> Duration {
    deadline.duration_since(clock.now()).unwrap_or(Duration::ZERO)
}

/// Polls `work` first, then the clock, up to `limit`. `None` means the clock won and the work is
/// dropped where it stands.
async fn until<'a, T>(
    clock: &'a dyn Clock,
    limit: Duration,
    mut work: BoxFuture<'a, T>,
) -> Option<T> {
    let mut timer = None;
    poll_fn(|cx| {
        if let Poll::Ready(value) = work.as_mut().poll(cx) {
            return Poll::Ready(Some(value));
        }
        let timer = timer.get_or_insert_with(|| clock.sleep(limit));
        if timer.as_mut().poll(cx).is_ready() { Poll::Ready(None) } else { Poll::Pending }
    })
    .await
}
