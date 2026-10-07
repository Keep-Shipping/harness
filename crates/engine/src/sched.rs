//! The scheduler: the running half of a [`Plan`], with no clock in it
//! ([#40](https://github.com/Keep-Shipping/harness/issues/40)).
//!
//! Independent steps may run in parallel — up to `jobs` at a time — but the
//! order they are *reported* in never depends on which one happened to finish
//! first. A step's records are held until every step with a lower sequence
//! number has settled, so the run log reads in plan order no matter how the
//! timing fell. Nothing here sleeps, retries or fails: timeouts and retries
//! are the executor's ([#41](https://github.com/Keep-Shipping/harness/issues/41)).
//!
//! Generic over the record type, so the plan tests can simulate a run with
//! plain strings.

use crate::plan::Plan;

/// How a step finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// It ran and produced its records.
    Done,
    /// It did not run: a `when:` of its own was false when the run reached it.
    Skipped,
    /// It ran and failed. Whatever the step itself logged is still released.
    Failed,
}

/// What the scheduler releases for a step: the records it produced, or the
/// reason it produced none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Emitted<T> {
    /// The step ran, and logged this.
    Ran(Vec<T>),
    /// The step ran and failed. Its records are kept: whatever it managed to
    /// say before failing is part of the log, and a failure that looks like a
    /// silent success is worse than one that does not.
    Failed(Vec<T>),
    /// The step is out, and here is why.
    Skipped(String),
}

/// Where a step is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Not started, and nothing has settled it.
    Pending,
    /// Started, not finished.
    Running,
    /// Finished, or never going to run. Its records are held for release.
    Settled,
}

/// A run over a [`Plan`]: which steps may start, which have settled, and what
/// may be written to the log. Borrows the plan, owns no clock and no I/O.
pub struct Scheduler<'p, T> {
    plan: &'p Plan,
    state: Vec<State>,
    /// What each settled step would log, until its turn to be released.
    held: Vec<Option<Emitted<T>>>,
    /// The 1-based sequence number of the next step that may be released.
    next: usize,
    running: usize,
    jobs: usize,
    /// The steps that depend on each step, so one skip cascades at once.
    dependents: Vec<Vec<usize>>,
}

impl<'p, T> Scheduler<'p, T> {
    /// A scheduler for `plan`, running at most `jobs` steps at a time — `jobs`
    /// of zero is read as one, because a run that may do nothing at all is
    /// not a run. A step the plan has already ruled out is settled from the
    /// start: it never starts, and its reason is logged in sequence order
    /// with the rest. So does anything waiting on such a step, whether or not
    /// the plan said so itself: the scheduler does not lean on that invariant.
    #[must_use]
    pub fn new(plan: &'p Plan, jobs: usize) -> Scheduler<'p, T> {
        let n = plan.steps.len();
        let mut dependents = vec![Vec::new(); n];
        for step in &plan.steps {
            for dep in &step.deps {
                dependents[dep - 1].push(step.seq);
            }
        }
        let mut scheduler = Scheduler {
            plan,
            state: vec![State::Pending; n],
            held: (0..n).map(|_| None).collect(),
            next: 1,
            running: 0,
            jobs: jobs.max(1),
            dependents,
        };
        // One pass in sequence order: a dependency always has the lower
        // number, so a step is reached after everything it waits on.
        let mut out = vec![false; n];
        for (i, step) in plan.steps.iter().enumerate() {
            let reason = match &step.gate {
                crate::plan::Gate::Skip { reason } => Some(reason.clone()),
                _ => step
                    .deps
                    .iter()
                    .map(|d| &plan.steps[*d - 1])
                    .find(|dep| out[dep.seq - 1])
                    .map(|dep| format!("{} is skipped", dep.name)),
            };
            if let Some(reason) = reason {
                out[i] = true;
                scheduler.state[i] = State::Settled;
                scheduler.held[i] = Some(Emitted::Skipped(reason));
            }
        }
        scheduler
    }

    /// The steps that may start now, lowest sequence number first, as many as
    /// `jobs` leaves room for: at most `jobs` counting what is already
    /// running. Empty when every step is started or settled.
    pub fn start(&mut self) -> Vec<usize> {
        let mut ready = Vec::new();
        for i in 0..self.plan.steps.len() {
            if self.running >= self.jobs {
                break;
            }
            if self.state[i] != State::Pending
                || self.plan.steps[i].deps.iter().any(|&d| self.state[d - 1] != State::Settled)
            {
                continue;
            }
            self.state[i] = State::Running;
            self.running += 1;
            ready.push(self.plan.steps[i].seq);
        }
        ready
    }

    /// Settle `seq` with `outcome` and whatever it logged, and return
    /// everything the run may now write, in sequence order. Records are
    /// returned once, and never out of order: a step that finishes early
    /// waits here for every step before it.
    ///
    /// A step that is not running is ignored — a sequence number that is not
    /// in the plan, a double `finish`, or a step a skip already settled while
    /// it was still waiting its turn — and whatever is due to be written goes
    /// out as it stands. Nothing is overwritten and no records are lost: a
    /// step settled by the cascade has its own log entry, and the later
    /// `finish` for it does not replace that reason.
    pub fn finish(
        &mut self,
        seq: usize,
        outcome: Outcome,
        records: Vec<T>,
    ) -> Vec<(usize, Emitted<T>)> {
        let Some(i) = seq.checked_sub(1).filter(|i| *i < self.state.len()) else {
            return self.release();
        };
        if self.state[i] != State::Running {
            return self.release();
        }
        self.running -= 1;
        self.state[i] = State::Settled;
        self.held[i] = Some(emitted(outcome, records));
        if matches!(outcome, Outcome::Skipped | Outcome::Failed) {
            self.cascade(seq, if outcome == Outcome::Skipped { "was skipped" } else { "failed" });
        }
        self.release()
    }

    /// A step that does not run cannot be depended on: everything waiting on
    /// it is out too, without running — and so is everything waiting on
    /// those, down the chain, each naming the step it was actually waiting on.
    fn cascade(&mut self, seq: usize, outcome_word: &str) {
        let mut queue = vec![(seq, format!("{} {outcome_word}", self.name(seq - 1)))];
        while let Some((skipped, reason)) = queue.pop() {
            for dependent in self.dependents[skipped - 1].clone() {
                if self.state[dependent - 1] == State::Pending {
                    self.state[dependent - 1] = State::Settled;
                    self.held[dependent - 1] = Some(Emitted::Skipped(reason.clone()));
                    let here = format!("{} {outcome_word}", self.name(dependent - 1));
                    queue.push((dependent, here));
                }
            }
        }
    }

    /// Whether every step has settled: the run is over. Records may still be
    /// waiting for their turn — see [`release`](Self::release).
    #[must_use]
    pub fn done(&self) -> bool {
        self.state.iter().all(|s| *s == State::Settled)
    }

    /// Whether `seq` has settled, run or not.
    #[must_use]
    pub fn is_settled(&self, seq: usize) -> bool {
        self.state.get(seq.wrapping_sub(1)) == Some(&State::Settled)
    }

    /// The step name at an index, for a reason a person reads.
    fn name(&self, i: usize) -> &str {
        self.plan.steps.get(i).map_or("", |s| s.name.as_str())
    }

    /// Everything settled so far that is due to be written, in sequence
    /// order. [`finish`](Self::finish) returns this as it goes; a caller
    /// driving a plan it never had to run anything from — every step ruled
    /// out before the start — collects the whole log here.
    pub fn release(&mut self) -> Vec<(usize, Emitted<T>)> {
        let mut out = Vec::new();
        while let Some(emitted) = self.held.get_mut(self.next - 1).and_then(Option::take) {
            out.push((self.next, emitted));
            self.next += 1;
        }
        out
    }
}

/// What a step's own outcome logs. A step that did not run has nothing of its
/// own to say, so a skip releases only its reason: the log reads out, never a
/// run, whatever the caller hands in with the skip.
fn emitted<T>(outcome: Outcome, records: Vec<T>) -> Emitted<T> {
    match outcome {
        Outcome::Done => Emitted::Ran(records),
        Outcome::Failed => Emitted::Failed(records),
        Outcome::Skipped => Emitted::Skipped("its `when:` was false at run time".to_string()),
    }
}
