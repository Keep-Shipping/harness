//! Parking a run that has to wait, and picking it up again
//! ([#97](https://github.com/Keep-Shipping/harness/issues/97)).
//!
//! A run that stops at an approval does not sit there. It writes itself down —
//! the record [`ks_engine::state`] keeps — and the process exits **4**, the code
//! `docs/CLI.md` names `waiting_for_approval`. Two kinds of run stop this way,
//! and both are one [`Outcome::Waiting`] that says why
//! ([`WaitReason`]):
//!
//! - a run nobody is watching (CI, a pipe, `--non-interactive`) reaches an
//!   approval nobody can answer — [`WaitReason::Approval`];
//! - an agent's own run reaches any approval at all, because an agent may not
//!   answer its own — [`WaitReason::AgentDecision`].
//!
//! [`resume`] is the job that carries the run on. Before it changes anything it
//! re-checks, in this order: the binding the record carries
//! ([`ks_engine::state::resume`] — `ship.ks` must still hash to what the run
//! started with, no approval may have expired, and every approval must still
//! cover the artifacts the run holds), the context gate `run` applies, and the
//! policy gate ([`PolicyGate::preflight`]). Any refusal leaves the record
//! byte-for-byte as it was, so the same run can still be resumed where it can
//! finish.
//!
//! Who may let the run go on depends on why it waits. A run parked on an
//! approval nobody was there to answer is answered by the resume itself: the
//! person (or the job an approval channel starts) running `resume` is the
//! approver, and the approval is recorded with an expiry and the artifacts it
//! covers, in the record's own format ([`RunState::approve_until`]). A run
//! parked on an agent's decision is never answered by `resume`: a human records
//! the answer with `keepshipping approve`, and `resume` then continues past it.
//! Nor does a resume an agent is running answer anything.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ks_core::ports::policy::effective_baseline;
use ks_core::ports::run_context::ActorKind;
use ks_core::step::{ActionClass, ActionKind};
use ks_core::{ContextName, Step, ids::RunId};
use ks_engine::policy_gate::{PolicyGate, PreflightStep};
use ks_engine::state::{CompletedStep, LocalStateStore, ResumeError, RunState};

use crate::args::USAGE;
use crate::blocks::wait;
use crate::drive::{self, Approver, Outcome, Parking, WAITING_ON, WaitReason};
use crate::{actor, check};

/// How long an approval a resume records stands. Long enough for an on-call
/// engineer to see the notification and look; short enough that a decision
/// does not outlive the plan it was given about.
const APPROVAL_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// The key in a parked record's `context` naming who the run was acting as —
/// `human`, `agent` or `ci` — so the resume decides policy for the same actor.
pub const ACTOR: &str = "actor";

/// The key in a parked record's `context` naming the environment the run
/// resolved. `keepshipping runs pending` shows it.
pub const ENVIRONMENT: &str = "environment";

/// A fresh run id: the wall clock in the time field, and the process id against
/// a counter in the random one, so two runs started in the same millisecond on
/// the same machine still differ. ULIDs sort by time, which is what lets
/// `keepshipping log` name the newest run without a query.
pub fn run_id() -> RunId {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    let counter = NEXT.fetch_add(1, Ordering::Relaxed);
    let random = u128::from(millis) ^ (u128::from(std::process::id()) << 64) ^ u128::from(counter);
    RunId::from_parts(millis, random)
}

/// The spelling [`ACTOR`] keeps for `kind`.
pub fn actor_word(kind: ActorKind) -> &'static str {
    match kind {
        ActorKind::Human => "human",
        ActorKind::Agent => "agent",
        ActorKind::Ci => "ci",
    }
}

/// Where a waiting run is written down: `<root>/.keepshipping/runs/<run>/`,
/// the store `keepshipping log`, `runs pending` and `approve` read.
///
/// Parking does three things and returns: it records the steps already done,
/// marks the step waited on, and writes the record once. No polling loop and no
/// read of stdin — a job that has parked is no longer a job.
pub struct Park {
    root: PathBuf,
    /// The record, carried across the park so a resumed run keeps what it has
    /// already done and already had approved.
    state: RunState,
}

impl Park {
    /// A run that has not started: `ship_ks` binds the record to the file this
    /// job read, and `event` is the trigger it is running for.
    pub fn new(run: RunId, ship_ks: &[u8], event: impl Into<String>) -> Park {
        Park { root: PathBuf::from("."), state: RunState::new(run, ship_ks, event) }
    }

    /// A run already parked, picked up again.
    pub fn resuming(state: RunState) -> Park {
        Park { root: PathBuf::from("."), state }
    }

    /// Records `key = value` in the run's context — the actor and the
    /// environment, which a later job needs and cannot re-derive.
    pub fn with_context(mut self, key: &str, value: &str) -> Park {
        self.state = self.state.with_context(key, value);
        self
    }

    /// The record as it stands.
    pub fn state(&self) -> &RunState {
        &self.state
    }

    fn store(&self) -> LocalStateStore {
        LocalStateStore::new(&self.root)
    }

    /// Writes the record as it stands.
    fn persist(&self) -> Result<(), ResumeError> {
        wait(ks_engine::state::park(&self.store(), &self.state))
    }
}

impl Parking for Park {
    fn park(&mut self, step: &str, completed: &[&Step], on: &WaitReason) -> Option<RunId> {
        // Only names: the CLI runs no built-in step kind yet, so there are no
        // outputs or plans to bind, and a later job re-derives what it needs.
        for done in completed {
            if !self.state.completed.iter().any(|c| c.name == done.name) {
                self.state.record(CompletedStep { name: done.name.clone(), ..Default::default() });
            }
        }
        if let Err(error) = self.state.park_at(step) {
            eprintln!("error: {error}");
            return None;
        }
        self.state.context.insert(WAITING_ON.to_string(), on.as_str().to_string());
        match self.persist() {
            Ok(()) => Some(self.state.run.clone()),
            Err(error) => {
                // Nothing was written, so there is nothing to resume later —
                // saying so beats exiting 4 over a record that is not there.
                eprintln!("error: the run could not be parked: {error}");
                None
            }
        }
    }
}

/// Parks through a borrowed [`Park`], so the caller keeps the record once
/// the run is over.
impl Parking for &mut Park {
    fn park(&mut self, step: &str, completed: &[&Step], on: &WaitReason) -> Option<RunId> {
        <Park as Parking>::park(self, step, completed, on)
    }
}

/// The notice a parked run leaves on stderr — what happened, and what carries
/// it on — and exit 4. Which command comes first depends on why it waits: an
/// agent's run needs a human's `approve` before `resume` will move it.
pub fn park_notice(run: &RunId, step: &str, on: &WaitReason) -> ExitCode {
    eprint!("{}", park_notice_text(run, step, on));
    ExitCode::from(ks_engine::exec::EXIT_WAITING_FOR_APPROVAL)
}

fn park_notice_text(run: &RunId, step: &str, on: &WaitReason) -> String {
    match on {
        WaitReason::Approval { .. } => format!(
            "parked at {step}; run {run} is waiting for an approval\n\
             nothing is running while it waits — approve and continue with:\n  \
             keepshipping resume {run}\n"
        ),
        WaitReason::AgentDecision { .. } => format!(
            "parked at {step}; run {run} is an agent's run and waits on a human decision\n\
             nothing is running while it waits — a human approves it, then it continues:\n  \
             keepshipping approve {run}\n  \
             keepshipping resume {run}\n"
        ),
    }
}

/// `keepshipping resume RUN-ID [FILE]` — the job that carries a parked run on.
///
/// `FILE` is the `ship.ks` the run parked from, default `ship.ks`: the resume
/// re-checks that it still hashes to what the record says. The context the
/// remaining steps are gated on is the one this job is in, detected the way
/// `run` detects it.
pub fn resume(args: &[String]) -> ExitCode {
    let Some((run, file)) = parse(args) else { return usage() };
    let source = match std::fs::read(&file) {
        Ok(source) => source,
        Err(error) => {
            eprintln!("error: {}: {error}", file.display());
            return ExitCode::from(2);
        }
    };
    let store = LocalStateStore::new(".");
    // The binding, re-checked before anything else: the file, every
    // approval's expiry, and the artifacts every approval covers.
    let mut state = match wait(ks_engine::state::resume(&store, &run, &source)) {
        Ok(state) => state,
        Err(error) => {
            eprintln!("error: {error}");
            // A run id that names nothing is a question about the command
            // line rather than a run that failed; everything else is.
            return match error {
                ResumeError::NotFound { .. } => ExitCode::from(2),
                _ => ExitCode::from(1),
            };
        }
    };

    let context = crate::args::detect_context();
    let interactive = std::io::stdin().is_terminal() && std::env::var_os("CI").is_none();
    // Who is resuming, under the same baseline this environment declares in
    // `KEEPSHIPPING_AGENTS` / `KEEPSHIPPING_REQUIRE_HUMAN`. Detection only ever
    // escalates to an agent, and so does the record: an agent's run stays an
    // agent's run whoever resumes it.
    let baseline = actor::ActorBaseline::from_env(&std::env::vars().collect());
    let resumer = actor::for_run(None, None, interactive, &baseline).kind;
    let recorded = recorded_actor(&state);
    let acting = if resumer == ActorKind::Agent { ActorKind::Agent } else { recorded };

    let gate = match gate(&state, resumer) {
        Ok(gate) => gate,
        Err(code) => return code,
    };

    // What is left to run, checked against this context and against policy
    // *before* the approval is taken or anything is written. A refused resume
    // must leave the record as it found it.
    let shown = file.display().to_string();
    let site = match check::load(&file, &shown, acting, false, context) {
        Ok(site) => site,
        Err(code) => return code,
    };
    let outstanding = match remaining_steps(&state, &site, context) {
        Ok(steps) => steps,
        Err(code) => return code,
    };
    if let Err(code) = refuses_by_policy(&site, &outstanding, acting) {
        return code;
    }

    if gate.answer
        && let Err(error) =
            state.approve_until(&gate.step, drive::local_user(), APPROVAL_TTL, SystemTime::now())
    {
        eprintln!("error: {error}");
        return ExitCode::from(1);
    }
    // The gate is behind the run now: recorded as done, and written down
    // before anything runs, so a crash half way through keeps the answer.
    state.record(CompletedStep { name: gate.step.clone(), ..Default::default() });
    state.next = None;
    state.context.remove(WAITING_ON);
    let mut park = Park::resuming(state);
    if let Err(error) = park.persist() {
        eprintln!("error: {error}");
        return ExitCode::from(1);
    }

    let steps: Vec<Step> = outstanding.into_iter().filter(|step| step.name != gate.step).collect();
    continue_run(&mut park, &steps, &file, acting == ActorKind::Agent, interactive)
}

/// The approval a resume continues past, and whether the resume answers it.
#[derive(Debug)]
struct Gate {
    step: String,
    /// True when the run is still parked on the step unanswered and this resume
    /// is the answer; false when the answer is already in the record.
    answer: bool,
}

/// Which approval this resume continues past.
///
/// A run still parked unanswered is answered here — unless it waits on an
/// agent's decision, or an agent is resuming it: neither may approve, so both
/// leave the run waiting (exit 4) and say who can. A run whose answer is
/// already recorded (`keepshipping approve`) continues past the latest
/// approval the run has not gone beyond. A run with neither has finished.
fn gate(state: &RunState, resumer: ActorKind) -> Result<Gate, ExitCode> {
    let run = &state.run;
    if let Some(step) = state.next.clone() {
        let waits_on_agent = state.context.get(WAITING_ON).is_some_and(|on| on == "agent");
        if waits_on_agent || resumer == ActorKind::Agent {
            let why = if waits_on_agent {
                "it is an agent's run, and waits on a human decision"
            } else {
                "an agent is resuming it, and an agent may not answer an approval"
            };
            eprintln!(
                "error: run {run} is still waiting at {step}: {why}; a human approves it with \
                 `keepshipping approve {run}`, then `keepshipping resume {run}` carries it on"
            );
            return Err(ExitCode::from(ks_engine::exec::EXIT_WAITING_FOR_APPROVAL));
        }
        return Ok(Gate { step, answer: true });
    }
    let done = |name: &str| state.completed.iter().any(|step| step.name == name);
    match state.approvals.iter().rev().find(|approval| !done(&approval.step)) {
        Some(approval) => Ok(Gate { step: approval.step.clone(), answer: false }),
        None => {
            eprintln!(
                "error: run {run} is not waiting for an approval of anything; \
                 the run has already finished, so there is nothing to resume"
            );
            Err(ExitCode::from(1))
        }
    }
}

/// The actor the record says the run was acting as; a record without one is a
/// human's, which is what every run recorded before the key existed was.
fn recorded_actor(state: &RunState) -> ActorKind {
    match state.context.get(ACTOR).map(String::as_str) {
        Some("agent") => ActorKind::Agent,
        Some("ci") => ActorKind::Ci,
        _ => ActorKind::Human,
    }
}

/// Every step of the file the record does not already have as done, the
/// approval being answered included — checked against `context` the way a
/// fresh run's steps are ([#34](https://github.com/Keep-Shipping/harness/issues/34)).
///
/// The gate covers the approval step too. An `approval` step can be `ci-only`,
/// and granting it from a context that cannot reach it is exactly the accident
/// the gate exists to stop; the caller drops it from what is driven only after
/// this has seen it. There is no `--allow-partial` here — a resume is a
/// machine's job, and nothing on its command line says the caller knows what it
/// is asking for.
///
/// The check's own errors are not re-judged: `state::resume` proved the file is
/// byte-for-byte the one `run` checked.
fn remaining_steps(
    state: &RunState,
    site: &check::Site,
    context: ContextName,
) -> Result<Vec<Step>, ExitCode> {
    let all = match drive::select(&site.checked.workflow, None, &[], &[]) {
        Ok(steps) => steps,
        Err(why) => {
            eprintln!("error: {why}");
            return Err(ExitCode::from(2));
        }
    };
    let done = |name: &str| state.completed.iter().any(|step| step.name == name);
    let outstanding: Vec<Step> =
        all.into_iter().filter(|step| !done(&step.name)).cloned().collect();
    let names: Vec<String> = outstanding.iter().map(|step| step.name.clone()).collect();
    crate::refuses_to_run_at(site, &names, false, context)?;
    Ok(outstanding)
}

/// The policy gate ([#103](https://github.com/Keep-Shipping/harness/issues/103)):
/// the steps left to run, decided for `actor` against the organisation's
/// baseline and the file's own `never:` rules before the run carries on. A step
/// certain to be refused refuses the resume — exit 5, nothing recorded — and a
/// step that will ask is said up front.
///
/// No `PolicyStore` adapter exists yet, so the baseline is the conservative
/// built-in ([`effective_baseline`] of nothing), the same one the engine's gate
/// falls back to.
fn refuses_by_policy(site: &check::Site, steps: &[Step], actor: ActorKind) -> Result<(), ExitCode> {
    let baseline = effective_baseline(None);
    let gate = PolicyGate::new(actor, &baseline, site.checked.workflow.policy());
    let preflight: Vec<PreflightStep> = steps
        .iter()
        .flat_map(|step| {
            let needs_secrets = site.checked.secret_uses.iter().any(|u| u.step == step.name);
            // A step the catalog cannot classify still answers to the rule
            // about secrets when it reads one.
            let actions = match (step.actions.is_empty(), needs_secrets) {
                (true, true) => vec![ActionClass::new(ActionKind::Other)],
                _ => step.actions.clone(),
            };
            actions.into_iter().map(move |action| PreflightStep {
                step: step.name.clone(),
                action,
                needs_secrets,
            })
        })
        .collect();
    match gate.preflight(&preflight) {
        Ok(asks) => {
            for ask in asks {
                eprintln!("note: step `{}` will need an approval: {}", ask.step, ask.rule);
            }
            Ok(())
        }
        Err(refused) => {
            eprintln!("error: refusing to resume: {refused}");
            Err(ExitCode::from(ks_engine::exec::EXIT_POLICY_REFUSED))
        }
    }
}

/// Drives what is left, and returns the run's honest outcome. An approval
/// further on parks the run again, the same way `run` parks it; a run that
/// ships is written down as finished.
fn continue_run(
    park: &mut Park,
    steps: &[Step],
    file: &Path,
    is_agent: bool,
    interactive: bool,
) -> ExitCode {
    if steps.is_empty() {
        // The approval was the last thing left: the record already says so.
        println!("✓ run {} is complete", park.state().run);
        return ExitCode::SUCCESS;
    }
    let what = file
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_else(|| file.display().to_string());
    let by: Vec<&Step> = steps.iter().collect();
    let tty = std::io::stdout().is_terminal() && std::env::var("TERM").is_ok_and(|t| t != "dumb");
    let shared = Mutex::new(crate::renderer(tty, false));
    let started = Instant::now();
    let outcome = {
        let mut approver: Box<dyn Approver + '_> = if is_agent {
            Box::new(drive::AgentRun { notified: None, parking: &mut *park })
        } else if interactive {
            Box::new(drive::TtyApprover::new(std::io::stdin().lock()))
        } else {
            Box::new(drive::Unwatched(&mut *park))
        };
        drive::with_spinner(tty, &shared, |renderer| {
            drive::drive(
                &by,
                &mut crate::Steps::default(),
                approver.as_mut(),
                renderer,
                &mut || started.elapsed(),
                &what,
            )
        })
    };
    match outcome {
        Outcome::Shipped => {
            // Everything ran: the record says so, so a second resume finds
            // nothing left rather than running it all again.
            for step in steps {
                if !park.state.completed.iter().any(|done| done.name == step.name) {
                    park.state
                        .record(CompletedStep { name: step.name.clone(), ..Default::default() });
                }
            }
            if let Err(error) = park.persist() {
                eprintln!("error: {error}");
                return ExitCode::from(1);
            }
            ExitCode::SUCCESS
        }
        // The park already wrote the record.
        Outcome::Waiting { run, step, on } => park_notice(&run, &step, &on),
        Outcome::Declined | Outcome::Failed => ExitCode::from(1),
    }
}

/// `RUN-ID [FILE]`: the id is required, the file defaults to `ship.ks`.
/// Anything else is a usage error rather than a guess about which run to open.
fn parse(args: &[String]) -> Option<(RunId, PathBuf)> {
    let mut run = None;
    let mut file = None;
    for arg in args {
        if arg.starts_with('-') {
            return None;
        } else if run.is_none() {
            run = Some(RunId::parse(arg).ok()?);
        } else if file.is_none() {
            file = Some(PathBuf::from(arg));
        } else {
            return None;
        }
    }
    Some((run?, file.unwrap_or_else(|| PathBuf::from("ship.ks"))))
}

fn usage() -> ExitCode {
    eprintln!("error: `resume` takes a run id and, optionally, the ship.ks it parked from");
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The notice is the whole of what a person has when a job ends waiting:
    /// it names the run, the step, and the command that carries on — and for
    /// an agent's run, that a human has to approve first.
    #[test]
    fn a_parked_run_says_where_it_stopped_and_how_to_carry_on() {
        let run = RunId::from_parts(1_700_000_000_000, 42);
        let approval = WaitReason::Approval { question: "approve?".into() };
        let notice = park_notice_text(&run, "review", &approval);
        for fragment in ["review", run.as_str(), &format!("keepshipping resume {run}")] {
            assert!(notice.contains(fragment), "{fragment:?} missing from {notice:?}");
        }
        assert!(!notice.contains("keepshipping approve"), "{notice}");

        let agent = WaitReason::AgentDecision { notified: None };
        let notice = park_notice_text(&run, "review", &agent);
        let approve = notice.find(&format!("keepshipping approve {run}")).expect("approve");
        let resume = notice.find(&format!("keepshipping resume {run}")).expect("resume");
        assert!(approve < resume, "a human approves before the run resumes: {notice}");
        assert!(notice.contains("human"), "{notice}");

        assert_eq!(ks_engine::exec::EXIT_WAITING_FOR_APPROVAL, 4);
        assert_eq!(park_notice(&run, "review", &agent), ExitCode::from(4));
    }

    /// An agent's run is never answered by a resume, and an agent never
    /// answers one either; a recorded answer is continued past by anybody.
    #[test]
    fn who_may_answer_depends_on_why_the_run_waits() {
        let run = RunId::from_parts(1_700_000_000_000, 1);
        let mut state = RunState::new(run, b"steps:\n", "manual");
        state.park_at("review").expect("parks");

        let gated = gate(&state, ActorKind::Human).expect("a human answers an approval");
        assert!(gated.answer && gated.step == "review");
        assert!(gate(&state, ActorKind::Agent).is_err(), "an agent does not answer");

        state.context.insert(WAITING_ON.into(), "agent".into());
        assert!(gate(&state, ActorKind::Human).is_err(), "an agent's run needs `approve`");

        state.approve("review", "ada").expect("a human approved it");
        let gated = gate(&state, ActorKind::Agent).expect("the answer is recorded");
        assert!(!gated.answer && gated.step == "review");

        state.record(CompletedStep { name: "review".into(), ..Default::default() });
        assert!(gate(&state, ActorKind::Human).is_err(), "nothing left to resume");
    }
}
