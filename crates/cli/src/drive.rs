//! Choosing which steps a run covers, and running them in order.
//!
//! Selection is what `--until`, `--only` and `--skip` mean. `--until` is a
//! step plus everything it depends on; `--skip` drops a step and everything
//! downstream, so a skipped approval takes its consumers with it rather than
//! going around them. `--only` names steps outright, so it is held to the
//! stricter rule that a step may never run without every step it depends on:
//! naming a step whose dependency you left out is a usage error, not a run
//! that quietly does less than the file says.
//!
//! The loop knows nothing about the engine: it takes a [`StepRunner`] and a
//! clock it reads the time from, so the site's run replays byte for byte in
//! a test.

use std::collections::{HashMap, HashSet};
use std::io::BufRead;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ks_core::ids::RunId;
use ks_core::{Step, Workflow};

use crate::progress::{Renderer, RunEvent};

/// How often the step in flight is redrawn while it runs.
const TICK: Duration = Duration::from_millis(100);

/// What one step's run produced: a line for the run, or a question that
/// needs a person before the run may go on.
#[allow(dead_code)] // no step kind runs yet, so only the tests build these
pub enum Done {
    Summary(String),
    Ask(String),
}

/// Runs one step. `log` takes the step's own output, which the renderer shows
/// under `-v` and drops otherwise.
pub trait StepRunner {
    fn run(&mut self, step: &Step, log: &mut dyn FnMut(&str)) -> Result<Done, String>;
}

/// An approval's answer: whether it was approved, who gave it, and whether
/// a person was at the keyboard to type one. `typed` is false when nothing
/// was there to read, and the renderer then has to close the prompt itself.
#[derive(Debug, PartialEq, Eq)]
pub struct Answer {
    pub approved: bool,
    /// The approver, for the run log
    /// ([#46](https://github.com/Keep-Shipping/harness/issues/46)).
    pub by: Option<String>,
    pub typed: bool,
}

/// Asks the approval question.
pub trait Approver {
    fn ask(&mut self, question: &str) -> Answer;

    /// That this approver cannot answer at all: the run waits on someone
    /// else instead of asking. `None` for every approver that can answer —
    /// a person at the keyboard, or a pipe that declines on its own.
    fn waits_on(&self) -> Option<WaitReason> {
        None
    }

    /// Writes the run down parked at `step`, waiting `on`, with `completed`
    /// as the steps it has already done, and returns the run's id — or
    /// `None`, which is what an approver with nowhere to write the run down
    /// returns ([`Declines`]).
    ///
    /// A run that has to wait parks rather than holds the process open
    /// ([#97](https://github.com/Keep-Shipping/harness/issues/97)): the record
    /// is persisted, the process exits 4, and `keepshipping resume` is a new
    /// job. This has to return at once — a CI job that sits here waiting for
    /// a human burns runner minutes and runs into its own timeout.
    fn park(&mut self, _step: &str, _completed: &[&Step], _on: &WaitReason) -> Option<RunId> {
        None
    }
}

/// Somewhere a waiting run is written down. The approvers that park
/// ([`AgentRun`], [`Unwatched`]) hand the writing to one of these, so the
/// state store stays out of this module and a test can park in memory.
pub trait Parking {
    /// As [`Approver::park`].
    fn park(&mut self, step: &str, completed: &[&Step], on: &WaitReason) -> Option<RunId>;
}

/// Why a run stopped at an approval and is waiting rather than running on.
/// Both are the same outcome, [`Outcome::Waiting`], parked the same way;
/// what differs is who may let the run go on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WaitReason {
    /// An approval nobody was there to answer — CI, a pipe,
    /// `--non-interactive`, a closed stdin
    /// ([#97](https://github.com/Keep-Shipping/harness/issues/97)). `question`
    /// is what the approval asked. Whoever resumes the run answers it.
    Approval { question: String },
    /// The run is an agent's own, and an agent may not decide its own
    /// approval: that would be approving itself
    /// ([#102](https://github.com/Keep-Shipping/harness/issues/102)). A human
    /// has to — `keepshipping approve` — before the run may be resumed.
    /// `notified` is whoever the policy's `ask:` has already told.
    AgentDecision { notified: Option<String> },
}

impl WaitReason {
    /// The word the parked record keeps for this reason, under
    /// [`WAITING_ON`]: `approval` or `agent`.
    pub fn as_str(&self) -> &'static str {
        match self {
            WaitReason::Approval { .. } => "approval",
            WaitReason::AgentDecision { .. } => "agent",
        }
    }
}

/// The key in a parked record's `context` that says why the run waits, as
/// [`WaitReason::as_str`] spells it. `resume` reads it back: an agent's run
/// is not one a resume may approve.
pub const WAITING_ON: &str = "waiting_on";

/// Nobody was asked: the run declined itself.
pub const NOBODY_ANSWERED: Answer = Answer { approved: false, by: None, typed: false };

/// How a run ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Every selected step ran.
    Shipped,
    /// An approval was declined; nothing after it ran.
    Declined,
    /// A step failed; nothing after it ran.
    Failed,
    /// The run parked at `step`, waiting `on` an answer, and was written
    /// down as `run`. Nothing after the approval ran, and nothing will until
    /// `keepshipping resume <run>`: the job is over, so no process is held
    /// open waiting for a human.
    Waiting { run: RunId, step: String, on: WaitReason },
}

/// The steps a run covers, in the order it runs them: all of them,
/// narrowed by `until`, then by `only`, then cut by `skip`.
///
/// An unknown step name, a selection nothing is left of, or an `only` that
/// would run a step without something it depends on is an error the caller
/// turns into a usage failure.
pub fn select<'a>(
    workflow: &'a Workflow,
    until: Option<&str>,
    only: &[&str],
    skip: &[&str],
) -> Result<Vec<&'a Step>, String> {
    let order = workflow.topo_order().ok_or("this file's steps form a cycle")?;
    let pos: HashMap<&str, usize> =
        order.iter().enumerate().map(|(i, name)| (name.as_str(), i)).collect();
    // Dependants and dependencies, so a step and its reach are one walk.
    let mut deps: Vec<Vec<usize>> = vec![Vec::new(); order.len()];
    let mut users: Vec<Vec<usize>> = vec![Vec::new(); order.len()];
    for (from, to) in workflow.edges() {
        let (Some(&f), Some(&t)) = (pos.get(from.as_str()), pos.get(to.as_str())) else {
            continue;
        };
        deps[t].push(f);
        users[f].push(t);
    }
    let lookup =
        |name: &str| pos.get(name).copied().ok_or_else(|| format!("no step `{name}` in this file"));

    let mut keep: Vec<bool> = vec![true; order.len()];
    if let Some(until) = until {
        let needed = reach(&deps, &[lookup(until)?]);
        for (i, k) in keep.iter_mut().enumerate() {
            *k = needed.contains(&i);
        }
    }
    if !only.is_empty() {
        let mut chosen = HashSet::new();
        for name in only {
            chosen.insert(lookup(name)?);
        }
        for (i, k) in keep.iter_mut().enumerate() {
            *k &= chosen.contains(&i);
        }
    }
    for name in skip {
        for i in reach(&users, &[lookup(name)?]) {
            keep[i] = false;
        }
    }
    let kept: HashSet<usize> =
        keep.iter().enumerate().filter(|(_, k)| **k).map(|(i, _)| i).collect();
    if kept.is_empty() {
        return Err("nothing left to run".into());
    }
    // A step never runs without what it depends on. Only `--only` can leave
    // one out: `--until` brings the dependencies along and `--skip` takes
    // the consumers with the step.
    for (i, name) in order.iter().enumerate() {
        if !kept.contains(&i) {
            continue;
        }
        let Some(missing) = reach(&deps, &[i])
            .into_iter()
            .filter(|d| !kept.contains(d))
            // An approval first: it is the one a reader can do something about.
            .max_by_key(|d| is_approval(workflow, &order[*d]))
        else {
            continue;
        };
        let need = &order[missing];
        return Err(if is_approval(workflow, need) {
            format!("`{name}` waits on approval `{need}`; use --until {name}")
        } else {
            format!("`{name}` needs `{need}`; use --until {name}")
        });
    }
    Ok(order
        .iter()
        .enumerate()
        .filter(|(i, _)| kept.contains(i))
        .map(|(_, name)| workflow.step(name).expect("a step of the order"))
        .collect())
}

/// Whether `name` is an `approval` step — the one kind that gates, so the
/// error that names it says what waiting means.
fn is_approval(workflow: &Workflow, name: &str) -> bool {
    workflow.step(name).is_some_and(|s| s.kind.as_deref() == Some("approval"))
}

/// `seeds` plus everything reachable through `adj`, walking the graph rather
/// than recursing, so a file with many steps cannot blow the stack.
fn reach(adj: &[Vec<usize>], seeds: &[usize]) -> HashSet<usize> {
    let mut seen: HashSet<usize> = HashSet::new();
    let mut queue: Vec<usize> = seeds.to_vec();
    while let Some(i) = queue.pop() {
        if !seen.insert(i) {
            continue;
        }
        queue.extend(adj[i].iter().copied());
    }
    seen
}

/// Runs `steps` in order, telling `renderer` what happens and reading time
/// from `clock` — a function returning how long the run has been going, so
/// the site's timings replay exactly. Stops at the first failure, declined
/// approval or park. An approver that cannot answer at all (an agent's run)
/// parks without being asked; one nobody answered parks if it has somewhere
/// to write the run down, and declines if it has not. Only a typed `no`
/// declines outright.
pub fn drive(
    steps: &[&Step],
    runner: &mut dyn StepRunner,
    approver: &mut dyn Approver,
    renderer: &mut dyn Renderer,
    clock: &mut dyn FnMut() -> Duration,
    what: &str,
) -> Outcome {
    let start = clock();
    let mut completed: Vec<&Step> = Vec::new();
    for step in steps {
        let name = &step.name;
        let at = clock();
        renderer.event(&RunEvent::Started { step: name.clone() });
        let result = {
            let mut log = |line: &str| {
                renderer.event(&RunEvent::Log { step: name.clone(), line: line.to_string() });
            };
            runner.run(step, &mut log)
        };
        match result {
            Ok(Done::Summary(summary)) => {
                completed.push(step);
                renderer.event(&RunEvent::Finished {
                    step: name.clone(),
                    summary,
                    took: clock().saturating_sub(at),
                });
            }
            Ok(Done::Ask(question)) => {
                // An approver that cannot answer is not asked: the run parks,
                // and everything after the approval is left alone.
                if let Some(on) = approver.waits_on() {
                    let Some(run) = approver.park(name, &completed, &on) else {
                        // A wait with no record is a run nobody can pick up
                        // again, so it is a failure, not a wait.
                        renderer.event(&RunEvent::Failed {
                            step: name.clone(),
                            error: "the run could not be written down to wait".to_string(),
                            took: clock().saturating_sub(at),
                        });
                        return Outcome::Failed;
                    };
                    let notified = match &on {
                        WaitReason::AgentDecision { notified } => notified.clone(),
                        WaitReason::Approval { .. } => None,
                    };
                    renderer.event(&RunEvent::Waiting {
                        step: name.clone(),
                        on: "a human".to_string(),
                        notified,
                    });
                    return Outcome::Waiting { run, step: name.clone(), on };
                }
                renderer
                    .event(&RunEvent::Asking { step: name.clone(), question: question.clone() });
                let answer = approver.ask(&question);
                renderer.event(&RunEvent::Answered {
                    step: name.clone(),
                    approved: answer.approved,
                    by: answer.by,
                    typed: answer.typed,
                });
                if !answer.approved {
                    // Nobody answered: a run that can be written down parks
                    // and the job ends; one that cannot has declined, as it
                    // always has. A typed `no` is an answer, and declines.
                    if !answer.typed {
                        let on = WaitReason::Approval { question };
                        if let Some(run) = approver.park(name, &completed, &on) {
                            renderer.event(&RunEvent::Parked {
                                run: run.to_string(),
                                step: name.clone(),
                            });
                            return Outcome::Waiting { run, step: name.clone(), on };
                        }
                    }
                    renderer.event(&RunEvent::Declined { step: name.clone() });
                    return Outcome::Declined;
                }
            }
            Err(error) => {
                renderer.event(&RunEvent::Failed {
                    step: name.clone(),
                    error,
                    took: clock().saturating_sub(at),
                });
                return Outcome::Failed;
            }
        }
    }
    renderer
        .event(&RunEvent::Shipped { what: what.to_string(), took: clock().saturating_sub(start) });
    Outcome::Shipped
}

/// The approver at a terminal: `y` or `yes` approves, and anything else —
/// including a closed stdin — declines. The approver's name comes from the
/// environment, falling back to `local`.
pub struct TtyApprover<R> {
    input: R,
    who: String,
}

impl<R: BufRead> TtyApprover<R> {
    pub fn new(input: R) -> Self {
        Self { input, who: local_user() }
    }
}

impl<R: BufRead> Approver for TtyApprover<R> {
    fn ask(&mut self, _question: &str) -> Answer {
        let mut line = String::new();
        // No line at all — a closed stdin, or a read that failed — is nobody
        // answering, so there is nothing for the terminal to have echoed.
        let Ok(read) = self.input.read_line(&mut line) else {
            return NOBODY_ANSWERED;
        };
        if read == 0 {
            return NOBODY_ANSWERED;
        }
        let yes = matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes");
        Answer { approved: yes, by: yes.then(|| self.who.clone()), typed: true }
    }
}

/// Who the local run is: `$USER`, then `$USERNAME`, then `local`. A name is
/// a label for the run log, not a credential.
pub(crate) fn local_user() -> String {
    ["USER", "USERNAME"]
        .into_iter()
        .find_map(|var| std::env::var(var).ok())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "local".to_string())
}

/// The approver of a run nobody is watching that has nowhere to write the run
/// down: it declines, always. A run that needs a person cannot get one from a
/// pipe. The binary parks instead ([`Unwatched`]), so only the tests build
/// this; it stays as the reference for what "nowhere to park" means.
#[allow(dead_code)]
pub struct Declines;

impl Approver for Declines {
    fn ask(&mut self, _question: &str) -> Answer {
        NOBODY_ANSWERED
    }
}

/// The approver of a run nobody is watching — CI, a pipe,
/// `--non-interactive`: nobody answers, so the run parks through `P` and the
/// job ends ([#97](https://github.com/Keep-Shipping/harness/issues/97)).
pub struct Unwatched<P>(pub P);

impl<P: Parking> Approver for Unwatched<P> {
    fn ask(&mut self, _question: &str) -> Answer {
        NOBODY_ANSWERED
    }

    fn park(&mut self, step: &str, completed: &[&Step], on: &WaitReason) -> Option<RunId> {
        self.0.park(step, completed, on)
    }
}

/// An agent's own run. An agent cannot approve the run it is making — that
/// would be approving itself — so its first approval is a wait, not a
/// question, and the run parks through `parking` like any other wait.
/// `notified` is whoever the policy's `ask:` has already been told to tell,
/// which the run says so a reader can go and find them.
pub struct AgentRun<P> {
    pub notified: Option<String>,
    pub parking: P,
}

impl<P: Parking> Approver for AgentRun<P> {
    fn ask(&mut self, _question: &str) -> Answer {
        // Unreachable in practice: `waits_on` sends the run to a human
        // before anything is ever asked.
        NOBODY_ANSWERED
    }

    fn waits_on(&self) -> Option<WaitReason> {
        Some(WaitReason::AgentDecision { notified: self.notified.clone() })
    }

    fn park(&mut self, step: &str, completed: &[&Step], on: &WaitReason) -> Option<RunId> {
        self.parking.park(step, completed, on)
    }
}

/// Runs `body` with a ticker redrawing the step in flight every [`TICK`] when
/// `animated`, and with no thread at all when not — a plain stream has
/// nothing to animate, and a thread per run for that is waste.
pub fn with_spinner<R>(
    animated: bool,
    renderer: &Mutex<Box<dyn Renderer + Send>>,
    body: impl FnOnce(&mut dyn Renderer) -> R,
) -> R {
    if !animated {
        return body(&mut Shared(renderer));
    }
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let ticker = scope.spawn(|| {
            while !stop.load(Ordering::Acquire) {
                std::thread::sleep(TICK);
                if let Ok(mut r) = renderer.lock() {
                    r.tick();
                }
            }
        });
        let out = body(&mut Shared(renderer));
        stop.store(true, Ordering::Release);
        let _ = ticker.join();
        out
    })
}

/// A renderer that borrows the shared one, locking per event.
struct Shared<'a>(&'a Mutex<Box<dyn Renderer + Send>>);

impl Renderer for Shared<'_> {
    fn event(&mut self, e: &RunEvent) {
        if let Ok(mut r) = self.0.lock() {
            r.event(e);
        }
    }

    fn tick(&mut self) {
        if let Ok(mut r) = self.0.lock() {
            r.tick();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::rc::Rc;
    use std::time::Instant;

    use super::*;
    use crate::progress::{Run, prompt_line, screen};

    /// The site's run: the same five steps, the same approval in the middle.
    const SITE: &str = include_str!("../tests/fixtures/site/ship.ks");

    /// Two steps, one dependency, no approval to confuse the message with.
    const PLAIN: &str = "\
name: plain
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: build.digest
";

    /// What each step reports and how long it takes. The review's 20s is the
    /// person deciding; the total is the 2m 18s the shipped line shows.
    const SCRIPT: [(&str, &str, u64); 5] = [
        ("build", "sha256:9f2c…e1  signed", 38),
        ("plan", "+2 ~1 -0", 11),
        ("review", "approve 3 changes?", 20),
        ("apply", "3 resources", 42),
        ("deploy", "4/4 pods healthy", 27),
    ];

    /// The agent run's script: the same five steps with the agent's own
    /// numbers, and every step free of time — a run that waits reports what
    /// it did, not how long it is taking.
    const AGENT_SCRIPT: [(&str, &str, u64); 5] = [
        ("build", "sha256:4be1…07  signed", 0),
        ("plan", "+1 ~0 -1  1 destroy", 0),
        ("review", "approve 1 change?", 0),
        ("apply", "1 resource", 0),
        ("deploy", "1/1 pods healthy", 0),
    ];

    /// What `select` chooses out of `src`, by name.
    fn chosen(
        src: &str,
        until: Option<&str>,
        only: &[&str],
        skip: &[&str],
    ) -> Result<Vec<String>, String> {
        let parse = ks_lang::parse(src);
        let workflow = ks_core::check(&parse).workflow;
        select(&workflow, until, only, skip).map(|steps| names(&steps))
    }

    /// Every step of the site's file, in the order a run would take them.
    fn site_steps() -> Vec<Step> {
        let parse = ks_lang::parse(SITE);
        let workflow = ks_core::check(&parse).workflow;
        select(&workflow, None, &[], &[]).expect("every step").into_iter().cloned().collect()
    }

    /// The golden for `name`: re-run with `UPDATE_GOLDEN=1 cargo test -p ks-cli`
    /// after reviewing the diff. The rules the bytes follow are in
    /// `docs/DIAGNOSTICS.md`.
    fn read_or_update(name: &str, actual: &str) -> String {
        let path: PathBuf =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/run").join(name);
        if std::env::var_os("UPDATE_GOLDEN").is_some() {
            fs::create_dir_all(path.parent().expect("a directory")).expect("make the golden dir");
            fs::write(&path, actual).expect("write golden");
            return actual.to_string();
        }
        fs::read_to_string(path).unwrap_or_default()
    }

    /// The site's run, moving a clock of its own as the steps go, so the
    /// timings are the site's whatever the machine is doing. Each step has a
    /// log line, which the runs here are quiet enough to drop.
    struct Scripted {
        now: Rc<Cell<Duration>>,
        script: &'static [(&'static str, &'static str, u64)],
    }

    impl StepRunner for Scripted {
        fn run(&mut self, step: &Step, log: &mut dyn FnMut(&str)) -> Result<Done, String> {
            let Some((_, summary, secs)) =
                self.script.iter().find(|(name, _, _)| *name == step.name)
            else {
                return Err(format!("no scripted step `{name}`", name = step.name));
            };
            log(&format!("{}: working", step.name));
            self.now.set(self.now.get() + Duration::from_secs(*secs));
            // The review asks instead of reporting; its summary is its
            // question.
            Ok(if summary.starts_with("approve") {
                Done::Ask((*summary).into())
            } else {
                Done::Summary((*summary).into())
            })
        }
    }

    /// An approver with a scripted answer. `typed` says whether it stands
    /// for a person at the keyboard.
    struct ScriptedApprover(bool, bool);

    impl Approver for ScriptedApprover {
        fn ask(&mut self, _question: &str) -> Answer {
            Answer { approved: self.0, by: self.0.then(|| "ada".into()), typed: self.1 }
        }
    }

    fn names(steps: &[&Step]) -> Vec<String> {
        steps.iter().map(|s| s.name.clone()).collect()
    }

    /// The whole site's run into a string, animated at a terminal and plain
    /// everywhere else, with the script's clock.
    fn site_run(approved: bool, typed: bool, tty: bool) -> (String, Outcome, Rc<Cell<Duration>>) {
        let steps = site_steps();
        let by: Vec<&Step> = steps.iter().collect();
        let now = Rc::new(Cell::new(Duration::ZERO));
        let mut runner = Scripted { now: now.clone(), script: &SCRIPT };
        let mut approver = ScriptedApprover(approved, typed);
        let mut out = Vec::new();
        let mut renderer = Run::new(&mut out, false, tty);
        let mut clock = || now.get();
        let outcome =
            drive(&by, &mut runner, &mut approver, &mut renderer, &mut clock, "api@a41c9e");
        (String::from_utf8(out).expect("utf-8"), outcome, now)
    }

    /// The site's run as an agent runs it: the check it stands on, then the
    /// steps it may take on its own, then the approval it may not answer.
    fn agent_run(notified: Option<&str>, tty: bool) -> (String, Outcome, Rc<Cell<Duration>>) {
        let steps = site_steps();
        let by: Vec<&Step> = steps.iter().collect();
        let now = Rc::new(Cell::new(Duration::ZERO));
        let mut runner = Scripted { now: now.clone(), script: &AGENT_SCRIPT };
        let mut approver =
            AgentRun { notified: notified.map(str::to_string), parking: InMemory::new() };
        let mut out = Vec::new();
        let mut renderer = Run::new(&mut out, false, tty);
        let mut clock = || now.get();
        renderer.event(&RunEvent::Checked { path: "ship.ks".to_string() });
        let outcome =
            drive(&by, &mut runner, &mut approver, &mut renderer, &mut clock, "api@a41c9e");
        (String::from_utf8(out).expect("utf-8"), outcome, now)
    }

    /// The site's agent run, in the one form it is written down here.
    const AGENT_RUN: &str = concat!(
        "✓ check   ship.ks is valid\n",
        "▸ build   sha256:4be1…07  signed\n",
        "▸ plan    +1 ~0 -1  1 destroy\n",
        "⏸ review  waiting on a human\n",
        "          @platform notified, plan attached\n",
        "nothing applied. agent is free to wait.\n",
    );

    /// Parks in memory: names a fixed run and remembers what it was handed,
    /// the way the CLI's `Park` writes it to a state store.
    struct InMemory {
        run: RunId,
        parked: Rc<Cell<bool>>,
    }

    impl InMemory {
        fn new() -> InMemory {
            InMemory { run: parked_run(), parked: Rc::new(Cell::new(false)) }
        }
    }

    impl Parking for InMemory {
        fn park(&mut self, _step: &str, _completed: &[&Step], _on: &WaitReason) -> Option<RunId> {
            self.parked.set(true);
            Some(self.run.clone())
        }
    }

    /// Nowhere to write anything: every park fails.
    struct Nowhere;

    impl Parking for Nowhere {
        fn park(&mut self, _step: &str, _completed: &[&Step], _on: &WaitReason) -> Option<RunId> {
            None
        }
    }

    /// The id the in-memory runs park under.
    fn parked_run() -> RunId {
        RunId::from_parts(1_700_000_000_000, 7)
    }

    /// The outcome an agent's run waiting at the site's review has.
    fn agent_waiting(notified: Option<&str>) -> Outcome {
        Outcome::Waiting {
            run: parked_run(),
            step: "review".into(),
            on: WaitReason::AgentDecision { notified: notified.map(str::to_string) },
        }
    }

    #[test]
    fn the_agent_run_is_the_sites_agent_run_line_for_line() {
        let (plain, outcome, now) = agent_run(Some("@platform"), false);
        assert_eq!(outcome, agent_waiting(Some("@platform")));
        assert_eq!(now.get(), Duration::ZERO, "nothing after the review ran");
        // Not just the golden: the site's lines, so a stray UPDATE_GOLDEN
        // cannot redefine them.
        assert_eq!(plain, AGENT_RUN);
        assert_eq!(plain, read_or_update("site.agent.plain", &plain));
        // The terminal animates the steps and rewrites them; whoever is
        // watching is left with the same lines.
        let (raw, outcome, _) = agent_run(Some("@platform"), true);
        assert_eq!(outcome, agent_waiting(Some("@platform")));
        assert_eq!(screen(raw.as_bytes()), AGENT_RUN);
    }

    /// A run nobody was told about says so by leaving the notification out.
    #[test]
    fn an_agent_run_with_nobody_to_notify_waits_without_naming_a_person() {
        let (plain, outcome, _) = agent_run(None, false);
        assert_eq!(outcome, agent_waiting(None));
        assert_eq!(
            plain,
            concat!(
                "✓ check   ship.ks is valid\n",
                "▸ build   sha256:4be1…07  signed\n",
                "▸ plan    +1 ~0 -1  1 destroy\n",
                "⏸ review  waiting on a human\n",
                "nothing applied. agent is free to wait.\n",
            )
        );
    }

    /// An agent's run that cannot be written down cannot wait either: there
    /// would be nothing for a human to approve or for `resume` to pick up.
    #[test]
    fn an_agent_run_with_nowhere_to_park_fails_rather_than_waits() {
        let steps = site_steps();
        let by: Vec<&Step> = steps.iter().collect();
        let now = Rc::new(Cell::new(Duration::ZERO));
        let mut runner = Scripted { now: now.clone(), script: &AGENT_SCRIPT };
        let mut approver = AgentRun { notified: None, parking: Nowhere };
        let mut out = Vec::new();
        let mut renderer = Run::new(&mut out, false, false);
        let mut clock = || now.get();
        let outcome = drive(&by, &mut runner, &mut approver, &mut renderer, &mut clock, "api");
        assert_eq!(outcome, Outcome::Failed);
        let out = String::from_utf8(out).expect("utf-8");
        assert!(out.contains("could not be written down"), "{out}");
        assert!(!out.contains("free to wait"), "{out}");
    }

    /// A run nobody is watching parks: it returns at once, names the step it
    /// is waiting on and why, and nothing after the approval ran (#97).
    #[test]
    fn an_unwatched_run_parks_at_the_approval_instead_of_declining_or_waiting() {
        let steps = site_steps();
        let by: Vec<&Step> = steps.iter().collect();
        let now = Rc::new(Cell::new(Duration::ZERO));
        let mut runner = Scripted { now: now.clone(), script: &SCRIPT };
        let parking = InMemory::new();
        let parked = Rc::clone(&parking.parked);
        let mut approver = Unwatched(parking);
        let mut out = Vec::new();
        let mut renderer = Run::new(&mut out, false, false);
        let mut clock = || now.get();
        let started = Instant::now();
        let outcome =
            drive(&by, &mut runner, &mut approver, &mut renderer, &mut clock, "api@a41c9e");

        let run = parked_run();
        assert_eq!(
            outcome,
            Outcome::Waiting {
                run: run.clone(),
                step: "review".into(),
                on: WaitReason::Approval { question: "approve 3 changes?".into() },
            }
        );
        assert!(parked.get(), "the run was written down");
        assert_eq!(
            String::from_utf8(out).expect("utf-8"),
            format!(
                concat!(
                    "▸ build   sha256:9f2c…e1  signed    38s\n",
                    "▸ plan    +2 ~1 -0                  11s\n",
                    "▸ review  approve 3 changes? n\n",
                    "⏸ parked at review (run {run})\n",
                ),
                run = run,
            )
        );
        // The acceptance criterion: the call came back. The work between the
        // two clock reads is in memory, so anything near a second is a loop
        // or a sleep.
        assert!(
            started.elapsed() < Duration::from_millis(250),
            "parking blocks for {:?}; it must return at once",
            started.elapsed()
        );
        assert_eq!(now.get(), Duration::from_secs(69), "nothing after the review ran");
    }

    /// Parking is for nobody answering. A person who typed `n` answered, and
    /// the run declines even with somewhere to park.
    #[test]
    fn a_typed_no_declines_even_where_the_run_could_park() {
        struct TypedNo(InMemory);
        impl Approver for TypedNo {
            fn ask(&mut self, _question: &str) -> Answer {
                Answer { approved: false, by: None, typed: true }
            }
            fn park(&mut self, step: &str, done: &[&Step], on: &WaitReason) -> Option<RunId> {
                self.0.park(step, done, on)
            }
        }
        let steps = site_steps();
        let by: Vec<&Step> = steps.iter().collect();
        let now = Rc::new(Cell::new(Duration::ZERO));
        let mut runner = Scripted { now: now.clone(), script: &SCRIPT };
        let parking = InMemory::new();
        let parked = Rc::clone(&parking.parked);
        let mut approver = TypedNo(parking);
        let mut out = Vec::new();
        let mut renderer = Run::new(&mut out, false, false);
        let mut clock = || now.get();
        let outcome = drive(&by, &mut runner, &mut approver, &mut renderer, &mut clock, "api");
        assert_eq!(outcome, Outcome::Declined);
        assert!(!parked.get(), "a typed answer is not a park");
    }

    /// The approver with nowhere to park still declines.
    #[test]
    fn an_approver_with_nowhere_to_park_still_declines() {
        let on = WaitReason::Approval { question: "approve?".into() };
        assert!(Declines.park("review", &[], &on).is_none());
        let (_, outcome, _) = site_run(false, false, false);
        assert_eq!(outcome, Outcome::Declined);
    }

    #[test]
    fn the_plain_run_is_the_sites_run_line_for_line() {
        let (plain, outcome, _) = site_run(true, true, false);
        assert_eq!(outcome, Outcome::Shipped);
        // Not just the golden: the site's lines, so a stray UPDATE_GOLDEN
        // cannot redefine them.
        assert_eq!(
            plain,
            concat!(
                "▸ build   sha256:9f2c…e1  signed    38s\n",
                "▸ plan    +2 ~1 -0                  11s\n",
                "▸ review  approve 3 changes? y\n",
                "▸ apply   3 resources               42s\n",
                "▸ deploy  4/4 pods healthy          27s\n",
                "✓ shipped api@a41c9e in 2m 18s\n",
            )
        );
        assert_eq!(plain, read_or_update("site.plain", &plain));
    }

    /// The TTY renderer animates and rewrites; what a person is left looking
    /// at must still be the plain run.
    #[test]
    fn the_terminal_run_leaves_the_person_with_the_plain_lines() {
        // Both approvals are covered: the one a person typed at, whose `y`
        // the terminal echoed, and the one nobody answered, which the
        // renderer closes itself. Only the first needs the echo.
        for (typed, echo) in [(true, "y\n"), (false, "")] {
            let (raw, outcome, _) = site_run(true, typed, true);
            assert_eq!(outcome, Outcome::Shipped);
            let mut bytes = raw.into_bytes();
            let plain = read_or_update("site.plain", "");
            if typed {
                // After the prompt, where the user's `y` and its newline
                // would have appeared.
                let prompt = prompt_line("review", "approve 3 changes?");
                let at = bytes
                    .windows(prompt.len())
                    .position(|w| w == prompt.as_bytes())
                    .expect("the prompt is in the bytes")
                    + prompt.len();
                bytes.splice(at..at, echo.bytes());
            }
            assert_eq!(screen(&bytes), plain, "typed={typed}");
        }
    }

    #[test]
    fn declining_stops_the_run_before_apply() {
        let (raw, outcome, now) = site_run(false, false, false);
        assert_eq!(outcome, Outcome::Declined);
        assert_eq!(now.get(), Duration::from_secs(69), "nothing after the review ran");
        assert_eq!(
            raw,
            concat!(
                "▸ build   sha256:9f2c…e1  signed    38s\n",
                "▸ plan    +2 ~1 -0                  11s\n",
                "▸ review  approve 3 changes? n\n",
                "✗ declined at review\n",
            )
        );
    }

    #[test]
    fn until_brings_the_step_and_what_it_depends_on() {
        assert_eq!(
            chosen(SITE, Some("apply"), &[], &[]).expect("--until apply"),
            ["plan", "review", "apply"]
        );
    }

    #[test]
    fn skipping_an_approval_takes_its_consumers_with_it() {
        assert_eq!(chosen(SITE, None, &[], &["review"]).expect("--skip review"), ["build", "plan"]);
    }

    #[test]
    fn only_refuses_to_run_a_step_without_what_it_depends_on() {
        // An approval says what waiting means.
        assert_eq!(
            chosen(SITE, None, &["apply"], &[]).expect_err("gated"),
            "`apply` waits on approval `review`; use --until apply"
        );
        // An ordinary dependency says what is missing.
        assert_eq!(
            chosen(PLAIN, None, &["deploy"], &[]).expect_err("needs build"),
            "`deploy` needs `build`; use --until deploy"
        );
        // Named together it is a plain selection.
        assert_eq!(
            chosen(SITE, None, &["plan", "review", "apply"], &[]).expect("with its deps"),
            ["plan", "review", "apply"]
        );
    }

    #[test]
    fn an_unknown_step_name_and_an_empty_selection_are_usage_errors() {
        assert_eq!(
            chosen(SITE, Some("nope"), &[], &[]).expect_err("unknown --until"),
            "no step `nope` in this file"
        );
        assert_eq!(
            chosen(SITE, None, &["plan"], &["plan"]).expect_err("nothing left"),
            "nothing left to run"
        );
    }

    #[test]
    fn a_terminal_approves_on_y_and_declines_on_anything_else() {
        for (answer, approved) in
            [("y\n", true), ("Y\n", true), ("yes\n", true), ("n\n", false), ("\n", false)]
        {
            let mut approver = TtyApprover::new(std::io::Cursor::new(answer.as_bytes()));
            let asked = approver.ask("approve 3 changes?");
            assert_eq!(asked.approved, approved, "{answer:?}");
            assert!(asked.typed, "{answer:?}");
        }
        // A closed stdin answers for nobody and echoes nothing.
        let mut approver = TtyApprover::new(std::io::Cursor::new("".as_bytes()));
        assert_eq!(approver.ask("approve 3 changes?"), NOBODY_ANSWERED);
    }
}
