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
}

/// Nobody was asked: the run declined itself.
pub const NOBODY_ANSWERED: Answer = Answer { approved: false, by: None, typed: false };

/// How a run ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Every selected step ran.
    Shipped,
    /// An approval was declined; nothing after it ran.
    Declined,
    /// A step failed; nothing after it ran.
    Failed,
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
/// the site's timings replay exactly. Stops at the first failure or declined
/// approval; a declined one answers itself when nobody was there to type.
pub fn drive(
    steps: &[&Step],
    runner: &mut dyn StepRunner,
    approver: &mut dyn Approver,
    renderer: &mut dyn Renderer,
    clock: &mut dyn FnMut() -> Duration,
    what: &str,
) -> Outcome {
    let start = clock();
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
            Ok(Done::Summary(summary)) => renderer.event(&RunEvent::Finished {
                step: name.clone(),
                summary,
                took: clock().saturating_sub(at),
            }),
            Ok(Done::Ask(question)) => {
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
fn local_user() -> String {
    ["USER", "USERNAME"]
        .into_iter()
        .find_map(|var| std::env::var(var).ok())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "local".to_string())
}

/// The approver of a run nobody is watching: it declines, always. A run that
/// needs a person cannot get one from a pipe.
pub struct Declines;

impl Approver for Declines {
    fn ask(&mut self, _question: &str) -> Answer {
        NOBODY_ANSWERED
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
    }

    impl StepRunner for Scripted {
        fn run(&mut self, step: &Step, log: &mut dyn FnMut(&str)) -> Result<Done, String> {
            let Some((_, summary, secs)) = SCRIPT.iter().find(|(name, _, _)| *name == step.name)
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
        let mut runner = Scripted { now: now.clone() };
        let mut approver = ScriptedApprover(approved, typed);
        let mut out = Vec::new();
        let mut renderer = Run::new(&mut out, false, tty);
        let mut clock = || now.get();
        let outcome =
            drive(&by, &mut runner, &mut approver, &mut renderer, &mut clock, "api@a41c9e");
        (String::from_utf8(out).expect("utf-8"), outcome, now)
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
