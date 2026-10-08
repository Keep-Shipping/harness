//! What a run has to say, and the renderer that says it.
//!
//! [`drive`](crate::drive) publishes a stream of [`RunEvent`]s — a CLI-local
//! stand-in for the run log
//! ([#46](https://github.com/Keep-Shipping/harness/issues/46)); a renderer
//! only reads it. At a terminal the step in flight gets a spinner and a
//! running clock, rewritten in place; anywhere else — a pipe, a CI log, a
//! test — the same lines are written once each, with no escape codes and no
//! cursor movement. One renderer, one `tty` flag: the two agree line for
//! line, which the tests prove by replaying the animated bytes through
//! `screen`.

use std::io::Write;
use std::time::{Duration, Instant};

use ks_core::ids::RunId;

/// One thing that happened in a run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunEvent {
    /// A step began; its line is still empty until it reports something.
    Started { step: String },
    /// A line of the step's own output, shown under `-v`.
    Log { step: String, line: String },
    /// A step finished: the one-line summary it goes on the run as.
    Finished { step: String, summary: String, took: Duration },
    /// A step failed; the run stops here.
    Failed { step: String, error: String, took: Duration },
    /// An approval step is asking its question, and waits for an answer.
    Asking { step: String, question: String },
    /// The answer, and who gave it — the approver's name rides along for the
    /// run log ([#46](https://github.com/Keep-Shipping/harness/issues/46)).
    /// `typed` is false when nobody was there to answer: the prompt is then
    /// still open on the terminal and has to be closed.
    Answered { step: String, approved: bool, by: Option<String>, typed: bool },
    /// Every selected step ran and the run shipped `what`.
    Shipped { what: String, took: Duration },
    /// The approval at `step` was declined; nothing after it ran.
    Declined { step: String },
    /// The run is parked at `step`: the approval needs a person, and there
    /// was nobody to ask. `team` is the step's `from:` handle when it named
    /// one, and `run` the id the run reports itself under.
    Waiting { step: String, team: Option<String>, run: String },
}

/// Something that draws a run as it happens.
pub trait Renderer {
    fn event(&mut self, e: &RunEvent);

    /// Redraws the step in flight. The ticker calls this between events; a
    /// renderer with nothing in flight does nothing.
    fn tick(&mut self) {}
}

/// The columns of a step line: the name, then the summary, then the time.
/// Every step line is the same width so a run reads as a table.
const NAME_WIDTH: usize = 8;
const SUMMARY_WIDTH: usize = 25;

/// The spinner, one braille dot hopping around the eighth of a circle.
const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Carriage return, then erase the line: the only cursor movement there is.
const CLEAR: &str = "\r\x1b[2K";

/// `38s`, or `2m 18s` from a minute on.
pub fn duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 { format!("{secs}s") } else { format!("{}m {}s", secs / 60, secs % 60) }
}

/// The line a finished step goes on the run as:
/// `▸ build   sha256:9f2c…e1  signed    38s`. A summary longer than its
/// column is cut with an `…` rather than pushing the time out of line.
pub fn step_line(step: &str, summary: &str, took: Duration) -> String {
    let chars: Vec<char> = summary.chars().collect();
    let short: String = match chars.len() {
        n if n <= SUMMARY_WIDTH => summary.to_string(),
        _ => chars[..SUMMARY_WIDTH - 1].iter().chain([&'…']).collect(),
    };
    format!("▸ {step:<NAME_WIDTH$}{short:<SUMMARY_WIDTH$} {}", duration(took))
}

/// The line a failed step leaves: the step, and what stopped it.
pub fn fail_line(step: &str, error: &str) -> String {
    format!("✗ {step:<NAME_WIDTH$}{error}")
}

/// The line `--dry-run` prints: the step and its kind, with no time.
pub fn kind_line(step: &str, kind: &str) -> String {
    format!("▸ {step:<NAME_WIDTH$}{kind}")
}

/// The prompt an approval asks, with the answer's place left open: a terminal
/// fills it in as the user types, and a renderer with nobody at the keyboard
/// closes it with `y` or `n`.
pub fn prompt_line(step: &str, question: &str) -> String {
    format!("▸ {step:<NAME_WIDTH$}{question} ")
}

/// The line a run parked at an approval leaves: where it stopped, and for
/// whom. An approval with no `from:` names no team, so the line says only
/// where it is.
pub fn wait_line(step: &str, team: Option<&str>, run: &str) -> String {
    let where_ = match team {
        Some(team) => format!("at {step} for {team}"),
        None => format!("at {step}"),
    };
    format!("⏸ waiting {where_} — run {run}")
}

/// The command that reports where a parked run got to, named once because a
/// report and the JSON both have to spell it the same way.
fn status_command(run: &str) -> String {
    format!("keepshipping runs status {run}")
}

/// The follow-up: what to run next to find out where the run got to.
pub fn check_line(run: &str) -> String {
    format!("  check: {}", status_command(run))
}

/// What an approval answered, in the answer's place.
fn answer(approved: bool) -> &'static str {
    if approved { "y" } else { "n" }
}

/// The step being drawn, and when it started.
struct Live {
    step: String,
    since: Instant,
}

/// The renderer. `tty` decides whether the step in flight is animated and
/// redrawn, or simply left out until the step is over.
pub struct Run<W> {
    out: W,
    verbose: bool,
    tty: bool,
    /// The step in flight, if any; always `None` when `tty` is false.
    live: Option<Live>,
    /// An approval was asked and nothing has closed its line yet. A person who
    /// answered echoed their own newline; a run parked at the approval never
    /// will, so the waiting lines have to close it themselves.
    prompted: bool,
    frame: usize,
}

impl<W: Write> Run<W> {
    pub fn new(out: W, verbose: bool, tty: bool) -> Self {
        Self { out, verbose, tty, live: None, prompted: false, frame: 0 }
    }

    /// Erases the line, whatever is on it.
    fn wipe(&mut self) {
        let _ = write!(self.out, "{CLEAR}");
    }

    /// Retires the line in flight so the next thing written starts clean.
    /// With nothing in flight the bytes are left alone: a prompt must not
    /// move a cursor it did not use.
    fn retire(&mut self) {
        if self.live.take().is_some() {
            self.wipe();
        }
    }

    /// Closes an approval's open line, if one is open, so what is written
    /// next starts on its own line rather than trailing the question.
    fn close_prompt(&mut self) {
        if self.prompted {
            self.prompted = false;
            let _ = writeln!(self.out);
        }
    }

    /// The spinner line: the step name, the frame, and how long it has run.
    fn draw(&mut self) {
        let Some(live) = &self.live else { return };
        let elapsed = duration(live.since.elapsed());
        let _ = write!(self.out, "▸ {:<NAME_WIDTH$}{} {elapsed}", live.step, FRAMES[self.frame]);
        let _ = self.out.flush();
    }
}

impl<W: Write> Renderer for Run<W> {
    fn event(&mut self, e: &RunEvent) {
        match e {
            RunEvent::Started { step } => {
                self.retire();
                if self.tty {
                    self.live = Some(Live { step: step.clone(), since: Instant::now() });
                    self.draw();
                }
            }
            RunEvent::Log { line, .. } if self.verbose => {
                self.retire();
                let _ = writeln!(self.out, "    {line}");
                self.draw();
            }
            RunEvent::Finished { step, summary, took } => {
                self.retire();
                let _ = writeln!(self.out, "{}", step_line(step, summary, *took));
            }
            RunEvent::Failed { step, error, .. } => {
                self.retire();
                let _ = writeln!(self.out, "{}", fail_line(step, error));
            }
            // Nothing spins while a person is typing: the prompt is the
            // line, and the answer lands on the end of it.
            RunEvent::Asking { step, question } => {
                self.retire();
                let _ = write!(self.out, "{}", prompt_line(step, question));
                self.prompted = true;
                let _ = self.out.flush();
            }
            // A terminal echoed what the user typed, newline and all, and
            // writing it twice would leave them looking at `yy`. Nobody
            // typed, so the prompt is still open and the answer closes it —
            // and a pipe has no echo to lean on either way.
            RunEvent::Answered { approved, typed, .. } if !self.tty || !typed => {
                let _ = writeln!(self.out, "{}", answer(*approved));
                self.prompted = false;
            }
            RunEvent::Answered { .. } => self.prompted = false,
            RunEvent::Shipped { what, took } => {
                let _ = writeln!(self.out, "✓ shipped {what} in {}", duration(*took));
            }
            RunEvent::Declined { step } => {
                let _ = writeln!(self.out, "✗ declined at {step}");
            }
            // Waiting is neither ✓ nor ✗: nothing broke, and nobody refused.
            // The person reading it has to know there is something to go and
            // do, and which team has to do it.
            RunEvent::Waiting { step, team, run } => {
                self.close_prompt();
                let _ = writeln!(self.out, "{}", wait_line(step, team.as_deref(), run));
                let _ = writeln!(self.out, "{}", check_line(run));
            }
            _ => {}
        }
    }

    fn tick(&mut self) {
        if self.live.is_none() {
            return;
        }
        self.frame = (self.frame + 1) % FRAMES.len();
        self.wipe();
        self.draw();
    }
}

/// The run as JSON Lines, schema v1: one self-contained object per line, and
/// nothing else on stdout — no banner, no spinner, no footer — so an agent can
/// read the stream with `jq` while it is still running.
///
/// Every line carries `"version":1` and a `"type"` naming what happened. The
/// first is `run.started` and the last `run.finished`, so a reader that only
/// reads those two knows the run's id and its outcome without tracking state.
/// `run.finished` carries the `status` an agent branches on and the `exit_code`
/// the process itself will return, so the two can never disagree. Fields are
/// only ever added within a version; a rename or a removal bumps it. The
/// schemas are in `docs/CLI.md`.
pub struct Json<W> {
    out: W,
    /// This run's id. `run.started` and `run.finished` carry it, so lines from
    /// two runs interleaved in one log can still be told apart.
    run: String,
}

impl<W: Write> Json<W> {
    /// A new stream, which opens by saying which run this is and where it is
    /// running — the one line a reader needs before it can follow anything.
    pub fn new(out: W, run: &RunId, env: &str) -> Self {
        let mut json = Self { out, run: run.to_string() };
        let started = run_started(&json.run, env);
        let _ = writeln!(json.out, "{started}");
        json
    }

    /// The `"run":"…"` key the closing lines carry.
    fn run_key(&self) -> String {
        format!(",\"run\":{}", crate::render::json_str(&self.run))
    }

    /// One line: an object whose first two keys are always `version` and
    /// `type`, so a reader can dispatch on it without a schema lookup.
    fn line(&mut self, fields: &str) {
        let _ = writeln!(self.out, "{{\"version\":1,\"type\":{fields}}}");
        let _ = self.out.flush();
    }
}

/// `"step":"review"` — the key every event but `run.started` and
/// `run.finished` starts with.
fn step_key(step: &str) -> String {
    format!(",\"step\":{}", crate::render::json_str(step))
}

/// A string, or `null` when it is absent — an approval that named no team
/// says so rather than omitting the key.
fn opt_str(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_string(), crate::render::json_str)
}

/// The `waiting` object of a `run.finished`: where the run stopped, who has to
/// move it, and how to check. The last is the command a human runs — and the
/// one an agent reports back — when the run is parked.
fn waiting(step: &str, team: Option<&str>, run: &str) -> String {
    format!(
        "{{\"step\":{},\"team\":{},\"check\":{}}}",
        crate::render::json_str(step),
        opt_str(team),
        crate::render::json_str(&status_command(run))
    )
}

impl<W: Write> Renderer for Json<W> {
    fn event(&mut self, e: &RunEvent) {
        let json_str = crate::render::json_str;
        match e {
            RunEvent::Started { step } => self.line(&format!("\"step.started\"{}", step_key(step))),
            RunEvent::Log { step, line } => {
                self.line(&format!("\"step.log\"{},\"line\":{}", step_key(step), json_str(line)));
            }
            RunEvent::Finished { step, summary, took } => self.line(&format!(
                "\"step.finished\"{},\"summary\":{},\"took_ms\":{}",
                step_key(step),
                json_str(summary),
                took.as_millis()
            )),
            // A failure is terminal, so it closes the stream here rather than waiting
            // for an event that will not come: an agent must not have to know
            // that `step.failed` means the run is over.
            RunEvent::Failed { step, error, took } => {
                self.line(&format!(
                    "\"step.failed\"{},\"error\":{},\"took_ms\":{}",
                    step_key(step),
                    json_str(error),
                    took.as_millis()
                ));
                let run_key = self.run_key();
                self.line(&format!(
                    "\"run.finished\"{run_key},\"status\":\"failed\",\"exit_code\":{},\
                     \"step\":{}",
                    crate::exit::FAILED,
                    json_str(step)
                ));
            }
            RunEvent::Asking { step, question } => self.line(&format!(
                "\"approval.asked\"{},\"question\":{}",
                step_key(step),
                json_str(question)
            )),
            RunEvent::Answered { step, approved, by, .. } => self.line(&format!(
                "\"approval.answered\"{},\"approved\":{},\"by\":{}",
                step_key(step),
                approved,
                opt_str(by.as_deref())
            )),
            RunEvent::Shipped { what, took } => {
                let run_key = self.run_key();
                self.line(&format!(
                    "\"run.finished\"{run_key},\"status\":\"shipped\",\"exit_code\":{},\
                     \"what\":{},\"took_ms\":{}",
                    crate::exit::SHIPPED,
                    json_str(what),
                    took.as_millis()
                ));
            }
            RunEvent::Declined { step } => {
                let run_key = self.run_key();
                self.line(&format!(
                    "\"run.finished\"{run_key},\"status\":\"denied\",\"exit_code\":{},\
                     \"step\":{}",
                    crate::exit::DENIED,
                    json_str(step)
                ));
            }
            RunEvent::Waiting { step, team, run } => {
                let run_key = self.run_key();
                self.line(&format!(
                    "\"run.finished\"{run_key},\"status\":\"waiting_for_approval\",\
                     \"exit_code\":{},\"waiting\":{}",
                    crate::exit::WAITING,
                    waiting(step, team.as_deref(), run)
                ));
            }
        }
    }

    /// A JSON stream has no cursor to redraw: a spinner would be a line of
    /// escape codes between two objects, and the objects are the whole point.
    fn tick(&mut self) {}
}

/// `run.started` goes out before the first step, so the stream opens with the
/// run's id and the environment it chose.
pub fn run_started(run: &str, env: &str) -> String {
    format!(
        "{{\"version\":1,\"type\":\"run.started\",\"run\":{},\"env\":{}}}",
        crate::render::json_str(run),
        crate::render::json_str(env)
    )
}

/// What a person would be left looking at: the bytes with `\r\x1b[2K`
/// applied, so a redrawn line replaces the one before it. Enough of a
/// terminal to prove the animated rendering says what the plain one says.
#[cfg(test)]
pub(crate) fn screen(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::new();
    let mut line = String::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            '\r' => line.clear(),
            // Skip a control sequence up to its final letter; the renderer
            // only ever emits `\x1b[2K`.
            '\x1b' => {
                for c in chars.by_ref() {
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            '\n' => {
                out.push_str(&line);
                out.push('\n');
                line.clear();
            }
            c => line.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_the_way_the_site_writes_them() {
        assert_eq!(duration(Duration::from_secs(0)), "0s");
        assert_eq!(duration(Duration::from_secs(38)), "38s");
        assert_eq!(duration(Duration::from_secs(59)), "59s");
        assert_eq!(duration(Duration::from_secs(60)), "1m 0s");
        assert_eq!(duration(Duration::from_secs(138)), "2m 18s");
    }

    #[test]
    fn a_step_line_is_the_columns_the_site_lines_have() {
        assert_eq!(
            step_line("build", "sha256:9f2c…e1  signed", Duration::from_secs(38)),
            "▸ build   sha256:9f2c…e1  signed    38s"
        );
        assert_eq!(
            step_line("deploy", "4/4 pods healthy", Duration::from_secs(27)),
            "▸ deploy  4/4 pods healthy          27s"
        );
        // A summary past its column is cut, so the time stays in line.
        assert_eq!(
            step_line("deploy", "4/4 pods healthy and warm for a while", Duration::from_secs(27)),
            "▸ deploy  4/4 pods healthy and war… 27s"
        );
    }

    #[test]
    fn a_step_says_nothing_until_it_is_over_and_logs_are_for_verbose() {
        let mut out = Vec::new();
        {
            let mut plain = Run::new(&mut out, false, false);
            plain.event(&RunEvent::Started { step: "build".into() });
            plain.event(&RunEvent::Log { step: "build".into(), line: "pulling".into() });
        }
        assert!(out.is_empty(), "a step says nothing until it is over");
        {
            let mut loud = Run::new(&mut out, true, false);
            loud.event(&RunEvent::Log { step: "build".into(), line: "pulling acme/api".into() });
            loud.event(&RunEvent::Finished {
                step: "build".into(),
                summary: "sha256:9f2c…e1  signed".into(),
                took: Duration::from_secs(38),
            });
        }
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "    pulling acme/api\n▸ build   sha256:9f2c…e1  signed    38s\n"
        );
    }

    /// The question, and an answer to it: `typed` says whether a person was
    /// at the keyboard.
    fn asking_and(approved: bool, typed: bool) -> (RunEvent, RunEvent) {
        (
            RunEvent::Asking { step: "review".into(), question: "approve 3 changes?".into() },
            RunEvent::Answered {
                step: "review".into(),
                approved,
                by: approved.then(|| "ada".to_string()),
                typed,
            },
        )
    }

    #[test]
    fn a_pipe_always_writes_the_answer_and_a_terminal_only_writes_an_untouched_one() {
        let (asking, typed) = asking_and(true, true);
        let mut out = Vec::new();
        {
            let mut plain = Run::new(&mut out, false, false);
            plain.event(&asking);
            plain.event(&typed);
        }
        assert_eq!(String::from_utf8(out).unwrap(), "▸ review  approve 3 changes? y\n");

        // A terminal echoed the `y` as it was typed; writing it twice would
        // leave the person looking at `yy`.
        let mut out = Vec::new();
        {
            let mut tty = Run::new(&mut out, false, true);
            tty.event(&asking);
            tty.event(&typed);
        }
        assert_eq!(String::from_utf8(out).unwrap(), "▸ review  approve 3 changes? ");

        // Nobody typed: the prompt is still open, and the answer closes it,
        // so the decline lands on a line of its own.
        let (asking, untyped) = asking_and(false, false);
        let mut out = Vec::new();
        {
            let mut tty = Run::new(&mut out, false, true);
            tty.event(&asking);
            tty.event(&untyped);
            tty.event(&RunEvent::Declined { step: "review".into() });
        }
        assert_eq!(screen(&out), "▸ review  approve 3 changes? n\n✗ declined at review\n");
    }

    #[test]
    fn ticking_redraws_the_line_in_flight_and_finishing_erases_it() {
        let mut out = Vec::new();
        {
            let mut tty = Run::new(&mut out, false, true);
            tty.event(&RunEvent::Started { step: "build".into() });
            tty.tick();
            tty.tick();
            tty.tick();
            tty.event(&RunEvent::Finished {
                step: "build".into(),
                summary: "signed".into(),
                took: Duration::from_secs(38),
            });
        }
        let bytes = String::from_utf8(out).unwrap();
        assert_eq!(bytes.matches(CLEAR).count(), 4, "three ticks and the finish: {bytes:?}");
        assert!(bytes.ends_with("▸ build   signed                    38s\n"), "{bytes:?}");
        // Whatever the spinner drew, the person is left with the summary.
        assert_eq!(screen(bytes.as_bytes()), "▸ build   signed                    38s\n");
    }
}
