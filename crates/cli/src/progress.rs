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

/// One thing that happened in a run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunEvent {
    /// The file checked clean, ahead of the steps: what an agent's run
    /// stands on before it goes near anything.
    Checked { path: String },
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
    /// The approval at `step` was not answered at all: the run waits on
    /// `on`, and `notified` says who has already been told, if anyone.
    /// Nothing after it ran, so the event closes the run with what that
    /// means — the reader, an agent included, is free to stop here.
    Waiting { step: String, on: String, notified: Option<String> },
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

/// How far in a line that continues another one sits: under the name column,
/// which starts after the glyph and its space.
const CONTINUATION: usize = 1 + 1 + NAME_WIDTH;

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
/// column is cut with an `…` rather than pushing the time out of line, and
/// a step that took no time has no time column at all.
pub fn step_line(step: &str, summary: &str, took: Duration) -> String {
    let chars: Vec<char> = summary.chars().collect();
    let short: String = match chars.len() {
        n if n <= SUMMARY_WIDTH => summary.to_string(),
        _ => chars[..SUMMARY_WIDTH - 1].iter().chain([&'…']).collect(),
    };
    // A step that took no time says no time: an agent's run reports what it
    // did before it waited, and a time column of `0s` there is noise.
    if took.is_zero() {
        return format!("▸ {step:<NAME_WIDTH$}{short}");
    }
    format!("▸ {step:<NAME_WIDTH$}{short:<SUMMARY_WIDTH$} {}", duration(took))
}

/// The line a checked file goes on a run as: `✓ check   ship.ks is valid`,
/// in the same name column the steps use.
pub fn check_line(path: &str) -> String {
    format!("✓ {:<NAME_WIDTH$}{path} is valid", "check")
}

/// The line a run nobody can answer leaves:
/// `⏸ review  waiting on a human`.
pub fn waiting_line(step: &str, on: &str) -> String {
    format!("⏸ {step:<NAME_WIDTH$}waiting on {on}")
}

/// Who has been told, under the line that says who the run waits on:
/// `          @platform notified, plan attached`.
pub fn notified_line(who: &str) -> String {
    format!("{:<CONTINUATION$}{who} notified, plan attached", "")
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
    frame: usize,
}

impl<W: Write> Run<W> {
    pub fn new(out: W, verbose: bool, tty: bool) -> Self {
        Self { out, verbose, tty, live: None, frame: 0 }
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
            RunEvent::Checked { path } => {
                self.retire();
                let _ = writeln!(self.out, "{}", check_line(path));
            }
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
                let _ = self.out.flush();
            }
            // A terminal echoed what the user typed, newline and all, and
            // writing it twice would leave them looking at `yy`. Nobody
            // typed, so the prompt is still open and the answer closes it —
            // and a pipe has no echo to lean on either way.
            RunEvent::Answered { approved, typed, .. } if !self.tty || !typed => {
                let _ = writeln!(self.out, "{}", answer(*approved));
            }
            RunEvent::Answered { .. } => {}
            RunEvent::Shipped { what, took } => {
                let _ = writeln!(self.out, "✓ shipped {what} in {}", duration(*took));
            }
            RunEvent::Declined { step } => {
                let _ = writeln!(self.out, "✗ declined at {step}");
            }
            // Nobody is answering, so there is no prompt to leave open and
            // no answer to close it: the wait is the line, and the run ends
            // saying what it did not do — the reader stops here.
            RunEvent::Waiting { step, on, notified } => {
                self.retire();
                let _ = writeln!(self.out, "{}", waiting_line(step, on));
                if let Some(who) = notified {
                    let _ = writeln!(self.out, "{}", notified_line(who));
                }
                let _ = writeln!(self.out, "nothing applied. agent is free to wait.");
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
        // A step that merely rounded down to `0s` still has a time: only a
        // duration of exactly zero loses the column.
        assert_eq!(
            step_line("apply", "1 resource", Duration::from_millis(900)),
            "▸ apply   1 resource                0s"
        );
        assert_eq!(step_line("apply", "1 resource", Duration::ZERO), "▸ apply   1 resource");
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
