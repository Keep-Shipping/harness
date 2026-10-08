//! The `keepshipping decide --explain` command: what a run sent to a decision model
//! ([#107](https://github.com/Keep-Shipping/harness/issues/107)).
//!
//! A `decide` step may call a hosted model, and the state it sends is the plan's *shape* —
//! addresses, types, actions, attribute names, counts — built by [`ks_core::redact`]. That promise
//! is only worth something if the user can read what was sent, so this replays each `decide.sent`
//! event from the run log: the question, and the state as the journal recorded it. Any value the
//! journal scrubbed is scrubbed here too — a registered secret reads as `***`, which is the whole
//! point of it having been scrubbed.
//!
//! The chain is verified first, and a broken one is a refusal rather than a print: the point of
//! this command is to tell the user truthfully what left their machine, and a log someone has
//! edited is not evidence of that. `log` prints a broken log anyway, to read the tamper
//! ([`crate::log`]); here the tamper is the thing being denied.

use std::io::Write;
use std::process::ExitCode;

use ks_core::ids::RunId;

use crate::args::USAGE;
use crate::log::read_run;
use crate::run_log::verify;

/// The entry point for `keepshipping decide --explain [RUN-ID]`.
///
/// 0 for a run whose chain holds, whether or not it sent anything; 1 for a broken chain or a write
/// failure; 2 for usage and for a run that is not there — the same set `log` uses.
pub fn decide(args: &[String]) -> ExitCode {
    let Some(named) = parse(args) else { return usage() };

    let (path, text) = match read_run(named.as_ref()) {
        Ok(found) => found,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };
    if let Err(broken) = verify(&text) {
        eprintln!("{}:{}: chain broken: {}", path.display(), broken.line, broken.reason);
        return ExitCode::from(1);
    }

    // The run's own id, read back off the file `read_run` found: the name of a run's log *is* its
    // id, and with no id given the reader still wants to know which run this is about.
    let run = path.file_stem().and_then(|stem| stem.to_str()).unwrap_or("?");
    let sent = sent(&text);
    let mut out = std::io::stdout().lock();
    let rendered = if sent.is_empty() {
        // Nothing was sent, so there is nothing to show — but the run was read and its chain
        // holds, which is itself the answer to the question a reader has here.
        writeln!(out, "run {run}: no decide step sent anything to a decision model")
            .map_err(|e| e.to_string())
    } else {
        render(&mut out, &sent, run).map_err(|e| e.to_string())
    };
    if let Err(message) = rendered {
        eprintln!("error: writing the explanation failed ({message})");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// The run id `--explain` was given, or `None` for the most recent run; `None` overall when these
/// are not those arguments. Parsed by hand rather than through `args::parse_args` because `decide`
/// takes a run id — not a site file — which that parse has no place for, the same note `log` makes.
fn parse(args: &[String]) -> Option<Option<RunId>> {
    let mut explained = false;
    let mut run = None;
    for arg in args {
        match arg.as_str() {
            "--explain" => {
                // Repeated, it is a mistake worth naming rather than a flag to shrug at.
                if explained {
                    return None;
                }
                explained = true;
            }
            _ if run.is_none() => run = Some(RunId::parse(arg).ok()?),
            _ => return None,
        }
    }
    explained.then_some(run)
}

fn usage() -> ExitCode {
    eprintln!("error: `decide` needs `--explain`, and takes at most one run id");
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

/// The `decide.sent` events in a run log, in the order they were journalled. `verify` has already
/// parsed every line, so an entry that does not name the event is simply not one of ours.
fn sent(text: &str) -> Vec<serde_json::Value> {
    text.lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|entry| {
            entry.get("type").and_then(serde_json::Value::as_str) == Some("decide.sent")
        })
        .collect()
}

/// What each event contributed, as recorded: the step and model, then each question's id and the
/// instructions it was asked with, then the state as the journal wrote it — no re-render and no
/// trimming, because a secret the journal masked as `***` must read here as masked, not as value.
///
/// The state is unindented and unterminated: a prefix on each of its lines, or a newline it did
/// not have, would both be decoration added between the reader and the bytes being explained.
fn render(w: &mut impl Write, events: &[serde_json::Value], run: &str) -> std::io::Result<()> {
    writeln!(w, "run {run}: {} event(s) sent to a decision model", events.len())?;
    for (n, entry) in events.iter().enumerate() {
        if n > 0 {
            writeln!(w)?;
        }
        writeln!(w, "step {} sent to model {}", text(entry, "step"), text(entry, "model"))?;
        // No questions is not a shape the port builds, but a line a later build writes must not read as a
        // run with nothing to say.
        let none: Vec<serde_json::Value> = Vec::new();
        let questions =
            entry.get("questions").and_then(serde_json::Value::as_array).unwrap_or(&none);
        if questions.is_empty() {
            writeln!(w, "  (no question recorded)")?;
        }
        for question in questions {
            writeln!(w, "question {}:", text(question, "id"))?;
            for line in text(question, "instructions").lines() {
                writeln!(w, "  {line}")?;
            }
        }
        writeln!(w, "state, as sent:")?;
        let state = text(entry, "state");
        write!(w, "{state}")?;
        if !state.ends_with('\n') {
            writeln!(w)?;
        }
    }
    Ok(())
}

/// One string field of an entry, or `(none)` when the line does not carry it: a reader is owed a
/// line for every field they were promised, not a blank where one would have been.
fn text(value: &serde_json::Value, key: &str) -> String {
    value.get(key).and_then(serde_json::Value::as_str).unwrap_or("(none)").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(text: &[&str]) -> Vec<String> {
        text.iter().map(|s| s.to_string()).collect()
    }

    /// The forms that work: the flag alone, and the flag with a run id in either order. The forms
    /// that do not: no flag, a second id, a second flag, and an id that is not a ULID.
    #[test]
    fn explain_is_required_and_takes_at_most_one_run_id() {
        const ID: &str = "01HQ0000000000000000000000";
        for (given, named) in [
            (&["--explain"][..], Some(None)),
            (&["--explain", ID][..], Some(Some(ID))),
            (&[ID, "--explain"][..], Some(Some(ID))),
        ] {
            // The id parses to the same `RunId` either way round, so comparing the string is the
            // whole claim: the flag was taken, and the id that went with it.
            let parsed = parse(&args(given)).map(|run| run.map(|id| id.to_string()));
            assert_eq!(parsed, named.map(|id| id.map(str::to_string)), "{given:?}");
        }
        for bad in [
            vec![],
            vec![ID],
            vec!["--explain", ID, "01HQ0000000000000000000001"],
            vec!["--explain", "--explain"],
            vec!["--explain", "nope"],
        ] {
            assert!(parse(&args(&bad)).is_none(), "{bad:?} should not parse");
        }
    }
}
