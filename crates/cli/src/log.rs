//! The `keepshipping log` command: print a run's events, or check that its log has not been
//! edited ([#46](https://github.com/Keep-Shipping/harness/issues/46)).
//!
//! Three forms, one per question:
//!
//! - `keepshipping log [RUN-ID]` — what did the run do, one line per event;
//! - `keepshipping log [RUN-ID] --format json` — the entries as stored, for tools;
//! - `keepshipping log verify [RUN-ID]` — does the hash chain still hold, the check a CI job runs
//!   after fetching the log as a CI artifact.
//!
//! With no id the most recent run in `.keepshipping/runs/` is used, which sorts by ULID time so
//! the newest is simply the last.
//!
//! Exit codes follow the house rules: 0 when the log could be read (whatever it says), 1 when
//! `verify` finds a broken chain, 2 for usage problems and a run that is not there. Printing never
//! verifies: a run whose chain is broken still prints, so the tamper can be read.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ks_core::ids::RunId;

use crate::args::USAGE;
use crate::render::Format;
use crate::run_log::{JsonlRunLog, RUNS_DIR, verify};

/// The entry point for `keepshipping log [verify] [RUN-ID]`.
pub fn log(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("verify") => check(&args[1..]),
        _ => show(args),
    }
}

/// `log [RUN-ID] [--format human|json]`. An id that is not a ULID is a usage error: it cannot name
/// a file, and guessing would read the wrong run. Parsed here rather than through
/// `args::parse_args` because `log` takes a run id — not a site file — and a `verify` subcommand
/// that parse has no place for.
fn show(args: &[String]) -> ExitCode {
    let Some((run, format)) = parse_show(args) else { return usage() };

    let (_path, text) = match read_run(run.as_ref()) {
        Ok(found) => found,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };
    let mut out = std::io::stdout().lock();
    let rendered: Result<(), String> = match format {
        // As stored, byte for byte: a tool that re-checks the chain hashes exactly these lines, so
        // a re-rendered entry would not verify.
        Format::Json => out.write_all(text.as_bytes()).map_err(|e| e.to_string()),
        _ if text.lines().next().is_none() => writeln!(out, "no events").map_err(|e| e.to_string()),
        _ => human(&mut out, &text).map_err(|e| e.to_string()),
    };
    if let Err(message) = rendered {
        eprintln!("error: writing the log failed ({message})");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// `log verify [RUN-ID]`: the offline check. A break is 1 — the log is not what it claims to be —
/// with the file and the first line that does not hold, in the `path:line:` shape the rest of the
/// tool prints.
fn check(args: &[String]) -> ExitCode {
    let run = match args {
        [] => None,
        [id] => match RunId::parse(id) {
            Ok(run) => Some(run),
            Err(error) => {
                eprintln!("error: `{id}` is not a run id: {error}");
                return usage();
            }
        },
        _ => return usage(),
    };
    let (path, text) = match read_run(run.as_ref()) {
        Ok(found) => found,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };
    match verify(&text) {
        Ok(entries) => {
            println!("ok: {entries} entries, chain intact");
            ExitCode::SUCCESS
        }
        Err(broken) => {
            eprintln!("{}:{}: chain broken: {}", path.display(), broken.line, broken.reason);
            ExitCode::from(1)
        }
    }
}

/// The run id and the format, or `None` if these are not those.
fn parse_show(args: &[String]) -> Option<(Option<RunId>, Format)> {
    let mut run = None;
    let mut format = Format::Human;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if arg == "--format" {
            format = Format::parse(rest.next()?)?;
        } else if run.is_none() {
            run = Some(RunId::parse(arg).ok()?);
        } else {
            return None;
        }
    }
    // GitHub annotations annotate source spans; a log entry has none.
    (format != Format::Github).then_some((run, format))
}

fn usage() -> ExitCode {
    eprintln!("error: `log` takes a run id and an optional --format human|json");
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

/// The run's file and its text, or why there is nothing to read: no run at all, an id no run has,
/// or a file that is not UTF-8.
fn read_run(run: Option<&RunId>) -> Result<(PathBuf, String), String> {
    let dir = Path::new(RUNS_DIR);
    let run = match run {
        Some(run) => run.clone(),
        None => JsonlRunLog::latest(dir)
            .ok_or_else(|| format!("no runs logged under {RUNS_DIR}; run something first"))?,
    };
    let path = JsonlRunLog::path_for(dir, &run);
    let text = std::fs::read_to_string(&path)
        .map_err(|error| format!("cannot read the log for run {run}: {error}"))?;
    Ok((path, text))
}

/// Human output: `HH:MM:SS  type  the rest of the event`, one line per entry. The time is UTC — a
/// log read in CI has no local zone to mean anything by.
fn human(w: &mut impl Write, text: &str) -> std::io::Result<()> {
    for line in text.lines() {
        let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) else {
            writeln!(w, "(unreadable entry)")?;
            continue;
        };
        let at = entry.get("at").and_then(serde_json::Value::as_u64).unwrap_or(0);
        let kind = entry.get("type").and_then(serde_json::Value::as_str).unwrap_or("?");
        let detail = detail(&entry);
        if detail.is_empty() {
            writeln!(w, "{}  {kind}", hms(at))?;
        } else {
            writeln!(w, "{}  {kind}  {detail}", hms(at))?;
        }
    }
    Ok(())
}

/// `HH:MM:SS` for unix milliseconds, UTC. Wrapping at a day is honest enough for a clock time in
/// a log and saves the date arithmetic.
fn hms(millis: u64) -> String {
    let seconds = millis / 1000;
    format!("{:02}:{:02}:{:02}", seconds / 3600 % 24, seconds / 60 % 60, seconds % 60)
}

/// The event's own fields as one clause: every key the entry carries beyond the five the adapter
/// always writes, as `key=value`. Generic rather than per-kind, so an event a later build adds
/// prints without a line here. A digest is long, so a list is spelled out only while it is short.
fn detail(entry: &serde_json::Value) -> String {
    const RESERVED: [&str; 5] = ["at", "hash", "prev", "run", "seq"];
    let Some(fields) = entry.as_object() else { return String::new() };
    fields
        .iter()
        .filter(|(key, _)| !(RESERVED.contains(&key.as_str()) || *key == "type"))
        .map(|(key, value)| format!("{key}={}", readable(key, value)))
        .collect::<Vec<_>>()
        .join("  ")
}

/// One value as a person reads it: a duration in seconds, a short list spelled out. A digest is
/// long, so a long one is counted.
fn readable(key: &str, value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Array(items) if items.len() <= 3 => {
            items.iter().map(|item| readable(key, item)).collect::<Vec<_>>().join(",")
        }
        serde_json::Value::Array(items) => format!("{} items", items.len()),
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Number(n) if key == "duration_ms" => {
            format!("{:.1}s", n.as_f64().unwrap_or_default() / 1000.0)
        }
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(text: &[&str]) -> Vec<String> {
        text.iter().map(|s| s.to_string()).collect()
    }

    /// One run id, and an optional `human`/`json` format. The forms that work: a bare id, an id
    /// with a format, and no arguments at all (the latest run). The forms that do not: a second
    /// id, a format with no source spans to annotate, a format with no value, and an id that is
    /// not a ULID.
    #[test]
    fn one_id_and_an_optional_human_or_json_format() {
        for (given, format, named) in [
            (&["01HQ0000000000000000000000"][..], Format::Human, true),
            (&["01HQ0000000000000000000000", "--format", "json"][..], Format::Json, true),
            (&["--format", "json"][..], Format::Json, false),
            (&[][..], Format::Human, false),
        ] {
            let (run, parsed) = parse_show(&args(given)).unwrap_or_else(|| panic!("{given:?}"));
            assert_eq!((parsed, run.is_some()), (format, named), "{given:?}");
        }
        for bad in [
            vec!["--format", "github"],
            vec!["--format"],
            vec!["01HQ0000000000000000000000", "01HQ0000000000000000000001"],
            vec!["nope"],
        ] {
            assert!(parse_show(&args(&bad)).is_none(), "{bad:?} should not parse");
        }
    }
}
