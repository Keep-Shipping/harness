//! The `keepshipping decisions` commands: what the decision models have actually been right
//! about, read back from the local run logs
//! ([#108](https://github.com/Keep-Shipping/harness/issues/108)).
//!
//! `report [--json]` is for a person, `export` is one JSON line per decision for
//! `scripts/calibrate.py`. Both render from a single report value, so the human text and the JSON
//! cannot drift apart.
//!
//! Logs are parsed generically as [`serde_json::Value`], not as `RunEvent`s: the run log port is
//! append-only *by design* and has no reader, so a report must keep working — showing the decisions
//! it can read — when a log predates a field. A missing `version` is `-` and a missing hash is
//! `null`, never a reason to drop a decision.
//!
//! A broken chain is loud: the log is named on stderr with the line and the reason, its decisions
//! are left out, and the exit code is 1 — a calibration built on an edited audit trail is worse
//! than no calibration. The other logs still report, because one tampered file is not a reason to
//! hide the rest.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde_json::{Map, Value, json};

use crate::args::USAGE;
use crate::run_log::{RUNS_DIR, verify};

/// `AUTO` is the outcome a run acted on without asking a human. Nothing in the tree fixes an
/// outcome vocabulary — the decide step is not wired up yet — so **anything that is not `auto` is
/// treated as escalated**, and that escalation is what makes a later approval evidence about the
/// confidence. It is named here, in one place, because this is the assumption a calibration rests
/// on. `APPROVED` is the reason an override inferred from an approval carries, since an approval
/// has no reason of its own. `BANDS` is the histogram's width: ten, wide enough to see where the
/// mass is, narrow enough that a small report does not print ten rows of nothing — and
/// `scripts/calibrate.py` bands the same way.
const AUTO: &str = "auto";
const APPROVED: &str = "a human approved the escalated decision";
const BANDS: usize = 10;

/// The entry point for `keepshipping decisions report [--json]` and `… export`.
pub fn decisions(args: &[String]) -> ExitCode {
    let (as_json, export) = match args.first().map(String::as_str) {
        Some("report") => match args.get(1..) {
            None | Some([]) => (false, false),
            Some([flag]) if flag.as_str() == "--json" => (true, false),
            _ => return usage(),
        },
        Some("export") if args.len() == 1 => (false, true),
        _ => return usage(),
    };

    let (mut logs, mut tampered) = (0usize, false);
    let (mut found, mut overrides, mut approvals) = (Vec::new(), Vec::new(), Vec::new());
    for path in log_files(Path::new(RUNS_DIR)) {
        let run = path.file_stem().and_then(|s| s.to_str()).unwrap_or("?").to_string();
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        match verify(&text) {
            Ok(_) => {}
            Err(broken) => {
                eprintln!(
                    "{}:{}: chain broken: {} — its decisions are left out of the report",
                    path.display(),
                    broken.line,
                    broken.reason
                );
                tampered = true;
                continue;
            }
        }
        logs += 1;
        let parsed = parse_log(&run, &text);
        found.extend(parsed.decisions);
        overrides.extend(parsed.overrides);
        approvals.extend(parsed.approvals);
    }
    // Only once every log is read: an override usually lands in a later run than the decision it
    // corrects — the rollback case — so the join is over the whole set, not log by log.
    for decision in &mut found {
        decision.human = override_for(decision, &overrides, &approvals);
    }

    if as_json {
        println!("{}", report_json(&found, logs));
    } else if export {
        let mut out = String::new();
        for decision in &found {
            let _ = writeln!(out, "{}", export_line(decision));
        }
        let mut stdout = std::io::stdout().lock();
        if let Err(message) = stdout.write_all(out.as_bytes()) {
            eprintln!("error: writing the export failed ({message})");
            return ExitCode::from(1);
        }
    } else if found.is_empty() {
        println!("no decisions recorded under {RUNS_DIR}");
    } else if let Err(message) = report(&report_json(&found, logs)) {
        eprintln!("error: writing the report failed ({message})");
        return ExitCode::from(1);
    }

    if tampered {
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// The report a person reads, rendered out of the value `report_json` builds — every number here is
/// read from that object rather than recomputed, which is what keeps the two forms equal. Sorted,
/// and with the histogram bar scaled to its fullest band, so two reports of the same logs come out
/// identical and a small one is still readable.
fn report(value: &Value) -> std::io::Result<()> {
    let count = |key: &str| value[key].as_u64().unwrap_or(0);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} decisions from {} run logs under {RUNS_DIR}\n",
        count("decisions"),
        count("logs")
    );
    for (title, key) in [("answers", "answers"), ("outcomes", "outcomes"), ("models", "models")] {
        let row: Vec<String> = value[key]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(name, n)| format!("{name} {}", n.as_u64().unwrap_or(0)))
            .collect();
        let _ = writeln!(out, "{title}\n  {}", row.join("  "));
        out.push('\n');
    }

    let bands = value["confidence_histogram"].as_array().cloned().unwrap_or_default();
    let peak = bands.iter().filter_map(|b| b["count"].as_u64()).max().unwrap_or(1).max(1);
    let _ = writeln!(out, "confidence");
    for band in &bands {
        let count = band["count"].as_u64().unwrap_or(0);
        // No bar and no padding either: an empty row is two columns of numbers, not a line of
        // trailing spaces.
        let row = match count {
            0 => format!("  {}  0", field(band, "band")),
            _ => format!(
                "  {}  {count:<4}{}",
                field(band, "band"),
                "#".repeat(count as usize * 40 / peak as usize)
            ),
        };
        let _ = writeln!(out, "{row}");
    }
    out.push('\n');

    let overrides = value["overrides"].as_array().cloned().unwrap_or_default();
    let _ = writeln!(out, "overrides ({})", overrides.len());
    for over in &overrides {
        let _ = writeln!(
            out,
            "  {} {} {} {:.2} by {} — {}",
            field(over, "run"),
            field(over, "step"),
            field(over, "answer"),
            over["confidence"].as_f64().unwrap_or(0.0),
            field(over, "by"),
            field(over, "reason")
        );
    }
    std::io::stdout().lock().write_all(out.as_bytes())
}

/// One decision, as the report and the export need it. `probabilities` is carried as the value the
/// log stored rather than parsed, since only the export reads it and re-shaping it would be work
/// for nothing; `question_hash` and `state_hash` are `None` for a log written before the fields
/// existed, and `version` is `-` for the same reason.
#[derive(Debug, Clone)]
struct Decision {
    run: String,
    seq: u64,
    step: String,
    model: String,
    version: String,
    question_hash: Option<String>,
    state_hash: Option<String>,
    answer: String,
    probabilities: Value,
    confidence: f64,
    threshold: f64,
    outcome: String,
    human: Option<Human>,
}

/// A human's answer to the question the model answered: who, and why.
#[derive(Debug, Clone, PartialEq)]
struct Human {
    by: String,
    reason: String,
}

/// One run's log, parsed into the three things a report joins: its decisions, the overrides
/// recorded anywhere in it as `(decision_run, step, human)` — keyed by the run they *name*, which
/// is not the log they sit in — and its approvals as `(run, step, approver, seq)`, where `seq` is
/// what tells an approval after a decision from one before it.
#[derive(Debug, Default)]
struct Parsed {
    decisions: Vec<Decision>,
    overrides: Vec<(String, String, Human)>,
    approvals: Vec<(String, String, String, u64)>,
}

/// The run logs under `dir`, sorted so two reports of the same logs read the same way.
fn log_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
        .collect();
    files.sort();
    files
}

/// A string field, `-` when the log did not have it: a missing field is reported, never guessed.
/// The hash twin differs in returning `None`, because `null` is the honest rendering of "this log
/// said nothing" and a calibration must be able to tell it from a hash.
fn field(entry: &Value, key: &str) -> String {
    entry.get(key).and_then(Value::as_str).unwrap_or("-").to_string()
}

fn opt(entry: &Value, key: &str) -> Option<String> {
    entry.get(key).and_then(Value::as_str).map(str::to_string)
}

fn number(entry: &Value, key: &str) -> f64 {
    entry.get(key).and_then(Value::as_f64).unwrap_or(0.0)
}

/// Every decision, override and approval in one verified log.
fn parse_log(run: &str, body: &str) -> Parsed {
    let mut parsed = Parsed::default();
    for line in body.lines() {
        let Ok(entry) = serde_json::from_str::<Value>(line) else { continue };
        let run_of = |key: &str| entry.get(key).and_then(Value::as_str).unwrap_or(run).to_string();
        let seq = entry.get("seq").and_then(Value::as_u64).unwrap_or(0);
        match entry.get("type").and_then(Value::as_str).unwrap_or("") {
            "decide.answered" => parsed.decisions.push(Decision {
                run: run_of("run"),
                seq,
                step: field(&entry, "step"),
                model: field(&entry, "model"),
                version: field(&entry, "version"),
                question_hash: opt(&entry, "question_hash"),
                state_hash: opt(&entry, "state_hash"),
                answer: field(&entry, "answer"),
                probabilities: entry.get("probabilities").cloned().unwrap_or(Value::Null),
                confidence: number(&entry, "confidence"),
                threshold: number(&entry, "threshold"),
                outcome: field(&entry, "outcome"),
                human: None,
            }),
            "decision.overridden" => parsed.overrides.push((
                field(&entry, "decision_run"),
                field(&entry, "step"),
                Human { by: field(&entry, "by"), reason: field(&entry, "reason") },
            )),
            "approval.granted" => parsed.approvals.push((
                run_of("run"),
                field(&entry, "step"),
                field(&entry, "approver"),
                seq,
            )),
            _ => {}
        }
    }
    parsed
}

/// The human answer to `decision`, if a human gave one. Two routes, and the recorded one wins: a
/// `decision.overridden` is a person saying so in words, where an approval is only the shape of a
/// run that asked them. The approval route needs the approval to come *after* the decision in the
/// same run — one that precedes it was about something else — and the decision to have been
/// escalated rather than acted on automatically ([`AUTO`]).
fn override_for(
    decision: &Decision,
    overrides: &[(String, String, Human)],
    approvals: &[(String, String, String, u64)],
) -> Option<Human> {
    if let Some((_, _, human)) =
        overrides.iter().find(|(run, step, _)| *run == decision.run && *step == decision.step)
    {
        return Some(human.clone());
    }
    if decision.outcome == AUTO {
        return None;
    }
    approvals
        .iter()
        .find(|(run, step, _, seq)| {
            *run == decision.run && *step == decision.step && *seq > decision.seq
        })
        .map(|(_, _, by, _)| Human { by: by.clone(), reason: APPROVED.to_string() })
}

/// The confidence histogram's band for `confidence`: `BANDS` half-open bands, except the last,
/// which is closed so a confidence of exactly 1.0 has somewhere to go. A confidence outside 0..=1
/// clamps rather than panicking — a log is data, and data is not always the shape we expect.
fn band(confidence: f64) -> usize {
    if !confidence.is_finite() || confidence < 0.0 {
        return 0;
    }
    ((confidence * BANDS as f64) as usize).min(BANDS - 1)
}

fn band_label(index: usize) -> String {
    format!("{:.1}-{:.1}", index as f64 / BANDS as f64, (index + 1) as f64 / BANDS as f64)
}

/// Counts per key, sorted, so two reports of the same logs are identical.
fn tally(found: &[Decision], key: impl Fn(&Decision) -> String) -> Vec<(String, usize)> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for decision in found {
        *counts.entry(key(decision)).or_default() += 1;
    }
    counts.into_iter().collect()
}

/// One exported decision: the whole of what a calibration report needs, and room for a human to add
/// the `label` field the script reads.
fn export_line(decision: &Decision) -> Value {
    json!({
        "run": decision.run,
        "step": decision.step,
        "model": decision.model,
        "version": decision.version,
        "question_hash": decision.question_hash,
        "state_hash": decision.state_hash,
        "answer": decision.answer,
        "probabilities": decision.probabilities,
        "confidence": decision.confidence,
        "threshold": decision.threshold,
        "outcome": decision.outcome,
        "human_override": decision.human.as_ref().map(|h| json!({"by": h.by, "reason": h.reason})),
    })
}

/// The report as an object, the one both the human text and `--json` are rendered from.
fn report_json(found: &[Decision], logs: usize) -> Value {
    let counts = |key: fn(&Decision) -> String| {
        Value::Object(Map::from_iter(tally(found, key).into_iter().map(|(k, n)| (k, json!(n)))))
    };
    let mut histogram = [0usize; BANDS];
    for decision in found {
        histogram[band(decision.confidence)] += 1;
    }
    json!({
        "logs": logs,
        "decisions": found.len(),
        "answers": counts(|d| d.answer.clone()),
        "outcomes": counts(|d| d.outcome.clone()),
        "models": counts(|d| format!("{}@{}", d.model, d.version)),
        "confidence_histogram": histogram.iter().enumerate().map(|(index, count)| json!({
            "band": band_label(index),
            "low": index as f64 / BANDS as f64,
            "high": (index + 1) as f64 / BANDS as f64,
            "count": count,
        })).collect::<Vec<_>>(),
        "overrides": found.iter().filter_map(|d| {
            let human = d.human.as_ref()?;
            Some(json!({"run": d.run, "step": d.step, "answer": d.answer,
                        "confidence": d.confidence, "by": human.by, "reason": human.reason}))
        }).collect::<Vec<_>>(),
    })
}

fn usage() -> ExitCode {
    eprintln!("error: `decisions` takes `report [--json]` or `export`");
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lone `decide.answered` on `deploy`, as a log line. `run`/`seq` default to `r1`/2, which is
    /// what the join tests compare approvals against.
    fn log(kind: &str, fields: &[(&str, Value)]) -> String {
        let mut map = Map::new();
        map.insert("type".into(), json!(kind));
        for (key, value) in fields {
            map.insert((*key).into(), value.clone());
        }
        Value::Object(map).to_string()
    }

    fn decided(outcome: &str) -> Decision {
        let line =
            log("decide.answered", &[("step", json!("deploy")), ("outcome", json!(outcome))]);
        parse_log("r1", &format!("{line}\n")).decisions.remove(0)
    }

    /// Ten half-open bands, with 1.0 in the last rather than off the end, and anything odd
    /// clamped: the histogram counts decisions, it must not drop one or panic on it.
    #[test]
    fn every_confidence_lands_in_exactly_one_band() {
        assert_eq!(band(0.0), 0);
        assert_eq!(band(0.099), 0);
        assert_eq!(band(0.1), 1);
        assert_eq!(band(0.95), 9);
        assert_eq!(band(1.0), 9, "the last band is closed");
        assert_eq!(band(1.5), 9, "an impossible confidence still has a band");
        assert_eq!(band(-0.2), 0);
        assert_eq!(band(f64::NAN), 0);
    }

    /// Both routes to an override, and what disqualifies each. A recorded override wins wherever
    /// both apply, and survives into a later run; an approval only counts after the decision it
    /// follows, and only for a decision the run escalated.
    #[test]
    fn an_override_is_the_words_and_an_approval_is_only_the_shape() {
        let human = Human { by: "ada".into(), reason: "it took the cluster down".into() };
        let decision = decided(AUTO);
        assert_eq!(
            override_for(&decision, &[("r1".into(), "deploy".into(), human.clone())], &[]),
            Some(human.clone()),
            "an override of an `auto` decision, recorded in another run, still counts"
        );
        assert_eq!(
            override_for(&decision, &[("r1".into(), "migrate".into(), human.clone())], &[]),
            None,
            "a step it does not name is not an override of this one"
        );

        let escalated = decided("escalated");
        let after = [("r1".to_string(), "deploy".to_string(), "ada".to_string(), 9)];
        let approved = Some(Human { by: "ada".into(), reason: APPROVED.into() });
        assert_eq!(override_for(&escalated, &[], &after), approved);
        let before = [("r1".to_string(), "deploy".to_string(), "ada".to_string(), 0)];
        assert_eq!(
            override_for(&escalated, &[], &before),
            None,
            "an earlier approval was about something else"
        );
        assert_eq!(
            override_for(&decision, &[], &after),
            None,
            "an answer the run acted on itself is not a human's"
        );
    }

    /// A log written before the version and hash fields existed still reports its decisions, with
    /// `-` and `null` for what it did not say — an old log is thinner, not unreadable.
    #[test]
    fn an_older_log_reports_with_the_fields_it_lacks() {
        let decision = decided("auto");
        assert_eq!(
            (decision.version.as_str(), decision.question_hash, decision.state_hash),
            ("-", None, None)
        );
    }
}
