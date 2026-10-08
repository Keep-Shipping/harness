//! End-to-end tests of `keepshipping decisions`: what a report says about the decision models that
//! actually ran, read back out of the run logs the adapter wrote
//! ([#108](https://github.com/Keep-Shipping/harness/issues/108)).
//!
//! The logs under `fixtures/decisions/` were written by the real `JsonlRunLog`, so each entry
//! hashes into the chain a run would really have produced. **Any hand edit breaks that chain** —
//! which is exactly what the tamper test below relies on: it edits one line and expects the
//! command to notice. This file copies the fixtures into a working directory as
//! `.keepshipping/runs/<id>.jsonl` rather than re-deriving the chain here.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The two runs the fixtures hold: the spec's example ULID, and the rollback run that overrides a
/// decision the first one made.
const FIRST: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const SECOND: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAA";

/// A fresh working directory holding the fixtures as run logs. Each test names its own, and the
/// name is part of the path it removes, so tests running in parallel cannot delete each other's
/// run files.
fn workspace(name: &str) -> PathBuf {
    let dir = fresh(name);
    let runs = dir.join(".keepshipping/runs");
    std::fs::create_dir_all(&runs).expect("runs dir");
    for run in [FIRST, SECOND] {
        std::fs::copy(fixture(run), runs.join(format!("{run}.jsonl"))).expect("copy the fixture");
    }
    dir
}

/// An empty directory under the temp dir, named for this process and this test.
fn fresh(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("keepshipping-decisions-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn fixture(run: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/fixtures/decisions/{run}.jsonl"))
}

fn keepshipping(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_keepshipping"))
        .arg("decisions")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run keepshipping");
    let (code, stdout, stderr) = (out.status.code().expect("exit code"), out.stdout, out.stderr);
    (
        code,
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
    )
}

/// The report a person reads: what was answered, what the run did, which model said it, and where a
/// human disagreed. Both override routes show up — the recorded one from the later run, and the
/// approval that followed an escalated decision.
#[test]
fn the_report_shows_the_decisions_and_the_overrides() {
    let (code, stdout, stderr) = keepshipping(&workspace("report"), &["report"]);
    assert_eq!(code, 0, "{stderr}");
    for line in [
        "2 decisions from 2 run logs under .keepshipping/runs",
        "  allow 1  block 1",
        "  auto 1  escalated 1",
        "  jev@2026-09-01 2",
        "  0.4-0.5  1   ",
        "  0.9-1.0  1   ",
        // An empty band is two columns of numbers, not a line of trailing spaces.
        "  0.0-0.1  0\n",
        "overrides (2)",
        "  01ARZ3NDEKTSV4RRFFQ69G5FAV deploy allow 0.94 by ada — it took the staging cluster down",
        "  01ARZ3NDEKTSV4RRFFQ69G5FAV migrate block 0.42 by ada — a human approved the escalated decision",
    ] {
        assert!(stdout.contains(line), "the report is missing {line:?}:\n{stdout}");
    }
}

/// The tool form is one JSON object with the same numbers in it — the human text is rendered from
/// this value, so the two cannot disagree.
#[test]
fn the_json_report_is_the_same_numbers_as_an_object() {
    let (code, stdout, stderr) = keepshipping(&workspace("json"), &["report", "--json"]);
    assert_eq!(code, 0, "{stderr}");
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("one json object");
    assert_eq!(report["decisions"], 2);
    assert_eq!(report["logs"], 2);
    assert_eq!(report["answers"]["allow"], 1);
    assert_eq!(report["outcomes"]["escalated"], 1);
    assert_eq!(report["models"]["jev@2026-09-01"], 2);
    // The band a confidence of 0.94 falls in, and the one that is empty.
    assert_eq!(report["confidence_histogram"][9]["band"], "0.9-1.0");
    assert_eq!(report["confidence_histogram"][9]["count"], 1);
    assert_eq!(report["confidence_histogram"][4]["count"], 1);
    assert_eq!(report["overrides"].as_array().map(Vec::len), Some(2));
}

/// The export is the calibration script's input: one line per decision, carrying what was asked
/// (as hashes), what came back, and whether a human disagreed.
#[test]
fn the_export_is_one_json_line_per_decision() {
    let (code, stdout, stderr) = keepshipping(&workspace("export"), &["export"]);
    assert_eq!(code, 0, "{stderr}");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "{stdout}");
    let parsed: Vec<serde_json::Value> =
        lines.iter().map(|line| serde_json::from_str(line).expect("each line is json")).collect();
    for decision in &parsed {
        assert_eq!(decision["model"], "jev");
        assert_eq!(decision["version"], "2026-09-01");
        assert!(decision["question_hash"].as_str().is_some_and(|h| h.starts_with("sha256:")));
        // Room for a human to add the label the calibration script reads.
        assert!(decision.get("label").is_none(), "the label is the human's to add");
        assert!(decision["human_override"]["by"].is_string(), "{decision}");
    }
    // Both routes reach the export: the recorded override from the later run, and the approval.
    assert_eq!(
        parsed[0]["human_override"]["reason"], "it took the staging cluster down",
        "the override recorded in the other run is joined onto the decision"
    );
    assert_eq!(parsed[1]["human_override"]["by"], "ada");
}

/// Tampered audit data must be loud: the log is named with the line that does not hold, its
/// decisions are left out, and the exit code says the report cannot be trusted — while the logs
/// that *are* intact still report.
#[test]
fn a_tampered_log_is_named_and_makes_the_run_a_failure() {
    let dir = workspace("tampered");
    let path = dir.join(".keepshipping/runs").join(format!("{SECOND}.jsonl"));
    let mut lines: Vec<String> =
        std::fs::read_to_string(&path).expect("read").lines().map(String::from).collect();
    lines[1] = lines[1].replace("it took the staging cluster down", "the operator was right");
    std::fs::write(&path, lines.join("\n") + "\n").expect("write");

    let (code, stdout, stderr) = keepshipping(&dir, &["report"]);
    assert_eq!(code, 1, "a broken chain is a failure, not a clean report");
    assert!(stderr.contains(&format!("{SECOND}.jsonl:2: chain broken:")), "{stderr}");
    // The other run still reports — one tampered file is not a reason to hide the rest — but the
    // override it carried is gone with it, so only the approval-based one is left.
    assert!(stdout.contains("2 decisions from 1 run logs"), "{stdout}");
    assert!(!stdout.contains("the operator was right"), "a tampered line was read: {stdout}");
    assert!(stdout.contains("overrides (1)"), "{stdout}");
}

/// Nothing to report is not a failure — a repository that has not run a decision yet gets a
/// sentence, not an error.
#[test]
fn an_empty_working_directory_reports_no_decisions() {
    let (code, stdout, stderr) = keepshipping(&fresh("empty"), &["report"]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout, "no decisions recorded under .keepshipping/runs\n");
}

#[test]
fn anything_that_is_not_a_subcommand_is_a_usage_error() {
    let dir = workspace("usage");
    for args in [
        vec![],
        vec!["report", "--yaml"],
        vec!["report", "--json", "extra"],
        vec!["export", "--json"],
        vec!["reportt"],
    ] {
        let (code, stdout, stderr) = keepshipping(&dir, &args);
        assert_eq!(code, 2, "{args:?}: {stdout}{stderr}");
        assert!(stdout.is_empty(), "{args:?}: {stdout}");
        assert!(stderr.contains("keepshipping decisions report"), "{args:?}: {stderr}");
    }
}
