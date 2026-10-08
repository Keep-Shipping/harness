//! End-to-end tests of `keepshipping log`: the run log the adapter wrote is read back the way a
//! person and a tool read it, and — the promise in the issue — a line that was edited after the
//! fact is caught by `keepshipping log verify`, which says which line.
//!
//! The log itself is the committed golden (`fixtures/run-log/golden.jsonl`), written by the
//! adapter through a `FakeClock` so it is byte-stable; these tests copy it into a working
//! directory as `.keepshipping/runs/<id>.jsonl` rather than re-deriving the chain here, so what
//! the command checks is what a run really writes.

use std::path::Path;
use std::process::Command;

/// The run the golden log belongs to: the spec's example ULID.
const RUN: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const GOLDEN: &str = include_str!("fixtures/run-log/golden.jsonl");

/// A fresh working directory holding `GOLDEN` as the run's log. Each test names its own, so
/// tests running in parallel cannot share a run's file.
fn workspace(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("keepshipping-log-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let runs = dir.join(".keepshipping/runs");
    std::fs::create_dir_all(&runs).expect("runs dir");
    std::fs::write(runs.join(format!("{RUN}.jsonl")), GOLDEN).expect("write the run's log");
    dir
}

/// Rewrites the run's log, so a test can tamper with what is on disk.
fn tamper(dir: &Path, edit: impl Fn(&mut Vec<String>)) {
    let path = dir.join(".keepshipping/runs").join(format!("{RUN}.jsonl"));
    let mut lines: Vec<String> =
        std::fs::read_to_string(&path).expect("read").lines().map(String::from).collect();
    edit(&mut lines);
    std::fs::write(path, lines.join("\n") + "\n").expect("write");
}

fn keepshipping(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_keepshipping"))
        .arg("log")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run keepshipping");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn a_run_prints_one_line_per_event() {
    let dir = workspace("print");
    let (code, stdout, stderr) = keepshipping(&dir, &[RUN]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    assert_eq!(
        stdout,
        "\
22:13:20  run.started  actor=ci  file_hash=sha256:aa  is_agent=false  trigger=push main
22:13:20  step.started  step=build
22:13:20  step.finished  duration_ms=1.2s  ok=true  outputs=digest  step=build
22:13:20  approval.requested  artifacts=sha256:bb  channel=github  step=deploy
22:13:20  approval.denied  approver=grace  artifacts=sha256:bb  channel=github  reason=denied by grace: not today  step=deploy
22:13:20  approval.expired  artifacts=sha256:bb  channel=github  step=deploy
22:13:20  approval.aborted  artifacts=sha256:bb  channel=github  proposer=agent-runtime  step=deploy
22:13:20  approval.rejected  artifacts=sha256:bb  channel=github  detail=mallory is not a member of @platform  step=deploy
22:13:20  run.finished  shipped=sha256:cc  status=shipped
"
    );
}

#[test]
fn the_json_format_is_the_entries_as_stored() {
    let dir = workspace("json");
    let (code, stdout, stderr) = keepshipping(&dir, &[RUN, "--format", "json"]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout, GOLDEN, "the tool form is the stored bytes");
    // And it is JSON Lines: every line a self-contained object.
    for line in stdout.lines() {
        serde_json::from_str::<serde_json::Value>(line).expect("each line is json");
    }
}

/// No id means the most recent run, which is what a person typing `log` wants.
#[test]
fn with_no_run_id_the_latest_run_is_printed() {
    let dir = workspace("latest");
    let (code, stdout, stderr) = keepshipping(&dir, &[]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("run.finished"), "{stdout}");
}

#[test]
fn verify_passes_on_an_untouched_log() {
    let dir = workspace("verify-ok");
    let (code, stdout, stderr) = keepshipping(&dir, &["verify", RUN]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    assert_eq!(stdout, "ok: 9 entries, chain intact\n");
}

/// The acceptance criterion: change one field of one line and `verify` fails, naming that line.
/// The same holds for a deleted entry, whose successor then points at a hash that is gone.
#[test]
fn verify_reports_the_line_that_was_edited_or_deleted() {
    for (name, damage) in [
        (
            "verify-edited",
            (|lines: &mut Vec<String>| {
                lines[2] = lines[2].replace("\"ok\":true", "\"ok\":false");
            }) as fn(&mut Vec<String>),
        ),
        ("verify-deleted", |lines: &mut Vec<String>| {
            lines.remove(2);
        }),
    ] {
        let dir = workspace(name);
        tamper(&dir, damage);
        let (code, stdout, stderr) = keepshipping(&dir, &["verify", RUN]);
        assert_eq!(code, 1, "{name}: a broken chain is a failure, not a clean run");
        assert!(stdout.is_empty(), "{name}: {stdout}");
        assert!(stderr.contains(".jsonl:3: chain broken:"), "{name}: {stderr}");
    }
}

/// Printing a broken log is not a failure: the point is to read what happened.
#[test]
fn a_broken_log_still_prints() {
    let dir = workspace("print-broken");
    tamper(&dir, |lines| {
        lines[2] = lines[2].replace("\"ok\":true", "\"ok\":false");
    });
    let (code, stdout, _) = keepshipping(&dir, &[RUN]);
    assert_eq!(code, 0);
    assert!(stdout.contains("step.finished  duration_ms=1.2s  ok=false"), "{stdout}");
}

#[test]
fn anything_that_names_no_run_is_a_usage_error() {
    let dir = workspace("missing");
    for args in [
        vec!["01HQZZZZZZZZZZZZZZZZZZZZZZ"],
        vec!["verify", "01HQZZZZZZZZZZZZZZZZZZZZZZ"],
        // Not a ULID: it cannot name a file, so it must not be guessed at.
        vec!["nope"],
        vec!["verify", "a", "b"],
    ] {
        let (code, stdout, stderr) = keepshipping(&dir, &args);
        assert_eq!(code, 2, "{args:?}: {stdout}{stderr}");
        assert!(stdout.is_empty(), "{args:?}: {stdout}");
        assert!(stderr.starts_with("error:"), "{args:?}: {stderr}");
    }

    // And a directory holding no runs at all: still exit 2, but for the other reason.
    let empty = std::env::temp_dir().join(format!("keepshipping-log-{}-empty", std::process::id()));
    let _ = std::fs::remove_dir_all(&empty);
    std::fs::create_dir_all(&empty).expect("temp dir");
    let (code, stdout, stderr) = keepshipping(&empty, &[]);
    assert_eq!(code, 2);
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("no runs logged"), "{stderr}");
}
