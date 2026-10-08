//! End-to-end tests of `run --input KEY=VALUE`: the override grammar, what a
//! malformed pair says about itself, and what `--dry-run` shows of an input
//! it does not use. No step kind is executable yet, so `--dry-run` is the one
//! path a run gets to the end of — and the only place an input is visible.

use std::path::PathBuf;
use std::process::Command;

use ks_core::ports::run_context::{AGENT_TYPICAL_ENV, KNOWN_AGENT_MARKERS};

/// One step and no approvals: the smallest file a `--dry-run` can graph to
/// the end, so the only lines in its output are the ones under test.
const SIMPLE: &str = "\
name: inputs
steps:
  build: oci.image
    from: ./Dockerfile
";

/// Write a temp site file; the caller runs the binary against it and the
/// path is removed after the command returns.
fn temp_site(name: &str, src: &str) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("keepshipping-input-{}-{name}", std::process::id()));
    std::fs::write(&path, src).expect("write temp site file");
    path
}

fn keepshipping(args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_keepshipping"));
    cmd.args(args);
    // These tests assert exact output, and the suite itself may be running
    // on CI — where a header-less file gains an advisory warning it would
    // not have anywhere else. The environment under test is the one these
    // tests describe, not the one they happen to run in.
    cmd.env_remove("CI");
    // Nor is it an agent's: a detected agent's run opens with a check line
    // these exact-output assertions do not expect.
    for marker in KNOWN_AGENT_MARKERS {
        cmd.env_remove(marker);
    }
    for (name, _) in AGENT_TYPICAL_ENV {
        cmd.env_remove(*name);
    }
    let out = cmd
        .env_remove("GITHUB_ACTIONS")
        .env_remove("KEEPSHIPPING_REQUIRE_HUMAN")
        .env_remove("KEEPSHIPPING_AGENTS")
        .output()
        .expect("run keepshipping");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn run_only_with_input_dry_runs_that_one_step_with_its_inputs() {
    let path = temp_site("one.ks", SIMPLE);
    let (code, stdout, stderr) = keepshipping(&[
        "run",
        "--dry-run",
        "--only",
        "build",
        "--input",
        "tag=v1.2.3",
        path.to_str().unwrap(),
    ]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 0, "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    assert_eq!(
        stdout,
        concat!(
            "environment: default\n",
            "▸ build   oci.image\n",
            "inputs:\n",
            "  input tag = v1.2.3\n",
            "0 steps ran. Nothing was touched.\n",
        ),
        "{stdout}"
    );
}

#[test]
fn an_input_without_an_equals_names_the_form_it_wants() {
    let path = temp_site("noeq.ks", SIMPLE);
    let (code, stdout, stderr) =
        keepshipping(&["run", "--dry-run", "--input", "tag", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 2);
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("`--input tag` has no `=`"), "{stderr}");
    assert!(stderr.contains("--input KEY=VALUE"), "the way out is named: {stderr}");
}

#[test]
fn an_input_with_an_empty_key_names_the_form_it_wants() {
    let path = temp_site("nokey.ks", SIMPLE);
    let (code, _, stderr) =
        keepshipping(&["run", "--dry-run", "--input", "=v1.2.3", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 2);
    assert!(stderr.contains("`--input =v1.2.3` has an empty key"), "{stderr}");
    assert!(stderr.contains("--input KEY=VALUE"), "the way out is named: {stderr}");
}

#[test]
fn a_secret_input_is_echoed_as_a_reference_and_never_as_a_value() {
    let path = temp_site("secret.ks", SIMPLE);
    let (code, stdout, stderr) =
        keepshipping(&["run", "--dry-run", "--input", "db=@secret:dev-db", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 0, "{stderr}");
    // What the file says is a reference and nothing more: the marker is kept
    // in the output, so the line cannot read as a resolved value.
    assert!(stdout.contains("  input db = @secret:dev-db (reference)\n"), "{stdout}");
    // Nothing else carries the key, and no step line claims one was read.
    assert_eq!(stdout.matches("dev-db").count(), 1, "{stdout}");
    assert!(stdout.ends_with("0 steps ran. Nothing was touched.\n"), "{stdout}");
}

#[test]
fn a_secret_marker_naming_nothing_is_a_usage_error() {
    let path = temp_site("bare-secret.ks", SIMPLE);
    let (code, _, stderr) =
        keepshipping(&["run", "--dry-run", "--input", "db=@secret:", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 2);
    assert!(stderr.contains("`--input db=@secret:` names no secret"), "{stderr}");
    assert!(stderr.contains("--input KEY=@secret:RESOLVER:NAME"), "{stderr}");
}

#[test]
fn the_last_of_two_inputs_for_one_key_is_the_one_that_counts() {
    let path = temp_site("dup.ks", SIMPLE);
    let (code, stdout, stderr) = keepshipping(&[
        "run",
        "--dry-run",
        "--input",
        "tag=v1",
        "--input",
        "tag=v2",
        path.to_str().unwrap(),
    ]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("  input tag = v2\n"), "{stdout}");
    assert!(!stdout.contains("v1"), "the overridden value is not shown: {stdout}");
}

#[test]
fn a_negative_value_is_a_value_and_not_a_flag() {
    let path = temp_site("negative.ks", SIMPLE);
    let (code, stdout, stderr) =
        keepshipping(&["run", "--dry-run", "--input", "retries=-1", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("  input retries = -1\n"), "{stdout}");
}

/// The report `--dry-run` writes is line-oriented, so a pair that breaks a
/// line is refused rather than printed: a forged line is indistinguishable
/// from a real one, which is exactly what makes it worth forging.
#[test]
fn a_newline_in_a_key_cannot_forge_a_report_line() {
    let path = temp_site("nlkey.ks", SIMPLE);
    let (code, stdout, stderr) = keepshipping(&[
        "run",
        "--dry-run",
        "--input",
        "ad\n  input admin = true\nmin",
        path.to_str().unwrap(),
    ]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 2);
    assert!(stdout.is_empty(), "nothing is reported: {stdout}");
    assert!(stderr.contains("breaks a line in its key"), "{stderr}");
    assert!(stderr.contains("write --input KEY=VALUE as one line"), "{stderr}");
    // The usage error stays on one line too: the pair is quoted with the
    // break escaped, so it cannot forge a line of its own.
    assert_eq!(stderr.lines().count(), 1, "one line of prose: {stderr}");
}

#[test]
fn a_newline_in_a_value_cannot_forge_a_report_line() {
    let path = temp_site("nlvalue.ks", SIMPLE);
    let (code, stdout, stderr) = keepshipping(&[
        "run",
        "--dry-run",
        "--input",
        "k=v\n  input admin = true",
        path.to_str().unwrap(),
    ]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 2);
    assert!(stdout.is_empty(), "nothing is reported: {stdout}");
    assert!(stderr.contains("breaks a line in its value"), "{stderr}");
    assert!(stderr.contains("write --input KEY=VALUE as one line"), "{stderr}");
    assert_eq!(stderr.lines().count(), 1, "one line of prose: {stderr}");
}

#[test]
fn a_carriage_return_is_a_line_break_too() {
    let path = temp_site("cr.ks", SIMPLE);
    let (code, stdout, stderr) = keepshipping(&[
        "run",
        "--dry-run",
        "--input",
        "k=v\r  input admin = true",
        path.to_str().unwrap(),
    ]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 2);
    assert!(stdout.is_empty(), "nothing is reported: {stdout}");
    assert!(stderr.contains("breaks a line in its value"), "{stderr}");
    assert_eq!(stderr.lines().count(), 1, "one line of prose: {stderr}");
}

#[test]
fn whitespace_around_a_key_or_a_value_is_padding_a_report_cannot_show() {
    let path = temp_site("pad.ks", SIMPLE);
    for (pair, where_) in [(" k=v", "key"), ("k =v", "key"), ("k= v", "value"), ("k=v ", "value")] {
        let (code, stdout, stderr) =
            keepshipping(&["run", "--dry-run", "--input", pair, path.to_str().unwrap()]);
        assert_eq!(code, 2, "`--input {pair}` is a usage error: {stdout}");
        assert!(stdout.is_empty(), "nothing is reported: {stdout}");
        assert!(
            stderr.contains(&format!("has whitespace around its {where_}")),
            "`--input {pair}` names the problem: {stderr}"
        );
        assert!(
            stderr.contains("write --input KEY=VALUE with no padding"),
            "the way out is named: {stderr}"
        );
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn whitespace_inside_a_key_names_it_as_one_name() {
    let path = temp_site("keyspace.ks", SIMPLE);
    let (code, stdout, stderr) =
        keepshipping(&["run", "--dry-run", "--input", "db host=v1", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 2);
    assert!(stdout.is_empty(), "nothing is reported: {stdout}");
    assert!(stderr.contains("has whitespace inside its key"), "{stderr}");
    assert!(stderr.contains("a key is one name"), "{stderr}");
}

/// Interior whitespace is the value's own business: `two words` is a
/// legitimate value, and only the report's own line breaks and invisible
/// padding are refused.
#[test]
fn interior_whitespace_in_a_value_is_still_a_value() {
    let path = temp_site("inner.ks", SIMPLE);
    let (code, stdout, stderr) = keepshipping(&[
        "run",
        "--dry-run",
        "--input",
        "message=two words please",
        path.to_str().unwrap(),
    ]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("  input message = two words please\n"), "{stdout}");
}

/// `k=` is a value that happens to be empty, which a step can be told; a
/// bare `@secret:` names nothing, which it cannot.
#[test]
fn an_empty_value_is_a_value_and_an_empty_secret_reference_is_not() {
    let path = temp_site("empty.ks", SIMPLE);
    let (code, stdout, stderr) =
        keepshipping(&["run", "--dry-run", "--input", "tag=", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("  input tag = \n"), "{stdout}");
}

#[test]
fn an_unknown_flag_is_still_a_usage_error() {
    let path = temp_site("unknown.ks", SIMPLE);
    let (code, _, stderr) =
        keepshipping(&["run", "--dry-run", "--inpt", "tag=v1", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 2);
    assert!(stderr.contains("usage: keepshipping"), "{stderr}");
}

#[test]
fn dry_run_without_an_input_prints_only_the_graph() {
    let path = temp_site("bare.ks", SIMPLE);
    let (code, stdout, stderr) = keepshipping(&["run", "--dry-run", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(
        stdout,
        concat!(
            "environment: default\n",
            "▸ build   oci.image\n",
            "0 steps ran. Nothing was touched.\n",
        ),
        "{stdout}"
    );
}
