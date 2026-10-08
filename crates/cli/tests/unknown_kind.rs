//! The unknown-step-kind warning (KS0603) through the real binary: a file
//! whose step kinds name nothing in the catalog still checks — the warnings
//! print, the exit code stays 0 — until `--warnings-as-errors` turns them
//! into a failure.

use std::process::Command;

const SITE: &str = "tests/fixtures/unknown-kind/ship.ks";

fn check(extra: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_keepshipping"))
        .arg("check")
        .args(extra)
        .arg(SITE)
        // The fixture declares no `keepshipping:` header, and a headerless
        // file gains an advisory warning under CI that would blur what these
        // cases are about: the environment under test is a plain laptop.
        .env_remove("CI")
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
fn an_unknown_kind_warns_and_the_check_still_passes() {
    let (code, stdout, stderr) = check(&[]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    assert!(!stdout.contains('✗'), "warnings only, never an error: {stdout}");
    assert!(stdout.contains("unknown step kind `tofu.plna`"), "{stdout}");
    // The misspelling is one edit from a known kind: the hint comes along.
    assert!(stdout.contains("did you mean `tofu.plan`?"), "{stdout}");
    // `madeup.kind` is close to nothing, so it warns without a hint.
    assert!(stdout.contains("unknown step kind `madeup.kind`"), "{stdout}");
    assert!(stdout.contains(&format!("✓ {SITE}")), "{stdout}");
    assert!(stdout.ends_with("0 steps ran. Nothing was touched.\n"), "{stdout}");
    // The report keeps its shape: diagnostics print before the all-clear.
    assert!(
        stdout.find('⚠').is_some_and(|w| stdout.find('✓').is_some_and(|ok| w < ok)),
        "the warnings precede the ✓ line: {stdout}"
    );
}

#[test]
fn warnings_as_errors_turns_the_unknown_kind_into_a_failure() {
    let (code, stdout, stderr) = check(&["--warnings-as-errors"]);
    assert_eq!(code, 1, "{stderr}");
    // Still rendered as a warning — the flag changes the exit, not the bytes.
    assert!(stdout.contains("⚠"), "{stdout}");
    assert!(stdout.contains("unknown step kind `tofu.plna`"), "{stdout}");
}
