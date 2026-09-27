//! End-to-end tests of the `keepshipping` binary.

use std::path::PathBuf;
use std::process::Command;

const TWO_ENVS: &str = "\
name: two
envs:
  staging:
    ci-only: true
  prod:
    ci-only: true
steps:
  build: oci.image
    from: ./Dockerfile
";

const BROKEN: &str = "\
name: broken
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: build.tag
";

const HERO: &str = include_str!("../../lang/tests/fixtures/site-hero.ks");

const MISPLACED: &str = "\
name: misplaced
steps:
  deploy: k8s.rollout
    image: nope.digest
    wait: build.tag
  build: oci.image
    from: 5
";

/// Write a temp site file; the caller runs the binary against it and the
/// path is removed after the command returns.
fn temp_site(name: &str, src: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("keepshipping-cli-{}-{name}", std::process::id()));
    std::fs::write(&path, src).expect("write temp site file");
    path
}

fn keepshipping(path: &PathBuf, extra: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_keepshipping"))
        .args(extra)
        .arg(path)
        .output()
        .expect("run keepshipping");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn check_reports_ok_for_the_hero_file() {
    let path = temp_site("hero.ks", HERO);
    let (code, stdout, stderr) = keepshipping(&path, &["check"]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("ok"), "{stdout}");
}

#[test]
fn check_prints_diagnostics_and_exits_1() {
    let path = temp_site("broken.ks", BROKEN);
    let (code, stdout, stderr) = keepshipping(&path, &["check"]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 1);
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("error: "), "{stderr}");
    assert!(stderr.contains("expected `oci.Digest`, got `String`"), "{stderr}");
    assert!(stderr.contains("hint: did you mean `build.digest`?"), "{stderr}");
}

#[test]
fn run_without_a_choice_fails_non_interactively() {
    let path = temp_site("ambiguous.ks", TWO_ENVS);
    let (code, _, stderr) = keepshipping(&path, &["run"]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 2, "{stderr}");
    assert!(
        stderr.contains(
            "error: this file declares several environments (staging, prod); pass --env <name>"
        ),
        "{stderr}"
    );
}

#[test]
fn run_with_env_selects_it() {
    let path = temp_site("env.ks", TWO_ENVS);
    let (code, stdout, stderr) = keepshipping(&path, &["run", "--env", "prod"]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("environment: prod"), "{stdout}");
    assert!(stdout.contains("not implemented yet"), "{stdout}");
}

#[test]
fn run_rejects_an_unknown_env_with_did_you_mean() {
    let path = temp_site("wrong-env.ks", TWO_ENVS);
    let (code, _, stderr) = keepshipping(&path, &["run", "--env", "prodd"]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("unknown environment `prodd`"), "{stderr}");
}

#[test]
fn diagnostics_carry_exact_line_and_column() {
    // Several diagnostics on different lines: every position must be right
    // (the CLI used to rescan the file per diagnostic).
    let path = temp_site("misplaced.ks", MISPLACED);
    let (code, _, stderr) = keepshipping(&path, &["check"]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 1);
    // `nope.digest` starts at line 4, column 12; `5` at line 7, column 11.
    assert!(stderr.contains("misplaced.ks:4:12:"), "{stderr}");
    assert!(stderr.contains("misplaced.ks:7:11:"), "{stderr}");
}

#[test]
fn a_flag_where_a_value_belongs_is_a_usage_error() {
    let path = temp_site("flag-value.ks", TWO_ENVS);
    let (code, _, stderr) = keepshipping(&path, &["run", "--env", "--non-interactive"]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 2);
    assert!(stderr.contains("usage: keepshipping"), "{stderr}");
}
