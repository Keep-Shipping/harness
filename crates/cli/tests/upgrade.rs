//! End-to-end tests of `keepshipping fmt --upgrade`: what it pins, what it
//! rewrites, what it refuses, and what it says when there is no formatter
//! yet. The upgrade itself is covered against fixtures in
//! `crates/core/tests/format.rs`; what is tested here is the command.

use std::path::PathBuf;
use std::process::Command;

/// One site file, with the comment worth keeping: the rewrite must add a
/// header above it without touching anything else.
const SITE: &str = "\
# the build everyone copies
steps:
  build: oci.image
    from: ./Dockerfile
";

/// The same file pinned at the format this build writes — and, with a
/// version no build migrates from, the file `fmt` refuses.
fn site(header: &str) -> String {
    format!("{header}{SITE}")
}

/// A temp directory holding a `ship.ks`, removed when the test returns.
fn site_file(name: &str, src: &str) -> (PathBuf, TempDir) {
    let dir = TempDir::new(name);
    let path = dir.0.join("ship.ks");
    std::fs::write(&path, src).expect("write temp site file");
    (path, dir)
}

/// A temp directory that deletes itself on drop, so no test can forget.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir()
            .join(format!("keepshipping-upgrade-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("make temp dir");
        TempDir(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Runs the binary with `CI` removed, unless `env` names variables to set —
/// so a test can be in CI on purpose, and no other test accidentally is.
fn run(args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_keepshipping"));
    cmd.args(args);
    cmd.env_remove("CI");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run keepshipping");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn upgrade_pins_a_headerless_file_and_is_its_own_inverse() {
    let (path, _dir) = site_file("pin", &site(""));
    let shown = path.to_str().unwrap();

    let (code, stdout, stderr) = run(&["fmt", "--upgrade", shown], &[]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout, format!("pinned {shown}: keepshipping 0.1\n"), "{stdout}");

    let after = std::fs::read_to_string(&path).expect("reread");
    assert_eq!(
        after,
        site("keepshipping: 0.1\n"),
        "the header goes above the comment, and the comment survives"
    );

    // The second run must write the same bytes again, or `upgrade` is not
    // idempotent and the command would churn files for no reason.
    let (code, stdout, stderr) = run(&["fmt", "--upgrade", shown], &[]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout, format!("unchanged {shown}: 0.1\n"), "{stdout}");
    assert_eq!(std::fs::read_to_string(&path).expect("reread"), after, "no second write");
}

#[test]
fn upgrade_leaves_a_pinned_file_alone() {
    let pinned = site("keepshipping: 0.1\n");
    let (path, _dir) = site_file("pinned", &pinned);
    let (code, stdout, stderr) = run(&["fmt", "--upgrade", path.to_str().unwrap()], &[]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout, format!("unchanged {}: 0.1\n", path.display()), "{stdout}");
    assert_eq!(std::fs::read_to_string(&path).expect("reread"), pinned);
}

#[test]
fn upgrade_refuses_a_format_it_cannot_migrate_from_and_writes_nothing() {
    let future = site("keepshipping: 0.9\n");
    let (path, _dir) = site_file("refuse", &future);
    let (code, stdout, stderr) = run(&["fmt", "--upgrade", path.to_str().unwrap()], &[]);
    assert_eq!(code, 1, "a refusal is the run's result, not a crash: {stdout}");
    assert_eq!(stdout, "", "{stdout}");
    assert!(
        stderr.contains(&format!("error: {}:1: this keepshipping reads 0.1", path.display())),
        "{stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(&path).expect("reread"),
        future,
        "a refused file is left byte for byte"
    );
}

#[test]
fn fmt_without_upgrade_is_a_usage_error() {
    let (path, _dir) = site_file("noflag", &site("keepshipping: 0.1\n"));
    let (code, stdout, stderr) = run(&["fmt", path.to_str().unwrap()], &[]);
    assert_eq!(code, 2, "{stdout}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("error: fmt --upgrade"), "{stderr}");
    assert!(stderr.contains("the formatter itself is not available yet"), "{stderr}");
    assert!(stderr.contains("keepshipping fmt --upgrade [PATH...]"), "{stderr}");
    assert_eq!(std::fs::read_to_string(&path).expect("reread"), site("keepshipping: 0.1\n"));
}

#[test]
fn a_missing_file_is_a_usage_error_naming_the_path() {
    let dir = TempDir::new("missing");
    let missing = dir.0.join("nope.ks");
    let (code, _stdout, stderr) = run(&["fmt", "--upgrade", missing.to_str().unwrap()], &[]);
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("no such file"), "{stderr}");
}

/// The warning that says nobody pinned the format fires in CI and nowhere
/// else: a pipeline owner wants to hear it, a local run would only nag.
/// `--actor ci` fires it too, without the environment — the actor is what
/// policy binds and is never inferred from `CI`.
#[test]
fn check_warns_about_a_missing_format_header_only_under_ci() {
    let (path, _dir) = site_file("ciwarn", &site(""));
    let shown = path.to_str().unwrap();

    let (code, stdout, stderr) = run(&["check", shown], &[("CI", "true")]);
    assert_eq!(code, 0, "a warning alone still passes: {stderr}");
    assert!(stdout.contains("⚠") && stdout.contains("declares no format version"), "{stdout}");

    let (code, stdout, stderr) = run(&["check", shown], &[]);
    assert_eq!(code, 0, "{stderr}");
    assert!(!stdout.contains("declares no format version"), "no CI, no warning: {stdout}");

    // An empty `CI=` says nothing, so it is not CI either.
    let (_code, stdout, _stderr) = run(&["check", shown], &[("CI", "")]);
    assert!(!stdout.contains("declares no format version"), "an empty CI is not CI: {stdout}");

    let (code, stdout, stderr) = run(&["check", "--actor", "ci", shown], &[("CI", "")]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("declares no format version"), "`--actor ci` fires it too: {stdout}");
}

/// A pinned file says nothing under CI: the warning is about the absence,
/// not about CI itself.
#[test]
fn check_says_nothing_about_a_pinned_file_under_ci() {
    let (path, _dir) = site_file("ciclean", &site("keepshipping: 0.1\n"));
    let (code, stdout, stderr) = run(&["check", path.to_str().unwrap()], &[("CI", "true")]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout, format!("✓ {}\n0 steps ran. Nothing was touched.\n", path.display()));
}
