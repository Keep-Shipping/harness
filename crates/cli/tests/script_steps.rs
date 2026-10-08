//! Script steps end to end ([#89](https://github.com/Keep-Shipping/harness/issues/89)):
//! a step whose kind is a path to a `.ts` file beside the `ship.ks`. It
//! checks like any other step, an agent in production is stopped by one that
//! declares no `action:`, and the run reaches it — where it stops, because the
//! script runtime is not built into the binary yet.

use std::path::PathBuf;
use std::process::Command;

/// A directory holding one valid `ship.ks`, the hero file and its script.
const HERO: &str = "tests/fixtures/hero";

/// The issue's example, with the environments a `--env` selects between, and
/// a build step `--only` can name.
const SITE: &str = "\
name: gate
envs:
  staging:
    secrets: staging
  prod:
    secrets: prod
steps:
  build:   oci.image
    from:   ./Dockerfile
  migrate: ./ship/migrate.ts
    db:     secret(\"db-url\")
";

/// The same, with the step declaring what kind of run it is.
const DECLARED: &str = "\
name: gate
envs:
  staging:
    secrets: staging
  prod:
    secrets: prod
steps:
  build:   oci.image
    from:   ./Dockerfile
  migrate: ./ship/migrate.ts
    db:     secret(\"db-url\")
    action: apply
";

/// The message a script step stops a run with, having no runtime behind it.
const NO_RUNTIME: &str = "script steps need the script runtime";

/// Runs `keepshipping` from the crate root over a temporary site file.
fn run(name: &str, src: &str, args: &[&str]) -> (i32, String, String) {
    let path: PathBuf =
        std::env::temp_dir().join(format!("keepshipping-scripts-{}-{name}", std::process::id()));
    std::fs::write(&path, src).expect("write temp site file");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_keepshipping"));
    cmd.args(args).arg(&path);
    // The environment under test is the one these tests describe, not the one
    // they happen to run in.
    let out = cmd
        .env_remove("CI")
        .env_remove("GITHUB_ACTIONS")
        .env_remove("KEEPSHIPPING_REQUIRE_HUMAN")
        .env_remove("KEEPSHIPPING_AGENTS")
        .output()
        .expect("run keepshipping");
    let _ = std::fs::remove_file(&path);
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The run got past every gate and named the environment it selected.
fn assert_started(stdout: &str, stderr: &str) {
    assert!(!stderr.contains("refusing to start"), "the gate refused it: {stderr}");
    assert!(stdout.contains("environment:"), "the run started: {stdout}{stderr}");
}

#[test]
fn the_hero_file_with_a_script_step_checks_clean() {
    let out = Command::new(env!("CARGO_BIN_EXE_keepshipping"))
        .arg("check")
        .current_dir(HERO)
        .env_remove("CI")
        .env_remove("KEEPSHIPPING_REQUIRE_HUMAN")
        .env_remove("KEEPSHIPPING_AGENTS")
        .output()
        .expect("run keepshipping");
    assert_eq!(out.status.code().expect("exit code"), 0);
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("✓ "));
}

#[test]
fn an_agent_in_production_is_refused_before_the_run_starts() {
    let (code, stdout, stderr) =
        run("prod.ks", SITE, &["run", "--actor", "agent", "--env", "prod"]);
    assert_eq!(code, 1, "{stdout}{stderr}");
    assert!(
        stderr.contains(
            "refusing to start: step `migrate` runs `./ship/migrate.ts`, which declares no `action:`; \
             an agent needs an `approval` step before it in prod"
        ),
        "{stderr}"
    );
    assert!(stderr.contains("declare `action:`"), "{stderr}");
    assert!(!stdout.contains("environment:"), "nothing runs: {stdout}");
}

#[test]
fn what_gets_the_agent_past_the_gate_is_the_step_not_the_run() {
    // A human is never gated, and neither is a step that says what it does.
    for (name, src, actor) in [
        ("human.ks", SITE, "human"),
        ("declared.ks", DECLARED, "agent"),
        ("staging.ks", SITE, "agent"),
    ] {
        let env = if name == "staging.ks" { "staging" } else { "prod" };
        let (code, stdout, stderr) =
            run(name, src, &["run", "--actor", actor, "--env", env, "--only", "migrate"]);
        assert_started(&stdout, &stderr);
        // It runs, and stops at the script step — on the runtime, not the gate.
        assert_eq!(code, 1, "{stdout}{stderr}");
        assert!(stdout.contains(NO_RUNTIME), "{stdout}");
    }
}

#[test]
fn a_run_that_covers_no_script_step_is_never_refused() {
    let (code, stdout, stderr) =
        run("only.ks", SITE, &["run", "--actor", "agent", "--env", "prod", "--only", "build"]);
    assert_started(&stdout, &stderr);
    assert!(!stdout.contains(NO_RUNTIME), "the script step never ran: {stdout}");
    assert!(stdout.contains("`oci.image` steps are not built in yet"), "{stdout}");
    assert_eq!(code, 1, "{stdout}{stderr}");
}
