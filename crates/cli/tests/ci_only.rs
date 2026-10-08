//! End-to-end behaviour of `--context` and the run gate
//! ([#34](https://github.com/Keep-Shipping/harness/issues/34)): a CI-only
//! step warns on a laptop, is clean on CI, and stops a run that cannot
//! finish. The warning, the refusal and `--until` all count in one run
//! order, so the way out a warning suggests is a way out that works.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The site fixture shape: everything up to `apply` runs on a laptop;
/// `deploy` says it will not.
const SITE: &str = "\
name: api
steps:
  build:   oci.image
    from:   ./Dockerfile
  plan:    tofu.plan
    dir:    ./infra/prod
  review:  approval
    show:   plan.changes
    from:   @platform
  apply:   tofu.apply
    plan:   plan.file
  deploy:  k8s.rollout
    ci-only: true
    image:  build.digest
    to:     apply.out.cluster
";

/// Two CI-only steps with a runnable one between them: one stop point has
/// to serve both.
const TWO_CI_ONLY: &str = "\
steps:
  build:   oci.image
    from:   ./Dockerfile
  sign:    oci.image
    from:   ./Dockerfile
    ci-only: true
  plan:    tofu.plan
    dir:    ./infra/prod
  deploy:  oci.image
    from:   ./Dockerfile
    ci-only: true
";

/// A file whose order is not its run order: `deploy` is written first but
/// reads `build.digest`, so it runs last.
const REVERSED: &str = "\
steps:
  deploy:  k8s.rollout
    image:  build.digest
    ci-only: true
  build:   oci.image
    from:   ./Dockerfile
";

/// Each test gets its own file, so two of them writing at once cannot read
/// half of each other's site file.
fn temp_site(src: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "keepshipping-ci-only-{}-{}.ks",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, src).expect("write temp site file");
    path
}

/// Runs the binary with the detection variables cleared, so a test says what
/// context it means regardless of where it runs.
fn run(args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_keepshipping"));
    cmd.args(args).env_remove("GITHUB_ACTIONS").env_remove("CI");
    cmd.env_remove("KEEPSHIPPING_REQUIRE_HUMAN");
    cmd.env_remove("KEEPSHIPPING_AGENTS");
    let out = cmd.output().expect("run keepshipping");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A run the gate lets through has started: no step kind is executable yet,
/// so it stops at its first step (exit 1), but it was neither refused nor a
/// usage error.
fn assert_started(code: i32, err: &str, what: &str) {
    assert!(code == 0 || code == 1, "{what}: exit {code}: {err}");
    assert!(!err.contains("refusing to start"), "{what}: {err}");
}

#[test]
fn check_warns_locally_and_is_clean_on_ci() {
    let file = temp_site(SITE).to_string_lossy().into_owned();
    let (code, out, err) = run(&["check", &file, "--context", "local"]);
    assert_eq!(code, 0, "a warning alone still passes: {err}");
    assert!(out.contains("step `deploy` needs CI (not available locally)"), "{out}");
    assert!(out.contains("--until apply"), "the way out is suggested: {out}");

    let (code, out, err) = run(&["check", &file, "--context", "ci"]);
    assert_eq!(code, 0, "{err}");
    assert!(!out.contains("needs CI"), "CI has what a ci-only step needs: {out}");

    let (code, _, _) = run(&["check", &file, "--context", "local", "--warnings-as-errors"]);
    assert_eq!(code, 1, "only --warnings-as-errors makes the warning an error");
}

#[test]
fn without_the_flag_the_environment_decides() {
    let file = temp_site(SITE).to_string_lossy().into_owned();
    let (_, local, _) = run(&["check", &file]);
    assert!(local.contains("needs CI"), "no CI variables set: {local}");

    for set in [("CI", "1"), ("GITHUB_ACTIONS", "true")] {
        let out = Command::new(env!("CARGO_BIN_EXE_keepshipping"))
            .args(["check", &file])
            .env(set.0, set.1)
            .env_remove(if set.0 == "CI" { "GITHUB_ACTIONS" } else { "CI" })
            .env_remove("KEEPSHIPPING_REQUIRE_HUMAN")
            .env_remove("KEEPSHIPPING_AGENTS")
            .output()
            .expect("run keepshipping");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(!stdout.contains("needs CI"), "{}={} means CI: {stdout}", set.0, set.1);
    }

    // `false` is a system saying it is not CI; only unsetting `CI` would say
    // so unambiguously.
    let out = Command::new(env!("CARGO_BIN_EXE_keepshipping"))
        .args(["check", &file])
        .env("CI", "false")
        .env_remove("GITHUB_ACTIONS")
        .env_remove("KEEPSHIPPING_REQUIRE_HUMAN")
        .env_remove("KEEPSHIPPING_AGENTS")
        .output()
        .expect("run keepshipping");
    assert!(String::from_utf8_lossy(&out.stdout).contains("needs CI"), "CI=false is not CI");
}

#[test]
fn run_refuses_a_run_bound_to_fail_on_a_laptop() {
    let file = temp_site(SITE).to_string_lossy().into_owned();
    let (code, _, err) = run(&["run", &file, "--context", "local"]);
    assert_eq!(code, 1);
    assert!(
        err.contains("refusing to start: step `deploy` (5 of 5) needs CI (not available locally)"),
        "{err}"
    );
    assert!(err.contains("--allow-partial"), "{err}");
    assert!(err.contains("--until apply"), "the way out is suggested: {err}");
}

#[test]
fn a_run_that_stops_before_the_step_starts() {
    let file = temp_site(SITE).to_string_lossy().into_owned();
    for tail in [
        vec!["--context", "local", "--until", "apply"],
        vec!["--context", "local", "--skip", "deploy"],
        vec!["--context", "ci"],
    ] {
        let mut args = vec!["run", file.as_str()];
        args.extend(&tail);
        let (code, _, err) = run(&args);
        assert_started(code, &err, &format!("{tail:?} should start"));
    }
}

/// The stop point is the last runnable step before the *first* that cannot
/// run, and both warnings offer it — once, in run order.
#[test]
fn one_stop_point_serves_every_unmet_step() {
    let file = temp_site(TWO_CI_ONLY).to_string_lossy().into_owned();
    let (_, out, _) = run(&["check", &file, "--context", "local"]);
    assert_eq!(out.matches("--until build").count(), 2, "both steps suggest it: {out}");
    assert!(!out.contains("--until sign"), "nothing after a step that cannot run: {out}");

    let (code, _, err) = run(&["run", &file, "--context", "local", "--until", "build"]);
    assert_started(code, &err, "the suggested stop point starts the run");
}

/// Run order is not file order: `deploy` is written first, and the refusal
/// still counts it as step 2 of 2.
#[test]
fn the_gate_counts_in_run_order_not_file_order() {
    let file = temp_site(REVERSED).to_string_lossy().into_owned();
    let (_, out, _) = run(&["check", &file, "--context", "local"]);
    assert!(out.contains("--until build"), "{out}");

    let (code, _, err) = run(&["run", &file, "--context", "local"]);
    assert_eq!(code, 1);
    assert!(err.contains("step `deploy` (2 of 2)"), "{err}");

    let (code, _, err) = run(&["run", &file, "--context", "local", "--until", "build"]);
    assert_started(code, &err, "the suggested stop point starts the run");
}

#[test]
fn allow_partial_starts_the_run_anyway_saying_what_will_happen() {
    let file = temp_site(SITE).to_string_lossy().into_owned();
    let (code, _, err) = run(&["run", &file, "--context", "local", "--allow-partial"]);
    assert_started(code, &err, "--allow-partial starts the run");
    assert!(
        err.contains(
            "note: continuing with --allow-partial; step `deploy` will be skipped or fail"
        ),
        "{err}"
    );
}

#[test]
fn bad_contexts_step_names_and_flags_are_usage_errors() {
    let file = temp_site(SITE).to_string_lossy().into_owned();
    for args in [
        vec!["check", &file, "--context", "foo"],
        vec!["run", &file, "--context", "ci", "--until", "nope"],
        vec!["run", &file, "--context", "ci", "--skip", "nope"],
        vec!["run", &file, "--all"],
        vec!["check", &file, "--until", "apply"],
        vec!["check", &file, "--allow-partial"],
    ] {
        let (code, _, err) = run(&args);
        assert_eq!(code, 2, "{args:?} is not a valid command line: {err}");
        assert!(err.contains("usage:"), "{args:?}: {err}");
    }
}
