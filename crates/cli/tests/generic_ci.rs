//! Generic CI mode end to end: any CI that can run a binary
//! ([#130](https://github.com/Keep-Shipping/harness/issues/130)).
//!
//! These drive the real binary with Buildkite's and GitLab's environment
//! variables set the way those runners set them, and read what the run says
//! about itself. The note is the whole promise of the mode — it names the CI
//! that was detected, and says in the same line that its identity is
//! self-declared — so that line is what these turn on, along with the two
//! behaviours that make the mode safe to point at a CI: `--ci` implies nobody
//! is watching, and a bare `--ci` with nothing in the environment still runs.
//!
//! Detection variables are scrubbed everywhere, so a test means what it says
//! wherever the suite runs — including on a runner.

use std::path::PathBuf;
use std::process::Command;

/// A site with an approval step, so a `--ci` run has somewhere to park. The
/// step after it is a kind the binary cannot run yet, which is what a run
/// nobody is watching ends on.
const SITE: &str = "\
steps:
  review:  approval
  apply:   oci.image
    from:   ./Dockerfile
";

/// Every variable a CI system could be detected from, so a test says what it
/// means regardless of where it runs.
const MARKERS: &[&str] =
    &["GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "CIRCLECI", "JENKINS_URL", "CI"];

/// Runs the binary in `dir` with the detection variables cleared, then with
/// whatever `vars` add.
fn run_in(dir: &std::path::Path, args: &[&str], vars: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_keepshipping"));
    cmd.args(args).current_dir(dir);
    for marker in MARKERS {
        cmd.env_remove(marker);
    }
    for (name, value) in vars {
        cmd.env(name, value);
    }
    let out = cmd.output().expect("run keepshipping");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A `--ci` run from a clean directory, so a run that parks writes its record
/// somewhere the suite can throw away.
fn work_dir(label: &str, src: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("generic-ci-{label}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the work directory can be created");
    std::fs::write(dir.join("ship.ks"), src).expect("write the site file");
    dir
}

/// What Buildkite sets on an agent running a `push` build of `main` by `ada`.
const BUILDKITE: &[(&str, &str)] = &[
    ("CI", "true"),
    ("BUILDKITE", "true"),
    ("BUILDKITE_COMMIT", "9f2c1e4b7a0d6c5e3f8a1b2c3d4e5f60718293a4"),
    ("BUILDKITE_BRANCH", "main"),
    ("BUILDKITE_EVENT", "push"),
    ("BUILDKITE_BUILD_AUTHOR", "ada"),
];

/// What GitLab sets on a merge request pipeline: the pipeline source says it is
/// a merge request, and the iid is the number.
const GITLAB_MR: &[(&str, &str)] = &[
    ("CI", "true"),
    ("GITLAB_CI", "true"),
    ("CI_COMMIT_SHA", "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"),
    ("CI_COMMIT_REF_NAME", "feature/x"),
    ("CI_PIPELINE_SOURCE", "merge_request_event"),
    ("CI_MERGE_REQUEST_IID", "42"),
    ("GITLAB_USER_LOGIN", "grace"),
];

#[test]
fn buildkite_env_is_recognised() {
    let dir = work_dir("buildkite", SITE);
    let (code, out, err) = run_in(&dir, &["run", "ship.ks", "--ci", "--dry-run"], BUILDKITE);
    assert_eq!(code, 0, "a dry run says what it would do: {err}");
    assert!(
        err.contains("--ci buildkite: actor=ada event=push ref=refs/heads/main sha=9f2c1e4b7a0d6c5e3f8a1b2c3d4e5f60718293a4"),
        "the note names the CI, the actor and the commit: {err}"
    );
    // It says in the same line that none of it is verified: the one thing a
    // generic run must never let a reader assume.
    assert!(err.contains("self-declared; generic mode verifies no OIDC identity"), "{err}");
    // The CI variables do not make the run interactive either: nothing about a
    // pipe and a job's environment is a terminal.
    assert!(!out.contains("environment ("), "no prompt was offered: {out}");
    assert!(out.contains("environment: "), "the chosen environment is still named: {out}");
}

#[test]
fn gitlab_merge_request_env_is_recognised() {
    let dir = work_dir("gitlab", SITE);
    let (code, _, err) = run_in(&dir, &["run", "ship.ks", "--ci", "--dry-run"], GITLAB_MR);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("--ci gitlab:"), "the CI is named: {err}");
    assert!(err.contains("event=pr 42"), "the merge request iid is the number: {err}");
    assert!(err.contains("actor=grace"), "the pipeline's login is the actor: {err}");
    assert!(err.contains("ref=refs/heads/feature/x"), "the branch is the ref: {err}");
}

#[test]
fn explicit_overrides_win() {
    let dir = work_dir("overrides", SITE);
    let args = ["run", "ship.ks", "--ci", "--actor", "agent", "--sha", "deadbeef", "--dry-run"];
    let (code, _, err) = run_in(&dir, &args, BUILDKITE);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("actor=agent"), "a declared actor beats the CI's login: {err}");
    assert!(err.contains("sha=deadbeef"), "a stated commit beats the one detected: {err}");
    // The CI is still what it is: an override says who and what, not where.
    assert!(err.contains("--ci buildkite:"), "{err}");
    // And `--event` says what the run was for, which is what no generic
    // adapter can map from a CI's events for it.
    let args = ["run", "ship.ks", "--ci", "--event", "pr 7", "--dry-run"];
    let (code, _, err) = run_in(&dir, &args, BUILDKITE);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("event=pr 7"), "the command line named the event: {err}");
}

#[test]
fn ci_implies_non_interactive() {
    let dir = work_dir("parking", SITE);
    let (code, _, err) = run_in(&dir, &["run", "ship.ks", "--ci"], BUILDKITE);
    // 2 would be a usage error, which is not what a run that started should
    // ever be. 4 is the parked run; 1 is the step kind that is not built yet.
    assert!(matches!(code, 0 | 1 | 4), "the run started: exit {code}: {err}");
    assert!(!err.contains("approve 3 changes"), "nobody was asked anything: {err}");
    assert!(!err.contains("environment ("), "no prompt was offered: {err}");
    // Nobody is watching, so the approval parks the run and the job ends
    // instead of holding a runner open (#97).
    assert!(
        err.contains("parked at review") || code == 1,
        "a run nobody is watching parks: exit {code}: {err}"
    );
}

#[test]
fn a_bare_ci_flag_is_still_a_ci() {
    // "Any CI that can run a binary": no marker variable at all, only the
    // flag. Everything it can say is `-`, and the run goes anyway.
    let dir = work_dir("bare", SITE);
    let (code, out, err) = run_in(&dir, &["run", "ship.ks", "--ci", "--dry-run"], &[]);
    assert_eq!(code, 0, "a CI that exports nothing still runs: {err}");
    assert!(err.contains("--ci unknown:"), "there is no system to name: {err}");
    assert!(err.contains("ref=-"), "no ref is invented: {err}");
    assert!(err.contains("sha=-"), "no commit is invented: {err}");
    // Nothing named an event either, and a guess of `push` would be a claim the
    // environment never made: a scheduled CI exports no more than a push does.
    assert!(err.contains("event=manual"), "{err}");
    // The actor and the `unknown` a bare `--ci` records under `ci` are one
    // name, so a log line and the record it wrote cannot disagree.
    assert!(err.contains("actor=unknown"), "{err}");
    assert!(out.contains("environment: "), "{out}");
    // And the CI context is forced: the flag is the assertion, so a site whose
    // run covers a `ci-only:` step starts where a laptop would have refused.
    let ci_only = "\
steps:
  plan:    oci.image
    from:   ./Dockerfile
  deploy:  oci.image
    from:   ./Dockerfile
    ci-only: true
";
    let dir = work_dir("bare-ci-only", ci_only);
    let (_, _, laptop) = run_in(&dir, &["run", "ship.ks"], &[]);
    assert!(laptop.contains("needs CI (not available locally)"), "{laptop}");
    let (_, _, err) = run_in(&dir, &["run", "ship.ks", "--ci"], &[]);
    assert!(!err.contains("needs CI (not available locally)"), "the flag settled it: {err}");
    assert!(err.contains("--ci unknown:"), "{err}");
}

#[test]
fn the_binary_needs_nothing_but_the_ci_variables() {
    // #130 asks for a container simulating Buildkite and GitLab, and there is
    // no Docker here — but the promise a container makes is the same one this
    // makes: an agent with no home, no toolchain and no other CI's markers,
    // which is what the binary is launched on when a real job starts it. Every
    // other test inherits this suite's environment, so nothing so far proves it
    // reads only what a CI exports.
    let dir = work_dir("bare-env", SITE);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_keepshipping"));
    cmd.args(["run", "ship.ks", "--ci"]).current_dir(&dir).env_clear();
    // The binary is reached by its absolute path, so `PATH` is not needed to
    // find it, and nothing in this run shells out.
    for (name, value) in BUILDKITE {
        cmd.env(name, value);
    }
    let out = cmd.output().expect("run keepshipping");
    let code = out.status.code().expect("exit code");
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    // The same outcome the parking test turns on: a run that started and parked
    // or hit the step kind that is not built yet, and never a usage error.
    assert!(matches!(code, 0 | 1 | 4), "the run started on a bare env: exit {code}: {err}");
    assert!(
        err.contains("parked at review") || code == 1,
        "a run nobody is watching parks: exit {code}: {err}"
    );
}

#[test]
fn bad_flags_are_usage_errors() {
    let dir = work_dir("usage", SITE);
    // A missing value, a flag that belongs to `run` alone used elsewhere, and
    // the same flag used where `run` is not: three ways to be wrong, one exit
    // code.
    for args in [
        vec!["run", "ship.ks", "--ci", "--sha"],
        vec!["check", "ship.ks", "--ci"],
        vec!["fmt", "--ci"],
        vec!["graph", "ship.ks", "--ci"],
    ] {
        let (code, _, err) = run_in(&dir, &args, BUILDKITE);
        assert_eq!(code, 2, "{args:?} is not a valid command line: {err}");
        assert!(err.contains("usage:"), "{args:?}: {err}");
    }
    // `--sha` states the commit for a CI run context. Without `--ci` there is
    // none to state it to, so the flag used to parse and then be dropped
    // silently — a caller would believe a run was about a commit it never
    // named. It is a usage error instead, with the flag that makes it mean
    // something.
    let (code, _, err) = run_in(&dir, &["run", "ship.ks", "--sha", "deadbeef", "--dry-run"], &[]);
    assert_eq!(code, 2, "--sha without --ci says nothing: {err}");
    assert!(err.contains("usage:"), "{err}");
    assert!(err.contains("--sha"), "{err}");
    assert!(!err.contains("environment:"), "the run did not start: {err}");
}

#[test]
#[cfg(unix)]
fn a_non_utf8_variable_does_not_take_a_ci_run_down() {
    // `env::vars` panics on a single variable that is not valid UTF-8, and the
    // actor is decided from the environment before anything else a `--ci` run
    // does — so one stray byte in a job's environment used to end the run over
    // a name it may never read. Nothing about the run changes; it just starts.
    use std::os::unix::ffi::OsStringExt;
    let dir = work_dir("non-utf8", SITE);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_keepshipping"));
    cmd.args(["run", "ship.ks", "--ci", "--dry-run"]).current_dir(&dir);
    for marker in MARKERS {
        cmd.env_remove(marker);
    }
    // Bytes a real job inherits: a detection marker whose value is not UTF-8,
    // and a variable nothing ever reads, which is what made this a defect
    // rather than a CI edge case.
    fn bad() -> std::ffi::OsString {
        std::ffi::OsString::from_vec(vec![0xff, 0xfe])
    }
    cmd.env("BUILDKITE", bad());
    cmd.env("TOTALLY_UNRELATED", bad());
    cmd.env(std::ffi::OsString::from_vec(b"WEIRD\xffNAME".to_vec()), "true");
    let out = cmd.output().expect("run keepshipping");
    let code = out.status.code().expect("exit code");
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(code, 0, "the run started: exit {code}: {err}");
    assert!(!err.contains("panicked"), "the environment was read, not fatal: {err}");
    // And it is the same run as any other: the marker is still read through the
    // lossy conversion, so the note names the CI rather than the run giving up.
    assert!(err.contains("--ci buildkite:"), "the CI is still named: {err}");
}

#[test]
fn a_named_agent_is_named_in_a_ci_note() {
    let dir = work_dir("as-name", SITE);
    // `--as agent:deployer` names which agent proposed the run. The CI context
    // carries the name into the note the way the local path carries it into
    // the run log — reporting only `agent` drops the one word the caller wrote.
    let (code, _, err) =
        run_in(&dir, &["run", "ship.ks", "--ci", "--as", "agent:deployer", "--dry-run"], BUILDKITE);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("actor=deployer"), "the name survives the CI context: {err}");
    // `--actor agent` still names the kind: there is no name to carry.
    let (code, _, err) =
        run_in(&dir, &["run", "ship.ks", "--ci", "--actor", "agent", "--dry-run"], BUILDKITE);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("actor=agent"), "{err}");

    // A tag override carries its ref with it, so the note never puts the run
    // on `refs/heads/main` and calls it `v1.2.3` at once. The ref rules
    // themselves are pinned in the unit tests beside the code that reads them.
    let (code, _, err) =
        run_in(&dir, &["run", "ship.ks", "--ci", "--event", "tag v1.2.3", "--dry-run"], BUILDKITE);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("event=tag v1.2.3 ref=refs/tags/v1.2.3"), "{err}");
}
