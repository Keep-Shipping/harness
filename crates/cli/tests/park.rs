//! Parking a run and picking it up again from the outside
//! ([#97](https://github.com/Keep-Shipping/harness/issues/97)).
//!
//! A run that has to wait ends its job rather than holding a runner open, and
//! `keepshipping resume <run>` is the job that carries it on. These tests drive
//! the real binary over real parked records — written with the engine's own
//! [`park`], so the bytes on disk are the ones a parking job leaves behind —
//! and read the refusals as closely as the happy path. A resume that quietly
//! carried on under a stale approval, in a context that cannot run the steps,
//! past policy, or on an agent's say-so, would be the bug this turns on.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use ks_core::ids::RunId;
use ks_core::ports::run_context::{AGENT_TYPICAL_ENV, KNOWN_AGENT_MARKERS};
use ks_engine::state::{CompletedStep, LocalStateStore, RunState, park, resume};

/// An approval with a step after it, so resuming has something to carry on to.
/// The file's bytes are the binding the parked record carries.
const SITE: &str = "\
steps:
  review:  approval
  apply:   oci.image
    from:   ./Dockerfile
";

/// The same file with a step that needs CI behind the approval: a run parked
/// on a runner and resumed on a laptop is the case the context gate is for.
const CI_GATED: &str = "\
steps:
  review:  approval
  apply:   oci.image
    from:   ./Dockerfile
    ci-only: true
";

/// The approval itself behind CI. The step being answered is not exempt from
/// the gate.
const CI_APPROVAL: &str = "\
steps:
  review:  approval
    ci-only: true
  apply:   oci.image
    from:   ./Dockerfile
";

/// A file whose own policy forbids people to build: the step after the
/// approval is one the policy gate refuses.
const NEVER_BUILD: &str = "\
steps:
  review:  approval
  apply:   oci.image
    from:   ./Dockerfile
policy:
  humans:
    never: build
";

/// A file that applies into an environment named `prod`, which is `ci-only`
/// without saying so ([#123](https://github.com/Keep-Shipping/harness/issues/123)).
/// Parking on a runner and resuming on a laptop must not be the way around
/// that gate — the same gate a fresh local run gets.
const PROD_ENV: &str = "\
envs:
  staging:
    secrets: staging
  prod:
    secrets: prod
steps:
  review:  approval
  plan:    tofu.plan
    dir:    ./infra
  apply:   tofu.apply
    plan:   plan.file
";

/// What the binary prints when the run gets past the approval and reaches a
/// step kind it cannot run yet.
const NOT_BUILT: &str = "`oci.image` steps are not built in yet";

/// A file whose step after the approval reaches past the checkout: applying is
/// what a run about somebody else's code may not do, whatever the file says.
const APPLIES: &str = "\
steps:
  review:  approval
  apply:   tofu.apply
    dir:    ./infra/prod
";

/// The same refusal asked for in the only words a script step has. Its kind is
/// not a catalog name, so `action:` is the whole of what the file says about
/// what the body does — and the file is the fork's.
const SCRIPT_APPLIES: &str = "\
steps:
  review:  approval
  pwn:     ./ship/pwn.ts
    action: apply
";

/// The same file with the declaration left out. Declaring `apply` and
/// declaring nothing have to come to the same place for a run about somebody
/// else's code: the line is only ever something a file said about itself, and
/// a fork that writes nothing has said the same thing for free.
const SCRIPT_UNDECLARED: &str = "\
steps:
  review:  approval
  pwn:     ./ship/pwn.ts
";

/// A step nothing decides is a step that runs — which cuts the other way
/// too. This file belongs to the repository, says nothing about provenance,
/// and its own script step declares the one action the baseline never allows
/// anybody: `destroy`. Before the undeclared script step reached the preflight
/// it was invisible to policy, so this file ran (exit 1, the script runtime not
/// built in yet); now the declaration is decided like every other step and the
/// default's never-rule reaches it. The refusal is `baseline:` and not
/// `provenance:` — nothing here is about whose code this is.
const SCRIPT_DESTROYS: &str = "\
steps:
  review:  approval
  wreck:   ./ship/wreck.ts
    action: destroy
";

/// The variables that say whose code a run is about, as GitHub sets them for a
/// pull request opened from a fork.
const FORK_PR: &[(&str, &str)] = &[
    ("GITHUB_EVENT_NAME", "pull_request"),
    ("GITHUB_HEAD_REPOSITORY", "someone/fork"),
    ("GITHUB_REPOSITORY", "Keep-Shipping/harness"),
];

/// The same file's step, as a `pull_request_target` run reads it: untrusted
/// whoever opened it and wherever the head lives.
const TARGET_PR: &[(&str, &str)] = &[
    ("GITHUB_EVENT_NAME", "pull_request_target"),
    ("GITHUB_HEAD_REPOSITORY", "Keep-Shipping/harness"),
    ("GITHUB_REPOSITORY", "Keep-Shipping/harness"),
];

fn run_id() -> RunId {
    RunId::from_parts(1_700_000_000_000, 42)
}

/// A clean directory under `CARGO_TARGET_TMPDIR` holding `src` as `ship.ks`.
fn work_dir(label: &str, src: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(label);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the work directory can be created");
    std::fs::write(dir.join("ship.ks"), src).expect("write the site file");
    dir
}

/// Parks `state` under `dir` exactly as a parking job would.
fn park_run(dir: &Path, state: &RunState) {
    ks_testing::block_on(park(&LocalStateStore::new(dir), state)).expect("the run parks");
    ks_testing::block_on(resume(
        &LocalStateStore::new(dir),
        &state.run,
        &std::fs::read(dir.join("ship.ks")).expect("the site file the record is bound to"),
    ))
    .expect("the parked run reads back");
}

/// What `run` leaves when nobody is watching: waiting at the approval, for the
/// reason `waiting_on` says.
fn parked_at_review(src: &str, waiting_on: &str) -> RunState {
    parked_at_review_in(src, waiting_on, None)
}

/// The same, for a run that resolved `env` — the record carries the
/// environment `run` selected, which a later job cannot re-derive.
fn parked_at_review_in(src: &str, waiting_on: &str, env: Option<&str>) -> RunState {
    let mut state = RunState::new(run_id(), src.as_bytes(), "push main")
        .with_context("waiting_on", waiting_on)
        .with_context("actor", if waiting_on == "agent" { "agent" } else { "human" });
    if let Some(env) = env {
        state = state.with_context("environment", env);
    }
    state.park_at("review").expect("review has not run");
    state
}

/// Runs the binary in `dir` as a person on a laptop: no CI and nothing that
/// makes the process look like an agent, plus whatever `vars` add.
fn keepshipping(dir: &Path, args: &[&str], vars: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_keepshipping"));
    cmd.args(args).current_dir(dir).env_remove("GITHUB_ACTIONS").env_remove("CI");
    // The variables that say whose code a run is about, so a test says what
    // provenance it means — and so a test suite run on a GitHub runner does not
    // answer for the tests that mean nothing by it.
    for name in ["GITHUB_EVENT_NAME", "GITHUB_HEAD_REPOSITORY", "GITHUB_REPOSITORY"] {
        cmd.env_remove(name);
    }
    for marker in KNOWN_AGENT_MARKERS {
        cmd.env_remove(marker);
    }
    for (name, _) in AGENT_TYPICAL_ENV {
        cmd.env_remove(*name);
    }
    // The organisation baseline too, so an exported `KEEPSHIPPING_*` cannot
    // change what these tests are about.
    cmd.env_remove("KEEPSHIPPING_REQUIRE_HUMAN").env_remove("KEEPSHIPPING_AGENTS");
    for (name, value) in vars {
        cmd.env(name, value);
    }
    let out = cmd.output().expect("run keepshipping");
    (
        out.status.code().expect("an exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The record on disk, as the JSON a later job parses, so a test asserts on
/// field names rather than on this crate's structs.
fn record_on_disk(dir: &Path) -> serde_json::Value {
    let path = LocalStateStore::new(dir).run_dir(&run_id()).join("state.json");
    let bytes = std::fs::read(&path).expect("the parked record is on disk");
    serde_json::from_slice(&bytes).expect("the parked record is JSON")
}

/// Asserts the record is still waiting at `review` with nothing approved — a
/// refused resume changed nothing, so the same run can be resumed elsewhere.
fn still_waiting(dir: &Path) {
    let after = record_on_disk(dir);
    assert_eq!(after["next"], serde_json::json!("review"), "still waiting: {after}");
    assert!(after["approvals"].as_array().expect("approvals").is_empty(), "{after}");
    assert!(after["completed"].as_array().expect("completed").is_empty(), "{after}");
}

#[test]
fn resume_answers_an_approval_nobody_was_there_for_and_carries_on() {
    let dir = work_dir("park-resume", SITE);
    park_run(&dir, &parked_at_review(SITE, "approval"));
    let (code, out, err) = keepshipping(&dir, &["resume", run_id().as_str()], &[]);

    // Past the approval and on to `apply`, which no step kind can run yet: the
    // point is that it got *past* the approval rather than parking again.
    assert!(out.contains(NOT_BUILT), "{out}{err}");
    assert_eq!(code, 1, "{out}{err}");

    // The approval is in the record's own format: who, an RFC 3339 expiry,
    // and the artifacts it covers.
    let record = record_on_disk(&dir);
    let approval = &record["approvals"][0];
    assert_eq!(approval["step"], serde_json::json!("review"));
    assert!(approval["by"].is_string(), "{record}");
    let expires = approval["expires_at"].as_str().expect("the approval has a window");
    assert!(expires.ends_with('Z') && expires.contains('T'), "RFC 3339: {expires}");
    assert!(approval["artifacts"].is_array(), "{record}");
    assert!(approval.get("expires").is_none(), "no second expiry format: {record}");
    // The gate is behind the run: done, and not waited on any more.
    assert_eq!(record["next"], serde_json::Value::Null, "{record}");
    assert_eq!(record["completed"][0]["name"], serde_json::json!("review"), "{record}");
}

#[test]
fn a_run_that_is_not_parked_is_refused() {
    let dir = work_dir("park-not-parked", SITE);
    park_run(&dir, &RunState::new(run_id(), SITE.as_bytes(), "push main"));
    let (code, _, err) = keepshipping(&dir, &["resume", run_id().as_str()], &[]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("nothing to resume"), "{err}");
    assert!(err.contains("already finished"), "{err}");
}

/// The acceptance criterion: a resume after an approval's window has passed
/// is refused rather than carried on under a decision nobody stands behind.
#[test]
fn a_resume_after_the_approval_expired_is_refused() {
    let dir = work_dir("park-expired", SITE);
    let mut state = parked_at_review(SITE, "approval");
    // Approved for an hour, a long time ago.
    let then = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
    state.approve_until("review", "ada", Duration::from_secs(3600), then).expect("parked there");
    park_run_unchecked(&dir, &state);

    let (code, _, err) = keepshipping(&dir, &["resume", run_id().as_str()], &[]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("expired"), "{err}");
    assert!(err.contains("review"), "the refusal names the approval: {err}");
    // Refused means nothing ran and nothing was recorded against it.
    let after = record_on_disk(&dir);
    assert!(after["completed"].as_array().expect("completed").is_empty(), "{after}");
}

/// [`park_run`] without the read-back, for a record the engine itself would
/// refuse to resume.
fn park_run_unchecked(dir: &Path, state: &RunState) {
    ks_testing::block_on(park(&LocalStateStore::new(dir), state)).expect("the run parks");
}

/// An approval already recorded — `keepshipping approve` — is continued past,
/// and one with no window never goes stale.
#[test]
fn a_recorded_approval_is_continued_past() {
    let dir = work_dir("park-approved", SITE);
    let mut state = parked_at_review(SITE, "approval");
    state.approve("review", "ada").expect("the run is parked at review");
    park_run(&dir, &state);

    let (code, out, err) = keepshipping(&dir, &["resume", run_id().as_str()], &[]);
    assert!(!err.contains("expired"), "{err}");
    assert!(out.contains(NOT_BUILT), "past the approval: {out}{err}");
    assert_eq!(code, 1, "{out}{err}");
    let record = record_on_disk(&dir);
    assert_eq!(record["approvals"].as_array().expect("approvals").len(), 1, "not re-approved");
    assert_eq!(record["approvals"][0]["by"], serde_json::json!("ada"), "{record}");
}

/// An agent's run waits on a human. `resume` will not answer it, whoever runs
/// it; `keepshipping approve` does, and then `resume` carries it on.
#[test]
fn an_agents_run_waits_for_a_human_to_approve_before_it_resumes() {
    let dir = work_dir("park-agent", SITE);
    park_run(&dir, &parked_at_review(SITE, "agent"));

    let (code, _, err) = keepshipping(&dir, &["resume", run_id().as_str()], &[]);
    assert_eq!(code, 4, "still waiting: {err}");
    assert!(err.contains(&format!("keepshipping approve {}", run_id())), "{err}");
    still_waiting(&dir);

    let (code, _, err) = keepshipping(&dir, &["approve", run_id().as_str()], &[]);
    assert_eq!(code, 0, "{err}");
    let (code, out, err) = keepshipping(&dir, &["resume", run_id().as_str()], &[]);
    assert!(out.contains(NOT_BUILT), "past the approval: {out}{err}");
    assert_eq!(code, 1, "{out}{err}");
}

/// An agent resuming a run nobody answered does not thereby answer it.
#[test]
fn an_agent_resuming_does_not_answer_the_approval() {
    let dir = work_dir("park-agent-resumes", SITE);
    park_run(&dir, &parked_at_review(SITE, "approval"));
    let (code, _, err) = keepshipping(&dir, &["resume", run_id().as_str()], &[("CLAUDECODE", "1")]);
    assert_eq!(code, 4, "{err}");
    assert!(err.contains("an agent may not answer"), "{err}");
    still_waiting(&dir);
}

#[test]
fn a_run_id_that_names_no_parked_run_is_a_usage_error() {
    let dir = work_dir("park-unknown", SITE);
    let (code, _, err) = keepshipping(&dir, &["resume", "01ARZ3NDEKTSV4RRFFQ69G5FAV"], &[]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("no parked state for run"), "{err}");
}

#[test]
fn resume_rejects_what_is_not_a_run_id_or_too_many_arguments() {
    let dir = work_dir("park-usage", SITE);
    for args in [vec!["resume"], vec!["resume", "nope"], vec!["resume", "--force"]] {
        let (code, _, err) = keepshipping(&dir, &args, &[]);
        assert_eq!(code, 2, "{args:?}: {err}");
        assert!(err.contains("`resume` takes a run id"), "{args:?}: {err}");
    }
}

/// A `ship.ks` edited between the park and the resume refuses: the approver
/// answered about the file as it stood.
#[test]
fn a_file_edited_since_the_run_parked_is_refused() {
    let dir = work_dir("park-edited", SITE);
    park_run(&dir, &parked_at_review(SITE, "approval"));
    std::fs::write(dir.join("ship.ks"), format!("{SITE}  # edited")).expect("edit the file");
    let (code, _, err) = keepshipping(&dir, &["resume", run_id().as_str()], &[]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("changed since the run parked"), "{err}");
}

/// A run parked on a runner and resumed on a laptop is refused the way a
/// fresh run on the laptop is ([#34](https://github.com/Keep-Shipping/harness/issues/34)),
/// before anything is approved.
#[test]
fn a_resume_in_a_context_that_cannot_run_the_steps_is_refused() {
    let dir = work_dir("park-context", CI_GATED);
    park_run(&dir, &parked_at_review(CI_GATED, "approval"));
    let (code, _, err) = keepshipping(&dir, &["resume", run_id().as_str()], &[]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("refusing to start"), "the gate speaks: {err}");
    assert!(err.contains("apply") && err.contains("needs CI"), "{err}");
    still_waiting(&dir);
}

/// The environment guard a fresh run gets ([#123](https://github.com/Keep-Shipping/harness/issues/123)):
/// a run parked in CI on `prod` and resumed on a laptop is refused the same
/// way a fresh local run into `prod` is — before the approval is answered and
/// nothing recorded.
#[test]
fn a_resume_into_production_from_a_laptop_is_refused() {
    let dir = work_dir("park-prod-env", PROD_ENV);
    park_run(&dir, &parked_at_review_in(PROD_ENV, "approval", Some("prod")));
    let (code, _, err) = keepshipping(&dir, &["resume", run_id().as_str()], &[]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("refusing to start"), "the guard speaks: {err}");
    assert!(err.contains("step `apply` applies into `prod`"), "{err}");
    assert!(err.contains("prod credentials belong in CI"), "{err}");
    still_waiting(&dir);
}

/// The same run resumed where the apply belongs — in CI — is carried on, so
/// the gate has not simply closed the door.
#[test]
fn a_resume_into_production_in_ci_is_carried_on() {
    let dir = work_dir("park-prod-ci", PROD_ENV);
    park_run(&dir, &parked_at_review_in(PROD_ENV, "approval", Some("prod")));
    let (code, out, err) = keepshipping(
        &dir,
        &["resume", run_id().as_str()],
        &[("CI", "true"), ("GITHUB_ACTIONS", "true")],
    );
    assert!(!err.contains("refusing to start"), "CI is the route through: {out}{err}");
    assert_eq!(code, 1, "{out}{err}");
    // Past the approval and on to the first step it cannot run yet, which is
    // what a resume that was let through looks like.
    assert!(out.contains("steps are not built in yet"), "{out}{err}");
}

/// The environment beside it, which is not production: the same parked record
/// shape, resumed into `staging`, is not this guard's business.
#[test]
fn a_resume_into_staging_is_not_the_guards_business() {
    let dir = work_dir("park-staging-env", PROD_ENV);
    park_run(&dir, &parked_at_review_in(PROD_ENV, "approval", Some("staging")));
    let (code, out, err) = keepshipping(&dir, &["resume", run_id().as_str()], &[]);
    assert!(!err.contains("refusing to start"), "{out}{err}");
    assert_eq!(code, 1, "{out}{err}");
    assert!(out.contains("steps are not built in yet"), "{out}{err}");
}

/// The gate covers the approval being answered: a CI-only approval is not
/// granted from a laptop.
#[test]
fn an_approval_step_that_needs_ci_is_not_approved_from_a_context_that_has_none() {
    let dir = work_dir("park-ci-approval", CI_APPROVAL);
    park_run(&dir, &parked_at_review(CI_APPROVAL, "approval"));
    let (code, _, err) = keepshipping(&dir, &["resume", run_id().as_str()], &[]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("refusing to start") && err.contains("review"), "{err}");
    assert!(err.contains("needs CI"), "{err}");
    still_waiting(&dir);
}

/// Policy is decided again before the run carries on (#103): a step the
/// policy refuses refuses the resume, exit 5, before anything is approved.
#[test]
fn a_resume_policy_refuses_is_refused_before_anything_is_approved() {
    let dir = work_dir("park-policy", NEVER_BUILD);
    park_run(&dir, &parked_at_review(NEVER_BUILD, "approval"));
    let (code, _, err) = keepshipping(&dir, &["resume", run_id().as_str()], &[]);
    assert_eq!(code, 5, "{err}");
    assert!(err.contains("refusing to resume") && err.contains("apply"), "{err}");
    still_waiting(&dir);
}

/// Whose code the run is about is the run's own first policy question
/// (#126): a `ship.ks` a fork wrote may not apply, even though the baseline
/// lets this actor apply and even though that same file could say `can: apply`.
/// The workflow's `pull_request` permissions are the only defence otherwise,
/// and a resume is exactly the path where a runner holds the credentials.
#[test]
fn a_resume_about_someone_elses_code_may_not_apply() {
    // The control: the same file, the same parked run, an environment that says
    // nothing about provenance — so the refusal below is the code's origin and
    // not this fixture's shape.
    let ours = work_dir("park-provenance-ours", APPLIES);
    park_run(&ours, &parked_at_review(APPLIES, "approval"));
    let (code, _, err) = keepshipping(&ours, &["resume", run_id().as_str()], &[]);
    assert_ne!(code, 5, "our own code is not a provenance refusal: {err}");

    for (label, vars, said) in [
        ("fork", FORK_PR, "a fork pull request"),
        ("target", TARGET_PR, "a pull_request_target run"),
    ] {
        let dir = work_dir(&format!("park-provenance-{label}"), APPLIES);
        park_run(&dir, &parked_at_review(APPLIES, "approval"));
        let (code, _, err) = keepshipping(&dir, &["resume", run_id().as_str()], vars);
        assert_eq!(code, 5, "{label}: refused by policy, nothing approved: {err}");
        assert!(err.contains("refusing to resume"), "{label}: {err}");
        assert!(err.contains("apply"), "{label}: it names the step: {err}");
        assert!(err.contains("provenance"), "{label}: it names the question: {err}");
        assert!(err.contains(said), "{label}: it names which case this is: {err}");
        still_waiting(&dir);
    }
}

/// A script step is the same question asked in a file the catalog cannot read:
/// `./pwn.ts` has no kind this crate can classify, so the only thing the run
/// knows about what the body does is the `action:` the file itself declared —
/// and in a fork's file that word is the fork's. Leaving it out of the
/// preflight is what made it run: a step nothing decides is a step that runs.
#[test]
fn a_resume_may_not_run_a_fork_script_step_that_declares_an_apply() {
    let dir = work_dir("park-script-apply", SCRIPT_APPLIES);
    std::fs::create_dir_all(dir.join("ship")).expect("the script's directory");
    std::fs::write(dir.join("ship/pwn.ts"), "console.log('pwned')\n").expect("the script");
    park_run(&dir, &parked_at_review(SCRIPT_APPLIES, "approval"));

    let (code, out, err) = keepshipping(&dir, &["resume", run_id().as_str()], FORK_PR);
    assert_eq!(code, 5, "refused by policy, nothing approved: {out}{err}");
    assert!(err.contains("refusing to resume"), "{err}");
    assert!(err.contains("pwn") && err.contains("apply"), "{err}");
    assert!(err.contains("provenance") && err.contains("fork"), "{err}");
    // Refused before the step ran: the record still says the approval is the
    // next thing, and the script left no trace.
    still_waiting(&dir);
    assert!(!out.contains("pwned"), "the fork's script ran: {out}{err}");
}

/// The same step with no `action:` at all. A step nothing decides is a step
/// that runs, so a fork could buy what `action: apply` is refused for by
/// saying nothing — the cheapest spelling of the same request
/// ([#126](https://github.com/Keep-Shipping/harness/issues/126)).
#[test]
fn a_resume_may_not_run_a_fork_script_step_that_declares_no_action() {
    let dir = work_dir("park-script-undeclared", SCRIPT_UNDECLARED);
    std::fs::create_dir_all(dir.join("ship")).expect("the script's directory");
    std::fs::write(dir.join("ship/pwn.ts"), "console.log('pwned')\n").expect("the script");
    park_run(&dir, &parked_at_review(SCRIPT_UNDECLARED, "approval"));

    let (code, out, err) = keepshipping(&dir, &["resume", run_id().as_str()], FORK_PR);
    assert_eq!(code, 5, "refused by policy, nothing approved: {out}{err}");
    assert!(err.contains("refusing to resume"), "{err}");
    assert!(err.contains("pwn"), "it names the step: {err}");
    assert!(err.contains("provenance") && err.contains("fork"), "it names the question: {err}");
    still_waiting(&dir);
    assert!(!out.contains("pwned"), "the fork's script ran: {out}{err}");

    // The refusal is about whose code this is, not about undeclared script
    // steps: on the repository's own the same file gets as far as it always
    // did.
    let ours = work_dir("park-script-undeclared-ours", SCRIPT_UNDECLARED);
    std::fs::create_dir_all(ours.join("ship")).expect("the script's directory");
    std::fs::write(ours.join("ship/pwn.ts"), "console.log('pwned')\n").expect("the script");
    park_run(&ours, &parked_at_review(SCRIPT_UNDECLARED, "approval"));
    let (code, _, err) = keepshipping(&ours, &["resume", run_id().as_str()], &[]);
    assert_ne!(code, 5, "our own code is not a provenance refusal: {err}");
}

/// The same decision on the repository's own code, and the behaviour change
/// worth writing down. Leaving a script step out of the preflight made it
/// invisible to policy, so a file that declared `action: destroy` used to run
/// (exit 1, the script runtime not built in yet); the fix that lets a fork be
/// stopped by what it declared also makes the declaration count on a trusted
/// run. That is the conservative default's never-rule reaching a step it could
/// not see before, and the refusal says so — `baseline:`, never `provenance:` —
/// so an operator reading the log can tell which question was asked. It becomes
/// live for existing repositories when the script runtime lands.
#[test]
fn a_trusted_script_step_may_not_destroy_either() {
    let dir = work_dir("park-script-destroy", SCRIPT_DESTROYS);
    std::fs::create_dir_all(dir.join("ship")).expect("the script's directory");
    std::fs::write(dir.join("ship/wreck.ts"), "console.log('wrecked')\n").expect("the script");
    park_run(&dir, &parked_at_review(SCRIPT_DESTROYS, "approval"));

    // No provenance variables: a laptop running the repository's own code.
    let (code, out, err) = keepshipping(&dir, &["resume", run_id().as_str()], &[]);
    assert_eq!(code, 5, "refused by policy, nothing approved: {out}{err}");
    assert!(err.contains("refusing to resume"), "{err}");
    assert!(err.contains("wreck") && err.contains("destroy"), "it names the step: {err}");
    assert!(err.contains("baseline"), "it is the baseline's never-rule that says no: {err}");
    assert!(!err.contains("provenance"), "our own code is not a provenance refusal: {err}");
    // Refused before the step ran, exactly as a refused fork run is: the
    // record is untouched and the script left no trace.
    still_waiting(&dir);
    assert!(!out.contains("wrecked"), "the script ran: {out}{err}");
}

/// A resumed run keeps what the record already had done, and adds the gate
/// it was let past.
#[test]
fn a_resumed_run_keeps_what_was_already_done() {
    const TWO: &str = "\
steps:
  review:  approval
  again:   approval
    after:  review
";
    let dir = work_dir("park-twice", TWO);
    let mut state =
        RunState::new(run_id(), TWO.as_bytes(), "push main").with_context("waiting_on", "approval");
    state.record(CompletedStep { name: "build".to_string(), ..Default::default() });
    state.park_at("review").expect("review has not run");
    park_run(&dir, &state);
    let (code, out, err) = keepshipping(&dir, &["resume", run_id().as_str()], &[]);
    // `approval` is not a built-in step kind yet, so the run stops there
    // rather than asking; what matters is the first gate was passed.
    assert_ne!(code, 0, "{out}{err}");
    let record = record_on_disk(&dir);
    let done: Vec<&str> = record["completed"]
        .as_array()
        .expect("completed")
        .iter()
        .filter_map(|step| step["name"].as_str())
        .collect();
    assert!(done.contains(&"build") && done.contains(&"review"), "{record}");
}
