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
