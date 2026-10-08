//! End-to-end tests of the approver-facing commands
//! ([#95](https://github.com/Keep-Shipping/harness/issues/95)): what a person parked run waits on,
//! what `approve` does to the state and the run log, what `deny` deliberately does not do, and the
//! two things that must be refused — a run that is not waiting, and an approver the caller chose.
//!
//! The parked state is written by hand as the JSON [`ks_engine::state::RunState::to_json`] writes,
//! because a run that parks itself needs the engine to execute it, and `run` does not execute yet
//! (#45). The run's log is the committed golden (`fixtures/run-log/golden.jsonl`), which already
//! carries an `approval.requested`, so an appended `approval.granted` has a real chain to continue
//! rather than starting a new one.

use std::path::Path;
use std::process::Command;

/// The run the fixtures belong to: the spec's example ULID.
const RUN: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const GOLDEN: &str = include_str!("fixtures/run-log/golden.jsonl");

/// How many `approval.denied` entries `types` holds. The golden already carries one (#99), so
/// "nothing was denied" means no more than the golden had.
fn denials(types: &[String]) -> usize {
    types.iter().filter(|t| *t == "approval.denied").count()
}

/// The `approval.denied` entries the seeded golden log starts with.
fn denials_in_golden() -> usize {
    GOLDEN.matches(r#""type":"approval.denied""#).count()
}

/// A fresh working directory with `run`'s state parked on `next`, and the golden as the run's log.
/// `None` writes a state that is not waiting on anything. Each test names its own directory, so
/// tests running in parallel cannot share a run's files.
fn workspace(name: &str, next: Option<&str>) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("keepshipping-approve-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let runs = dir.join(".keepshipping/runs");
    let run_dir = runs.join(RUN);
    std::fs::create_dir_all(&run_dir).expect("run dir");
    std::fs::write(runs.join(format!("{RUN}.jsonl")), GOLDEN).expect("write the run's log");
    let state = serde_json::json!({
        "version": 1,
        "run": RUN,
        "file_sha256": "a".repeat(64),
        "event": "push main",
        "context": { "environment": "production" },
        "completed": [],
        "approvals": [],
        "next": next,
    });
    std::fs::write(
        run_dir.join("state.json"),
        serde_json::to_vec(&state).expect("the state serializes"),
    )
    .expect("write the parked state");
    dir
}

/// The workspace's parked state, read back as JSON.
fn state_of(dir: &Path) -> serde_json::Value {
    let bytes = std::fs::read(dir.join(".keepshipping/runs").join(RUN).join("state.json"))
        .expect("read the parked state");
    serde_json::from_slice(&bytes).expect("the state is json")
}

/// The run's log, one event's `type` per line.
fn log_types(dir: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(dir.join(".keepshipping/runs").join(format!("{RUN}.jsonl")))
        .expect("read the run's log");
    text.lines()
        .map(|line| {
            let entry: serde_json::Value = serde_json::from_str(line).expect("each line is json");
            entry["type"].as_str().expect("each line names its type").to_string()
        })
        .collect()
}

/// `keepshipping <args...>` in `dir`, with `USER` set to `who` so the approver the command records
/// is a name the test chose.
fn keepshipping(dir: &Path, who: &str, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_keepshipping"))
        .args(args)
        .current_dir(dir)
        .env("USER", who)
        .output()
        .expect("run keepshipping");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// How many entries the run's log chains, or the first line that breaks it. `log verify` cannot
/// say this any more for a run that is still going: since #112 it refuses an unsealed log, and a
/// sealed one must end in `run.finished`, so a parked run's log is checked here the way the
/// command's own chain check reads it — each `hash` the sha256 of the entry's canonical bytes
/// without it, each `prev` the hash above, each `seq` its position.
fn chain_length(dir: &Path) -> Result<usize, String> {
    use sha2::Digest as _;
    fn canonical(value: &serde_json::Value) -> String {
        match value {
            serde_json::Value::Object(entry) => {
                let mut keys: Vec<&String> = entry.keys().collect();
                keys.sort_unstable();
                let body: Vec<String> = keys
                    .into_iter()
                    .map(|key| {
                        format!(
                            "{}:{}",
                            serde_json::to_string(key).expect("key"),
                            canonical(&entry[key])
                        )
                    })
                    .collect();
                format!("{{{}}}", body.join(","))
            }
            serde_json::Value::Array(items) => {
                format!("[{}]", items.iter().map(canonical).collect::<Vec<_>>().join(","))
            }
            scalar => serde_json::to_string(scalar).expect("scalar"),
        }
    }
    let text = std::fs::read_to_string(dir.join(".keepshipping/runs").join(format!("{RUN}.jsonl")))
        .expect("read the run's log");
    let mut prev = "0".repeat(64);
    for (seq, line) in text.lines().enumerate() {
        let mut entry: serde_json::Value = serde_json::from_str(line).expect("a JSON line");
        let hash = entry["hash"].as_str().expect("a hash").to_string();
        entry.as_object_mut().expect("an object").remove("hash");
        let digest = sha2::Sha256::digest(canonical(&entry).as_bytes());
        let computed: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        if computed != hash || entry["prev"] != prev.as_str() || entry["seq"] != seq as u64 {
            return Err(format!("line {}: chain broken", seq + 1));
        }
        prev = hash;
    }
    Ok(text.lines().count())
}

/// The listing shows a run parked on a person: the id, the step, and the environment the record
/// names. And a workspace where nothing has ever run is an empty queue, not a failure.
#[test]
fn pending_lists_the_runs_waiting_on_a_person() {
    let dir = workspace("pending", Some("deploy"));
    let (code, stdout, stderr) = keepshipping(&dir, "ada", &["runs", "pending"]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    assert_eq!(stdout, format!("{RUN}  deploy        production\n"), "{}", stdout);

    // Nothing parked, and no runs directory at all: both say so, and both exit 0.
    let done = workspace("pending-done", None);
    let (code, stdout, stderr) = keepshipping(&done, "ada", &["runs", "pending"]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout, "nothing is waiting for approval\n");

    let empty = std::env::temp_dir()
        .join(format!("keepshipping-approve-{}-pending-empty", std::process::id()));
    let _ = std::fs::remove_dir_all(&empty);
    std::fs::create_dir_all(&empty).expect("temp dir");
    let (code, stdout, stderr) = keepshipping(&empty, "ada", &["runs", "pending"]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout, "nothing is waiting for approval\n");
}

/// An approval releases the park: `next` is cleared, the approval is recorded against the step and
/// the person who gave it, and the run log carries `approval.granted`.
#[test]
fn approve_releases_the_parked_step() {
    let dir = workspace("approve", Some("deploy"));
    let (code, stdout, stderr) = keepshipping(&dir, "ada", &["approve", RUN]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout, format!("approved {RUN} at deploy as ada\n"), "{}", stdout);

    let state = state_of(&dir);
    assert_eq!(state["next"], serde_json::Value::Null, "the run is no longer parked");
    let approvals = state["approvals"].as_array().expect("the approvals");
    assert_eq!(approvals.len(), 1, "one approval, recorded once: {approvals:?}");
    assert_eq!(approvals[0]["step"], "deploy");
    assert_eq!(approvals[0]["by"], "ada", "the approver is the environment's own user");

    assert!(log_types(&dir).contains(&"approval.granted".to_string()), "the log has the approval");
}

/// The comment is the person's and is printed back to them; nothing else carries it.
#[test]
fn a_comment_is_echoed_in_the_confirmation() {
    let dir = workspace("comment", Some("deploy"));
    let (code, stdout, stderr) =
        keepshipping(&dir, "ada", &["approve", RUN, "--comment", "checked the diff"]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout, format!("approved {RUN} at deploy as ada — checked the diff\n"));
}

/// The appended event continues the run's chain from the tip the golden left, so `log verify` — the
/// check a CI job runs on a log it fetched as an artifact — still holds. That is the proof the
/// approval was appended rather than written over.
#[test]
fn the_appended_approval_keeps_the_chain_intact() {
    let dir = workspace("chain", Some("deploy"));
    assert!(
        log_types(&dir).contains(&"approval.requested".to_string()),
        "the seeded log is not empty"
    );

    let (code, _, stderr) = keepshipping(&dir, "ada", &["approve", RUN]);
    assert_eq!(code, 0, "{stderr}");

    assert_eq!(chain_length(&dir), Ok(10), "nine seeded, one appended");
}

/// A run that is not waiting cannot be moved by an approval — including a run that has already
/// finished — and an id no run has is not a thing to approve.
#[test]
fn a_run_that_is_not_waiting_cannot_be_approved() {
    let done = workspace("approve-done", None);
    let (code, stdout, stderr) = keepshipping(&done, "ada", &["approve", RUN]);
    assert_eq!(code, 2, "{stdout}{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("is not waiting for approval"), "{stderr}");
    assert_eq!(state_of(&done)["approvals"].as_array().expect("approvals").len(), 0);

    let missing = workspace("approve-missing", Some("deploy"));
    let (code, _, stderr) =
        keepshipping(&missing, "ada", &["approve", "01HQZZZZZZZZZZZZZZZZZZZZZZ"]);
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("has no parked state"), "{stderr}");
}

/// An id that is not a ULID cannot name a run's directory, so it is a usage error rather than
/// something guessed at.
#[test]
fn a_run_id_that_is_not_a_ulid_is_a_usage_error() {
    let dir = workspace("not-a-ulid", Some("deploy"));
    for args in [
        vec!["approve", "not-a-ulid"],
        vec!["approve", RUN, "--as", "ada"],
        vec!["deny", "not-a-ulid", "--reason", "no"],
    ] {
        let (code, stdout, stderr) = keepshipping(&dir, "ada", &args);
        assert_eq!(code, 2, "{args:?}: {stdout}{stderr}");
        assert!(stdout.is_empty(), "{args:?}: {stdout}");
        assert!(stderr.starts_with("error:"), "{args:?}: {stderr}");
    }
}

/// There is no `--as`: an approver the caller names is one an agent could name, which is what the
/// approval port exists to prevent. The flag is not accepted, and the approval did not happen.
#[test]
fn there_is_no_as_flag() {
    let dir = workspace("as", Some("deploy"));
    let (code, stdout, stderr) = keepshipping(&dir, "root", &["approve", RUN, "--as", "ada"]);
    assert_eq!(code, 2, "{stdout}{stderr}");
    assert!(stderr.contains("--comment"), "the usage names the flags there are: {stderr}");
    assert_eq!(state_of(&dir)["next"], "deploy", "the run is still parked");
    assert_eq!(state_of(&dir)["approvals"].as_array().expect("approvals").len(), 0);
    assert!(!log_types(&dir).contains(&"approval.granted".to_string()));
}

/// A refusal is recorded and the run stays exactly where it was: `deny` appends `approval.denied`
/// naming the person and the step, and leaves the state untouched so the run is still the one an
/// approver sees in the listing.
#[test]
fn deny_records_the_refusal_and_leaves_the_run_parked() {
    let dir = workspace("deny", Some("deploy"));
    let before = std::fs::read(dir.join(".keepshipping/runs").join(RUN).join("state.json"))
        .expect("read the state");

    let (code, stdout, stderr) =
        keepshipping(&dir, "ada", &["deny", RUN, "--reason", "not this week"]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout, format!("denied {RUN} at deploy as ada — not this week\n"), "{}", stdout);

    let after = std::fs::read(dir.join(".keepshipping/runs").join(RUN).join("state.json"))
        .expect("read the state");
    assert_eq!(after, before, "a refusal does not advance the run");
    assert_eq!(state_of(&dir)["next"], "deploy");

    let denied =
        std::fs::read_to_string(dir.join(".keepshipping/runs").join(format!("{RUN}.jsonl")))
            .expect("read the run's log");
    let last: serde_json::Value = denied
        .lines()
        .next_back()
        .expect("the log has entries")
        .parse()
        .expect("the last line is json");
    assert_eq!(last["type"], "approval.denied");
    assert_eq!(last["step"], "deploy");
    assert_eq!(last["approver"], "ada");
    assert_eq!(last["channel"], "local");

    // And the chain the refusal was appended into still holds.
    assert_eq!(chain_length(&dir), Ok(10));
}

/// A refusal with no reason is a usage error, and the run must be left alone. The reason is
/// required because a refusal has to be a considered one; it is printed back to the operator, and
/// the durable record — `approval.denied` — says that the run was refused, by whom, and why.
#[test]
fn deny_without_a_reason_is_a_usage_error() {
    let dir = workspace("deny-no-reason", Some("deploy"));
    let before = std::fs::read(dir.join(".keepshipping/runs").join(RUN).join("state.json"))
        .expect("read the state");
    for args in [vec!["deny", RUN], vec!["deny", RUN, "--reason"], vec!["deny"]] {
        let (code, stdout, stderr) = keepshipping(&dir, "ada", &args);
        assert_eq!(code, 2, "{args:?}: {stdout}{stderr}");
        assert!(stdout.is_empty(), "{args:?}: {stdout}");
        assert!(stderr.starts_with("error:"), "{args:?}: {stderr}");
    }
    assert_eq!(denials(&log_types(&dir)), denials_in_golden(), "nothing was recorded");
    assert_eq!(
        std::fs::read(dir.join(".keepshipping/runs").join(RUN).join("state.json")).unwrap(),
        before
    );
}

/// A flag where a value should be is a usage error, exactly as a missing value is. `--comment
/// --as` is a typo, not a run whose approver's comment is the string `--as`: the flag is not the
/// person's words, and the run must be left parked.
#[test]
fn a_flag_where_a_value_should_be_is_a_usage_error() {
    let dir = workspace("flag-as-comment", Some("deploy"));
    for args in [
        vec!["approve", RUN, "--comment", "--as"],
        vec!["approve", RUN, "--comment", "-x"],
        vec!["deny", RUN, "--reason", "--as"],
    ] {
        let (code, stdout, stderr) = keepshipping(&dir, "ada", &args);
        assert_eq!(code, 2, "{args:?}: {stdout}{stderr}");
        assert!(stdout.is_empty(), "{args:?}: {stdout}");
        assert!(stderr.starts_with("error:"), "{args:?}: {stderr}");
    }
    let state = state_of(&dir);
    assert_eq!(state["next"], "deploy", "the run is still parked");
    assert_eq!(state["approvals"].as_array().expect("approvals").len(), 0);
    let types = log_types(&dir);
    assert!(!types.contains(&"approval.granted".to_string()), "nothing was granted");
    assert_eq!(denials(&types), denials_in_golden(), "nothing was denied");
}

/// The approval is written to the run whose directory it was read from. A record whose `run` field
/// names a *different* run — hand-edited, or a copied directory — must be refused rather than
/// sending the approval into the other run's state and destroying the record it holds.
#[test]
fn a_state_for_another_run_is_refused() {
    const OTHER: &str = "01HQZZZZZZZZZZZZZZZZZZZZZZ";
    let dir = workspace("wrong-run", Some("deploy"));
    let other_dir = dir.join(".keepshipping/runs").join(OTHER);
    std::fs::create_dir_all(&other_dir).expect("the other run's directory");

    // The same record, relabelled: it sits in RUN's directory but says it is OTHER's.
    let state = state_of(&dir);
    let mut relabelled = state.clone();
    relabelled["run"] = serde_json::json!(OTHER);
    std::fs::write(
        dir.join(".keepshipping/runs").join(RUN).join("state.json"),
        serde_json::to_vec(&relabelled).expect("the state serializes"),
    )
    .expect("write the relabelled state");

    let (code, stdout, stderr) = keepshipping(&dir, "ada", &["approve", RUN]);
    assert_eq!(code, 2, "{stdout}{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains(&format!("the parked state in {RUN} is for run {OTHER}")), "{stderr}");

    // Nothing was written anywhere: not to the directory it was read from, and not to the run it
    // claimed to be for.
    assert_eq!(state_of(&dir), relabelled, "the record it read is unchanged");
    assert!(!other_dir.join("state.json").exists(), "the other run's state was not created");
    assert!(!log_types(&dir).contains(&"approval.granted".to_string()));
}
