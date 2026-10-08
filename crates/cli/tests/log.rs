//! End-to-end tests of `keepshipping log`: the run log the adapter wrote is read back the way a
//! person and a tool read it, and — the promise in the issue — a line that was edited after the
//! fact is caught by `keepshipping log verify`, which says which line.
//!
//! The log itself is the committed golden (`fixtures/run-log/golden.jsonl`), written by the
//! adapter through a `FakeClock` so it is byte-stable; these tests copy it into a working
//! directory as `.keepshipping/runs/<id>.jsonl` rather than re-deriving the chain here, so what
//! the command checks is what a run really writes.

use std::path::Path;
use std::process::Command;

use sha2::Digest as _;

/// The run the golden log belongs to: the spec's example ULID.
const RUN: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const GOLDEN: &str = include_str!("fixtures/run-log/golden.jsonl");

/// A fresh working directory holding `GOLDEN` as the run's log. Each test names its own, so
/// tests running in parallel cannot share a run's file.
fn workspace(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("keepshipping-log-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let runs = dir.join(".keepshipping/runs");
    std::fs::create_dir_all(&runs).expect("runs dir");
    std::fs::write(runs.join(format!("{RUN}.jsonl")), GOLDEN).expect("write the run's log");
    dir
}

/// Rewrites the run's log, so a test can tamper with what is on disk.
fn tamper(dir: &Path, edit: impl Fn(&mut Vec<String>)) {
    let path = dir.join(".keepshipping/runs").join(format!("{RUN}.jsonl"));
    let mut lines: Vec<String> =
        std::fs::read_to_string(&path).expect("read").lines().map(String::from).collect();
    edit(&mut lines);
    std::fs::write(path, lines.join("\n") + "\n").expect("write");
}

fn keepshipping(dir: &Path, args: &[&str]) -> (i32, String, String) {
    runs(dir, &[], args)
}

/// The same, with environment set for the child — how a CI job points `log
/// seal` at a key it has mounted.
fn runs(dir: &Path, env: &[(&str, String)], args: &[&str]) -> (i32, String, String) {
    let mut out = Command::new(env!("CARGO_BIN_EXE_keepshipping"));
    out.arg("log").args(args).current_dir(dir);
    for (name, value) in env {
        out.env(name, value);
    }
    let out = out.output().expect("run keepshipping");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn a_run_prints_one_line_per_event() {
    let dir = workspace("print");
    let (code, stdout, stderr) = keepshipping(&dir, &[RUN]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    assert_eq!(
        stdout,
        "\
22:13:20  run.started  actor=ci  file_hash=sha256:aa  is_agent=false  trigger=push main
22:13:20  step.started  step=build
22:13:20  step.finished  duration_ms=1.2s  ok=true  outputs=digest  step=build
22:13:20  approval.requested  artifacts=sha256:bb  channel=github  step=deploy
22:13:20  approval.denied  approver=grace  artifacts=sha256:bb  channel=github  reason=denied by grace: not today  step=deploy
22:13:20  approval.expired  artifacts=sha256:bb  channel=github  step=deploy
22:13:20  approval.aborted  artifacts=sha256:bb  channel=github  proposer=agent-runtime  step=deploy
22:13:20  approval.rejected  artifacts=sha256:bb  channel=github  detail=mallory is not a member of @platform  step=deploy
22:13:20  run.finished  shipped=sha256:cc  status=shipped
"
    );
}

#[test]
fn the_json_format_is_the_entries_as_stored() {
    let dir = workspace("json");
    let (code, stdout, stderr) = keepshipping(&dir, &[RUN, "--format", "json"]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout, GOLDEN, "the tool form is the stored bytes");
    // And it is JSON Lines: every line a self-contained object.
    for line in stdout.lines() {
        serde_json::from_str::<serde_json::Value>(line).expect("each line is json");
    }
}

/// No id means the most recent run, which is what a person typing `log` wants.
#[test]
fn with_no_run_id_the_latest_run_is_printed() {
    let dir = workspace("latest");
    let (code, stdout, stderr) = keepshipping(&dir, &[]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("run.finished"), "{stdout}");
}

/// The seed every sealed test signs with. Fixed, so a failure is a failure of the tool rather
/// than of a key that changed.
const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

/// `GOLDEN` in a working directory, signed: the seed file `KEEPSHIPPING_SIGNING_KEY` points at,
/// the public key `--key` is given, and the seal beside the log. Both key files are returned as
/// paths — the private one so a test can seal with the wrong one, the public so it can verify
/// with it.
fn sealed(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = workspace(name);
    let seed = key_file(&dir, "signing.key", SEED);
    let public = key_file(&dir, "signing.pub", &public_hex(SEED));
    let (code, _, stderr) =
        runs(&dir, &[("KEEPSHIPPING_SIGNING_KEY", seed.display().to_string())], &["seal", RUN]);
    assert_eq!(code, 0, "{name}: sealing must work: {stderr}");
    (dir, public)
}

/// A key file holding 64 hex characters.
fn key_file(dir: &Path, name: &str, hex: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, format!("{hex}\n")).expect("write a key");
    path
}

/// The public half of a seed, as the CLI writes it.
fn public_hex(seed: &str) -> String {
    let bytes = (0..32)
        .map(|at| u8::from_str_radix(&seed[at * 2..at * 2 + 2], 16).expect("hex"))
        .collect::<Vec<u8>>();
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    hex_of(&ed25519_dalek::SigningKey::from_bytes(&key).verifying_key().to_bytes())
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// One more entry, chained onto the log as a writer would: the chain holds, the seal does not
/// cover it.
fn append_after_sealing(dir: &Path) {
    let path = dir.join(".keepshipping/runs").join(format!("{RUN}.jsonl"));
    let text = std::fs::read_to_string(&path).expect("read");
    let last: serde_json::Value =
        serde_json::from_str(text.lines().last().expect("entries")).expect("json");
    let prev = last["hash"].as_str().expect("a hash");
    let seq = last["seq"].as_u64().expect("a seq") + 1;
    let body = format!(
        "{{\"at\":1700000000000,\"prev\":\"{prev}\",\"run\":\"{RUN}\",\"seq\":{seq},\"type\":\"approval.denied\"}}"
    );
    let hash = hex_of(&sha2::Sha256::digest(body.as_bytes()));
    let entry = body.replacen("\"prev\"", &format!("\"hash\":\"{hash}\",\"prev\""), 1);
    std::fs::write(&path, text + &entry + "\n").expect("append");
}

/// Without a seal, `verify` fails closed rather than passing: the chain cannot say whether the
/// end was cut off or rewritten.
#[test]
fn an_unsealed_log_is_refused_rather_than_passed() {
    let dir = workspace("unsealed");
    let (code, stdout, stderr) = keepshipping(&dir, &["verify", RUN]);
    assert_eq!(code, 1, "an unasserted log is not a verified one");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("not sealed: truncation and rewrite cannot be ruled out"), "{stderr}");
}

/// The acceptance criterion: a sealed, untouched log verifies and prints the story it tells.
#[test]
fn verify_passes_on_an_untouched_sealed_log() {
    let (dir, public) = sealed("verify-ok");
    let (code, stdout, stderr) =
        keepshipping(&dir, &["verify", RUN, "--key", &public.display().to_string()]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    assert!(stdout.starts_with(&format!("run {RUN}  9 entries")), "{stdout}");
    assert!(stdout.contains("proposed by  ci"), "{stdout}");
    assert!(stdout.contains("sealed at    seq 8 by key:ed25519:"), "{stdout}");
    assert!(stdout.contains("shipped      sha256:cc"), "{stdout}");
    assert!(stdout.contains("status       shipped"), "{stdout}");
}

/// Every way of changing a sealed log afterwards, and the line each is caught at. Three are the
/// chain's; the truncation and the append are the seal's, and are exactly what a chain cannot see.
#[test]
fn verify_names_the_line_of_every_tamper_with_a_sealed_log() {
    for (name, damage, expected) in [
        (
            "verify-edited",
            (|dir: &Path| {
                tamper(dir, |lines| lines[2] = lines[2].replace("\"ok\":true", "\"ok\":false"))
            }) as fn(&Path),
            ".jsonl:3: chain broken:",
        ),
        (
            "verify-removed",
            |dir: &Path| {
                tamper(dir, |lines| {
                    lines.remove(2);
                })
            },
            ".jsonl:3: chain broken:",
        ),
        (
            "verify-reordered",
            |dir: &Path| tamper(dir, |lines| lines.swap(1, 2)),
            ".jsonl:2: chain broken:",
        ),
        (
            "verify-truncated",
            |dir: &Path| tamper(dir, |lines| lines.truncate(3)),
            ".jsonl:4: entry missing — log truncated after seal",
        ),
        (
            "verify-appended",
            (|dir: &Path| append_after_sealing(dir)) as fn(&Path),
            ".jsonl:10: entry not covered by any seal (appended after sealing)",
        ),
    ] {
        let (dir, public) = sealed(name);
        damage(&dir);
        let (code, stdout, stderr) =
            keepshipping(&dir, &["verify", RUN, "--key", &public.display().to_string()]);
        assert_eq!(code, 1, "{name}: a changed log is a failure, not a clean run");
        assert!(stdout.is_empty(), "{name}: {stdout}");
        assert!(stderr.contains(expected), "{name}: {stderr}");
    }
}

/// The key is the point: another key's signature is not this log's, and a sealed log verified
/// with no key says which key it needs instead of checking nothing.
#[test]
fn the_wrong_key_is_a_failure_and_no_key_says_which_is_needed() {
    let (dir, _public) = sealed("wrong-key");
    let other = key_file(&dir, "other.pub", &public_hex(&"11".repeat(32)));
    let (code, stdout, stderr) =
        keepshipping(&dir, &["verify", RUN, "--key", &other.display().to_string()]);
    assert_eq!(code, 1, "{stdout}{stderr}");
    assert!(stderr.contains(".seals.jsonl:1: signature does not verify:"), "{stderr}");

    let (code, _, stderr) = keepshipping(&dir, &["verify", RUN]);
    assert_ne!(code, 0, "checking the signatures with nothing is not verifying");
    assert!(stderr.contains("this run is sealed by key:ed25519:"), "{stderr}");
    assert!(stderr.contains("pass --key <public-key-file>"), "{stderr}");
}

/// The two that are not about a log at all: sealing needs a key, and a digest names a registry
/// object rather than a run.
#[test]
fn sealing_needs_a_key_and_a_digest_is_not_a_run() {
    let dir = workspace("seal-no-key");
    let (code, stdout, stderr) = keepshipping(&dir, &["seal", RUN]);
    assert_eq!(code, 2, "{stdout}{stderr}");
    assert!(stderr.contains("KEEPSHIPPING_SIGNING_KEY"), "{stderr}");

    // Any digest reference, not only the one algorithm that happened to be handled first.
    for algo in ["sha256", "sha512"] {
        let digest = format!("registry.example/team/app@{algo}:{}", "cd".repeat(32));
        let (code, stdout, stderr) = keepshipping(&dir, &["verify", &digest]);
        assert_eq!(code, 2, "{algo}: {stdout}{stderr}");
        assert!(stderr.contains("registry adapter"), "{algo}: {stderr}");
    }
}

/// Printing a broken log is not a failure: the point is to read what happened.
#[test]
fn a_broken_log_still_prints() {
    let dir = workspace("print-broken");
    tamper(&dir, |lines| {
        lines[2] = lines[2].replace("\"ok\":true", "\"ok\":false");
    });
    let (code, stdout, _) = keepshipping(&dir, &[RUN]);
    assert_eq!(code, 0);
    assert!(stdout.contains("step.finished  duration_ms=1.2s  ok=false"), "{stdout}");
}

#[test]
fn anything_that_names_no_run_is_a_usage_error() {
    let dir = workspace("missing");
    for args in [
        vec!["01HQZZZZZZZZZZZZZZZZZZZZZZ"],
        vec!["verify", "01HQZZZZZZZZZZZZZZZZZZZZZZ"],
        // Not a ULID: it cannot name a file, so it must not be guessed at.
        vec!["nope"],
        vec!["verify", "a", "b"],
    ] {
        let (code, stdout, stderr) = keepshipping(&dir, &args);
        assert_eq!(code, 2, "{args:?}: {stdout}{stderr}");
        assert!(stdout.is_empty(), "{args:?}: {stdout}");
        assert!(stderr.starts_with("error:"), "{args:?}: {stderr}");
    }

    // And a directory holding no runs at all: still exit 2, but for the other reason.
    let empty = std::env::temp_dir().join(format!("keepshipping-log-{}-empty", std::process::id()));
    let _ = std::fs::remove_dir_all(&empty);
    std::fs::create_dir_all(&empty).expect("temp dir");
    let (code, stdout, stderr) = keepshipping(&empty, &[]);
    assert_eq!(code, 2);
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("no runs logged"), "{stderr}");
}
