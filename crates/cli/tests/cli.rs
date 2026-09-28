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
    assert!(stderr.contains("expected oci.Digest, got string"), "{stderr}");
    assert!(
        stderr.contains("hint: use build.digest so prod runs exactly the image you built"),
        "{stderr}"
    );
}

/// Needs a secret the policy forbids agents to read: an agent run must be
/// refused before anything starts.
const AGENT_SECRET: &str = "\
name: gated
envs:
  prod:
    ci-only: true
steps:
  migrate: db.migrate
    url: secrets.db_url
policy:
  agents:
    never: read secrets
";

/// Two environments, only one with a resolver: the listing names the
/// reference for one and flags the missing resolver for the other.
const SECRET_LISTING: &str = "\
name: listed
envs:
  staging:
    secrets: vault
  prod:
    ci-only: true
steps:
  migrate: db.migrate
    url: secrets.db_url
  report: db.report
    key: secrets.db_url
";

#[test]
fn check_secrets_lists_each_environments_references_without_touching_a_store() {
    // The guarantee is structural: the listing is a pure projection of the
    // checked file (`ks_core::secret_requirements`), so this command has no
    // resolver to construct and no store to read — parsing and checking
    // never touch I/O.
    let path = temp_site("listed.ks", SECRET_LISTING);
    let (code, stdout, stderr) = keepshipping(&path, &["check", "--secrets"]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("staging: vault:db_url (migrate, report)"), "{stdout}");
    assert!(stdout.contains("prod: db_url (migrate, report) [no `secrets:` resolver]"), "{stdout}");
    assert!(stdout.contains("ok (2 steps)"), "{stdout}");
}

#[test]
fn check_secrets_says_none_when_nothing_is_needed() {
    let path = temp_site("hero-secrets.ks", HERO);
    let (code, stdout, stderr) = keepshipping(&path, &["check", "--secrets"]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("default: (none)"), "{stdout}");
}

/// `--secrets` is a `check` flag: `run` rejects it as unknown, and `check`
/// still exits 1 on errors even with the listing printed.
#[test]
fn run_rejects_secrets_and_check_prints_the_listing_despite_errors() {
    let path = temp_site("run-secrets.ks", SECRET_LISTING);
    let (code, stdout, stderr) = keepshipping(&path, &["run", "--secrets"]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 2);
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("usage: keepshipping"), "{stderr}");

    let path = temp_site("gated-secrets.ks", AGENT_SECRET);
    let (code, stdout, stderr) = keepshipping(&path, &["check", "--secrets", "--actor", "agent"]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 1, "errors still fail the check: {stderr}");
    assert!(stderr.contains("policy forbids agents from reading secrets"), "{stderr}");
    assert!(
        stdout.contains("prod: db_url (migrate) [no `secrets:` resolver]"),
        "the listing is printed anyway: {stdout}"
    );
    assert!(!stdout.contains("ok"), "{stdout}");
}

#[test]
fn check_actor_agent_refuses_secrets_the_policy_forbids() {
    let path = temp_site("gated.ks", AGENT_SECRET);
    let (code, _, stderr) = keepshipping(&path, &["check", "--actor", "agent"]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 1);
    assert!(
        stderr.contains(
            "error: policy forbids agents from reading secrets, but this run needs secrets.db_url"
        ),
        "{stderr}"
    );
    assert!(stderr.contains("hint: the rule is `policy: agents: never: read secrets`"), "{stderr}");

    // The same file is fine for a human, the default actor.
    let path = temp_site("gated.ks", AGENT_SECRET);
    let (code, stdout, stderr) = keepshipping(&path, &["check"]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("ok (1 steps)"), "{stdout}");

    // An unknown actor is a usage error.
    let path = temp_site("gated.ks", AGENT_SECRET);
    let (code, _, stderr) = keepshipping(&path, &["check", "--actor", "robot"]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 2);
    assert!(stderr.contains("usage: keepshipping"), "{stderr}");
}

#[test]
fn run_actor_agent_refuses_before_anything_starts() {
    let path = temp_site("gated-run.ks", AGENT_SECRET);
    let (code, stdout, stderr) = keepshipping(&path, &["run", "--env", "prod", "--actor", "agent"]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 1, "{stdout}");
    assert!(stderr.contains("policy forbids agents from reading secrets"), "{stderr}");
    assert!(!stdout.contains("environment:"), "nothing runs: {stdout}");
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
