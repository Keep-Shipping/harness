//! End-to-end tests of the `keepshipping` binary: output formats, exit
//! codes and the `--all` walk. The byte-exact output snapshots live in
//! `snapshots.rs`; here it is the behaviour that must hold for any file.

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

/// The one warning-only mistake: a digest pasted by value. No error, so the
/// check passes — until `--warnings-as-errors`.
const WARNED: &str = concat!(
    "steps:\n",
    "  build: oci.image\n",
    "    from: ./Dockerfile\n",
    "  deploy: k8s.rollout\n",
    "    image: \"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"\n",
);

/// A step declared twice: the second declaration carries a secondary label
/// pointing at the first.
const DUP: &str = "\
name: dup
steps:
  build: oci.image
    from: ./Dockerfile
  build: oci.image
    from: ./Dockerfile
";

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

/// Write a temp site file; the caller runs the binary against it and the
/// path is removed after the command returns.
fn temp_site(name: &str, src: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("keepshipping-cli-{}-{name}", std::process::id()));
    std::fs::write(&path, src).expect("write temp site file");
    path
}

fn keepshipping(args: &[&str]) -> (i32, String, String) {
    run_in(None, args)
}

/// Runs the binary from `dir` when given, else from the crate root.
fn run_in(dir: Option<&std::path::Path>, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_keepshipping"));
    cmd.args(args);
    // These tests assert exact output, and the suite itself may be running
    // on CI — where a header-less file gains an advisory warning it would
    // not have anywhere else. The environment under test is the one these
    // tests describe, not the one they happen to run in.
    cmd.env_remove("CI");
    if let Some(dir) = dir {
        cmd.current_dir(dir);
    }
    let out = cmd.output().expect("run keepshipping");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn check_reports_a_clean_file_and_promises_nothing_ran() {
    let path = temp_site("hero.ks", HERO);
    let (code, stdout, stderr) = keepshipping(&["check", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 0, "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    assert_eq!(stdout, format!("✓ {}\n0 steps ran. Nothing was touched.\n", path.display()));
}

#[test]
fn check_prints_diagnostics_to_stdout_and_exits_1() {
    let path = temp_site("broken.ks", BROKEN);
    let (code, stdout, stderr) = keepshipping(&["check", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 1);
    assert!(stderr.is_empty(), "{stderr}");
    assert!(stdout.contains(&format!("✗ {}:6  deploy.image", path.display())), "{stdout}");
    assert!(stdout.contains("expected oci.Digest, got string"), "{stdout}");
    assert!(stdout.contains("hint: use build.digest so prod runs"), "{stdout}");
    assert!(stdout.ends_with("0 steps ran. Nothing was touched.\n"), "{stdout}");
}

#[test]
fn a_warning_passes_until_warnings_as_errors() {
    let path = temp_site("warned.ks", WARNED);
    let (code, stdout, stderr) = keepshipping(&["check", path.to_str().unwrap()]);
    assert_eq!(code, 0, "warnings alone still pass: {stderr}");
    assert!(stdout.contains("⚠"), "{stdout}");
    assert!(!stdout.contains("✗"), "{stdout}");

    let (code, stdout, stderr) =
        keepshipping(&["check", "--warnings-as-errors", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 1, "{stderr}");
    assert!(stdout.contains("⚠"), "the warning still renders as a warning: {stdout}");
}

#[test]
fn a_secondary_label_points_at_the_first_definition() {
    let path = temp_site("dup.ks", DUP);
    let (code, stdout, stderr) = keepshipping(&["check", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 1, "{stderr}");
    assert!(stdout.contains("duplicate step `build`"), "{stdout}");
    assert!(stdout.contains("----- first defined here"), "{stdout}");
}

#[test]
fn json_format_carries_exact_positions() {
    // Several diagnostics on different lines: every position must be right
    // (the CLI used to rescan the file per diagnostic).
    let path = temp_site("misplaced.ks", MISPLACED);
    let (code, stdout, stderr) =
        keepshipping(&["check", "--format", "json", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 1);
    assert!(stderr.is_empty(), "{stderr}");
    // `nope.digest` starts at line 4, column 12; `5` at line 7, column 11.
    let positions: Vec<(usize, usize)> = stdout.lines().map(position).collect();
    assert_eq!(positions, vec![(4, 12), (7, 11)], "{stdout}");
}

/// The `"line":L,"column":C` of a v1 JSON diagnostic line: the stable key
/// order makes a scan enough.
fn position(json: &str) -> (usize, usize) {
    let rest = &json[json.find("\"line\":").expect("span line") + 7..];
    let line: usize = rest[..rest.find(',').expect("line ends")].parse().expect("line number");
    let rest = &rest[rest.find("\"column\":").expect("span column") + 9..];
    let column: usize =
        rest[..rest.find([',', '}']).expect("column ends")].parse().expect("column");
    (line, column)
}

#[test]
fn no_colour_reaches_the_output_without_a_terminal() {
    let path = temp_site("plain.ks", BROKEN);
    let (code, stdout, stderr) =
        keepshipping(&["check", "--format", "github", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 1, "{stderr}");
    assert!(!stdout.contains('\x1b'), "{stdout}");

    let path = temp_site("plain.ks", BROKEN);
    let out = Command::new(env!("CARGO_BIN_EXE_keepshipping"))
        .args(["check", path.to_str().unwrap()])
        .env("NO_COLOR", "1")
        .output()
        .expect("run keepshipping");
    let _ = std::fs::remove_file(&path);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains('\x1b'), "{stdout}");
}

#[test]
fn missing_files_and_bad_flags_are_usage_errors() {
    // An explicit path that does not exist.
    let (code, stdout, stderr) = keepshipping(&["check", "no/such/file.ks"]);
    assert_eq!(code, 2);
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("no such file"), "{stderr}");

    // No default ship.ks in the working directory either.
    let empty = std::env::temp_dir().join(format!("keepshipping-empty-{}", std::process::id()));
    std::fs::create_dir_all(&empty).expect("create temp dir");
    let (code, _, stderr) = run_in(Some(&empty), &["check"]);
    let _ = std::fs::remove_dir(&empty);
    assert_eq!(code, 2);
    assert!(stderr.contains("no ship.ks in the current directory"), "{stderr}");

    // An unknown format, and a check-only flag on run.
    let (code, _, stderr) = keepshipping(&["check", "--format", "xml"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("usage: keepshipping"), "{stderr}");
    let (code, _, stderr) = keepshipping(&["run", "--format", "json"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("usage: keepshipping"), "{stderr}");
}

#[test]
fn a_second_file_argument_is_a_usage_error_not_a_second_file() {
    let (code, _, stderr) = keepshipping(&["check", "a.ks", "b.ks"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("usage: keepshipping"), "{stderr}");
    let (code, _, stderr) = keepshipping(&["check", "--all", "a", "b"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("usage: keepshipping"), "{stderr}");
}

#[test]
fn unreadable_files_are_usage_errors_too() {
    // A directory is not a site file.
    let dir = std::env::temp_dir().join(format!("keepshipping-dir-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let (code, _, stderr) = keepshipping(&["check", dir.to_str().unwrap()]);
    let _ = std::fs::remove_dir(&dir);
    assert_eq!(code, 2);
    assert!(stderr.contains("is a directory"), "{stderr}");

    // Nor is a file that is not UTF-8.
    let path = std::env::temp_dir().join(format!("keepshipping-bin-{}.ks", std::process::id()));
    std::fs::write(&path, [0xff, 0xfe]).expect("write temp bytes");
    let (code, _, stderr) = keepshipping(&["check", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 2);
    assert!(stderr.contains("is not valid UTF-8"), "{stderr}");
}

#[test]
fn all_checks_every_ship_ks_and_prints_paths_relative_to_the_root() {
    // From the fixture root itself, no path argument.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/monorepo");
    let (code, stdout, stderr) = run_in(Some(&dir), &["check", "--all"]);
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    assert!(stdout.contains("✓ api/ship.ks\n"), "{stdout}");
    assert!(stdout.contains("✗ web/ship.ks:7"), "{stdout}");
    assert_eq!(
        stdout.matches("0 steps ran. Nothing was touched.").count(),
        1,
        "the footer is printed once: {stdout}"
    );

    // Or from anywhere, naming the tree: the same relative paths.
    let (code, stdout, stderr) = keepshipping(&["check", "--all", dir.to_str().unwrap()]);
    assert_eq!(code, 1, "{stderr}");
    assert!(stdout.contains("✓ api/ship.ks\n"), "{stdout}");
    assert!(stdout.contains("✗ web/ship.ks:7"), "{stdout}");

    // A tree without any ship.ks is a usage error, not a silent pass.
    let empty = std::env::temp_dir().join(format!("keepshipping-bare-{}", std::process::id()));
    std::fs::create_dir_all(&empty).expect("create temp dir");
    let (code, _, stderr) = run_in(Some(&empty), &["check", "--all"]);
    let _ = std::fs::remove_dir(&empty);
    assert_eq!(code, 2);
    assert!(stderr.contains("no ship.ks under"), "{stderr}");
}

#[test]
fn check_secrets_lists_each_environments_references_without_touching_a_store() {
    // The guarantee is structural: the listing is a pure projection of the
    // checked file (`ks_core::secret_requirements`), so this command has no
    // resolver to construct and no store to read — parsing and checking
    // never touch I/O.
    let path = temp_site("listed.ks", SECRET_LISTING);
    let (code, stdout, stderr) = keepshipping(&["check", "--secrets", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("✓"), "{stdout}");
    assert!(stdout.contains("staging: vault:db_url (migrate, report)"), "{stdout}");
    assert!(stdout.contains("prod: db_url (migrate, report) [no `secrets:` resolver]"), "{stdout}");
}

#[test]
fn check_secrets_says_none_when_nothing_is_needed() {
    let path = temp_site("hero-secrets.ks", HERO);
    let (code, stdout, stderr) = keepshipping(&["check", "--secrets", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("default: (none)"), "{stdout}");
}

/// `--secrets` is a `check` flag, and its listing is written for people: an
/// argument in a machine format refuses the combination instead of
/// corrupting the stream.
#[test]
fn run_rejects_secrets_and_the_listing_refuses_machine_formats() {
    let path = temp_site("run-secrets.ks", SECRET_LISTING);
    let (code, stdout, stderr) = keepshipping(&["run", "--secrets"]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 2);
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("usage: keepshipping"), "{stderr}");

    let path = temp_site("listed.ks", SECRET_LISTING);
    let (code, stdout, stderr) =
        keepshipping(&["check", "--secrets", "--format", "json", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 2);
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("--secrets prints a listing for people"), "{stderr}");
}

#[test]
fn check_actor_agent_refuses_secrets_the_policy_forbids() {
    let path = temp_site("gated.ks", AGENT_SECRET);
    let (code, stdout, stderr) =
        keepshipping(&["check", "--actor", "agent", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 1);
    assert!(stderr.is_empty(), "{stderr}");
    assert!(
        stdout.contains(
            "policy forbids agents from reading secrets, but this run needs secrets.db_url"
        ),
        "{stdout}"
    );
    assert!(stdout.contains("hint: the rule is `policy: agents:"), "{stdout}");
    assert!(stdout.contains("never: read secrets`"), "{stdout}");

    // The same file is fine for a human, the default actor.
    let path = temp_site("gated.ks", AGENT_SECRET);
    let (code, stdout, stderr) = keepshipping(&["check", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.starts_with("✓ "), "{stdout}");

    // An unknown actor is a usage error.
    let path = temp_site("gated.ks", AGENT_SECRET);
    let (code, _, stderr) = keepshipping(&["check", "--actor", "robot", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 2);
    assert!(stderr.contains("usage: keepshipping"), "{stderr}");
}

#[test]
fn run_actor_agent_refuses_before_anything_starts() {
    let path = temp_site("gated-run.ks", AGENT_SECRET);
    let (code, stdout, _) =
        keepshipping(&["run", "--env", "prod", "--actor", "agent", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 1, "{stdout}");
    assert!(stdout.contains("policy forbids agents from reading secrets"), "{stdout}");
    assert!(!stdout.contains("environment:"), "nothing runs: {stdout}");
}

#[test]
fn run_without_a_choice_fails_non_interactively() {
    let path = temp_site("ambiguous.ks", TWO_ENVS);
    let (code, _, stderr) = keepshipping(&["run", path.to_str().unwrap()]);
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
    let (code, stdout, stderr) = keepshipping(&["run", "--env", "prod", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("environment: prod"), "{stdout}");
    assert!(stdout.contains("not implemented yet"), "{stdout}");
}

#[test]
fn run_rejects_an_unknown_env_with_did_you_mean() {
    let path = temp_site("wrong-env.ks", TWO_ENVS);
    let (code, _, stderr) = keepshipping(&["run", "--env", "prodd", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("unknown environment `prodd`"), "{stderr}");
}

#[test]
fn a_flag_where_a_value_belongs_is_a_usage_error() {
    let path = temp_site("flag-value.ks", TWO_ENVS);
    let (code, _, stderr) =
        keepshipping(&["run", "--env", "--non-interactive", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 2);
    assert!(stderr.contains("usage: keepshipping"), "{stderr}");
}
