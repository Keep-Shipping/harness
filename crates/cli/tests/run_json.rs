//! Golden snapshots of `run --format json`: the JSON Lines a run writes on
//! stdout, one object per line, with every human notice kept to stderr. Re-run
//! with `UPDATE_GOLDEN=1 cargo test -p ks-cli --test run_json` after reviewing
//! the diff; the contract the lines follow lives in `docs/CLI.md`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use ks_core::ports::run_context::{AGENT_TYPICAL_ENV, KNOWN_AGENT_MARKERS};

/// The fixture: an approval, an apply behind it, and the file's own policy
/// asking an agent about the apply before it runs. The run stops at that gate,
/// so nothing here is ever read — which is why the directory holds the one
/// file and nothing else.
const SITE: &str = "tests/fixtures/run_json";

/// On the default branch: a build the policy forbids an agent outright.
const ON_MAIN: &str = "\
name: api
steps:
  build: oci.image
    from: ./Dockerfile
policy:
  agents:
    never: build
";

/// The same file on a branch that widens the rule away — the copy that is
/// checked out, and so the copy `check` sees. Only the run folds the default
/// branch's half in, which is what makes this a run-time refusal (exit 5) and
/// not a check failure (exit 1).
const WIDENED: &str = "\
name: api
steps:
  build: oci.image
    from: ./Dockerfile
policy:
  agents:
    can: build
";

/// The run id a park mints is the wall clock and the process id, so the
/// goldens keep the literal `RUN` where one stood. It is the only field that
/// varies: nothing completes in either stream, so no `took_ms` is written.
const RUN: &str = "RUN";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(SITE)
}

/// The golden for `name`: re-run with `UPDATE_GOLDEN=1` after reviewing the
/// diff. The rules the bytes follow live in `docs/CLI.md`.
fn read_or_update(name: &str, actual: &str) -> String {
    let path = fixtures().join(name);
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        fs::create_dir_all(path.parent().expect("a directory")).expect("make the golden dir");
        fs::write(&path, actual).expect("write golden");
        return actual.to_string();
    }
    fs::read_to_string(path).unwrap_or_default()
}

/// A clean directory under `CARGO_TARGET_TMPDIR` holding `name` as `src`: the
/// run parks into the copy, never into the source tree a second run of the
/// suite would trip over.
fn work_dir(label: &str, name: &str, src: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(label);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the work directory can be created");
    fs::write(dir.join(name), src).expect("write the site file");
    dir
}

/// The id of the one run parked under `dir`, as `runs pending` finds it: the
/// newest directory under `.keepshipping/runs/`. Only directories count — a
/// parked run's log file, once it has one, sits beside the record.
fn the_parked_run(dir: &Path) -> String {
    let runs = dir.join(".keepshipping/runs");
    std::fs::read_dir(&runs)
        .expect("the run wrote itself down")
        .filter_map(Result::ok)
        .find(|entry| entry.path().is_dir())
        .expect("exactly one parked run")
        .file_name()
        .to_string_lossy()
        .into_owned()
}

/// Runs the binary in `dir` as a person on a laptop: no CI, none of the
/// markers that make a bare invocation look agent-shaped, and no base the
/// machine could name — each test says which actor and which default branch it
/// means. The CI markers are cleared because a suite run on a runner must not
/// answer for a test that means to be a laptop (#305), the agent markers and
/// the agent-typical variables because `--as` is the only declaration these
/// runs make, and the `GIT_*` variables because they would point the binary at
/// the checkout the suite itself runs in.
fn keepshipping(dir: &Path, args: &[&str], vars: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_keepshipping"));
    cmd.args(args).current_dir(dir).env_remove("CI").env_remove("GITHUB_ACTIONS");
    for name in [
        "GITHUB_EVENT_NAME",
        "GITHUB_HEAD_REPOSITORY",
        "GITHUB_REPOSITORY",
        "GITLAB_CI",
        "CI_PIPELINE_SOURCE",
        "CI_MERGE_REQUEST_SOURCE_PROJECT_ID",
        "CI_MERGE_REQUEST_PROJECT_ID",
        "BUILDKITE",
        "BUILDKITE_BRANCH",
        "BUILDKITE_TAG",
        "CIRCLECI",
        "CIRCLE_BRANCH",
        "CIRCLE_TAG",
        "JENKINS_URL",
        "GIT_BRANCH",
        "KEEP_SHIPPING_TRUSTED_BRANCHES",
        "GITHUB_BASE_REF",
        "KEEPSHIPPING_BASE",
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_COMMON_DIR",
        "KEEPSHIPPING_REQUIRE_HUMAN",
        "KEEPSHIPPING_AGENTS",
    ] {
        cmd.env_remove(name);
    }
    for marker in KNOWN_AGENT_MARKERS {
        cmd.env_remove(marker);
    }
    for (name, _) in AGENT_TYPICAL_ENV {
        cmd.env_remove(*name);
    }
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

/// A repository under `CARGO_TARGET_TMPDIR` holding two commits: `main` with
/// `main`'s copy of the file, and a branch named `widen` with `branch`'s —
/// checked out, so the work tree is the branch and the run below runs the
/// widened policy against the default branch's refusal. The repository's git
/// directory is a sibling of the work tree, the way `base_policy.rs` stands
/// its own repositories up.
struct Repo {
    root: PathBuf,
}

impl Repo {
    fn build(label: &str, main: &str, branch: &str) -> Repo {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("run-json-{label}"));
        let _ = std::fs::remove_dir_all(&dir);
        let root = dir.join("repo");
        std::fs::create_dir_all(&root).expect("the work tree");
        let repo = Repo { root };
        repo.git(&[
            "init",
            "-b",
            "main",
            "-q",
            "--template=",
            "--separate-git-dir",
            dir.join("gitdata").to_str().expect("a path git can read"),
        ]);
        repo.write(main);
        repo.commit("on main");
        repo.git(&["checkout", "-q", "-b", "widen"]);
        repo.write(branch);
        repo.commit("widened");
        repo
    }

    /// Puts the site file where the run below reads it.
    fn write(&self, src: &str) {
        fs::write(self.root.join("ship.ks"), src).expect("write the site file");
    }

    fn git(&self, args: &[&str]) {
        let out = Command::new("git")
            .args(args)
            .current_dir(&self.root)
            // This process may be standing in a checkout that exported them,
            // and a child git that inherits them writes into that repository
            // instead of this one; a machine's own config may sign commits,
            // which needs a key this test has no business reaching for.
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .env_remove("GIT_COMMON_DIR")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("run git");
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    }

    fn commit(&self, message: &str) {
        self.git(&["add", "-A"]);
        self.git(&["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", message]);
    }
}

/// The facts every line of both streams must agree to, so a stray
/// `UPDATE_GOLDEN` cannot redefine the schema: one object per line, of
/// version 1, naming its event.
fn assert_schema_v1(stdout: &str) {
    for line in stdout.lines() {
        let value: serde_json::Value =
            serde_json::from_str(line).expect("each line is one JSON object");
        assert_eq!(value["version"], 1, "{line}");
        assert!(value.get("event").is_some(), "{line}");
    }
}

/// A run whose policy asks about the apply before it parks there: the opening
/// line, and the closing line that says what the exit code says, with the run
/// id the record was written under.
#[test]
fn run_parking_emits_the_documented_json_events() {
    let ship = fs::read_to_string(fixtures().join("ship.ks")).expect("the committed fixture");
    let dir = work_dir("run-json-parked", "ship.ks", &ship);
    let (code, stdout, stderr) =
        keepshipping(&dir, &["run", "--as", "agent", "--format", "json"], &[]);
    assert_eq!(code, 4, "{stdout}{stderr}");

    // Not just the golden: the shape the docs promise, so a stray
    // UPDATE_GOLDEN cannot redefine it.
    assert_schema_v1(&stdout);
    assert!(stdout.starts_with("{\"version\":1,\"event\":\"run_started\""), "{stdout}");
    let last = stdout.lines().last().expect("a closing line");
    assert!(
        last.contains("\"event\":\"run_finished\"")
            && last.contains("\"status\":\"waiting_for_approval\""),
        "{stdout}"
    );

    let run = the_parked_run(&dir);
    let actual = stdout.replace(&run, RUN);
    assert_eq!(actual, read_or_update("parked.jsonl", &actual));

    // The notices a person reads are not in the stream: stderr keeps them,
    // and it names the same run the last line does.
    assert!(stderr.contains("waiting at apply"), "{stderr}");
    assert!(stderr.contains(&format!("keepshipping approve {run}")), "{stderr}");
    assert!(!stdout.contains("parked at"), "{stdout}");
}

/// A run the default branch's policy refuses before anything runs: the opening
/// line, then the refusal as the closing line, exit 5 and all — and no park,
/// because there is no run to carry on.
#[test]
fn run_refused_by_policy_emits_a_final_line() {
    let repo = Repo::build("refused", ON_MAIN, WIDENED);
    let (code, stdout, stderr) = keepshipping(
        &repo.root,
        &["run", "--base", "main", "--as", "agent", "--format", "json"],
        &[],
    );
    assert_eq!(code, 5, "{stdout}{stderr}");

    assert_schema_v1(&stdout);
    assert!(stdout.starts_with("{\"version\":1,\"event\":\"run_started\""), "{stdout}");
    let last = stdout.lines().last().expect("a closing line");
    assert!(
        last.contains("\"status\":\"policy_refused\"") && last.contains("\"exit\":5"),
        "{stdout}"
    );

    // The whole stream: the opening line and the refusal, nothing else —
    // the run never started, so no step and no environment line ran either.
    assert_eq!(stdout.lines().count(), 2, "{stdout}");
    assert_eq!(stdout, read_or_update("refused.jsonl", &stdout));

    // The refusal itself is a person's to read, and stays on stderr.
    assert!(stderr.contains("refusing to start: step `build`"), "{stderr}");
    assert!(stderr.contains("never allowed for agent (default branch)"), "{stderr}");
}
