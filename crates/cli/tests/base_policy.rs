//! What the default branch's `policy:` block does to a run
//! ([#118](https://github.com/Keep-Shipping/harness/issues/118)): the block a
//! branch ships is a proposal, and the run decides against the block the
//! default branch has. These tests stand a real repository up under
//! `CARGO_TARGET_TMPDIR`, widen the policy on a branch, and read the binary's
//! answer — the run that parks, the run that refuses, the table `explain`
//! prints, and the ref `--base` will not accept.
//!
//! The repository's git directory is a sibling of the work tree rather than
//! the work tree's own `.git`: the tests run inside a checkout of this
//! harness, and a git that writes into the directory it is standing in is a
//! git that rewrites somebody else's history.

use std::path::{Path, PathBuf};
use std::process::Command;

use ks_core::ports::run_context::{AGENT_TYPICAL_ENV, KNOWN_AGENT_MARKERS};

/// On the default branch: an apply an agent has to ask about, a secrets read
/// it may not do at all, and no `approval` step anywhere.
const ON_MAIN: &str = "\
name: api
envs:
  staging:
    secrets: staging
steps:
  plan:  tofu.plan
    dir:  ./infra
  apply: tofu.apply
    plan: plan.file
policy:
  agents:
    before: apply
    never: read secrets
";

/// The same file on a branch that widens: the apply is allowed outright and
/// the `never: read secrets` is gone. Everything else is untouched.
const WIDENED: &str = "\
name: api
envs:
  staging:
    secrets: staging
steps:
  plan:  tofu.plan
    dir:  ./infra
  apply: tofu.apply
    plan: plan.file
policy:
  agents:
    can: apply
";

/// A repository under `CARGO_TARGET_TMPDIR` holding two commits: `main` with
/// `main`'s copy of the file, and a branch named `widen` with `branch`'s —
/// checked out, so the work tree is the branch and the runs below are runs of
/// a widened policy.
struct Repo {
    root: PathBuf,
    git_dir: PathBuf,
}

impl Repo {
    fn build(label: &str, main: &str, branch: &str) -> Repo {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("base-policy-{label}"));
        let _ = std::fs::remove_dir_all(&dir);
        let repo = Repo { root: dir.join("repo"), git_dir: dir.join("gitdata") };
        std::fs::create_dir_all(repo.root.join("services/api/infra")).expect("the work tree");
        repo.init();
        repo.write(main);
        repo.commit("on main");
        repo.git(&["checkout", "-q", "-b", "widen"]);
        repo.write(branch);
        repo.commit("widened");
        repo
    }

    /// Puts a site file where the runs below will read it: a directory below
    /// the repository's root, so the `./`-relative read out of git is
    /// exercised rather than assumed.
    fn write(&self, src: &str) {
        let site = self.root.join("services/api");
        std::fs::create_dir_all(site.join("infra")).expect("the work tree");
        std::fs::write(site.join("ship.ks"), src).expect("write the site file");
        std::fs::write(site.join("infra/main.tf"), "output \"x\" { value = \"1\" }\n")
            .expect("write the terraform the plan step reads");
        // The script step a case about secrets needs, declaring an `action:`
        // so the run is not turned away for running a script with no action.
        std::fs::create_dir_all(site.join("ship")).expect("the script directory");
        std::fs::write(site.join("ship/migrate.ts"), "// migrate\n").expect("write the script");
    }

    fn init(&self) {
        let git_dir = self.git_dir.to_str().expect("a path git can read");
        self.git(&["init", "-b", "main", "-q", "--template=", "--separate-git-dir", git_dir]);
    }

    /// One git command in this repository. Every one of them runs with the
    /// `GIT_*` variables removed: this process may be standing in a checkout
    /// that exported them, and a child git that inherits them writes into that
    /// repository instead of this one.
    fn git(&self, args: &[&str]) {
        let out = Command::new("git")
            .args(args)
            .current_dir(&self.root)
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .env_remove("GIT_COMMON_DIR")
            // A machine's own git config may sign its commits, which needs a
            // key this test has no business reaching for and which would make
            // `commit` fail for reasons that have nothing to do with policy.
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

    /// The binary over this repository, in an environment that is nobody in
    /// particular: no CI, none of the markers that make a bare invocation look
    /// agent-shaped, and no base ref of its own — each test says which actor
    /// and which default branch it means.
    fn keepshipping(&self, args: &[&str]) -> (i32, String, String) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_keepshipping"));
        cmd.args(args).current_dir(&self.root).env_remove("CI").env_remove("GITHUB_ACTIONS");
        // The markers the resume's CI dispatch reads next, and the one variable
        // that can make a generic run's branch the repository's own: a suite run
        // on a GitLab runner, on Buildkite or on Jenkins must not answer for a
        // test that means to be a laptop, and an operator's exported
        // `KEEP_SHIPPING_TRUSTED_BRANCHES` must not decide what a test is about
        // (#305).
        for marker in
            ["GITLAB_CI", "BUILDKITE", "CIRCLECI", "JENKINS_URL", "KEEP_SHIPPING_TRUSTED_BRANCHES"]
        {
            cmd.env_remove(marker);
        }
        for marker in KNOWN_AGENT_MARKERS {
            cmd.env_remove(marker);
        }
        for (name, _) in AGENT_TYPICAL_ENV {
            cmd.env_remove(*name);
        }
        // Every way this machine can name a base is cleared, so each test says
        // which base it means rather than inheriting the machine's. The
        // `GIT_*` variables matter for the same reason: they would make the
        // binary read the repository the test is standing in.
        for name in [
            "GITHUB_BASE_REF",
            "KEEPSHIPPING_BASE",
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_COMMON_DIR",
        ] {
            cmd.env_remove(name);
        }
        let out = cmd.output().expect("run keepshipping");
        (
            out.status.code().expect("an exit code"),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    /// The id of the one run parked here, as `runs pending` prints it.
    fn run_id(&self) -> String {
        let (code, stdout, stderr) = self.keepshipping(&["runs", "pending"]);
        assert_eq!(code, 0, "{stdout}{stderr}");
        stdout.split_whitespace().next().expect("a parked run").to_string()
    }

    /// The one parked record's state, read the way `keepshipping runs pending`
    /// finds it. The run's log (`<run>.jsonl`) sits beside the record's
    /// directory once an approval is appended to it, so only directories count.
    fn parked(&self) -> serde_json::Value {
        let runs = self.root.join(".keepshipping/runs");
        let run = std::fs::read_dir(&runs)
            .expect("a run wrote itself down")
            .filter_map(Result::ok)
            .find(|entry| entry.path().is_dir())
            .expect("exactly one parked run")
            .path();
        let bytes = std::fs::read(run.join("state.json")).expect("the parked record");
        serde_json::from_slice(&bytes).expect("the record is JSON")
    }
}

#[test]
fn a_run_over_a_widened_policy_parks_where_the_default_branch_asks() {
    let repo = Repo::build("park", ON_MAIN, WIDENED);
    let (code, stdout, stderr) =
        repo.keepshipping(&["run", "services/api/ship.ks", "--as", "agent", "--base", "main"]);
    assert_eq!(code, 4, "{stdout}{stderr}");
    // It says which step, and names the default branch as the authority: the
    // branch's own `can: apply` is what the wait is *not* resting on.
    assert!(stderr.contains("waiting at apply"), "{stderr}");
    assert!(stderr.contains("`apply` is asked about for agent (default branch)"), "{stderr}");
    assert!(stderr.contains("keepshipping approve"), "{stderr}");
    // Nothing ran: the gate is before the first step, not after the last.
    let state = repo.parked();
    assert_eq!(state["next"], serde_json::json!("apply"), "{state}");
    assert_eq!(state["context"]["policy_gate"], serde_json::json!("apply"), "{state}");
    assert_eq!(state["context"]["waiting_on"], serde_json::json!("agent"), "{state}");
    assert!(state["completed"].as_array().expect("completed").is_empty(), "{state}");
}

#[test]
fn the_same_run_parks_against_a_base_it_finds_for_itself() {
    // The same run without `--base`. Nothing here names a base, so the
    // resolver reads `main` out of the repository and the gate is the same
    // gate — the flag is a way to be explicit, not a way to be the only
    // caller who knows.
    let repo = Repo::build("auto", ON_MAIN, WIDENED);
    let (code, _, stderr) = repo.keepshipping(&["run", "services/api/ship.ks", "--as", "agent"]);
    assert_eq!(code, 4, "{stderr}");
    assert!(stderr.contains("waiting at apply"), "{stderr}");
}

#[test]
fn a_widened_rule_is_reported_as_an_ask_the_branch_did_not_ask() {
    let repo = Repo::build("explain", ON_MAIN, WIDENED);
    let (code, stdout, stderr) = repo.keepshipping(&[
        "policy",
        "explain",
        "services/api/ship.ks",
        "--as",
        "agent",
        "--base",
        "main",
    ]);
    assert_eq!(code, 0, "{stderr}");
    // The header says which document the run would fold this one against.
    assert!(
        stdout
            .lines()
            .any(|l| l.starts_with("default branch main: this file may narrow its policy")),
        "{stdout}"
    );
    // The branch says `can: apply`; the answer is an ask, and the source is
    // the default branch rather than the file.
    let apply = stdout.lines().find(|l| l.starts_with("apply ")).expect("an apply row");
    assert!(apply.contains("ask"), "{apply}");
    assert!(apply.contains("default branch"), "{apply}");
    // The rule is written on another file, so there is no line of this one to
    // point at: a span into the default branch's bytes would be a lie here.
    assert!(!apply.contains("ship.ks:"), "{apply}");
    // A step neither document has a rule about is still the leash's default,
    // so folding the two in did not invent an authority for it.
    let plan = stdout.lines().find(|l| l.starts_with("plan ")).expect("a plan row");
    assert!(plan.trim_end().ends_with("default"), "{plan}");
}

#[test]
fn deleting_a_never_rule_from_the_default_branch_is_refused() {
    // A step that reads a secret and applies. The branch's file allows both;
    // the default branch's file refuses the read, and the refusal is the one
    // the run answers with.
    let branch = WIDENED.replace(
        "  apply: tofu.apply\n    plan: plan.file\n",
        "  apply: tofu.apply\n    plan: plan.file\n  migrate: ./ship/migrate.ts\n    url: secrets.db_url\n    action: apply\n",
    );
    let repo = Repo::build("never", ON_MAIN, &branch);
    let (code, stdout, stderr) =
        repo.keepshipping(&["run", "services/api/ship.ks", "--as", "agent", "--base", "main"]);
    assert_eq!(code, 5, "{stdout}{stderr}");
    assert!(stderr.contains("refusing to start: step `migrate`"), "{stderr}");
    assert!(
        stderr.contains("`read secrets` is never allowed for agent (default branch)"),
        "{stderr}"
    );
    // Refused before anything ran: no environment line, no parked record.
    assert!(!stdout.contains("environment:"), "{stdout}");
    assert!(!repo.root.join(".keepshipping/runs").exists(), "nothing was parked");
}

#[test]
fn a_base_that_does_not_name_a_commit_is_a_usage_error() {
    let repo = Repo::build("nosuchref", ON_MAIN, WIDENED);
    let (code, stdout, stderr) =
        repo.keepshipping(&["policy", "explain", "services/api/ship.ks", "--base", "nosuchref"]);
    assert_eq!(code, 2, "{stdout}{stderr}");
    assert!(stderr.contains("`nosuchref` does not name a commit here"), "{stderr}");
    // An auto-detected base that is not there is not an error — that is the
    // ordinary case of a repository with no remote — so only a ref somebody
    // named out loud is held to it.
    assert!(!stdout.contains("step  "), "no table was printed: {stdout}");
}

#[test]
fn a_branch_may_still_narrow_what_the_default_branch_allows() {
    // `can: plan` on the default branch, `before: plan` on the branch. The
    // branch's own rule is stricter, so it wins — and because it is the
    // file's rule rather than the leash's, the run parks on it.
    let main = "\
name: api
envs:
  staging:
    secrets: staging
steps:
  plan: tofu.plan
    dir: ./infra
policy:
  agents:
    can: plan
";
    let narrowed = main.replace("    can: plan", "    before: plan");
    let repo = Repo::build("narrow", main, &narrowed);
    let (code, stdout, stderr) =
        repo.keepshipping(&["run", "services/api/ship.ks", "--as", "agent", "--base", "main"]);
    assert_eq!(code, 4, "{stdout}{stderr}");
    assert!(stderr.contains("waiting at plan"), "{stderr}");
    assert!(stderr.contains("`plan` is asked about for agent (file)"), "{stderr}");
}

#[test]
fn a_file_copied_where_the_default_branch_has_never_been_is_still_asked_about() {
    // The shape the intersection has to close: the default branch has no copy
    // of `services/edge/ship.ks` at all, so its only answer is the leash's. A
    // branch that copies a governed file aside and allows itself an apply has
    // proposed something nobody reviewed, and silence is not consent.
    let repo = Repo::build("copied", ON_MAIN, WIDENED);
    std::fs::create_dir_all(repo.root.join("services/edge")).expect("a directory to copy into");
    std::fs::copy(repo.root.join("services/api/ship.ks"), repo.root.join("services/edge/ship.ks"))
        .expect("copy the file aside");
    let (code, stdout, stderr) =
        repo.keepshipping(&["run", "services/edge/ship.ks", "--as", "agent", "--base", "main"]);
    assert_eq!(code, 4, "{stdout}{stderr}");
    assert!(stderr.contains("waiting at apply"), "{stderr}");
    assert!(stderr.contains("`apply` is asked about for agent (default branch)"), "{stderr}");

    // And `explain` says the base has no copy of this file rather than letting
    // it read like a base that granted something.
    let (code, stdout, stderr) = repo.keepshipping(&[
        "policy",
        "explain",
        "services/edge/ship.ks",
        "--as",
        "agent",
        "--base",
        "main",
    ]);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stdout
            .lines()
            .any(|l| l
                == "default branch main has no copy of this file: nothing it grants takes effect"),
        "{stdout}"
    );
}

#[test]
fn an_answered_gate_survives_a_resume_that_never_reached_it() {
    // The bug this pins: the run parks at `apply`, a human approves, and the
    // resume fails at `plan` before it gets there. The next resume has to
    // drive `apply` — it has still never run. Recording it as done would be
    // writing down a step that did not happen.
    let repo = Repo::build("resume", ON_MAIN, WIDENED);
    let (code, stdout, stderr) =
        repo.keepshipping(&["run", "services/api/ship.ks", "--as", "agent", "--base", "main"]);
    assert_eq!(code, 4, "{stdout}{stderr}");
    let run = repo.run_id();
    let (code, stdout, stderr) = repo.keepshipping(&["approve", &run]);
    assert_eq!(code, 0, "{stdout}{stderr}");

    for _ in 0..2 {
        let (code, stdout, stderr) = repo.keepshipping(&["resume", &run, "services/api/ship.ks"]);
        // `plan` is not a built-in step kind, so the drive stops there. That is
        // the point: the run got no further than `plan` either time.
        assert_ne!(code, 0, "the drive should not have finished: {stdout}{stderr}");
        let state = repo.parked();
        assert!(
            state["completed"].as_array().expect("completed").is_empty(),
            "`apply` never ran, so nothing completed: {state}"
        );
        assert_eq!(
            state["context"]["policy_gate"],
            serde_json::json!("apply"),
            "the gate outlives a resume that did not reach it: {state}"
        );
    }
}

#[test]
fn a_ref_that_looks_like_a_flag_is_refused_before_git_sees_it() {
    // `--upload-pack=…` is a flag to `git`, not a revision. On the command line
    // the flag parser turns it away first; through the environment it reaches
    // the resolver, which has to turn it away itself.
    let repo = Repo::build("dashref", ON_MAIN, WIDENED);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_keepshipping"));
    cmd.args(["policy", "explain", "services/api/ship.ks"])
        .current_dir(&repo.root)
        .env("KEEPSHIPPING_BASE", "--upload-pack=touch")
        .env_remove("CI")
        .env_remove("GITHUB_BASE_REF");
    let out = cmd.output().expect("run keepshipping");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code().expect("an exit code"), 2, "{stderr}");
    assert!(stderr.contains("`--upload-pack=touch` is not a ref"), "{stderr}");
}
