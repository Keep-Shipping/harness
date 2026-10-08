//! End-to-end tests of `keepshipping import github-actions`.
//!
//! What it writes passes `keepshipping check`, on every workflow in the corpus
//! and with the extractor reading the script stubs. The rest is about losing
//! nothing: the report names every original step, and a run never overwrites.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_yaml_ng::Value;

/// The starter workflows, verbatim: what a new repository actually has.
const DOCKER: &str = include_str!("fixtures/import/github-actions/docker-publish.yml");
const TERRAFORM: &str = include_str!("fixtures/import/github-actions/terraform.yml");
const AKS_HELM: &str =
    include_str!("fixtures/import/github-actions/azure-kubernetes-service-helm.yml");
const NODE: &str = include_str!("fixtures/import/github-actions/node.js.yml");

/// No action anyone here knows: the two commands a rollout is written from. The
/// last step is gated on a push, and the file also runs on a pull request, so
/// the rollout is held back from one.
const KUBECTL: &str = "\
name: Deploy
on:
  push:
    branches: [main]
  pull_request:
jobs:
  deploy:
    steps:
      - uses: actions/checkout@v4
      - uses: docker/build-push-action@v5
        with:
          context: ./app
          tags: ghcr.io/acme/app:${{ github.sha }}
          push: true
      - run: kubectl apply -f k8s/
        if: github.event_name == 'push'
      - run: helm upgrade app ./chart --namespace prod
";

/// Nothing in it is translated: a job with no `steps:`, a job that calls a
/// reusable workflow, and a job whose only steps are ones this build drops. The
/// dropped step also carries every key a step may have, so the report has to
/// name them all.
const NOTHING: &str = "\
name: Nothing here
on: [push, pull_request_target]
jobs:
  empty:
    runs-on: ubuntu-latest
  reusable:
    uses: ./.github/workflows/build.yml
  dropped:
    steps:
      - uses: actions/checkout@v4
      - uses: vendor/unknown@v1
        id: save
        shell: bash
        timeout-minutes: 5
        continue-on-error: true
        env:
          HOME_DIR: /tmp
        with:
          token: ${{ secrets.TOKEN }}
";

/// A temp directory for this test, emptied first.
fn temp_dir(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("keepshipping-import-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn keepshipping(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_keepshipping"))
        .current_dir(dir)
        .args(args)
        // `check` warns about a file without a format header on CI, and an
        // agent's own markers make a run an agent's. These results must not
        // depend on where the test ran.
        .env_remove("CI")
        .env_remove("GITHUB_ACTIONS")
        .env_remove("CLAUDECODE")
        .env_remove("CLAUDE_CODE_ENTRYPOINT")
        .env_remove("GIT_EDITOR")
        .output()
        .expect("run keepshipping");
    let code = out.status.code().expect("exit code");
    let text = |b: Vec<u8>| String::from_utf8_lossy(&b).into_owned();
    (code, text(out.stdout), text(out.stderr))
}

/// Import `src` as `w.yml` into a fresh directory, and hand it back.
fn import_one(name: &str, src: &str) -> PathBuf {
    let dir = temp_dir(name);
    std::fs::write(dir.join("w.yml"), src).expect("write workflow");
    let (code, _, stderr) = keepshipping(&dir, &["import", "github-actions", "w.yml"]);
    assert_eq!(code, 0, "{stderr}");
    dir
}

/// The importer's own promise: the file checks clean, and is already canonical.
fn assert_checks(dir: &Path, file: &str) -> String {
    let (code, _, stderr) = keepshipping(dir, &["check", file]);
    assert_eq!(code, 0, "`keepshipping check {file}` failed: {stderr}");
    assert!(stderr.is_empty(), "{file} checked with output: {stderr}");
    let (code, _, _) = keepshipping(dir, &["fmt", "--check", file]);
    assert_eq!(code, 0, "`keepshipping fmt --check {file}` found changes");
    std::fs::read_to_string(dir.join(file)).expect("read the generated file")
}

/// Every one of these is in the file, or the test says which one is not.
fn has(ship: &str, wanted: &[&str]) {
    for want in wanted {
        assert!(ship.contains(want), "`{want}` is missing:\n{ship}");
    }
}

/// Every step the fixture declares: its own name, or what it runs.
fn original_steps(src: &str) -> Vec<String> {
    let doc: Value = serde_yaml_ng::from_str(src).expect("parse the fixture");
    let jobs = doc.get("jobs").and_then(Value::as_mapping).expect("the fixture has jobs");
    let mut out = Vec::new();
    for (_, job) in jobs {
        for step in job.get("steps").and_then(Value::as_sequence).into_iter().flatten() {
            let step = step.as_mapping().expect("a step is a mapping");
            let pick = |k: &str| step.get(k).and_then(Value::as_str);
            let label = pick("name").or_else(|| pick("uses")).or_else(|| pick("run"));
            let line = label.unwrap_or("a step").lines().next().unwrap_or_default();
            out.push(line.to_string());
        }
    }
    out
}

#[test]
fn a_docker_workflow_becomes_a_signed_oci_image() {
    let dir = import_one("docker", DOCKER);
    let ship = assert_checks(&dir, "ship.ks");
    has(&ship, &["oci.image", "from:", "./Dockerfile", "sign:", "TODO: `push:`", "tag \"v*.*.*\""]);
    // A fixture edited to suit the importer would prove nothing about it.
    assert!(DOCKER.contains("$default-branch"));
    assert!(TERRAFORM.contains("hashicorp/setup-terraform@v1"));
}

#[test]
fn a_terraform_workflow_becomes_a_plan_an_approval_and_an_apply() {
    let dir = import_one("terraform", TERRAFORM);
    let ship = assert_checks(&dir, "ship.ks");
    has(
        &ship,
        &["tofu.plan", "approval", "tofu.apply", "show:", ".changes", "`if:` is not translated"],
    );
    assert!(ship.find("approval") < ship.find("tofu.apply"), "{ship}");
}

#[test]
fn a_helm_workflow_becomes_a_rollout_with_the_image_it_has() {
    let dir = import_one("aks", AKS_HELM);
    let ship = assert_checks(&dir, "ship.ks");
    has(&ship, &["k8s.rollout", "TODO: `image:`", "TODO: `to:`", "manual"]);
}

#[test]
fn kubectl_apply_and_helm_upgrade_both_become_a_rollout() {
    let dir = import_one("kubectl", KUBECTL);
    let ship = assert_checks(&dir, "ship.ks");
    has(&ship, &["manifests:", "./k8s/", "namespace:", "prod", "image:", ".digest"]);
    assert_eq!(ship.matches("k8s.rollout").count(), 2, "{ship}");
    // A condition that could not be carried over, on a file that also runs on a
    // pull request, holds its step back from one — and says so either way.
    has(&ship, &["`if:` is not translated", "pr.number == null"]);
    assert_eq!(ship.matches("pr.number").count(), 1, "only the gated step: {ship}");
    // Nothing was stubbed, so there is no `ship/` of scripts to write.
    assert!(!dir.join("ship").exists(), "{}", dir.display());
}

#[test]
fn a_workflow_with_nothing_to_translate_still_imports_and_checks() {
    let dir = import_one("nothing", NOTHING);
    let ship = assert_checks(&dir, "ship.ks");
    assert_eq!(ship.matches("action:").count(), 3, "a stub per job: {ship}");
    let stubs = std::fs::read_dir(dir.join("ship")).expect("the stubs").count();
    assert_eq!(stubs, 3, "a stub module per job");
    let report = std::fs::read_to_string(dir.join("IMPORT-REPORT.md")).expect("the report");
    // A reusable workflow call, and every key the stubbed step carried.
    has(
        &report,
        &[
            "`uses: ./.github/workflows/build.yml`",
            "`id` is not translated",
            "`shell` is not translated",
            "`timeout-minutes` is not translated",
            "`continue-on-error` is not translated",
            "`env.HOME_DIR` is not translated",
            "`with.token` is not translated",
            "nothing in this job was translated",
        ],
    );
    // `pull_request_target` is not a review, and never becomes one.
    has(&report, &["on: pull_request_target", "write token"]);
    assert!(!ship.contains("pull_request_target"), "{ship}");
}

#[test]
fn an_untranslated_run_becomes_a_stub_that_throws() {
    let dir = import_one("node", NODE);
    assert!(assert_checks(&dir, "ship.ks").contains("./ship/"));
    let stubs: Vec<PathBuf> = std::fs::read_dir(dir.join("ship"))
        .expect("the stubs")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .collect();
    assert_eq!(stubs.len(), 1, "one run of untranslated steps, one stub");
    let stub = std::fs::read_to_string(&stubs[0]).expect("the stub module");
    has(&stub, &["// npm ci", "// TODO:", "npm run build --if-present"]);
    has(&stub, &["throw new Error", "not yet translated from GitHub Actions"]);
}

#[test]
fn the_report_names_every_step_of_every_workflow() {
    // Each workflow, with one construct of its own that did not come across.
    for (name, src, dropped) in [
        ("report-docker", DOCKER, "`permissions` is not translated"),
        ("report-terraform", TERRAFORM, "`permissions` is not translated"),
        ("report-aks", AKS_HELM, "`permissions` is not translated"),
        ("report-node", NODE, "`strategy` is not translated"),
    ] {
        let dir = import_one(name, src);
        assert_checks(&dir, "ship.ks");
        let report = std::fs::read_to_string(dir.join("IMPORT-REPORT.md")).expect("the report");
        let steps = original_steps(src);
        assert!(!steps.is_empty(), "{name} has no steps to look for");
        has(&report, &steps.iter().map(String::as_str).collect::<Vec<_>>());
        has(&report, &["## Untranslated constructs", dropped]);
    }
}

#[test]
fn a_directory_becomes_one_file_per_workflow_and_one_report() {
    let dir = temp_dir("corpus");
    for (name, src) in [
        ("docker-publish.yml", DOCKER),
        ("terraform.yml", TERRAFORM),
        ("azure-kubernetes-service-helm.yml", AKS_HELM),
        ("node.js.yml", NODE),
    ] {
        std::fs::write(dir.join(name), src).expect("write a workflow");
    }
    let (code, stdout, stderr) = keepshipping(&dir, &["import", "github-actions", "."]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("imported 4 workflow(s)"), "{stdout}");
    // One file per workflow, and no merged triggers: two workflows that deploy
    // on different events must not end up deploying on either one's.
    for name in
        ["docker-publish.ks", "terraform.ks", "azure-kubernetes-service-helm.ks", "node-js.ks"]
    {
        assert_checks(&dir, name);
    }
    let report = std::fs::read_to_string(dir.join("IMPORT-REPORT.md")).expect("one report");
    has(&report, &["docker-publish.yml", "terraform.yml", "node.js.yml"]);
}

#[test]
fn an_output_that_is_already_there_is_refused_until_it_is_forced() {
    let dir = import_one("force", TERRAFORM);
    std::fs::write(dir.join("ship.ks"), "# mine\n").expect("plant a file");
    let (code, _, stderr) = keepshipping(&dir, &["import", "github-actions", "w.yml"]);
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("--force"), "{stderr}");
    let mine = std::fs::read_to_string(dir.join("ship.ks")).unwrap();
    assert_eq!(mine, "# mine\n", "a refused run writes nothing");
    let (code, _, stderr) = keepshipping(&dir, &["import", "github-actions", "w.yml", "--force"]);
    assert_eq!(code, 0, "{stderr}");
    assert_checks(&dir, "ship.ks");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_unknown_flag_is_a_usage_error() {
    let dir = temp_dir("usage");
    for args in [
        vec!["import", "github-actions", "--dry-run"],
        vec!["import", "github-actions", "--out"],
        vec!["import", "bitbucket", "."],
        vec!["import"],
    ] {
        let (code, stdout, stderr) = keepshipping(&dir, &args);
        assert_eq!(code, 2, "{args:?} exited {code}: {stderr}");
        assert!(stdout.is_empty(), "{args:?} printed {stdout}");
        assert!(stderr.contains("import github-actions"), "{args:?}");
    }
}

#[test]
fn a_workflow_that_will_not_parse_names_the_file_and_writes_nothing() {
    let dir = temp_dir("broken");
    std::fs::write(dir.join("broken.yml"), "name: x\n  bad: [\n").expect("write a broken workflow");
    let (code, _, stderr) = keepshipping(&dir, &["import", "github-actions", "broken.yml"]);
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("broken.yml"), "{stderr}");
    assert!(!dir.join("ship.ks").exists());
    // A directory with nothing in it is the same kind of nothing found.
    let empty = temp_dir("empty");
    let (code, _, stderr) = keepshipping(&empty, &["import", "github-actions"]);
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains(".github/workflows"), "{stderr}");
}
