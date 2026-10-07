//! `keepshipping check --fix`: the machine-applicable edits are applied and
//! the file re-checked, and `policy:` is never touched — a policy change is
//! a human's decision ([ADR
//! 0012](https://github.com/Keep-Shipping/harness/blob/main/docs/adr/0012-policy-authority.md)).

use std::path::{Path, PathBuf};
use std::process::Command;

const SITE: &str = include_str!("fixtures/site/ship.ks");

/// The site's own example — one wrong `build.tag`, everything else clean —
/// plus two `policy:` blocks, each with a misspelled verb. The grammar
/// allows more than one, and both must be off limits.
const TAGGED_POLICY: &str = "\
name:  gated
envs:
  prod:
    ci-only: true
steps:
  build:   oci.image
    from:  ./Dockerfile
    push:  ghcr.io/acme/api:{git.sha}
  deploy:  k8s.rollout
    image: build.tag
    to:    apply.out.cluster
policy:
  agents:
    never: depoy prod
  humans:
    can: pubish prod
";

/// A directory of its own per call: two tests may run in parallel and
/// `--fix` rewrites what is in it.
fn temp_site(name: &str, src: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("keepshipping-fix-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp site dir");
    std::fs::write(dir.join("ship.ks"), src).expect("write temp site file");
    dir
}

fn check_in(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_keepshipping"))
        .arg("check")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run keepshipping");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn read(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("ship.ks")).expect("read fixed site file")
}

#[test]
fn fix_rewrites_the_tag_and_the_file_checks_clean() {
    let dir = temp_site("tag", SITE);
    let (code, stdout, stderr) = check_in(&dir, &["--fix"]);
    let fixed = read(&dir);
    let _ = std::fs::remove_dir_all(&dir);

    assert!(fixed.contains("image: build.digest"), "{fixed}");
    assert!(!fixed.contains("build.tag"), "{fixed}");
    // The re-check alone decides the exit code: the pre-fix one was 1.
    assert_eq!(code, 0, "{stdout}\\n{stderr}");
    assert!(stdout.contains("✓ ship.ks"), "the re-check passes:\\n{stdout}");
    assert!(stderr.contains("applied 1 fix"), "{stderr}");
}

#[test]
fn fix_leaves_every_policy_block_byte_identical_and_still_reports_them() {
    let dir = temp_site("policy", TAGGED_POLICY);
    let before = read(&dir);
    let (code, stdout, stderr) = check_in(&dir, &["--fix"]);
    let after = read(&dir);
    let _ = std::fs::remove_dir_all(&dir);

    // The edit outside `policy:` landed.
    assert!(after.contains("image: build.digest"), "{after}");
    // Neither edit inside a `policy:` block did — including the first
    // block, which a single-span guard would have left unguarded.
    assert_eq!(after.split("policy:").nth(1), before.split("policy:").nth(1), "{after}");
    assert!(after.contains("never: depoy prod"), "{after}");
    assert!(after.contains("can: pubish prod"), "{after}");

    assert_ne!(code, 0, "the misspelled verbs are still errors");
    assert!(stdout.contains("unknown action `depoy`"), "{stdout}");
    assert!(stdout.contains("did you mean `deploy`?"), "{stdout}");
    assert!(stdout.contains("unknown action `pubish`"), "{stdout}");
    assert!(
        stderr.contains("2 fixes inside `policy:` need a human and were not applied"),
        "{stderr}"
    );
    assert!(stderr.contains("applied 1 fix"), "{stderr}");
}

#[test]
fn fix_belongs_to_check_alone() {
    let dir = temp_site("usage", SITE);
    let out = Command::new(env!("CARGO_BIN_EXE_keepshipping"))
        .args(["run", "--fix"])
        .current_dir(&dir)
        .output()
        .expect("run keepshipping");
    let unchanged = read(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(out.status.code(), Some(2), "an unknown flag is a usage error");
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage: keepshipping check"));
    assert_eq!(unchanged, SITE, "run never edits a file");
}
