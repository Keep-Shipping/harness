//! End-to-end tests of `keepshipping import shell`: what it writes, and what
//! it says while writing it.
//!
//! The load-bearing one is [`the_imported_file_type_checks`]: a converter that
//! invented a step kind would pass, because an unknown kind type-checks clean.
//! [`every_emitted_step_kind_is_a_real_kind`] is the test that makes the rest
//! honest.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The acceptance fixture: a realistic deploy script exercising every shape
/// the converter claims to recognise, plus some it does not.
const DEPLOY2: &str = include_str!("fixtures/import-shell/deploy2.sh");

/// A script with nothing in it the converter recognises.
const ODD: &str = "\
#!/usr/bin/env bash
set -euo pipefail
make build
echo hi
rsync -a dist/ host:/srv
npm publish
";

/// A script that recognises cleanly, so the fold and the plan reference can be
/// asserted on their own.
const FOLD: &str = "\
docker build -f Dockerfile -t ghcr.io/acme/api:x .
docker push ghcr.io/acme/api:x
tofu plan -out=prod.tfplan ./infra/prod
tofu apply prod.tfplan
";

/// A command spread over `\` continuations, which is how deploy scripts are
/// actually written.
const CONTINUED: &str = "\
docker build \\
  -f Dockerfile.prod \\
  -t a/b:1 .
docker push a/b:1
";

/// Two pushes of different tags after one build that named no tag of its own,
/// so the *first push* is what sets `push:`.
const TWO_PUSH: &str = "\
docker build -f D .
docker push first/img:1
docker push second/img:2
";

/// A scratch directory, removed when the test finishes, so the import writes
/// somewhere of its own rather than into the repository.
fn scratch(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("keepshipping-import-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch directory");
    dir
}

fn write_script(dir: &Path, name: &str, src: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, src).expect("write the script to import");
    path
}

/// Runs the binary in `dir`. The suite may itself be running on CI, where a
/// header-less file gains an advisory warning it would not have anywhere else —
/// and these tests assert on output byte for byte.
fn keepshipping(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_keepshipping"))
        .args(args)
        .current_dir(dir)
        .env_remove("CI")
        .env_remove("GITHUB_ACTIONS")
        .output()
        .expect("run keepshipping");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Imports `script` into `dir`, returning the exit code, the report, the
/// emitted file's text and stderr.
fn import(dir: &Path, script: &Path, out: &str) -> (i32, String, String, String) {
    let (code, stdout, stderr) =
        keepshipping(dir, &["import", "shell", script.to_str().unwrap(), "--out", out]);
    let text = std::fs::read_to_string(dir.join(out))
        .unwrap_or_else(|e| panic!("the import should have written {out}: {e}"));
    (code, stdout, text, stderr)
}

#[test]
fn the_imported_file_type_checks() {
    let dir = scratch("checks");
    let script = write_script(&dir, "deploy2.sh", DEPLOY2);
    let (code, _report, text, stderr) = import(&dir, &script, "ship.ks");
    assert_eq!(code, 0, "import failed: {stderr}");

    let (code, stdout, stderr) = keepshipping(&dir, &["check", "ship.ks"]);
    assert_eq!(code, 0, "the imported file does not check clean:\n{stdout}\n{stderr}");
    assert_eq!(stderr, "", "check wrote to stderr:\n{stderr}");
    assert!(stdout.starts_with("✓ ship.ks"), "{stdout}");
    // And it is already in `fmt`'s canonical form, so the operator's own
    // `keepshipping fmt` changes nothing.
    let (fmt_code, _, _) = keepshipping(&dir, &["fmt", "--check", "ship.ks"]);
    assert_eq!(fmt_code, 0, "the imported file is not fmt-clean:\n{text}");
}

#[test]
fn every_emitted_step_kind_is_a_real_kind() {
    let dir = scratch("kinds");
    let script = write_script(&dir, "deploy2.sh", DEPLOY2);
    let (_code, _report, text, _stderr) = import(&dir, &script, "ship.ks");

    // An unknown kind type-checks clean, so this is the assertion `check`
    // cannot make for us.
    let catalog = ks_core::Catalog::builtin();
    let kinds: Vec<(String, String)> =
        step_headers(&text).iter().map(|h| split_header(h)).collect();
    assert_eq!(
        kinds,
        [
            ("build".to_string(), "oci.image".to_string()),
            ("plan".to_string(), "tofu.plan".to_string()),
            ("apply".to_string(), "tofu.apply".to_string()),
            ("deploy".to_string(), "k8s.rollout".to_string()),
            ("vm".to_string(), "vm.deploy".to_string()),
            ("deploy2".to_string(), "./deploy2.ts".to_string()),
        ],
        "the fixture should exercise every recognised shape:\n{text}"
    );
    for (id, kind) in &kinds {
        if ks_core::script_step::is_script_kind(kind) {
            assert!(kind.starts_with("./"), "a script kind must stay beside the file: {kind}");
            assert!(!kind.contains(".."), "a script kind must not escape: {kind}");
        } else {
            assert!(catalog.step(kind).is_some(), "step {id}: `{kind}` is not a built-in kind");
        }
    }
}

/// The step headers of a `.ks` file as `(id, kind)`: an id and a kind on one
/// line, at one level of indent, with the kind in the value column `fmt` puts
/// it in rather than flush against the colon.
fn step_headers(text: &str) -> Vec<String> {
    text.lines()
        .filter(|l| l.starts_with("  ") && !l.starts_with("    "))
        .filter(|l| !l.trim_start().starts_with('#'))
        .map(|l| {
            let (id, kind) = l.trim_start().split_once(':').expect("a step header has a colon");
            format!("{id}: {}", kind.trim())
        })
        .collect()
}

fn split_header(header: &str) -> (String, String) {
    let (id, kind) = header.split_once(": ").expect("a header is `id: kind`");
    (id.to_string(), kind.to_string())
}

/// A file with its column alignment collapsed to one space, for assertions
/// about *what* an input says rather than where `fmt` put it.
fn squash(text: &str) -> String {
    let mut out = String::new();
    let mut space = false;
    for c in text.chars() {
        if c.is_whitespace() {
            space = true;
        } else {
            if space && !out.is_empty() {
                out.push(' ');
            }
            space = false;
            out.push(c);
        }
    }
    out
}

#[test]
fn a_script_with_nothing_recognised_emits_only_the_script_step() {
    let dir = scratch("odd");
    let script = write_script(&dir, "deploy2.sh", ODD);
    let (code, report, text, stderr) = import(&dir, &script, "ship.ks");
    assert_eq!(code, 0, "{stderr}");

    // Only the script step, and it names a module beside the file.
    for kind in [
        "oci.image",
        "tofu.plan",
        "tofu.apply",
        "terraform.plan",
        "terraform.apply",
        "k8s.rollout",
        "vm.deploy",
        "approval",
        "decide",
    ] {
        assert!(
            !text.contains(kind),
            "nothing was recognised, so `{kind}` should not appear:\n{text}"
        );
    }
    assert_eq!(step_headers(&text), vec!["deploy2: ./deploy2.ts"], "{text}");
    assert!(squash(&text).contains("action: other"), "{text}");
    assert!(text.contains("  # you must write ./deploy2.ts yourself"), "{text}");
    assert!(text.starts_with("keepshipping: 0.1\n"), "{text}");
    assert!(text.contains("name:         deploy2"), "{text}");

    // Every command is listed as a candidate, with a line and a suggestion.
    for command in ["make build", "echo hi", "rsync -a dist/ host:/srv", "npm publish"] {
        assert!(report.contains(command), "{command} is missing from:\n{report}");
    }
    assert!(report.contains("unrecognised"), "{report}");
    assert!(report.contains("set -euo pipefail"), "the set flags are missing:\n{report}");
    // And it still checks.
    let (check, stdout, _) = keepshipping(&dir, &["check", "ship.ks"]);
    assert_eq!(check, 0, "{stdout}");
}

#[test]
fn a_push_folds_into_the_build_and_an_apply_names_the_plan_step() {
    let dir = scratch("fold");
    let script = write_script(&dir, "fold.sh", FOLD);
    let (code, report, text, stderr) = import(&dir, &script, "ship.ks");
    assert_eq!(code, 0, "{stderr}");

    // The push set the build's `push:`; it is not a step of its own, and there
    // is no `oci.push` kind for it to have become.
    let flat = squash(&text);
    assert!(flat.contains("push: ghcr.io/acme/api:x"), "{text}");
    assert!(!text.contains("oci.push"), "{text}");
    assert_eq!(text.matches("oci.image").count(), 1, "one image step, not two:\n{text}");
    assert!(report.contains("docker push ghcr.io/acme/api:x"), "{report}");
    assert!(report.contains("folded"), "the fold is not reported:\n{report}");

    // The apply points at the plan step that wrote the file.
    assert!(flat.contains("apply: tofu.apply"), "{text}");
    assert!(flat.contains("plan: plan.file"), "{text}");
    // And the report names the source line each came from.
    assert!(report.contains("tofu apply prod.tfplan"), "{report}");

    let (check, stdout, _) = keepshipping(&dir, &["check", "ship.ks"]);
    assert_eq!(check, 0, "{stdout}");
}

/// The regression for the continuation bug: a `docker build` split over
/// `\`-continued lines used to become one step missing its `-f`, plus two
/// bogus "unrecognised" flags — and the report cited the wrong line.
#[test]
fn a_continued_command_is_one_step_cited_at_its_first_line() {
    let dir = scratch("cont");
    let script = write_script(&dir, "cont.sh", CONTINUED);
    let (code, report, text, stderr) = import(&dir, &script, "ship.ks");
    assert_eq!(code, 0, "{stderr}");

    // One image step, with the `-f` that used to be dropped.
    assert_eq!(text.matches("oci.image").count(), 1, "one image step, not several:\n{text}");
    let flat = squash(&text);
    assert!(flat.contains("from: ./Dockerfile.prod"), "{text}");
    assert!(flat.contains("context: ."), "{text}");
    assert!(flat.contains("push: a/b:1"), "{text}");
    // No script step: none of the continuation lines were reported as commands.
    assert!(!text.contains("./cont.ts"), "the flags were read as commands:\n{report}");
    assert!(!report.contains("unrecognised"), "nothing was unrecognised:\n{report}");

    // The recognised table cites line 1 — where `docker build` starts.
    let build_row = report
        .lines()
        .find(|l| l.contains("docker build"))
        .unwrap_or_else(|| panic!("no docker build row in:\n{report}"));
    assert!(build_row.trim_start().starts_with('1'), "{report}");

    let (check, stdout, _) = keepshipping(&dir, &["check", "ship.ks"]);
    assert_eq!(check, 0, "{stdout}");
}

/// Two pushes: the first is the tag the build produced, and the report has to
/// say which line set it rather than claiming the last one won.
#[test]
fn the_first_of_several_pushes_wins_and_the_report_names_its_line() {
    let dir = scratch("twopush");
    let script = write_script(&dir, "two.sh", TWO_PUSH);
    let (code, report, text, stderr) = import(&dir, &script, "ship.ks");
    assert_eq!(code, 0, "{stderr}");

    assert!(squash(&text).contains("push: first/img:1"), "the last push won:\n{text}");
    assert!(!text.contains("second/img:2"), "the last push won:\n{text}");
    // Both pushes are still reported as recognised — they folded, not vanished.
    assert!(report.contains("docker push first/img:1"), "{report}");
    assert!(report.contains("docker push second/img:2"), "{report}");
    // And the fold note names the line that actually set `push:`.
    assert!(report.contains("the first one wins, and line 2 set it"), "{report}");

    let (check, stdout, _) = keepshipping(&dir, &["check", "ship.ks"]);
    assert_eq!(check, 0, "{stdout}");
}

#[test]
fn the_output_is_named_by_the_script_and_never_clobbered() {
    let dir = scratch("out");
    let script = write_script(&dir, "Deploy 2.sh", DEPLOY2);
    // No `--out`: the name comes from the script's stem, sanitised.
    let (code, stdout, stderr) = keepshipping(&dir, &["import", "shell", script.to_str().unwrap()]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("wrote deploy-2.ks"), "{stdout}");
    assert!(dir.join("deploy-2.ks").exists(), "{stdout}");

    // Importing again over a file that exists changes nothing and says why.
    let (code, stdout, stderr) = keepshipping(&dir, &["import", "shell", script.to_str().unwrap()]);
    assert_eq!(code, 2, "{stdout}");
    assert!(stderr.contains("already exists"), "{stderr}");
}

#[test]
fn a_script_that_cannot_be_read_is_a_usage_error() {
    let dir = scratch("missing");
    let (code, stdout, stderr) =
        keepshipping(&dir, &["import", "shell", "no-such-script.sh", "--out", "ship.ks"]);
    assert_eq!(code, 2, "{stdout}");
    assert!(stderr.contains("cannot read"), "{stderr}");
    assert!(!dir.join("ship.ks").exists(), "nothing should have been written");
}

#[test]
fn a_flag_that_is_not_ours_is_a_usage_error() {
    let dir = scratch("usage");
    let script = write_script(&dir, "deploy2.sh", DEPLOY2);
    let (code, _stdout, stderr) =
        keepshipping(&dir, &["import", "shell", script.to_str().unwrap(), "--all"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("usage: keepshipping"), "{stderr}");
}
