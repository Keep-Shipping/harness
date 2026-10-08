//! Rot guard for `examples/example-api`: the example is documentation, and
//! documentation does not fail a build when it goes stale.
//!
//! Three things rot on their own. The `ship.ks` stops checking as the language
//! moves; a file it names — the Dockerfile, the tofu directory — is renamed or
//! deleted and the check quietly stops meaning anything; and a step is
//! renamed in the file without the guide that walks through it noticing. Each
//! guard below fails with the file and the fix, not with a diff.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The example, as it sits in the repository.
fn example() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/example-api")
}

fn example_file(name: &str) -> String {
    let path = example().join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "examples/example-api/{name} should be readable UTF-8: {error}\n\
             The example is walked through in docs/GETTING_STARTED.md; if it was \
             renamed or removed, fix the guide as well."
        )
    })
}

/// Run the binary in the example directory. `CI` is unset: a non-empty `CI`
/// is what widens the undeclared-format warning, and this file has a header,
/// so the results must not depend on where the suite itself runs.
fn keepshipping(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_keepshipping"))
        .args(args)
        .current_dir(example())
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

/// The example's `ship.ks` is the file the guide teaches from: it must check
/// clean, or every step in the guide is teaching something the binary refuses.
#[test]
fn the_examples_ship_file_checks_clean() {
    let (code, stdout, stderr) = keepshipping(&["check"]);
    assert_eq!(
        code, 0,
        "examples/example-api/ship.ks no longer checks clean.\n{stdout}{stderr}\n\
         Fix: run `keepshipping check` (and `keepshipping fmt`) in \
         examples/example-api and repair the file until it checks; the guide in \
         docs/GETTING_STARTED.md follows this file line for line."
    );
    assert!(stderr.is_empty(), "unexpected stderr: {stderr}");
    assert!(!stdout.contains('✗'), "a finding survived a zero exit: {stdout}");
    assert!(stdout.contains("✓ ship.ks"), "not the file the example ships: {stdout}");
}

/// …and it must stay formatted: `fmt --check` is the same rewrite the guide
/// shows, so a file that drifts from it teaches a layout nobody writes.
#[test]
fn the_examples_ship_file_is_already_formatted() {
    let (code, stdout, stderr) = keepshipping(&["fmt", "--check"]);
    assert_eq!(
        code, 0,
        "examples/example-api/ship.ks is not `keepshipping fmt` output.\n{stdout}{stderr}\n\
         Fix: run `keepshipping fmt` in examples/example-api and commit the result."
    );
}

/// The step headers directly under `steps:`, as (name, kind), in file order.
/// `policy:` is a sibling top-level key, so it never contributes here.
fn declared_steps(src: &str) -> Vec<(String, String)> {
    let mut steps = Vec::new();
    let mut in_steps = false;
    for line in src.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if indent == 0 {
            in_steps = trimmed.starts_with("steps:");
            continue;
        }
        if !in_steps || indent != 2 {
            continue;
        }
        if let Some((name, kind)) = trimmed.split_once(':') {
            steps.push((name.trim().to_string(), kind.trim().to_string()));
        }
    }
    steps
}

/// Every `from:` and `dir:` value in the steps block, which are the paths the
/// checker resolves against the directory holding `ship.ks`.
fn named_paths(src: &str) -> Vec<(String, String)> {
    let mut paths = Vec::new();
    let mut in_steps = false;
    for line in src.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if indent == 0 {
            in_steps = trimmed.starts_with("steps:");
            continue;
        }
        if !in_steps {
            continue;
        }
        let Some((key, value)) = trimmed.split_once(':') else { continue };
        let value = value.trim();
        if matches!(key.trim(), "from" | "dir") && value.starts_with('.') {
            paths.push((key.trim().to_string(), value.to_string()));
        }
    }
    paths
}

/// Every path the example names is really there: a `from:` with no Dockerfile
/// beside it, or a `dir:` with no `.tf` files in it, is a check that stopped
/// checking without saying so.
#[test]
fn every_file_the_ship_file_names_exists() {
    let src = example_file("ship.ks");
    let paths = named_paths(&src);
    assert!(
        !paths.is_empty(),
        "examples/example-api/ship.ks names no `from:` or `dir:` path any more.\n\
         Fix: point the oci.image step at a `from:` Dockerfile and the tofu.plan \
         step at a `dir:` directory, or update the guard."
    );
    for (key, value) in &paths {
        let resolved = example().join(value);
        assert!(
            resolved.exists(),
            "examples/example-api/ship.ks says `{key}: {value}`, but {} does not exist.\n\
             Fix: restore the file, or change `{key}` in ship.ks to the path that \
             holds it and follow the change through docs/GETTING_STARTED.md.",
            resolved.display()
        );
    }
}

/// The route, pinned: the guide in `docs/GETTING_STARTED.md` walks this
/// example step by step, and a step renamed in `ship.ks` on its own would
/// leave the guide describing a run that no longer happens.
const ROUTE: &[(&str, &str)] = &[
    ("build", "oci.image"),
    ("plan", "tofu.plan"),
    ("review", "approval"),
    ("apply", "tofu.apply"),
    ("deploy", "k8s.rollout"),
];

/// `ship.ks` declares the route the guide describes — no more steps, no
/// fewer, and none of them renamed behind the guide's back.
#[test]
fn the_ship_file_still_declares_the_route_the_guide_walks() {
    let declared = declared_steps(&example_file("ship.ks"));
    let pinned: Vec<(String, String)> =
        ROUTE.iter().map(|(name, kind)| (name.to_string(), kind.to_string())).collect();
    assert_eq!(
        declared, pinned,
        "examples/example-api/ship.ks no longer declares the route \
         docs/GETTING_STARTED.md walks through.\n\
         Fix: either put the steps back, or change the step in ship.ks and in \
         the guide together — the guide is the thing this example exists for."
    );
}

/// `--dry-run` walks the route the file declares, so a step the file declares
/// but the run does not take shows up here rather than as a guide describing
/// a step the run skips.
#[test]
fn the_dry_run_takes_every_step_the_ship_file_declares() {
    let src = example_file("ship.ks");
    let declared = declared_steps(&src);
    assert!(!declared.is_empty(), "no steps were found under `steps:` in {src}");

    let (code, stdout, stderr) = keepshipping(&["run", "--dry-run"]);
    assert_eq!(code, 0, "`run --dry-run` should plan and touch nothing:\n{stdout}{stderr}");
    let planned: Vec<(String, String)> = stdout
        .lines()
        .filter_map(|line| line.strip_prefix('\u{25b8}'))
        .filter_map(|line| line.trim().split_once(char::is_whitespace))
        .map(|(name, kind)| (name.to_string(), kind.trim().to_string()))
        .collect();
    assert_eq!(
        planned, declared,
        "`keepshipping run --dry-run` does not take the steps ship.ks declares.\n{stdout}\
         Fix: keep the step names and kinds in ship.ks and the guide in \
         docs/GETTING_STARTED.md in step with each other."
    );
}

/// The example's CI is the other reader of `ship.ks`, and it is easy to write
/// a `uses:` line for an action that was never published.
#[test]
fn the_example_ci_checks_the_file_and_claims_no_unpublished_action() {
    let workflow = example_file(".github/workflows/ship.yml");
    assert!(
        workflow.contains("keepshipping check --format github"),
        "examples/example-api/.github/workflows/ship.yml must run \
         `keepshipping check --format github` so findings land on the diff.\n{workflow}"
    );
    // Comments are excluded: the step above the download explains why there is
    // no `uses:` here, and it has to be able to say so out loud.
    let steps: Vec<&str> =
        workflow.lines().filter(|line| !line.trim_start().starts_with('#')).collect();
    assert!(
        !steps.iter().any(|line| line.contains("uses: Keep-Shipping")),
        "examples/example-api/.github/workflows/ship.yml has a `uses:` step for a Keep \
         Shipping action, and no action.yml is published. Install the binary from the \
         release archive instead:\n{workflow}"
    );
    let readme = example_file("README.md");
    assert!(
        readme.contains("../../docs/GETTING_STARTED.md"),
        "examples/example-api/README.md must point at ../../docs/GETTING_STARTED.md, \
         the guide that walks this example step by step.\n{readme}"
    );
}
