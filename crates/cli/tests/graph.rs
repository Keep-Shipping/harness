//! `keepshipping graph`: the plan, printed without running anything
//! ([#40](https://github.com/Keep-Shipping/harness/issues/40)).
//!
//! The site fixture — a valid copy of the hero file — is the acceptance case:
//! the route it prints is the site's route. The wrong `ship.ks` in the other
//! fixture is the failure case: the diagnostics `check` would print, and exit
//! 1.

use std::process::Command;

/// A directory holding one valid `ship.ks`.
const HERO: &str = "tests/fixtures/hero";
/// A directory holding one `ship.ks` with a type error.
const SITE: &str = "tests/fixtures/site";
/// A directory holding one `ship.ks` with a single step.
const ONE: &str = "tests/fixtures/one";
/// A directory holding one `ship.ks` that declares no trigger.
const BARE: &str = "tests/fixtures/bare";

fn graph(dir: &str, extra: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_keepshipping"))
        .arg("graph")
        .args(extra)
        .current_dir(dir)
        // The ambient `CI` widens the "no format declared" warning, which
        // these tests are not about.
        .env_remove("CI")
        .output()
        .expect("run keepshipping");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn the_text_report_is_the_site_route() {
    let (code, stdout, stderr) = graph(HERO, &[]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    assert!(stdout.contains("route: push → build → plan → review → apply → deploy\n"), "{stdout}");
    assert!(stdout.ends_with("0 steps ran. Nothing was touched.\n"), "{stdout}");
    // One line per step, in sequence order, with the dependencies it waits on.
    let rows: Vec<&str> = stdout.lines().skip(2).take_while(|line| !line.is_empty()).collect();
    assert_eq!(rows.len(), 5, "{stdout}");
    assert!(rows[0].contains("1  build   oci.image"), "{stdout}");
    assert!(rows[3].contains("plan, review"), "{stdout}");
    assert!(rows[4].contains("build, apply"), "{stdout}");
    assert!(rows.iter().all(|row| row.contains("run")), "{stdout}");
}

#[test]
fn dot_is_a_digraph_with_a_node_and_an_edge_per_step() {
    let (code, stdout, stderr) = graph(HERO, &["--format", "dot"]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.starts_with("digraph plan {\n"), "{stdout}");
    assert!(stdout.ends_with("}\n"), "{stdout}");
    assert!(stdout.contains("\"build\" [label=\"1 build\"];"), "{stdout}");
    assert!(stdout.contains("\"plan\" -> \"apply\";"), "{stdout}");
    assert_eq!(stdout.lines().filter(|l| l.contains("->")).count(), 5, "{stdout}");
}

#[test]
fn json_is_the_plan_with_a_stable_key_order() {
    let (code, stdout, stderr) = graph(HERO, &["--format", "json"]);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stdout.starts_with(
            "{\n  \"version\": 1,\n  \"file\": \"ship.ks\",\n  \"env\": \"default\",\n  \
             \"triggers\": [\"push\"],\n  \"steps\": [\n"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "{\"seq\": 4, \"name\": \"apply\", \"kind\": \"tofu.apply\", \
             \"deps\": [\"plan\", \"review\"], \"gate\": {\"kind\": \"run\"}}"
        ),
        "{stdout}"
    );
    // The dependencies are on the steps; there is no second copy of them.
    assert!(!stdout.contains("\"edges\""), "{stdout}");
    // The listing is the whole stdout: no report, no footer.
    assert!(stdout.ends_with("]\n}\n"), "{stdout}");
    assert!(!stdout.contains("steps ran"), "{stdout}");
}

/// The report lines up: every column is as wide as the widest cell in it,
/// header included.
#[test]
fn the_columns_line_up() {
    let (code, stdout, stderr) = graph(HERO, &[]);
    assert_eq!(code, 0, "{stderr}");
    let lines: Vec<&str> = stdout.lines().collect();
    // Where each column starts, in characters: the header sets the width of
    // every one.
    let starts = |line: &str| -> Vec<usize> {
        let mut out = Vec::new();
        let mut gap = true;
        for (at, c) in line.chars().enumerate() {
            if c.is_whitespace() {
                gap = true;
            } else if gap {
                out.push(at);
                gap = false;
            }
        }
        out
    };
    let rows: Vec<Vec<usize>> = lines.iter().skip(1).take(6).map(|l| starts(l)).collect();
    assert_eq!(rows.len(), 6, "{stdout}");
    for (row, line) in rows.iter().zip(lines.iter().skip(1)).skip(1) {
        // Every column but the sequence numbers starts where the header's
        // does; the numbers are right-aligned under `seq`.
        let number = line.split_whitespace().next().expect("a sequence number");
        assert_eq!(
            row[0] + number.len(),
            rows[0][0] + "seq".len(),
            "the numbers are not right-aligned: {stdout}"
        );
        assert_eq!(&row[1..4], &rows[0][1..4], "a column moved out of line: {stdout}");
        // A dependency list is more than one word, so the gate column is the
        // last word on the line: it is the one that has to line up.
        assert_eq!(row.last(), rows[0].last(), "the gate column moved: {stdout}");
    }
    assert!(lines[1].starts_with("seq  step"), "{stdout}");
    assert!(lines[2].starts_with("  1  build"), "{stdout}");
    // One step is one step.
    let (code, stdout, stderr) = graph(ONE, &[]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.starts_with("ship.ks — 1 step, env: default\n"), "{stdout}");
}

#[test]
fn a_file_with_errors_is_reported_and_exits_one() {
    let (code, stdout, stderr) = graph(SITE, &[]);
    assert_eq!(code, 1, "{stderr}");
    assert!(
        stdout.starts_with("✗ ship.ks:21  deploy.image  expected oci.Digest, got oci.Tag\n"),
        "{stdout}"
    );
    assert!(!stdout.contains("route:"), "a file that does not check has no plan: {stdout}");
}

/// A machine format owns stdout: the diagnostics go to stderr, and the exit
/// code is the same one `check` would give.
#[test]
fn a_machine_format_keeps_stdout_free_of_diagnostics() {
    for format in ["dot", "json"] {
        let (code, stdout, stderr) = graph(SITE, &["--format", format]);
        assert_eq!(code, 1, "{stderr}");
        assert!(stdout.is_empty(), "{format}: {stdout}");
        assert!(stderr.starts_with("✗ ship.ks:21"), "{format}: {stderr}");
    }
}

/// An event no `on:` reaches is a usage error: the route it would print is
/// one no run takes.
#[test]
fn an_event_no_trigger_reaches_is_a_usage_error() {
    let (code, stdout, stderr) = graph(HERO, &["--event", "pr"]);
    assert_eq!(code, 2);
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("`--event pr` reaches nothing"), "{stderr}");
    assert!(stderr.contains("this file declares `on: push main`"), "{stderr}");
    // An event the file does declare still plans.
    let (code, stdout, stderr) = graph(HERO, &["--event", "push main"]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("route: push → build → plan → review → apply → deploy\n"), "{stdout}");
}

/// A file with no `on:` has no event to lead the route: the steps are the
/// whole of it.
#[test]
fn a_file_with_no_trigger_prints_the_route_as_the_steps() {
    let (code, stdout, stderr) = graph(BARE, &[]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("route: build → deploy\n"), "{stdout}");
    let (code, stdout, stderr) = graph(BARE, &["--format", "json"]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("  \"triggers\": [],\n"), "{stdout}");
    // And there is no event to plan for either.
    let (code, _, stderr) = graph(BARE, &["--event", "push"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("this file declares no `on:`"), "{stderr}");
}

/// An unknown format is a usage error, for `graph` as for `check` — and
/// `check --format dot` stays one too.
#[test]
fn an_unknown_format_is_a_usage_error() {
    let (code, stdout, stderr) = graph(HERO, &["--format", "graphviz"]);
    assert_eq!(code, 2);
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.starts_with("usage: keepshipping check"), "{stderr}");

    let out = Command::new(env!("CARGO_BIN_EXE_keepshipping"))
        .args(["check", "--format", "dot"])
        .current_dir(HERO)
        .env_remove("CI")
        .output()
        .expect("run keepshipping");
    assert_eq!(out.status.code(), Some(2));
}
