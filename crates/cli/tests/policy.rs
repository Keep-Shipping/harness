//! Golden snapshots of `keepshipping policy explain` on the site's policy over
//! the hero file: the documented decision table, byte for byte, colour off
//! (stdout is not a terminal under `cargo test`). Re-run with
//! `UPDATE_GOLDEN=1 cargo test -p ks-cli --test policy` after reviewing the
//! diff.

use std::fs;
use std::path::Path;
use std::process::Command;

const POLICY: &str = "tests/fixtures/policy";

fn explain(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_keepshipping"))
        .arg("policy")
        .arg("explain")
        .args(args)
        // The golden bytes are the ones from a terminal-less local run; a `CI`
        // in the parent would add the undeclared-format warning to the fixture
        // and rewrite the example this file pins.
        .env_remove("CI")
        .env_remove("GITHUB_ACTIONS")
        .current_dir(POLICY)
        .output()
        .expect("run keepshipping");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn read_or_update(name: &str, actual: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(POLICY).join(name);
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        fs::write(&path, actual).expect("write golden");
        return actual.to_string();
    }
    fs::read_to_string(path).unwrap_or_default()
}

#[test]
fn an_agent_may_build_and_plan_but_asks_before_it_applies_or_deploys_to_prod() {
    let (code, stdout, stderr) = explain(&["--as", "agent"]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    // Not just the golden: the rows that carry the site's intent are
    // asserted, so a stray UPDATE_GOLDEN cannot redefine the policy.
    for row in [
        "build   build           can            file ship.ks:34",
        "plan    plan            can            file ship.ks:34",
        "review  —               not governed   —",
        "apply   apply           ask @platform  file ship.ks:36",
        "        destroy*        ask @platform  file ship.ks:36",
        "deploy  deploy staging  can            file ship.ks:34",
        "deploy  deploy prod     ask @platform  file ship.ks:36",
    ] {
        assert!(stdout.contains(row), "missing row:\n{row}\n\n{stdout}");
    }
    assert_eq!(stdout, read_or_update("explain.agent", &stdout));
}

#[test]
fn no_row_carries_two_decisions() {
    // The apply's destroy face is a row of its own with an empty step cell. If
    // it ever folds back onto the apply row, one line would name two actions
    // and the table would stop being readable at a glance.
    for (name, args) in [
        ("agent", &["--as", "agent"][..]),
        ("human", &["--as", "human"]),
        ("prod", &["--env", "prod"]),
    ] {
        let (_, stdout, _) = explain(args);
        let apply = stdout
            .lines()
            .find(|l| l.trim_start().starts_with("apply "))
            .unwrap_or_else(|| panic!("no apply row:\n{stdout}"));
        assert!(!apply.contains("destroy"), "the apply row carries a second action:\n{apply}");
        // The continuation names `destroy`, optionally with an environment, and
        // ends at the `*` that points at the footnote under the table.
        let destroy = stdout
            .lines()
            .find(|l| l.starts_with(' ') && l.trim_start().starts_with("destroy"))
            .unwrap_or_else(|| panic!("no destroy continuation row:\n{stdout}"));
        assert!(destroy.trim_start().starts_with("destroy"), "{name}: {destroy}");
        assert!(destroy.contains('*'), "no footnote marker: {destroy}");
        assert!(
            stdout.contains("* an apply whose plan destroys or replaces anything is a destroy"),
            "{stdout}"
        );
        // Every decision cell is one of three words, so no row can hold two.
        for line in stdout.lines().skip(4) {
            let decisions = ["can", "ask", "never"].iter().filter(|d| line.contains(*d)).count();
            assert!(decisions <= 1, "row carries two decisions:\n{line}");
        }
    }
}

#[test]
fn a_human_follows_the_same_file_minus_the_leash() {
    let (code, stdout, stderr) = explain(&["--as", "human"]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    // The file declares no `humans:` section, so nothing binds a human and
    // every governed answer comes from `default` — including `destroy`, which
    // the hard rule reserves for agents.
    for row in stdout.lines().skip(4).take_while(|l| !l.is_empty()) {
        if row.contains("not governed") {
            continue;
        }
        assert!(row.contains("can"), "every governed row is an allow:\n{stdout}");
        assert!(row.contains("default"), "every source is `default`:\n{stdout}");
    }
    assert!(!stdout.contains("@platform"), "the leash does not reach a human:\n{stdout}");
    assert_eq!(stdout, read_or_update("explain.human", &stdout));
}

#[test]
fn naming_the_environment_takes_the_answer_that_environment_gets() {
    let (code, stdout, stderr) = explain(&["--env", "prod"]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    // The staging grant does not widen into prod: `can: deploy staging` is a
    // decision about staging, so only `deploy prod` is left to ask about.
    assert!(!stdout.contains("deploy staging"), "{stdout}");
    assert!(stdout.contains("deploy prod"), "{stdout}");
    assert_eq!(stdout, read_or_update("explain.agent.prod", &stdout));
}

#[test]
fn the_first_line_says_no_baseline_is_configured() {
    // ADR 0012's acceptance criterion for this command: the fail-open case is
    // stated before anything else, not as a footnote.
    for args in [&["--as", "agent"][..], &["--as", "human"], &["--env", "prod"]] {
        let (_, stdout, _) = explain(args);
        assert_eq!(
            stdout.lines().next().unwrap_or_default(),
            "no baseline configured: the effective policy is this file's own policy",
            "{args:?}"
        );
    }
}

#[test]
fn an_unknown_environment_is_a_usage_error() {
    let (code, stdout, stderr) = explain(&["--env", "qa"]);
    assert_eq!(code, 2, "{stdout}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("unknown environment `qa`"), "{stderr}");
    assert!(stderr.contains("staging, prod"), "{stderr}");
}
