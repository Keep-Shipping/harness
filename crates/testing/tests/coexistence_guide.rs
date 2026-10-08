//! Drift guard for [`docs/COEXISTENCE.md`](../../../docs/COEXISTENCE.md).
//!
//! That guide is an adoption document, and its whole value is that a reader can
//! trust the commands in it — so what is most likely to rot is checked here
//! against the code rather than a human's memory: the `ship.ks` example goes
//! through the **real checker**, and every flag the guide puts after
//! `keepshipping run` is one the CLI **actually accepts**, read out of
//! `args.rs`'s own `USAGE` rather than a list copied here that could itself go
//! stale. The YAML fences are parsed for syntax, which is what a fence is for,
//! and for each step carrying exactly one of `uses:` or `run:` — the one shape
//! error GitHub rejects and a YAML parser cannot see. A typo inside a value
//! still parses; this is not a linter.

use std::collections::BTreeSet;

/// The guide under test.
const GUIDE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/COEXISTENCE.md"));

/// The CLI's argument source, for its `USAGE` string — the single place every
/// accepted flag is written down.
const ARGS_SRC: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../cli/src/args.rs"));

/// What one walk of a workflow tree turned up: `steps:` lists GitHub will not
/// run, and keys that hand a job a way to authenticate.
#[derive(Default)]
struct Findings {
    steps: Vec<String>,
    credentials: Vec<String>,
}

/// Every fenced block tagged `lang`, in the order the guide shows them. A guide
/// that renames a fence's tag loses it here, which is the point.
fn fences(doc: &str, lang: &str) -> Vec<String> {
    let (open, close) = (format!("```{lang}\n"), "\n```");
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(found) = doc[at..].find(&open) {
        let start = at + found + open.len();
        let end = start + doc[start..].find(close).expect("an unclosed ``` fence");
        out.push(doc[start..end].to_string());
        at = end + close.len();
    }
    out
}

/// The flags `keepshipping run` accepts, read out of the `USAGE` constant.
///
/// `USAGE` lays `run` out over several indented continuation lines and starts
/// every other subcommand's line with `keepshipping` at that same indent, so
/// the run block runs from the line naming `keepshipping run` to the next one
/// that starts a subcommand.
fn accepted_run_flags() -> BTreeSet<String> {
    let body = ARGS_SRC
        .split_once("pub const USAGE: &str = \"\\")
        .unwrap_or_else(|| panic!("args.rs has no `USAGE` constant to read"))
        .1;

    let mut lines = body.lines().skip_while(|l| !l.contains("keepshipping run "));
    let opening = lines.next().expect("args.rs USAGE has no `keepshipping run` line");
    let block = std::iter::once(opening)
        .chain(lines.take_while(|l| !l.trim_start().starts_with("keepshipping ")));
    let flags: Vec<String> = block.flat_map(|l| token_flags(l).into_iter()).collect();

    // Canary: if the scan above ever comes back empty the flag check goes
    // vacuously green, which is the one failure mode a substring search has.
    for canary in ["--dry-run", "--env", "--until"] {
        assert!(flags.iter().any(|f| f == canary), "the run block lost {canary}: {flags:?}");
    }
    flags.into_iter().collect()
}

/// Every `--flag` token on one line, accepting the bracketed `[--flag]` spelling
/// `USAGE` uses. Short flags are not collected: `-v` is not what this is about.
fn token_flags(line: &str) -> BTreeSet<String> {
    let chars: Vec<char> = line.chars().collect();
    let mut flags = BTreeSet::new();
    let mut i = 0;
    while i + 1 < chars.len() {
        if chars[i..i + 2] != ['-', '-'] {
            i += 1;
            continue;
        }
        let end = i
            + 2
            + chars[i + 2..].iter().take_while(|c| c.is_ascii_alphanumeric() || **c == '-').count();
        if end > i + 2 {
            flags.insert(chars[i..end].iter().collect());
        }
        i = end;
    }
    flags
}

/// Walk a whole workflow tree, collecting step-shape errors and credential keys.
/// The tree, not just the top level: a job-level `permissions:` is exactly where
/// an `id-token` hides, and a top-level-only look would miss it.
fn walk(value: &serde_yaml_ng::Value, out: &mut Findings) {
    use serde_yaml_ng::Value::{Mapping, Sequence};
    match value {
        Mapping(map) => {
            for (k, v) in map {
                match k.as_str() {
                    Some("steps") => check_steps(v, out),
                    Some(name @ ("id-token" | "environment" | "secrets")) => {
                        out.credentials.push(name.to_string())
                    }
                    _ => walk(v, out),
                }
            }
        }
        Sequence(items) => items.iter().for_each(|item| walk(item, out)),
        _ => {}
    }
}

/// Every entry under a `steps:` list must carry exactly one of `uses:` (an
/// action) and `run:` (a command). A YAML parser is perfectly happy with a step
/// that carries neither, or both; GitHub is not, and these snippets get pasted.
fn check_steps(value: &serde_yaml_ng::Value, out: &mut Findings) {
    let serde_yaml_ng::Value::Sequence(entries) = value else {
        return out.steps.push("`steps:` is not a list".to_string());
    };
    for entry in entries {
        let serde_yaml_ng::Value::Mapping(step) = entry else {
            out.steps.push("a `steps:` entry is not a mapping".to_string());
            continue;
        };
        let has = |key: &str| step.contains_key(serde_yaml_ng::Value::from(key));
        match (has("uses"), has("run")) {
            (true, true) => out.steps.push("a step has both `uses:` and `run:`".to_string()),
            (false, false) => out.steps.push("a step has neither `uses:` nor `run:`".to_string()),
            _ => {}
        }
    }
}

/// The example site file is one the CLI accepts, with the edges the prose claims.
/// If this fails, the guide hands a reader something `keepshipping check` refuses.
#[test]
fn the_ship_ks_example_checks_clean() {
    let src = fences(GUIDE, "ks")
        .into_iter()
        .next()
        .expect("COEXISTENCE.md has no ```ks fence; this test checks the first one");

    let checked = ks_core::check(&ks_lang::parse(&src));
    assert!(
        checked.diagnostics.is_empty(),
        "the ship.ks example in COEXISTENCE.md does not check clean: {:#?}\n\n{src}",
        checked.diagnostics
    );

    // The guide's argument that ordering comes off the data, not a written
    // order, is only true if the edges it names are there.
    let mut edges = checked.workflow.edges().to_vec();
    edges.sort();
    let claimed = [("plan", "apply"), ("plan", "review"), ("review", "apply")];
    assert_eq!(
        edges,
        claimed.map(|(a, b)| (a.to_string(), b.to_string())),
        "the guide says `review` reads plan.changes and `apply` reads plan.file, so the \
         graph edges in the example no longer say that"
    );
    assert!(
        checked.workflow.topo_order().is_some(),
        "the example's graph has a cycle, which the guide's ordering story cannot survive"
    );
}

/// Every workflow fence parses, every step in it is one GitHub Actions runs, and
/// the first fence — the shadow job — grants no credential anywhere in its tree.
/// The credential half is the load-bearing part: the guide's whole stage-0
/// argument is that the shadow job cannot mint one, so the example growing an
/// `id-token: write` or an `environment:` is the guide becoming what it warns
/// against.
#[test]
fn every_workflow_example_parses_and_the_shadow_job_holds_no_credential() {
    let sources = fences(GUIDE, "yaml");
    assert!(!sources.is_empty(), "docs/COEXISTENCE.md has no ```yaml fence; this test parses them");

    for (index, src) in sources.iter().enumerate() {
        let doc: serde_yaml_ng::Value = serde_yaml_ng::from_str(src).unwrap_or_else(|e| {
            panic!("```yaml fence {index} is not parseable YAML: {e}\n\n{src}")
        });

        let mut found = Findings::default();
        walk(&doc, &mut found);
        assert!(
            found.steps.is_empty(),
            "a step in ```yaml fence {index} of COEXISTENCE.md is not one GitHub Actions accepts: \
             {:?}. Each step needs exactly one of `uses:` or `run:`.\n\n{src}",
            found.steps
        );

        if index == 0 {
            assert!(
                doc.as_mapping()
                    .is_some_and(|m| m.contains_key(serde_yaml_ng::Value::from("jobs"))),
                "the first ```yaml fence in COEXISTENCE.md has no `jobs:`; it is not a workflow:\n{src}"
            );
            assert!(
                found.credentials.is_empty(),
                "the first workflow in COEXISTENCE.md — the shadow job, which the guide says holds no \
                 credential — now declares {:?}. Adding `id-token: write` or an `environment:` to it is \
                 what turns the shadow into a second deploy path:\n{src}",
                found.credentials
            );
        }
    }
}

/// Every `keepshipping run --flag` in the guide is a flag the CLI accepts. A
/// guide that sends a reader to `run --foo` they cannot type is worse than one
/// that sends them nowhere: the first error costs an afternoon.
#[test]
fn every_run_flag_the_guide_shows_is_a_real_flag() {
    let accepted = accepted_run_flags();

    let mut shown = BTreeSet::new();
    for line in GUIDE.lines() {
        if let Some((_, rest)) = line.rsplit_once("keepshipping run") {
            shown.extend(token_flags(rest));
        }
    }
    assert!(!shown.is_empty(), "COEXISTENCE.md shows no `keepshipping run` to hold to");

    for flag in &shown {
        assert!(
            accepted.contains(flag),
            "COEXISTENCE.md shows `keepshipping run {flag}`, which the CLI does not accept; \
             run's flags are: {accepted:?}"
        );
    }
}

/// Resume is a subcommand. There is no `--resume` flag, and a reader who goes
/// looking for one has been told something false.
#[test]
fn the_guide_never_claims_a_resume_flag() {
    assert!(
        !GUIDE.contains("--resume"),
        "COEXISTENCE.md mentions `--resume`; resume is its own subcommand, `keepshipping resume RUN-ID [FILE]`"
    );
    assert!(
        GUIDE.contains("keepshipping resume RUN-ID [FILE]"),
        "COEXISTENCE.md should name the real form of resume, `keepshipping resume RUN-ID [FILE]`"
    );
}
