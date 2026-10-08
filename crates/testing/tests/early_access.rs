//! Drift guard for [`docs/EARLY-ACCESS.md`](../../../docs/EARLY-ACCESS.md).
//!
//! That runbook is only useful while it is true: it points at paths, and it
//! picks batch 1 as the stack the hero file actually exercises. Both rot
//! quietly — a renamed doc stops the team running the batch, and a hero file
//! that drops `tofu.apply` silently makes the audience wrong. So paths are
//! resolved against the working tree (two levels up from
//! `CARGO_MANIFEST_DIR`), the hero file and the doc are checked against *each
//! other* on the three steps the stack rests on, and the invite's one fenced
//! block is held to the one-email promise it is reviewed under. std-only.

use std::path::{Path, PathBuf};

/// The runbook under test.
const DOC: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/EARLY-ACCESS.md"));

/// The workflow file the doc names as the source of the batch-1 stack.
const HERO: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../cli/tests/fixtures/hero/ship.ks"));

/// The step names `tofu.plan` → `tofu.apply` → `k8s.rollout` that batch 1 is
/// defined by, in both the doc and the fixture.
const BATCH_ONE_STEPS: [&str; 3] = ["tofu.plan", "tofu.apply", "k8s.rollout"];

/// Only these prefixes are repo-relative paths the doc means as files; anything
/// else in backticks (`ship.ks`, `waitlist/confirm`, a step name) is not.
const PATH_PREFIXES: [&str; 5] = ["docs/", "crates/", "ventures/", "adapters/", "README.md"];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Backticked spans that start a repo-relative path, `:line`/`:NN` and
/// `#anchor` suffixes stripped.
fn referenced_paths(doc: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = doc;
    while let Some(start) = rest.find('`') {
        let tail = &rest[start + 1..];
        let Some(end) = tail.find('`') else { break };
        let raw = &tail[..end];
        if PATH_PREFIXES.iter().any(|p| raw.starts_with(p)) {
            let path = raw.split([':', '#']).next().unwrap_or(raw);
            out.push(path.to_string());
        }
        rest = &tail[end + 1..];
    }
    out
}

/// The single ```text fence: the invite email.
fn text_fence(doc: &str) -> Option<String> {
    let (open, close) = ("```text\n", "\n```");
    let start = doc.find(open)? + open.len();
    let end = start + doc[start..].find(close)?;
    Some(doc[start..end].to_string())
}

#[test]
fn every_referenced_repo_path_exists() {
    let root = workspace_root();
    let missing: Vec<String> =
        referenced_paths(DOC).into_iter().filter(|p| !root.join(p).exists()).collect();
    assert!(
        missing.is_empty(),
        "docs/EARLY-ACCESS.md names repo paths that do not exist: {missing:?}. The team \
         runs the batch from this doc, so fix the doc (or add the file); a stale path is \
         a broken step, not a typo."
    );
}

#[test]
fn the_hero_file_still_is_the_batch_one_stack() {
    for step in BATCH_ONE_STEPS {
        assert!(
            HERO.contains(step),
            "crates/cli/tests/fixtures/hero/ship.ks no longer uses `{step}`, and \
             docs/EARLY-ACCESS.md picks batch 1 (Terraform/OpenTofu + Kubernetes) because \
             that file is that stack. Put the step back, or re-pick the batch in the doc."
        );
        assert!(
            DOC.contains(step),
            "docs/EARLY-ACCESS.md stopped naming `{step}`, which the batch-1 stack claim is \
             built on (see `crates/cli/tests/fixtures/hero/ship.ks`). Restore the step list, \
             or re-derive batch 1 from the current hero file."
        );
    }
}

#[test]
fn the_invite_honours_the_one_email_promise() {
    let Some(invite) = text_fence(DOC) else {
        panic!(
            "docs/EARLY-ACCESS.md has no ```text fence. The invite is the whole point of \
                the batch — restore the fenced invite, reviewed against the site."
        )
    };
    assert_eq!(
        DOC.matches("```text").count(),
        1,
        "docs/EARLY-ACCESS.md should hold exactly one ```text fence (the invite). Any other \
         is an unreviewed promise; fold it into the invite or retag its fence."
    );
    let needles = [
        "one email",
        "Terraform",
        "OpenTofu",
        "Kubernetes",
        "GitHub Actions",
        "will not email you again",
    ];
    for needle in needles {
        assert!(
            invite.contains(needle),
            "the invite in docs/EARLY-ACCESS.md no longer says \"{needle}\". The site promises \
             \"One email when your invite is ready, nothing else\"; the review table under \
             the invite is only true while the wording stays."
        );
    }
    for banned in ["unsubscribe", "newsletter", "reminder"] {
        assert!(
            !invite.to_lowercase().contains(banned),
            "the invite in docs/EARLY-ACCESS.md now mentions \"{banned}\". The one-email \
             promise means no list, no reminder, no follow-up — if you keep the word, \
             re-read The promise and re-review the table."
        );
    }
}
