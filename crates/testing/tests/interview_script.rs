//! Drift guard for [`docs/INTERVIEWS.md`](../../../docs/INTERVIEWS.md).
//!
//! An interview script is the one document a founder reads out loud to a stranger, so the ways it
//! rots are all ways of telling a prospect something false: a block gone missing, `plan` and
//! `apply` written as subcommands that do not exist, a model string drifted from the adapter, or
//! the honesty constraint about a product that does not run yet quietly dropped.

const SCRIPT: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/INTERVIEWS.md"));
const JEV: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../adapters/jev/src/lib.rs"));

/// Every question block, in order. The numbers are the rows of the batch's answer table.
const BLOCKS: [&str; 6] = [
    "### 1. Current pipeline pain",
    "### 2. Which steps they'd move first",
    "### 3. Would they let agents run plan and apply",
    "### 4. Hosted approvals or a run-log viewer",
    "### 5. GitLab or Buildkite",
    "### 6. Jev, and what a decision is worth",
];

/// Every block is present, in order, and still carries what an interviewer reads off the page: what
/// it decides, and what a bad answer sounds like.
#[test]
fn every_question_block_is_present_and_still_carries_its_reading_guide() {
    let mut at = 0;
    for heading in BLOCKS {
        at += SCRIPT[at..]
            .find(heading)
            .unwrap_or_else(|| panic!("docs/INTERVIEWS.md lost the block heading `{heading}`"))
            + heading.len();
        // One block's body: up to the next `###` heading, or the end of the file.
        let body = &SCRIPT[at..];
        let body = body.split_once("\n### ").map_or(body, |(body, _)| body);
        for rule in ["*What it decides:*", "*What a bad answer sounds like:*"] {
            assert!(
                body.contains(rule),
                "the block `{heading}` lost its {rule} line; an interviewer with only the questions \
                 cannot tell a shrug from an answer"
            );
        }
    }
}

/// `plan` and `apply` are step names, selected with `--until STEP` or `--only STEP`. There is no
/// `keepshipping plan` and no `keepshipping apply` subcommand, so the script has to show the flags
/// and must not print the verbs after the binary.
#[test]
fn the_script_selects_plan_and_apply_as_step_names_not_subcommands() {
    for (flag, step) in [("--until plan", "plan"), ("--only apply", "apply")] {
        assert!(
            SCRIPT.contains(flag),
            "docs/INTERVIEWS.md must show `{step}` selected with `{flag}`; it is a step name, and \
             dropping the other half makes the block read as though an agent run would go through \
             to apply on its own"
        );
    }
    for invented in ["keepshipping plan", "keepshipping apply"] {
        assert!(
            !SCRIPT.contains(invented),
            "docs/INTERVIEWS.md prints `{invented}`, which is not a subcommand — plan and apply are \
             step names chosen with `--until` / `--only` (docs/CREDENTIALS.md)"
        );
    }
}

/// Pull the value of `PINNED_MODEL` out of the adapter source. Asserting the doc against a string
/// the test hardcodes only proves the doc still matches the test: if the pin moves to `jev-2.0.0`
/// and the doc does not, this has to go red.
fn pinned_model() -> String {
    let decl = "pub const PINNED_MODEL: &str = ";
    let start = JEV
        .find(decl)
        .expect("adapters/jev no longer declares `PINNED_MODEL`; take its new home into account")
        + decl.len();
    let rest =
        JEV[start..].split_once('"').expect("`PINNED_MODEL` is no longer a string literal").1;
    rest.split_once('"').expect("`PINNED_MODEL` has no closing quote").0.to_owned()
}

/// The doc quotes the pinned model, and the pin is read out of the adapter rather than trusted from
/// the doc: `jev-latest` is refused there because an alias "makes a decision unreproducible", so a
/// drifted doc string is how that guarantee gets lost in prose.
#[test]
fn the_pinned_model_in_the_script_matches_the_adapter() {
    let pinned = pinned_model();
    assert!(
        !pinned.is_empty() && SCRIPT.contains(&pinned),
        "adapters/jev pins `{pinned}`, but docs/INTERVIEWS.md does not name it; question 6 exists to \
         say the version is pinned rather than floating, and a stale version is worse than none"
    );
}

/// Nothing here runs yet, so the script must say so rather than asking a prospect to evaluate a
/// product. A doc that stops carrying this is a doc that pitches.
#[test]
fn the_script_still_says_the_product_does_not_run_yet() {
    assert!(
        SCRIPT.contains("Nothing here runs yet"),
        "docs/INTERVIEWS.md must say the product does not run yet, or quote README.md doing so. An \
         interview that evaluates it as running collects nothing"
    );
    assert!(
        SCRIPT.contains("not measurements"),
        "docs/INTERVIEWS.md must say the site's workflow files, CLI output and timings are not \
         measurements — that sentence is what stops an interviewer demoing them as results"
    );
}
