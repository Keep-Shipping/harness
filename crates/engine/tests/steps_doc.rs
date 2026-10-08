//! Drift check: `docs/STEPS.md` must describe exactly what
//! [`ks_engine::steps::builtin_steps`] builds. Run with `KS_BLESS=1` to
//! regenerate the file.

use std::fs;
use std::path::Path;

use ks_core::step::{StepKind, render_steps_markdown};

const REGENERATE: &str =
    "run KS_BLESS=1 cargo test -p ks-engine --test steps_doc to regenerate docs/STEPS.md";

/// The step kinds a cargo feature gates. The document describes what a
/// shipped build registers, so they are dropped from the rendering whichever
/// way the flag is set — otherwise `cargo test --all-features` would report
/// every gated step as drift and ask for a document no released build matches.
const FEATURE_GATED: &[&str] = &["decide"];

#[test]
fn steps_doc_matches_the_builtin_steps() {
    let steps = ks_engine::steps::builtin_steps();
    let refs: Vec<&dyn StepKind> = steps
        .iter()
        .filter(|step| !FEATURE_GATED.contains(&step.name()))
        .map(|step| step.as_ref())
        .collect();
    let rendered = render_steps_markdown(&refs, &ks_engine::steps::builtin_types());
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/STEPS.md");
    if std::env::var("KS_BLESS").as_deref() == Ok("1") {
        fs::write(&path, rendered).expect("docs/STEPS.md should be writable");
        return;
    }
    let current = fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("docs/STEPS.md is missing; {REGENERATE}"));
    assert!(rendered == current, "docs/STEPS.md is stale; {REGENERATE}");
}

/// Every built-in step's own `action()` must agree with the catalog's mapping
/// ([#101](https://github.com/Keep-Shipping/harness/issues/101)). The two are
/// written in different places — one on the implementation, one in the
/// catalog the checker reads — and a step that disagrees is a policy answer
/// that depends on which caller you asked.
#[test]
fn every_builtin_step_classifies_the_way_the_catalog_does() {
    use ks_core::action_kind;
    use ks_core::step::Inputs;

    let steps = ks_engine::steps::builtin_steps();
    assert!(!steps.is_empty(), "there are built-in steps to check");
    for step in &steps {
        let expected = action_kind(step.name());
        let actual = step.action(&Inputs::new()).kind;
        assert_eq!(actual, expected, "`{}` classifies itself differently", step.name());
    }
}
