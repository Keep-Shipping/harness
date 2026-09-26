//! Drift check: `docs/STEPS.md` must describe exactly what
//! [`ks_engine::steps::builtin_steps`] builds. Run with `KS_BLESS=1` to
//! regenerate the file.

use std::fs;
use std::path::Path;

use ks_core::step::{StepKind, render_steps_markdown};

const REGENERATE: &str =
    "run KS_BLESS=1 cargo test -p ks-engine --test steps_doc to regenerate docs/STEPS.md";

#[test]
fn steps_doc_matches_the_builtin_steps() {
    let steps = ks_engine::steps::builtin_steps();
    let refs: Vec<&dyn StepKind> = steps.iter().map(|step| step.as_ref()).collect();
    let rendered = render_steps_markdown(&refs);
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/STEPS.md");
    if std::env::var("KS_BLESS").as_deref() == Ok("1") {
        fs::write(&path, rendered).expect("docs/STEPS.md should be writable");
        return;
    }
    let current = fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("docs/STEPS.md is missing; {REGENERATE}"));
    assert!(rendered == current, "docs/STEPS.md is stale; {REGENERATE}");
}
