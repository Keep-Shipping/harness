//! The catalog of built-in step kinds — what `docs/STEPS.md` is generated from. Step families
//! land here as their crates land.

use std::sync::Arc;

use ks_core::step::StepKind;

/// Every built-in step kind, in registration order. Empty until the first step family ships;
/// `docs/STEPS.md` renders the placeholder until then.
pub fn builtin_steps() -> Vec<Arc<dyn StepKind>> {
    Vec::new()
}
