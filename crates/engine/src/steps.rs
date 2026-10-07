//! The catalog of built-in step kinds — what `docs/STEPS.md` is generated from. Step families
//! land here as their crates land. `approval` lands with the run loop: when it does, whether a
//! step auto-approves is decided by `ks_core::auto_rule::auto_approves`, which conjoins the
//! destroys guard whatever the file's `auto:` expression says.

use std::sync::Arc;

use ks_core::step::StepKind;

use crate::oci_verify::OciVerify;
use crate::tofu_plan::TofuPlan;

/// Every built-in step kind, in registration order. Empty until the first step family ships;
/// `docs/STEPS.md` renders the placeholder until then.
pub fn builtin_steps() -> Vec<Arc<dyn StepKind>> {
    vec![Arc::new(OciVerify), Arc::new(TofuPlan)]
}
