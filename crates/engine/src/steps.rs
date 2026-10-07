//! The catalog of built-in step kinds — what `docs/STEPS.md` is generated from — and the
//! nominal types their schemas name. Step families land here as their crates land. `approval`
//! lands with the run loop: when it does, whether a step auto-approves is decided by
//! `ks_core::auto_rule::auto_approves`, which conjoins the destroys guard whatever the file's
//! `auto:` expression says.

use std::sync::Arc;

use ks_core::ports::script_host::ValueType;
use ks_core::step::{StepKind, TypeDef};

use crate::oci_artifact::OciArtifactStep;
use crate::oci_image::OciImage;
use crate::oci_verify::OciVerify;
use crate::tofu_plan::TofuPlan;

/// Every built-in step kind, in registration order.
pub fn builtin_steps() -> Vec<Arc<dyn StepKind>> {
    vec![Arc::new(OciImage), Arc::new(OciArtifactStep), Arc::new(OciVerify), Arc::new(TofuPlan)]
}

/// The named types the built-in steps' schemas refer to, for a
/// [`Harness::builder`](ks_core::harness::HarnessBuilder) to register.
///
/// The checker already knows these names — they are the domain families in
/// `ks_core::catalog` — but a `TypeRef::Named` only resolves against a
/// `TypeDef` on the harness, so anything that composes a run needs this
/// list. Each is a string at heart; what the name buys is that a tag cannot
/// be passed where a digest is wanted, and a digest where a tag is.
#[must_use]
pub fn builtin_types() -> Vec<TypeDef> {
    vec![
        TypeDef {
            name: "oci.Digest",
            base: ValueType::String,
            doc: "an OCI content digest (`sha256:…`), so a reference to content stays one",
        },
        TypeDef {
            name: "oci.Ref",
            base: ValueType::String,
            doc: "an image reference pinned to a digest, as `<repository>@<digest>`",
        },
        TypeDef {
            name: "oci.Tag",
            base: ValueType::String,
            doc: "a mutable image reference, as `<repository>:<tag>`",
        },
        TypeDef {
            name: "oci.Artifact",
            base: ValueType::String,
            doc: "the digest of an artifact attached to an image — an SBOM, a signature",
        },
    ]
}
