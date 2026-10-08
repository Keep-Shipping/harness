//! Turns a deploy step's `verify:` input into a check over every image the
//! deploy is about to ship ([#113](https://github.com/Keep-Shipping/harness/issues/113)).
//!
//! [`oci.verify`](crate::oci_verify) reads one named image and changes nothing;
//! this is the same check run by a step that is about to change the world. It
//! is shared by `k8s.rollout` and `vm.deploy` because the rule is the same in
//! both: **an image the workflow named an identity for is deployed only if that
//! identity signed its digest.** A deploy that ships an unsigned image, or one
//! signed by a different workflow, is the failure this exists to catch — and a
//! check that runs *after* the first apply would catch it too late to matter.
//!
//! # Called before, never after
//!
//! [`verify_deploy`] takes the digests a deploy has *resolved but not yet
//! applied*, and both callers invoke it as the first thing after their inputs
//! are prepared and before the first call to a cluster or a shell. Verification
//! costs a registry read and changes nothing, so it can always be moved earlier;
//! a refusal that lands mid-deploy could only be reported, not taken back.
//!
//! # An empty image list is a refusal, not a pass
//!
//! A `verify:` asked for with nothing to check is the one shape that could fail
//! open: the loop below runs zero times, the step succeeds, and the run log has
//! no line saying anything was verified. So [`verify_deploy`] refuses an empty
//! `images` before it reads a registry. This is not a hypothetical — it is what
//! `k8s.rollout` produces for a manifest set whose workload kinds the step does
//! not model (a custom resource, an operator's own `Rollout`), whose images are
//! therefore neither pinned nor verified: the deploy would otherwise apply them
//! and report success under a `verify:` that asked about something else.

use ks_core::ports::script_host::Value;
use ks_core::ports::supply_chain::ImageRef;
use ks_core::step::{Inputs, Port, StepCtx, StepError};

use crate::signing::{SignedBy, identity_text, verify_signed};

/// The input a deploy step takes the identity to verify behind. Both callers
/// name it `verify`, and every refusal names this field, so an author is told
/// which of their inputs to edit.
pub const FIELD: &str = "verify";

/// The first `&str` input under `name`; inputs arrive prepared, so a wrong type
/// never reaches a step.
fn text<'a>(inputs: &'a Inputs, name: &str) -> &'a str {
    match inputs.get(name) {
        Some(Value::String(text)) => text,
        _ => "",
    }
}

/// Checks every image in `images` against the identity `verify` names, or does
/// nothing at all.
///
/// `images` are digest-pinned references — `repository@sha256:…` — as the
/// deploy resolved them, so what is verified is exactly what is about to be
/// applied rather than whatever the workflow wrote down.
///
/// An empty or absent `verify` returns `Ok`: nothing was asked for, so nothing
/// is checked. Anything else either passes or refuses, and there is no third
/// answer — a `verify:` the harness cannot satisfy is a failed run, not a
/// quietly skipped check. That is why the registry and the signer are
/// *optional* ports on the deploy steps: a composition with neither still
/// builds, but a run that asks for verification without them stops here.
///
/// A `verify:` with an empty `images` is the one shape that would fail open, so
/// it is refused here rather than left to a caller to notice: see the module's
/// note on it. The field named is `verify`, because that is the input the author
/// has to change.
pub async fn verify_deploy(
    ctx: &StepCtx,
    inputs: &Inputs,
    images: &[String],
) -> Result<(), StepError> {
    let asked = text(inputs, FIELD);
    if asked.trim().is_empty() {
        return Ok(());
    }
    let expected = SignedBy::parse(asked).map_err(|error| StepError::InvalidInput {
        field: FIELD.to_string(),
        reason: error.to_string(),
    })?;
    // Asking who signed nothing is a workflow that has not said what it ships,
    // and a step that answers it by checking nothing reports success over a
    // deploy it never verified. Refused here, before the registry read and
    // before anything the deploy would change.
    if images.is_empty() {
        return Err(StepError::InvalidInput {
            field: FIELD.to_string(),
            reason: format!(
                "`{FIELD}` asks for a signature, but this deploy names no image to verify. Give \
                 it the artifact it ships as `image: <repository>@sha256:…`, or clear `{FIELD}` \
                 to say no verification is wanted"
            ),
        });
    }

    // Only looked up once verification is asked for, so a composition with no
    // registry and no signer is still a valid one.
    let Some(registry) = ctx.ports().registry() else {
        return Err(StepError::Port {
            port: Port::Registry,
            message: "no registry was provided".to_string(),
        });
    };
    let Some(signer) = ctx.ports().signer() else {
        return Err(StepError::Port {
            port: Port::Signer,
            message: "no signer was provided".to_string(),
        });
    };

    for reference in images {
        let image = ImageRef::parse(reference).map_err(|error| StepError::InvalidInput {
            field: FIELD.to_string(),
            reason: format!("`{reference}` is not an image reference: {error}"),
        })?;
        let Some(digest) = image.digest() else {
            return Err(StepError::InvalidInput {
                field: FIELD.to_string(),
                reason: format!("`{image}` is a tag; verification needs a digest reference"),
            });
        };
        let identity = verify_signed(
            signer.as_ref(),
            registry.as_ref(),
            image.repository(),
            digest,
            &expected,
        )
        .await?;
        let identity = identity_text(&identity);
        ctx.log().info(
            &format!("{digest} is signed by {identity}"),
            &[("image", reference.as_str()), (FIELD, &expected.to_string())],
        );
    }
    Ok(())
}

/// The images a deploy step ships when it names them itself: the one digest
/// under `name`, or nothing.
///
/// A deploy that ships several images resolves its own list and hands that to
/// [`verify_deploy`]; this is for the ones with a single `image:` input, where
/// the list is the one reference or — for a step whose image is optional — no
/// reference at all. An absent image is not an error *here*: it is an empty
/// list, and a deploy that ships no image still deploys, exactly as it did
/// before `verify:` existed. What a `verify:` means over an empty list is
/// [`verify_deploy`]'s answer, not this function's.
pub fn images_of(inputs: &Inputs, name: &str) -> Vec<String> {
    let image = text(inputs, name);
    if image.trim().is_empty() { Vec::new() } else { vec![image.to_string()] }
}
