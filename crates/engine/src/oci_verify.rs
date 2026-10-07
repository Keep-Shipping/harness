//! The `oci.verify` step kind: refuses to go on with an image nobody signed as
//! the identity the workflow named ([#61](https://github.com/Keep-Shipping/harness/issues/61)).
//!
//! The step changes nothing. It reads the signatures attached to a digest, and
//! either names the identity that signed or refuses — the refusal is the point,
//! since a deploy that runs against an unsigned or wrongly signed image is the
//! failure this exists to catch.

use ks_core::ports::BoxFuture;
use ks_core::ports::script_host::{Value, ValueType};
use ks_core::ports::supply_chain::ImageRef;
use ks_core::step::{
    ActionClass, ActionKind, Field, Inputs, Outputs, Port, StepCtx, StepError, StepKind,
    StepSchema, TypeRef, Version,
};

use crate::signing::{SignedBy, identity_text, verify_signed};

/// The first `&str` input under `name`; inputs arrive prepared, so a wrong type
/// never reaches a step.
fn text<'a>(inputs: &'a Inputs, name: &str) -> &'a str {
    match inputs.get(name) {
        Some(Value::String(text)) => text,
        _ => "",
    }
}

/// Checks that an image was signed by a named identity, and says who.
#[derive(Debug, Default)]
pub struct OciVerify;

impl StepKind for OciVerify {
    fn name(&self) -> &'static str {
        "oci.verify"
    }

    fn version(&self) -> Version {
        Version::new(1, 0, 0)
    }

    fn schema(&self) -> StepSchema {
        StepSchema {
            doc: "Refuses to continue unless an image digest carries a signature from a named \
                  identity.",
            inputs: vec![
                Field::new(
                    "image",
                    TypeRef::Builtin(ValueType::String),
                    "the digest-pinned image to verify, as `repository@sha256:…`",
                ),
                Field::new(
                    "signed_by",
                    TypeRef::Builtin(ValueType::String),
                    "who must have signed it: `key:<key-id>`, or `<subject> from <issuer>`",
                ),
            ],
            outputs: vec![
                Field::new("digest", TypeRef::Builtin(ValueType::String), "the verified digest"),
                Field::new(
                    "identity",
                    TypeRef::Builtin(ValueType::String),
                    "the identity the signature was made as",
                ),
            ],
        }
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::Registry, Port::Signer]
    }

    /// Reading signatures changes nothing, so it needs no approval of its own —
    /// what needs one is whatever the workflow does next.
    fn action(&self, _inputs: &Inputs) -> ActionClass {
        ActionClass::new(ActionKind::Other)
    }

    fn run(&self, ctx: StepCtx, inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>> {
        Box::pin(async move {
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
            let image = ImageRef::parse(text(&inputs, "image")).map_err(|error| {
                StepError::InvalidInput { field: "image".to_string(), reason: error.to_string() }
            })?;
            let Some(digest) = image.digest() else {
                return Err(StepError::InvalidInput {
                    field: "image".to_string(),
                    reason: format!("`{image}` is a tag; verification needs a digest reference"),
                });
            };
            let expected = SignedBy::parse(text(&inputs, "signed_by")).map_err(|error| {
                StepError::InvalidInput {
                    field: "signed_by".to_string(),
                    reason: error.to_string(),
                }
            })?;
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
                &[("image", text(&inputs, "image")), ("signed_by", &expected.to_string())],
            );
            let mut outputs = Outputs::new();
            outputs.insert("digest".to_string(), Value::from(digest.to_string()));
            outputs.insert("identity".to_string(), Value::from(identity));
            Ok(outputs)
        })
    }
}
