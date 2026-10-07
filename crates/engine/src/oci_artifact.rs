//! The `oci.artifact` step: push files as an OCI artifact with an
//! `artifactType` and media types
//! ([#62](https://github.com/Keep-Shipping/harness/issues/62)).
//!
//! Helm charts (in the Helm OCI layout), SBOMs, policy bundles, block packages
//! and plan summaries are all OCI artifacts — files packaged with an
//! `artifactType`, linked to an image via a `subject` digest so `referrers`
//! can find them. This step reads files, resolves a shorthand (`helm`, `spdx`,
//! `cyclonedx`) or a verbatim media type to the `artifactType`, pushes the
//! artifact through the [`Registry`] port, tags it, and optionally signs the
//! manifest digest through the [`Signer`] port.
//!
//! The step ends where the next one begins: it hands back a digest and a
//! `repository@digest` reference. Installing that chart is a `Cluster` step's
//! job ([`Cluster::upgrade`](ks_core::ports::cluster::Cluster::upgrade)), and
//! it should consume the `ref`, so the cluster gets the pinned bytes rather
//! than whatever the tag points at a minute later.
//!
//! [`Registry`]: ks_core::ports::supply_chain::Registry
//! [`Signer`]: ks_core::ports::supply_chain::Signer

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ks_core::ports::BoxFuture;
use ks_core::ports::run_context::NetworkScope;
use ks_core::ports::script_host::{Value, ValueType};
use ks_core::ports::supply_chain::{
    ArtifactUpload, Digest, ImageRef, Registry, SignPayload, Signer, SignerIdentity,
};
use ks_core::step::{
    ActionClass, ActionKind, Field, Inputs, Outputs, Port, StepCapabilities, StepCtx, StepError,
    StepKind, StepSchema, TypeRef, Version,
};

/// The OCI image manifest media type artifacts are packaged as.
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

/// The manifest annotation carrying the media type of the artifact's layer.
///
/// [`ArtifactUpload`] has one `media_type` for the manifest and an
/// `artifact_type`, but no per-blob media type: an adapter that wrote every
/// layer as a plain OCI tar would package a Helm chart nobody can pull. The
/// annotation is where the resolved layer media type rides along, so the
/// manifest is self-describing and an adapter can pick it up. (A port that
/// carries layer descriptors outright would be the better home for it.)
const LAYER_MEDIA_TYPE_ANNOTATION: &str = "io.keepshipping.artifact.layerMediaType";

/// The `artifactType` a signature is pushed under: a referrer of the artifact
/// it signs, so `referrers` finds the signature exactly as it finds the SBOM.
/// Cosign writes `application/vnd.dev.cosign.simplesigning.v1+json` here; the
/// signatures this port produces are the signer's own bytes, not that
/// envelope, so it gets its own type rather than borrowing cosign's.
const SIGNATURE_ARTIFACT_TYPE: &str = "application/vnd.keepshipping.artifact.signature.v1";

/// The annotations naming who signed: `keyId` for a
/// [`SignerIdentity::Key`], `issuer` and `subject` for a
/// [`SignerIdentity::Keyless`]. They mirror the identity's own shape, so a
/// verifier rebuilds it from the descriptor without parsing a debug string.
const SIGNATURE_KEY_ID: &str = "io.keepshipping.signature.keyId";
const SIGNATURE_ISSUER: &str = "io.keepshipping.signature.issuer";
const SIGNATURE_SUBJECT: &str = "io.keepshipping.signature.subject";

/// The digest a signature artifact's layer is the signature over.
const SIGNATURE_PAYLOAD_ANNOTATION: &str = "io.keepshipping.signature.payload";

/// The `oci.artifact` step: push files as an OCI artifact.
pub struct OciArtifactStep;

impl StepKind for OciArtifactStep {
    fn name(&self) -> &'static str {
        "oci.artifact"
    }

    fn version(&self) -> Version {
        Version::new(1, 0, 0)
    }

    fn schema(&self) -> StepSchema {
        StepSchema {
            doc: "Push files as an OCI artifact with an artifactType and media types.",
            inputs: vec![
                Field::new(
                    "files",
                    TypeRef::Builtin(ValueType::List),
                    "the files to package as artifact layers",
                ),
                Field::new(
                    "type",
                    TypeRef::Builtin(ValueType::String),
                    "artifact type: `helm`, `spdx`, `cyclonedx`, or a verbatim media type",
                ),
                Field::new(
                    "push",
                    TypeRef::Named("oci.Tag"),
                    "where to push, e.g. `registry.example/charts/app:1.0.0`",
                ),
                Field::new(
                    "subject",
                    TypeRef::Named("oci.Digest"),
                    "the image digest this artifact describes, if any (empty for none)",
                )
                .with_default(Value::from("")),
                Field::new(
                    "sign",
                    TypeRef::Builtin(ValueType::Bool),
                    "sign the pushed manifest digest",
                )
                .with_default(Value::from(false)),
            ],
            outputs: vec![
                Field::new(
                    "digest",
                    TypeRef::Named("oci.Digest"),
                    "the manifest digest the registry reported",
                ),
                Field::new(
                    "ref",
                    TypeRef::Named("oci.Ref"),
                    "the repository@digest reference (by digest, never a tag)",
                ),
            ],
        }
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::Registry]
    }

    fn optional(&self) -> &'static [Port] {
        &[Port::Signer]
    }

    fn action(&self, _inputs: &Inputs) -> ActionClass {
        ActionClass::new(ActionKind::Build)
    }

    /// The registry the artifact goes to is named by `push`, so the hosts this
    /// step reaches cannot be enumerated ahead of the run.
    fn capabilities(&self) -> StepCapabilities {
        StepCapabilities { network: NetworkScope::Any, ..StepCapabilities::default() }
    }

    fn run(&self, ctx: StepCtx, inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>> {
        Box::pin(async move {
            let registry = ctx.ports().registry().ok_or_else(|| StepError::Port {
                port: Port::Registry,
                message: "no registry was provided".to_string(),
            })?;

            let files = file_paths(&inputs, "files")?;
            if files.is_empty() {
                return Err(StepError::InvalidInput {
                    field: "files".to_string(),
                    reason: "an artifact packages at least one file".to_string(),
                });
            }
            let artifact_type = resolve_artifact_type(text(&inputs, "type"))?;
            let blobs = read_blobs(&files)?;

            let push = text(&inputs, "push");
            let image = ImageRef::parse(push).map_err(|error| StepError::InvalidInput {
                field: "push".to_string(),
                reason: error.to_string(),
            })?;
            // `ImageRef::parse` defaults a bare repository to `latest`, which
            // would publish the artifact under a name the run never chose —
            // and one that can be moved the moment after. An `oci.Tag` the
            // caller wrote out is required, so the tag is checked against the
            // raw text rather than the parsed reference (which cannot say
            // whether `latest` was written or defaulted).
            if !names_a_tag(push) {
                return Err(StepError::InvalidInput {
                    field: "push".to_string(),
                    reason: "push must name a tag, e.g. `registry.example/charts/app:1.0.0`"
                        .to_string(),
                });
            }
            let tag = image.tag().ok_or_else(|| StepError::InvalidInput {
                field: "push".to_string(),
                reason: "push must name a tag, not a digest".to_string(),
            })?;
            let repository = image.repository().to_string();

            // Signing is resolved before anything is pushed: a run that asked
            // to sign and cannot is a refusal, not a published artifact the
            // next step has to distrust.
            let signer = if flag(&inputs, "sign") {
                Some(ctx.ports().signer().ok_or_else(|| StepError::Port {
                    port: Port::Signer,
                    message: "sign: true was set but no signer was provided".to_string(),
                })?)
            } else {
                None
            };

            let subject = match text(&inputs, "subject") {
                "" => None,
                text => Some(Digest::parse(text).map_err(|error| StepError::InvalidInput {
                    field: "subject".to_string(),
                    reason: error.to_string(),
                })?),
            };

            let mut annotations = BTreeMap::new();
            // A single-file artifact — a Helm chart, an SBOM — is named by its
            // file; the title annotation is where a client looks for it.
            if let Some(title) = files.first().and_then(|path| path.file_name()) {
                annotations.insert(
                    "org.opencontainers.image.title".to_string(),
                    title.to_string_lossy().into_owned(),
                );
            }
            annotations
                .insert(LAYER_MEDIA_TYPE_ANNOTATION.to_string(), artifact_type.layer.to_string());

            let upload = ArtifactUpload {
                media_type: OCI_MANIFEST.to_string(),
                artifact_type: artifact_type.artifact.to_string(),
                blobs,
                annotations,
                subject,
            };

            let descriptor =
                registry.push_artifact(&repository, &upload).await.map_err(|error| {
                    StepError::Port { port: Port::Registry, message: error.to_string() }
                })?;

            registry.tag(&repository, tag, &descriptor.digest).await.map_err(|error| {
                StepError::Port { port: Port::Registry, message: error.to_string() }
            })?;

            if let Some(signer) = signer {
                push_signature(registry, &repository, &descriptor.digest, signer).await?;
            }

            // The digest is the registry's answer and the ref is built from
            // it, never from the tag: the tag may be moved the moment after.
            let digest = descriptor.digest.to_string();
            let reference = format!("{repository}@{digest}");
            ctx.log().info(
                "pushed artifact",
                &[("digest", digest.as_str()), ("ref", reference.as_str())],
            );

            let mut outputs = Outputs::new();
            outputs.insert("digest".to_string(), Value::from(digest));
            outputs.insert("ref".to_string(), Value::from(reference));
            Ok(outputs)
        })
    }
}

/// Signs the pushed manifest digest and stores the signature as a referrer of
/// it, so `registry.referrers(digest)` returns the signature alongside whatever
/// else describes the artifact, and a verifier can pull the layer and check it
/// against the identity the annotations name.
///
/// This is the seam another in-flight issue (#61, an engine signing helper)
/// will replace: the helper will own the signer lookup and the signing call, so
/// steps do not each reach for the port directly. The signature *layout* — the
/// cosign envelope a real adapter would write — is that helper's concern; what
/// matters here is that the bytes are stored rather than discarded.
async fn push_signature(
    registry: &Arc<dyn Registry>,
    repository: &str,
    digest: &Digest,
    signer: &Arc<dyn Signer>,
) -> Result<(), StepError> {
    let payload = SignPayload::Digest(digest.clone());
    let signature = signer
        .sign(&payload)
        .await
        .map_err(|error| StepError::Port { port: Port::Signer, message: error.to_string() })?;

    let mut annotations = BTreeMap::new();
    annotations.insert(SIGNATURE_PAYLOAD_ANNOTATION.to_string(), digest.to_string());
    match &signature.identity {
        SignerIdentity::Key { key_id } => {
            annotations.insert(SIGNATURE_KEY_ID.to_string(), key_id.clone());
        }
        SignerIdentity::Keyless { issuer, subject } => {
            annotations.insert(SIGNATURE_ISSUER.to_string(), issuer.clone());
            annotations.insert(SIGNATURE_SUBJECT.to_string(), subject.clone());
        }
    }

    let upload = ArtifactUpload {
        media_type: OCI_MANIFEST.to_string(),
        artifact_type: SIGNATURE_ARTIFACT_TYPE.to_string(),
        blobs: vec![signature.bytes],
        annotations,
        // The signature is *for* this artifact, so the artifact is its subject
        // — the same link an SBOM carries to the image it describes.
        subject: Some(digest.clone()),
    };
    let _descriptor = registry
        .push_artifact(repository, &upload)
        .await
        .map_err(|error| StepError::Port { port: Port::Registry, message: error.to_string() })?;
    Ok(())
}

/// Whether `push` names its tag explicitly.
///
/// The last `/`-separated segment carries the repository's last path element
/// and, when a tag was written, a `:` after it. A registry host's `:port` is
/// always followed by a `/`, so it is never mistaken for one.
fn names_a_tag(push: &str) -> bool {
    let repository = push.split_once('@').map_or(push, |(repository, _)| repository);
    let last = repository.rsplit('/').next().unwrap_or(repository);
    last.contains(':')
}

/// The `&str` input under `name`; inputs arrive prepared, so a wrong type
/// never reaches a step.
fn text<'a>(inputs: &'a Inputs, name: &str) -> &'a str {
    match inputs.get(name) {
        Some(Value::String(text)) => text,
        _ => "",
    }
}

/// The boolean input under `name`, false when unset.
fn flag(inputs: &Inputs, name: &str) -> bool {
    matches!(inputs.get(name), Some(Value::Bool(true)))
}

/// The `files` input as a list of paths.
fn file_paths(inputs: &Inputs, name: &str) -> Result<Vec<PathBuf>, StepError> {
    match inputs.get(name) {
        Some(Value::List(items)) => {
            let mut paths = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::String(path) => paths.push(PathBuf::from(path)),
                    other => {
                        return Err(StepError::InvalidInput {
                            field: name.to_string(),
                            reason: format!(
                                "each file must be a string path, found a {}",
                                other.value_type()
                            ),
                        });
                    }
                }
            }
            Ok(paths)
        }
        Some(other) => Err(StepError::InvalidInput {
            field: name.to_string(),
            reason: format!("expected a list of paths, found a {}", other.value_type()),
        }),
        None => Err(StepError::InvalidInput {
            field: name.to_string(),
            reason: "it is required but missing".to_string(),
        }),
    }
}

/// Reads every file, in the order given, so a layer is the file the run named.
fn read_blobs(files: &[PathBuf]) -> Result<Vec<Vec<u8>>, StepError> {
    files
        .iter()
        .map(|path| std::fs::read(path).map_err(|error| unreadable(path, &error.to_string())))
        .collect()
}

/// The one message every way of failing to read a file gets.
fn unreadable(path: &Path, reason: &str) -> StepError {
    StepError::Failed(format!("cannot read file {}: {reason}", path.display()))
}

/// The media types an artifact type is packaged with. The `artifactType` is
/// borrowed when it is one of the known shorthands and owned when the caller
/// spelled one out.
struct MediaTypes<'a> {
    /// The manifest's `artifactType`.
    artifact: Cow<'a, str>,
    /// The media type of the layer the files are packaged as.
    layer: &'static str,
}

/// Resolves the `type` shorthand to its media types.
///
/// Known shorthands map to the conventional OCI media types — `helm` to the
/// Helm OCI layout's own config and chart-content types, so a chart pushed
/// here is a chart `helm pull oci://…` accepts. Anything containing `/` is
/// taken verbatim as the `artifactType`. An unknown bare word is rejected with
/// a clear error rather than pushed under a media type nobody recognises.
fn resolve_artifact_type(ty: &str) -> Result<MediaTypes<'_>, StepError> {
    let (artifact, layer) = match ty {
        "helm" => (
            Cow::Borrowed("application/vnd.cncf.helm.config.v1+json"),
            "application/vnd.cncf.helm.chart.content.v1.tar+gzip",
        ),
        "spdx" => (Cow::Borrowed("application/spdx+json"), "application/octet-stream"),
        "cyclonedx" => {
            (Cow::Borrowed("application/vnd.cyclonedx+json"), "application/octet-stream")
        }
        other if other.contains('/') => (Cow::Owned(other.to_string()), "application/octet-stream"),
        other => {
            return Err(StepError::InvalidInput {
                field: "type".to_string(),
                reason: format!(
                    "unknown artifact type {other:?}; use `helm`, `spdx`, `cyclonedx`, or a \
                     verbatim media type containing `/`"
                ),
            });
        }
    };
    Ok(MediaTypes { artifact, layer })
}
