//! The built-in `oci.image` step: build a container image from a Dockerfile, push it, and hand
//! back the registry's digest for it ([#59](https://github.com/Keep-Shipping/harness/issues/59)).
//!
//! Three rules shape it:
//!
//! - **The digest is the registry's.** A builder that says what it pushed is a builder being
//!   believed; [`Registry::resolve`] is the
//!   registry saying what it stored. The step tags, then asks, then compares — and fails rather
//!   than reporting a digest nobody confirmed.
//! - **Secrets are mounts, not args.** A build arg is recorded in the image history and in the
//!   provenance attestation, so a secret passed as one is a secret baked into the artifact. The
//!   values go to the builder as [`BuildSecrets`] and appear in no log line: the log carries the
//!   mount *names*, which are not secret.
//! - **Caching keys on the context.** A build of the same context is the same bytes, so the
//!   context is what the cache key covers — and a run that mounts secrets opts out entirely (see
//!   [`OciImage::caching`]).
//!
//! The BuildKit/buildx adapter this step talks to is not here yet; ADR
//! `0010-image-build-backend.md` describes it. Everything below is exercised against the
//! `ks-testing` fakes, which are content-addressed for real.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ks_core::ports::BoxFuture;
use ks_core::ports::script_host::{Value, ValueType};
use ks_core::ports::secrets::SecretValue;
use ks_core::ports::supply_chain::{
    BuildCache, BuildOutput, BuildRequest, BuildSecrets, Digest, ImageRef, OciLayoutContents,
    Reference, Registry, RegistryError, SignPayload,
};
use ks_core::step::{
    ActionClass, ActionKind, CacheCheck, CacheInput, Caching, Field, Inputs, Outputs, Port,
    StepCtx, StepError, StepKind, StepSchema, TypeRef, Version,
};

/// The step's registered name; what a workflow writes as `build: oci.image`.
pub const NAME: &str = "oci.image";

/// Builds a container image from a Dockerfile, pushes it under the tag it is given, and
/// reports the digest the registry confirms.
pub struct OciImage;

impl StepKind for OciImage {
    fn name(&self) -> &'static str {
        NAME
    }

    fn version(&self) -> Version {
        Version::new(1, 0, 0)
    }

    fn schema(&self) -> StepSchema {
        StepSchema {
            doc: "Builds a container image from a Dockerfile, pushes it, and reports the digest \
                  the registry confirms.",
            inputs: vec![
                Field::new("from", TypeRef::Named("path"), "the Dockerfile to build"),
                // No default, so that `context` means what the issue says it means: omit it and
                // the build context is the Dockerfile's own directory. A literal `.` default
                // would have looked equivalent and been a different directory entirely for a
                // Dockerfile kept in a subdirectory.
                Field::new(
                    "context",
                    TypeRef::Named("path"),
                    "the build context directory; defaults to the Dockerfile's own directory",
                )
                .optional(),
                Field::new("args", TypeRef::Builtin(ValueType::Map), "build args, as ARGs")
                    .with_default(Value::Map(BTreeMap::new())),
                Field::new(
                    "secrets",
                    TypeRef::Builtin(ValueType::Map),
                    "secret values by mount name, mounted into the build and never passed as args",
                )
                .with_default(Value::Map(BTreeMap::new())),
                Field::new(
                    "platforms",
                    TypeRef::Builtin(ValueType::List),
                    "platforms to build for; more than one produces an image index",
                )
                .with_default(Value::List(vec![Value::from(host_platform())])),
                Field::new("target", TypeRef::Builtin(ValueType::String), "the stage to build")
                    .with_default(Value::from("")),
                Field::new("push", TypeRef::Named("oci.Tag"), "the image reference to push"),
                Field::new("sign", TypeRef::Builtin(ValueType::Bool), "whether to sign the image")
                    .with_default(Value::from(false)),
                Field::new(
                    "sbom",
                    TypeRef::Builtin(ValueType::Bool),
                    "whether to ask for an SBOM alongside the image",
                )
                .with_default(Value::from(false)),
                Field::new(
                    "cache",
                    TypeRef::Builtin(ValueType::String),
                    "where the builder may keep its cache: `registry`, `local` or `none`",
                )
                .with_default(Value::from(BuildCache::default().as_str())),
            ],
            outputs: vec![
                Field::new("digest", TypeRef::Named("oci.Digest"), "the digest the registry holds"),
                Field::new(
                    "ref",
                    TypeRef::Named("oci.Ref"),
                    "the image pinned to that digest, as `<repository>@<digest>`",
                ),
                Field::new("tag", TypeRef::Named("oci.Tag"), "the reference that was pushed"),
                Field::new("signed", TypeRef::Builtin(ValueType::Bool), "whether it was signed"),
                Field::new(
                    "sbom",
                    TypeRef::Named("oci.Artifact"),
                    "the SBOM artifact's digest, or empty when there is none",
                ),
                Field::new(
                    "platforms",
                    TypeRef::Builtin(ValueType::List),
                    "the platforms the image was built for",
                ),
            ],
        }
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::ImageBuilder, Port::Registry]
    }

    fn optional(&self) -> &'static [Port] {
        // Only `sign: true` needs a signer; a run that does not sign must not be blocked by a
        // composition that provides none.
        &[Port::Signer]
    }

    fn action(&self, _inputs: &Inputs) -> ActionClass {
        ActionClass::new(ActionKind::Build)
    }

    /// The build context is the whole input: hashing it is what makes "unchanged" provable.
    fn caching(&self, inputs: &Inputs) -> Caching {
        // A mount's value never reaches the cache key, because the key is computed over the
        // *resolved inputs* — the secret values are inputs, and `cache_key` hashes every one of
        // them into a digest that is then written to disk and logged on every miss. A build that
        // mounts secrets therefore does not take part in the cache: rotating a secret would
        // change what a logged key stands for, and the image a hit names is not provably the one
        // this context would produce anyway.
        if !map(inputs, "secrets").is_empty() {
            return Caching::Never;
        }
        let context = context_of(inputs);
        let dockerfile = PathBuf::from(text(inputs, "from"));
        let mut key = vec![CacheInput::File(context.clone())];
        // A Dockerfile outside its own context is hashed separately — the context walk cannot
        // see it.
        if !dockerfile.starts_with(&context) {
            key.push(CacheInput::File(dockerfile));
        }
        Caching::Keyed(key)
    }

    fn verify_cached<'a>(
        &'a self,
        ctx: StepCtx,
        outputs: &'a Outputs,
    ) -> BoxFuture<'a, Result<CacheCheck, StepError>> {
        Box::pin(async move {
            let Some((repository, digest)) = repository_and_digest(outputs) else {
                return Ok(CacheCheck::Stale("the entry carries no digest".to_string()));
            };
            let registry = registry(&ctx)?;
            let exists = registry.exists(&repository, &digest).await.map_err(|error| {
                StepError::Port { port: Port::Registry, message: error.to_string() }
            })?;
            Ok(if exists {
                CacheCheck::Valid(format!("{digest} present in {repository}"))
            } else {
                CacheCheck::Stale(format!("{digest} no longer in {repository}"))
            })
        })
    }

    fn run(&self, ctx: StepCtx, inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>> {
        Box::pin(async move {
            let builder = ctx.ports().image_builder().ok_or_else(|| StepError::Port {
                port: Port::ImageBuilder,
                message: "no image builder was provided".to_string(),
            })?;
            let registry = registry(&ctx)?;
            let push = text(&inputs, "push").to_string();
            let image = ImageRef::parse(&push).map_err(|error| StepError::InvalidInput {
                field: "push".to_string(),
                reason: error.to_string(),
            })?;
            let repository = image.repository().to_string();
            let tag = image.tag().unwrap_or("latest").to_string();
            let context = context_of(&inputs);
            let dockerfile = PathBuf::from(text(&inputs, "from"));
            let platforms = list(&inputs, "platforms");
            let cache = BuildCache::parse(text(&inputs, "cache")).map_err(|offered| {
                StepError::InvalidInput {
                    field: "cache".to_string(),
                    reason: format!("`{offered}` is not registry, local or none"),
                }
            })?;
            let wants_signature = matches!(inputs.get("sign"), Some(Value::Bool(true)));

            // The mount names, never the values: a log line is somewhere a secret ends up.
            let mounted = map(&inputs, "secrets").keys().cloned().collect::<Vec<_>>().join(",");
            let context_text = context.to_string_lossy().into_owned();
            let dockerfile_text = dockerfile.to_string_lossy().into_owned();
            let platforms_text = platforms.join(",");
            ctx.log().info(
                &format!("building {push}"),
                &[
                    ("context", &context_text),
                    ("dockerfile", &dockerfile_text),
                    ("platforms", &platforms_text),
                    ("secrets", &mounted),
                ],
            );

            let request = BuildRequest {
                context,
                dockerfile,
                args: map(&inputs, "args"),
                platforms: platforms.clone(),
                target: non_empty(text(&inputs, "target")),
                push_to: Some(repository.clone()),
                secrets: mounts(&inputs),
                cache,
                sbom: matches!(inputs.get("sbom"), Some(Value::Bool(true))),
            };
            let built = builder
                .build(&request)
                .await
                .map_err(|error| StepError::Failed(error.to_string()))?;

            // Where the bytes are is the builder's business; where they are *addressed* is the
            // registry's. Either way the step ends holding a digest the registry is asked about.
            let reported = match built {
                BuildOutput::PushedImage { digest, .. } => digest,
                BuildOutput::OciLayout { path, manifest } => {
                    push_layout(registry.as_ref(), &repository, &path, &manifest).await?
                }
            };
            let digest = confirm(registry.as_ref(), &repository, &tag, &reported).await?;

            let signed = if wants_signature {
                let signer = ctx.ports().signer().ok_or_else(|| StepError::Port {
                    port: Port::Signer,
                    message: "`sign: true` needs a Signer port, and this composition provides none"
                        .to_string(),
                })?;
                signer.sign(&SignPayload::Digest(digest.clone())).await.map_err(|error| {
                    StepError::Failed(format!("signing {digest} failed: {error}"))
                })?;
                true
            } else {
                false
            };

            ctx.log().info(
                &format!("pushed {push}"),
                &[("digest", &digest.to_string()), ("signed", &signed.to_string())],
            );

            let mut outputs = Outputs::new();
            outputs.insert("digest".to_string(), Value::from(digest.to_string()));
            outputs.insert("ref".to_string(), Value::from(format!("{repository}@{digest}")));
            outputs.insert("tag".to_string(), Value::from(push));
            outputs.insert("signed".to_string(), Value::from(signed));
            // No port produces an SBOM yet, so there is never an artifact to name. The output
            // is declared (a step may not invent outputs) and empty means "none": once the
            // BuildKit adapter lands, ADR 0010 has it push the SBOM and report its digest.
            outputs.insert("sbom".to_string(), Value::from(""));
            outputs.insert(
                "platforms".to_string(),
                Value::List(
                    platforms.iter().map(|platform| Value::from(platform.as_str())).collect(),
                ),
            );
            Ok(outputs)
        })
    }
}

/// The platform this build runs on, as BuildKit spells it. `ARCH` is the Rust-level name;
/// the OCI ones are the Go ones every tool agrees on.
fn host_platform() -> String {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    format!("linux/{arch}")
}

/// The build context: the input, or the Dockerfile's own directory when it names none.
fn context_of(inputs: &Inputs) -> PathBuf {
    let context = text(inputs, "context");
    if !context.is_empty() {
        return PathBuf::from(context);
    }
    PathBuf::from(text(inputs, "from")).parent().map_or_else(PathBuf::new, Path::to_path_buf)
}

/// The secrets the run mounted, as BuildKit mounts. The values arrive already resolved: the
/// engine resolves a step's secrets and registers them with the run's redactor before it calls
/// [`run`](StepKind::run), so what arrives here is what the log is scrubbed against.
fn mounts(inputs: &Inputs) -> BuildSecrets {
    let mut secrets = BuildSecrets::new();
    if let Some(Value::Map(entries)) = inputs.get("secrets") {
        for (name, value) in entries {
            if let Value::String(text) = value {
                secrets.insert(name.clone(), SecretValue::new(text.clone().into_bytes()));
            }
        }
    }
    secrets
}

/// Reads the manifest a builder wrote into its local layout and pushes it. The OCI image-layout
/// spec fixes where a blob lives under its digest, so nothing here has to be invented.
async fn push_layout(
    registry: &dyn Registry,
    repository: &str,
    path: &Path,
    manifest: &ks_core::ports::supply_chain::Descriptor,
) -> Result<Digest, StepError> {
    let blob = path.join("blobs").join(manifest.digest.algorithm()).join(manifest.digest.hex());
    let bytes = std::fs::read(&blob).map_err(|error| {
        StepError::Failed(format!(
            "the built layout has no manifest at {}: {error}",
            blob.display()
        ))
    })?;
    let contents = OciLayoutContents {
        media_type: manifest.media_type.clone(),
        manifest: bytes,
        blobs: Vec::new(),
    };
    let pushed = registry
        .push_layout(repository, &contents)
        .await
        .map_err(|error| StepError::Port { port: Port::Registry, message: error.to_string() })?;
    Ok(pushed.digest)
}

/// The digest the registry holds for `repository:tag`, once it agrees with what the build
/// reported.
///
/// A builder that pushed *and tagged* in one go has already moved the tag, so the tag is
/// resolved first and a disagreement is the answer. Otherwise the tag is applied — which fails
/// when the registry does not have the digest at all, saying so rather than reporting content
/// nobody stored.
async fn confirm(
    registry: &dyn Registry,
    repository: &str,
    tag: &str,
    reported: &Digest,
) -> Result<Digest, StepError> {
    let tagged = ImageRef::new(repository, Reference::Tag(tag.to_string()));
    let stored = match registry.resolve(&tagged).await {
        Ok(digest) => digest,
        Err(RegistryError::NotFound { .. }) => {
            registry.tag(repository, tag, reported).await.map_err(|error| StepError::Port {
                port: Port::Registry,
                message: format!("tagging {repository}:{tag} failed: {error}"),
            })?;
            registry.resolve(&tagged).await.map_err(|error| StepError::Port {
                port: Port::Registry,
                message: error.to_string(),
            })?
        }
        Err(error) => {
            return Err(StepError::Port { port: Port::Registry, message: error.to_string() });
        }
    };
    if &stored != reported {
        return Err(StepError::Failed(format!(
            "the build reported {reported} for {repository}:{tag}, but the registry holds {stored}"
        )));
    }
    Ok(stored)
}

/// The `Registry` port, or the error a step that cannot run without it should fail with.
fn registry(ctx: &StepCtx) -> Result<std::sync::Arc<dyn Registry>, StepError> {
    ctx.ports().registry().cloned().ok_or_else(|| StepError::Port {
        port: Port::Registry,
        message: "no registry was provided".to_string(),
    })
}

/// The repository and digest a cached entry named, from its `ref` output.
fn repository_and_digest(outputs: &Outputs) -> Option<(String, Digest)> {
    let Some(Value::String(reference)) = outputs.get("ref") else { return None };
    let parsed = ImageRef::parse(reference).ok()?;
    let digest = parsed.digest()?.clone();
    Some((parsed.repository().to_string(), digest))
}

/// The `&str` under `name`; inputs arrive prepared, so a wrong type never reaches a step.
fn text<'a>(inputs: &'a Inputs, name: &str) -> &'a str {
    match inputs.get(name) {
        Some(Value::String(text)) => text,
        _ => "",
    }
}

/// The list of strings under `name`.
fn list(inputs: &Inputs, name: &str) -> Vec<String> {
    match inputs.get(name) {
        Some(Value::List(items)) => items
            .iter()
            .filter_map(|item| match item {
                Value::String(text) => Some(text.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// The string map under `name`; non-string entries are dropped rather than guessed at.
fn map(inputs: &Inputs, name: &str) -> BTreeMap<String, String> {
    match inputs.get(name) {
        Some(Value::Map(entries)) => entries
            .iter()
            .filter_map(|(key, value)| match value {
                Value::String(text) => Some((key.clone(), text.clone())),
                _ => None,
            })
            .collect(),
        _ => BTreeMap::new(),
    }
}

/// `Some(text)` when it says something, `None` when it is empty — the difference between "build
/// this stage" and "build the last one".
fn non_empty(text: &str) -> Option<String> {
    (!text.is_empty()).then(|| text.to_string())
}
