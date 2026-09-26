//! Fakes and conformance kits for the supply-chain ports
//! ([#50](https://github.com/Keep-Shipping/harness/issues/50)).
//!
//! [`FakeRegistry`] is genuinely content-addressed (real SHA-256, via this
//! crate's `sha2` dependency — `ks-core` stays hash-free),
//! [`FakeImageBuilder`] is deterministic per request, and [`FakeSigner`]
//! signs deterministically but is honest about not being cryptography. The
//! `registry_conformance` and `signer_conformance` kits run unchanged against
//! real adapters later.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::sync::{Arc, Mutex, MutexGuard};

use ks_core::ports::BoxFuture;
use ks_core::ports::supply_chain::{
    ArtifactUpload, BuildError, BuildOutput, BuildRequest, Descriptor, Digest, ImageBuilder,
    ImageRef, OciLayoutContents, Reference, Registry, RegistryError, SignError, SignPayload,
    Signature, Signer, SignerIdentity,
};
use sha2::{Digest as _, Sha256};

/// The manifest media type the fakes use for image and artifact manifests.
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
/// The layer media type the fake registry wraps artifact blobs in.
const OCI_LAYER: &str = "application/vnd.oci.image.layer.v1.tar";

/// SHA-256 of `bytes`, lowercase hex — the one real hashing helper here.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// The [`Digest`] of `bytes`, computed with the real algorithm.
fn digest_of(bytes: &[u8]) -> Digest {
    Digest::sha256_from_hex(&sha256_hex(bytes)).expect("sha256 hex is canonical")
}

/// The content store behind a `FakeRegistry`.
#[derive(Default)]
struct RegistryState {
    /// repository → digest → exact bytes (manifests and blobs alike).
    content: BTreeMap<String, BTreeMap<Digest, Vec<u8>>>,
    /// repository → tag → digest.
    tags: BTreeMap<String, BTreeMap<String, Digest>>,
    /// repository → subject digest → referring descriptors.
    referrers: BTreeMap<String, BTreeMap<Digest, Vec<Descriptor>>>,
    /// Repositories scripted to refuse every operation.
    unauthorized: BTreeSet<String>,
}

impl RegistryState {
    fn check_auth(&self, repository: &str) -> Result<(), RegistryError> {
        if self.unauthorized.contains(repository) {
            Err(RegistryError::Unauthorized { repository: repository.to_string() })
        } else {
            Ok(())
        }
    }

    fn store(&mut self, repository: &str, bytes: &[u8]) -> Digest {
        let digest = digest_of(bytes);
        self.content
            .entry(repository.to_string())
            .or_default()
            .insert(digest.clone(), bytes.to_vec());
        digest
    }

    fn lookup(&self, repository: &str, digest: &Digest) -> Option<&Vec<u8>> {
        self.content.get(repository)?.get(digest)
    }

    fn not_found(&self, repository: &str, reference: impl std::fmt::Display) -> RegistryError {
        RegistryError::NotFound {
            repository: repository.to_string(),
            reference: reference.to_string(),
        }
    }
}

/// An in-memory [`Registry`] that is genuinely content-addressed: every
/// digest it hands back is the real SHA-256 of the exact bytes stored, so
/// assertions on digests test the property real adapters must uphold.
///
/// Pushed artifacts are wrapped in a hand-formatted (serde-free) OCI image
/// manifest whose `subject` field points at the subject digest — which is
/// what makes [`Registry::referrers`] work. Unknown digests fail with
/// `NotFound` (`exists` answers `Ok(false)`); repositories scripted with
/// [`unauthorized`](FakeRegistry::unauthorized) refuse every operation —
/// including `exists` — with `Unauthorized`.
#[derive(Default)]
pub struct FakeRegistry {
    state: Mutex<RegistryState>,
}

impl FakeRegistry {
    /// Creates an empty registry.
    pub fn new() -> FakeRegistry {
        FakeRegistry { state: Mutex::new(RegistryState::default()) }
    }

    /// Scripts `repository` to refuse every operation with `Unauthorized`.
    pub fn unauthorized(mut self, repository: impl Into<String>) -> FakeRegistry {
        self.state.get_mut().expect("fake registry").unauthorized.insert(repository.into());
        self
    }

    /// The digests stored in `repository`, sorted — for assertions.
    pub fn stored_digests(&self, repository: &str) -> Vec<Digest> {
        self.lock()
            .content
            .get(repository)
            .map(|stored| stored.keys().cloned().collect())
            .unwrap_or_default()
    }

    fn lock(&self) -> MutexGuard<'_, RegistryState> {
        self.state.lock().expect("fake registry")
    }
}

impl Registry for FakeRegistry {
    fn resolve<'a>(&'a self, image: &'a ImageRef) -> BoxFuture<'a, Result<Digest, RegistryError>> {
        let state = self.lock();
        let repository = image.repository();
        let result = state.check_auth(repository).and_then(|()| match image.reference() {
            Reference::Tag(tag) => state
                .tags
                .get(repository)
                .and_then(|tags| tags.get(tag))
                .cloned()
                .ok_or_else(|| state.not_found(repository, format_args!("tag {tag}"))),
            Reference::Digest(digest) => {
                if state.lookup(repository, digest).is_some() {
                    Ok(digest.clone())
                } else {
                    Err(state.not_found(repository, digest))
                }
            }
        });
        Box::pin(std::future::ready(result))
    }

    fn push_layout<'a>(
        &'a self,
        repository: &'a str,
        layout: &'a OciLayoutContents,
    ) -> BoxFuture<'a, Result<Descriptor, RegistryError>> {
        let mut state = self.lock();
        let result = state.check_auth(repository).map(|()| {
            for blob in &layout.blobs {
                state.store(repository, blob);
            }
            let digest = state.store(repository, &layout.manifest);
            Descriptor {
                media_type: layout.media_type.clone(),
                digest,
                size: layout.manifest.len() as u64,
                annotations: BTreeMap::new(),
            }
        });
        Box::pin(std::future::ready(result))
    }

    fn push_artifact<'a>(
        &'a self,
        repository: &'a str,
        upload: &'a ArtifactUpload,
    ) -> BoxFuture<'a, Result<Descriptor, RegistryError>> {
        let mut state = self.lock();
        let result = state.check_auth(repository).map(|()| {
            for blob in &upload.blobs {
                state.store(repository, blob);
            }
            let manifest = artifact_manifest(upload);
            let size = manifest.len() as u64;
            let digest = state.store(repository, &manifest);
            let descriptor = Descriptor {
                media_type: upload.media_type.clone(),
                digest,
                size,
                annotations: upload.annotations.clone(),
            };
            if let Some(subject) = &upload.subject {
                state
                    .referrers
                    .entry(repository.to_string())
                    .or_default()
                    .entry(subject.clone())
                    .or_default()
                    .push(descriptor.clone());
            }
            descriptor
        });
        Box::pin(std::future::ready(result))
    }

    fn pull<'a>(
        &'a self,
        repository: &'a str,
        digest: &'a Digest,
    ) -> BoxFuture<'a, Result<Vec<u8>, RegistryError>> {
        let state = self.lock();
        let result = state.check_auth(repository).and_then(|()| {
            state
                .lookup(repository, digest)
                .cloned()
                .ok_or_else(|| state.not_found(repository, digest))
        });
        Box::pin(std::future::ready(result))
    }

    fn referrers<'a>(
        &'a self,
        repository: &'a str,
        digest: &'a Digest,
    ) -> BoxFuture<'a, Result<Vec<Descriptor>, RegistryError>> {
        let state = self.lock();
        let result = state.check_auth(repository).map(|()| {
            state
                .referrers
                .get(repository)
                .and_then(|by_subject| by_subject.get(digest))
                .cloned()
                .unwrap_or_default()
        });
        Box::pin(std::future::ready(result))
    }

    fn exists<'a>(
        &'a self,
        repository: &'a str,
        digest: &'a Digest,
    ) -> BoxFuture<'a, Result<bool, RegistryError>> {
        let state = self.lock();
        let result =
            state.check_auth(repository).map(|()| state.lookup(repository, digest).is_some());
        Box::pin(std::future::ready(result))
    }

    fn tag<'a>(
        &'a self,
        repository: &'a str,
        tag: &'a str,
        digest: &'a Digest,
    ) -> BoxFuture<'a, Result<(), RegistryError>> {
        let mut state = self.lock();
        let result = state.check_auth(repository).and_then(|()| {
            if state.lookup(repository, digest).is_some() {
                state
                    .tags
                    .entry(repository.to_string())
                    .or_default()
                    .insert(tag.to_string(), digest.clone());
                Ok(())
            } else {
                Err(state.not_found(repository, digest))
            }
        });
        Box::pin(std::future::ready(result))
    }
}

/// Wraps an [`ArtifactUpload`] in a hand-formatted OCI image manifest (no
/// serde here): schemaVersion 2, the conventional empty config, one layer per
/// blob, the `subject` link, the annotations. Keys and values are inlined
/// as-is — the fake is exercised with plain ASCII, and saying so beats a JSON
/// escaper.
fn artifact_manifest(upload: &ArtifactUpload) -> Vec<u8> {
    let mut json = format!(
        "{{\"schemaVersion\":2,\"mediaType\":\"{}\",\"artifactType\":\"{}\",\"config\":\
         {{\"mediaType\":\"application/vnd.oci.empty.v1+json\",\"digest\":\"sha256:{}\",\"size\":2}},\
         \"layers\":[",
        upload.media_type,
        upload.artifact_type,
        sha256_hex(b"{}"),
    );
    for (index, blob) in upload.blobs.iter().enumerate() {
        if index > 0 {
            json.push(',');
        }
        let _ = write!(
            json,
            "{{\"mediaType\":\"{OCI_LAYER}\",\"digest\":\"{}\",\"size\":{}}}",
            digest_of(blob),
            blob.len(),
        );
    }
    json.push(']');
    if let Some(subject) = &upload.subject {
        let _ = write!(
            json,
            ",\"subject\":{{\"mediaType\":\"{}\",\"digest\":\"{}\"}}",
            upload.media_type, subject,
        );
    }
    if !upload.annotations.is_empty() {
        json.push_str(",\"annotations\":{");
        for (index, (key, value)) in upload.annotations.iter().enumerate() {
            if index > 0 {
                json.push(',');
            }
            let _ = write!(json, "\"{key}\":\"{value}\"");
        }
        json.push('}');
    }
    json.push('}');
    json.into_bytes()
}

/// A deterministic [`ImageBuilder`]: the manifest it builds is a canonical
/// text rendering of the request, so the same request always yields the same
/// digest and any changed field (an arg, a platform, the target) yields a
/// different one. Every request is recorded in
/// [`requests`](FakeImageBuilder::requests).
///
/// With `push_to` set the output is [`BuildOutput::PushedImage`]; when the
/// fake is wired to a shared [`FakeRegistry`] via
/// [`pushing_into`](FakeImageBuilder::pushing_into) the layout really lands
/// there and the digest comes from the registry response. Otherwise the
/// output is a local [`BuildOutput::OciLayout`] under the build context.
#[derive(Default)]
pub struct FakeImageBuilder {
    registry: Option<Arc<FakeRegistry>>,
    failure: Option<String>,
    requests: Mutex<Vec<BuildRequest>>,
}

impl FakeImageBuilder {
    /// Creates a builder that always succeeds.
    pub fn new() -> FakeImageBuilder {
        FakeImageBuilder::default()
    }

    /// Wires the fake to a shared registry that `push_to` pushes land in.
    pub fn pushing_into(mut self, registry: Arc<FakeRegistry>) -> FakeImageBuilder {
        self.registry = Some(registry);
        self
    }

    /// Scripts every build to fail with `BuildError::Failed`.
    pub fn failing(mut self, reason: impl Into<String>) -> FakeImageBuilder {
        self.failure = Some(reason.into());
        self
    }

    /// Every build request so far, oldest first.
    pub fn requests(&self) -> Vec<BuildRequest> {
        self.requests.lock().expect("fake image builder").clone()
    }
}

impl ImageBuilder for FakeImageBuilder {
    fn build<'a>(
        &'a self,
        request: &'a BuildRequest,
    ) -> BoxFuture<'a, Result<BuildOutput, BuildError>> {
        self.requests.lock().expect("fake image builder").push(request.clone());
        let result = match &self.failure {
            Some(reason) => Err(BuildError::Failed { reason: reason.clone() }),
            None => self.finish(request),
        };
        Box::pin(std::future::ready(result))
    }
}

impl FakeImageBuilder {
    fn finish(&self, request: &BuildRequest) -> Result<BuildOutput, BuildError> {
        let manifest = synthetic_manifest(request);
        let descriptor = Descriptor {
            media_type: OCI_MANIFEST.to_string(),
            digest: digest_of(&manifest),
            size: manifest.len() as u64,
            annotations: BTreeMap::new(),
        };
        match &request.push_to {
            Some(repository) => match &self.registry {
                Some(registry) => {
                    let layout = OciLayoutContents {
                        media_type: OCI_MANIFEST.to_string(),
                        manifest,
                        blobs: Vec::new(),
                    };
                    // The fake registry's futures are always ready, so the
                    // crate's own block_on drives it inside a sync method.
                    let pushed = crate::block_on(registry.push_layout(repository, &layout));
                    let pushed = pushed.map_err(|error| BuildError::Push {
                        repository: repository.clone(),
                        message: error.to_string(),
                    })?;
                    Ok(BuildOutput::PushedImage {
                        repository: repository.clone(),
                        digest: pushed.digest,
                    })
                }
                None => Ok(BuildOutput::PushedImage {
                    repository: repository.clone(),
                    digest: descriptor.digest,
                }),
            },
            None => Ok(BuildOutput::OciLayout {
                path: request.context.join("fake-oci-layout"),
                manifest: descriptor,
            }),
        }
    }
}

/// A canonical stand-in for a real image manifest: a text rendering of
/// everything in the request that can change the output. Not a real manifest
/// — but the property under test (same request in, same digest out) holds of
/// the real bytes too.
fn synthetic_manifest(request: &BuildRequest) -> Vec<u8> {
    let mut text = format!(
        "dockerfile={}\ncontext={}\n",
        request.dockerfile.display(),
        request.context.display()
    );
    for (key, value) in &request.args {
        let _ = writeln!(text, "arg {key}={value}");
    }
    for platform in &request.platforms {
        let _ = writeln!(text, "platform {platform}");
    }
    if let Some(target) = &request.target {
        let _ = writeln!(text, "target {target}");
    }
    text.into_bytes()
}

/// A [`Signer`] whose signature is `sha256(identity bytes ‖ payload bytes)`.
///
/// This is **not** cryptographically meaningful — it is a deterministic
/// stand-in so tests can assert on signature bytes, tampering and identity
/// binding. Real adapters sign with real keys; the contract under test
/// (sign → verify returns the signing identity; a tampered payload or a
/// re-claimed identity fails with `Invalid`) is the same.
pub struct FakeSigner {
    identity: SignerIdentity,
}

impl FakeSigner {
    /// A signer with a [`SignerIdentity::Key`] identity.
    pub fn with_key(key_id: impl Into<String>) -> FakeSigner {
        FakeSigner { identity: SignerIdentity::Key { key_id: key_id.into() } }
    }

    /// A signer with a [`SignerIdentity::Keyless`] identity.
    pub fn keyless(issuer: impl Into<String>, subject: impl Into<String>) -> FakeSigner {
        FakeSigner {
            identity: SignerIdentity::Keyless { issuer: issuer.into(), subject: subject.into() },
        }
    }
}

/// The bytes an identity contributes to the fake's signature.
fn identity_bytes(identity: &SignerIdentity) -> Vec<u8> {
    match identity {
        SignerIdentity::Key { key_id } => format!("key:{key_id}").into_bytes(),
        SignerIdentity::Keyless { issuer, subject } => {
            format!("keyless:{issuer}:{subject}").into_bytes()
        }
    }
}

/// The bytes of a payload: a digest by its canonical string, raw bytes as-is.
fn payload_bytes(payload: &SignPayload) -> Vec<u8> {
    match payload {
        SignPayload::Digest(digest) => digest.to_string().into_bytes(),
        SignPayload::Bytes(bytes) => bytes.clone(),
    }
}

/// The fake's signature over `payload` as `identity`. Not a real signature.
fn mac(identity: &SignerIdentity, payload: &SignPayload) -> Vec<u8> {
    let mut input = identity_bytes(identity);
    input.extend_from_slice(&payload_bytes(payload));
    Sha256::digest(input).to_vec()
}

impl Signer for FakeSigner {
    fn identity(&self) -> SignerIdentity {
        self.identity.clone()
    }

    fn sign<'a>(&'a self, payload: &'a SignPayload) -> BoxFuture<'a, Result<Signature, SignError>> {
        Box::pin(std::future::ready(Ok(Signature {
            bytes: mac(&self.identity, payload),
            identity: self.identity.clone(),
        })))
    }

    fn verify<'a>(
        &'a self,
        payload: &'a SignPayload,
        signature: &'a Signature,
    ) -> BoxFuture<'a, Result<SignerIdentity, SignError>> {
        let result = if signature.bytes == mac(&signature.identity, payload) {
            Ok(signature.identity.clone())
        } else {
            Err(SignError::Invalid {
                reason: "signature does not match the payload under the identity it claims"
                    .to_string(),
            })
        };
        Box::pin(std::future::ready(result))
    }
}

/// The `Registry` conformance kit: every registry adapter — including
/// [`FakeRegistry`] — must pass this on `repository`. It later runs
/// unchanged against zot in the adapter job
/// ([#60](https://github.com/Keep-Shipping/harness/issues/60)).
///
/// Checks: a pushed layout comes back byte-for-byte under the digest of its
/// exact manifest bytes; a pushed artifact's descriptor digest equals SHA-256
/// of the pulled bytes (computed here, with `sha2`, independently of the
/// adapter), with a matching size; `exists` agrees; unknown digests are
/// `NotFound`, not errors or lies; `referrers` lists the artifact under its
/// subject and nothing under an unused digest; a tagged reference resolves to
/// the tagged digest, an unknown tag is `NotFound`.
pub async fn registry_conformance(registry: &dyn Registry, repository: &str) {
    let layout = OciLayoutContents {
        media_type: OCI_MANIFEST.to_string(),
        manifest: b"{\"schemaVersion\":2,\"config\":{}}".to_vec(),
        blobs: vec![b"conformance-layer".to_vec()],
    };
    let subject = registry
        .push_layout(repository, &layout)
        .await
        .expect("conformance: push_layout must succeed");
    assert_eq!(
        subject.digest,
        digest_of(&layout.manifest),
        "conformance: the pushed manifest's digest must be sha256 of its exact bytes"
    );
    let pulled = registry
        .pull(repository, &subject.digest)
        .await
        .expect("conformance: pushed layouts pull back");
    assert_eq!(pulled, layout.manifest, "conformance: pull must return the exact pushed bytes");

    let mut annotations = BTreeMap::new();
    annotations.insert("conformance".to_string(), "true".to_string());
    let upload = ArtifactUpload {
        media_type: OCI_MANIFEST.to_string(),
        artifact_type: "application/vnd.keepshipping.conformance".to_string(),
        blobs: vec![b"conformance-blob".to_vec()],
        annotations,
        subject: Some(subject.digest.clone()),
    };
    let artifact = registry
        .push_artifact(repository, &upload)
        .await
        .expect("conformance: push_artifact must succeed");
    let artifact_bytes = registry
        .pull(repository, &artifact.digest)
        .await
        .expect("conformance: pushed artifacts pull back");
    assert_eq!(
        digest_of(&artifact_bytes),
        artifact.digest,
        "conformance: the descriptor digest must equal sha256 of the pulled bytes"
    );
    assert_eq!(
        artifact_bytes.len() as u64,
        artifact.size,
        "conformance: size must match the bytes"
    );
    assert_eq!(
        registry.exists(repository, &artifact.digest).await,
        Ok(true),
        "conformance: exists must be true right after a push"
    );

    // A digest nothing pushed: sixty-four `ab` pairs.
    let stray = Digest::parse(&format!("sha256:{}", "ab".repeat(32))).expect("canonical stray");
    assert_eq!(
        registry.exists(repository, &stray).await,
        Ok(false),
        "conformance: nothing was pushed under the stray digest"
    );
    match registry.pull(repository, &stray).await {
        Err(RegistryError::NotFound { .. }) => {}
        other => panic!("conformance: pulling an unknown digest must be NotFound, got {other:?}"),
    }

    let referrers = registry
        .referrers(repository, &subject.digest)
        .await
        .expect("conformance: referrers must work");
    assert!(
        referrers.contains(&artifact),
        "conformance: referrers of the subject must list the artifact, got {referrers:?}"
    );
    assert!(
        registry
            .referrers(repository, &stray)
            .await
            .expect("conformance: referrers must work")
            .is_empty(),
        "conformance: nothing refers to the stray digest"
    );

    registry
        .tag(repository, "conformance", &artifact.digest)
        .await
        .expect("conformance: tag must work");
    let tagged = ImageRef::new(repository, Reference::Tag("conformance".to_string()));
    assert_eq!(
        registry.resolve(&tagged).await.expect("conformance: resolve must work"),
        artifact.digest,
        "conformance: a tagged reference resolves to the tagged digest"
    );
    let missing = ImageRef::new(repository, Reference::Tag("conformance-missing".to_string()));
    match registry.resolve(&missing).await {
        Err(RegistryError::NotFound { .. }) => {}
        other => panic!("conformance: resolving an unknown tag must be NotFound, got {other:?}"),
    }
}

/// The `Signer` conformance kit: every signer adapter — including
/// [`FakeSigner`] — must pass this. A fresh signature verifies to the
/// identity it carries; a tampered payload fails with `Invalid`; digest
/// payloads round-trip too.
pub async fn signer_conformance(signer: &dyn Signer) {
    let payload = SignPayload::Bytes(b"conformance payload".to_vec());
    let signature = signer.sign(&payload).await.expect("conformance: sign must succeed");
    let verified = signer
        .verify(&payload, &signature)
        .await
        .expect("conformance: a fresh signature must verify");
    assert_eq!(
        verified, signature.identity,
        "conformance: verify must return the identity the signature was made with"
    );

    let tampered = SignPayload::Bytes(b"conformance payload!".to_vec());
    match signer.verify(&tampered, &signature).await {
        Err(SignError::Invalid { .. }) => {}
        other => panic!("conformance: a tampered payload must not verify, got {other:?}"),
    }

    let digest = Digest::parse(&format!("sha256:{}", "cd".repeat(32))).expect("canonical digest");
    let digest_signature = signer
        .sign(&SignPayload::Digest(digest.clone()))
        .await
        .expect("conformance: digest payloads must sign");
    signer
        .verify(&SignPayload::Digest(digest), &digest_signature)
        .await
        .expect("conformance: a fresh digest signature must verify");
}
