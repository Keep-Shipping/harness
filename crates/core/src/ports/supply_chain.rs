//! The supply-chain ports: [`ImageBuilder`], [`Registry`] and [`Signer`]
//! ([#50](https://github.com/Keep-Shipping/harness/issues/50)).
//!
//! Everything a run produces that outlives it — an image, an SBOM
//! attestation, a run-log entry, a block — is addressed by content and, where
//! it matters, signed. Three rules encode that: a [`Digest`] is *parsed*,
//! never computed (hashing lives in adapters — `ks-core` has no deps, and the
//! digest always comes from the response of whatever holds the bytes);
//! builders and registries return descriptors, never tags (a tag is mutable
//! policy, a digest is the content); signatures are bound to a
//! [`SignerIdentity`] that [`verify`](Signer::verify) hands back.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

use super::BoxFuture;
use super::secrets::SecretValue;

/// A content digest: `sha256:<64 lowercase hex>` or `sha512:<128 lowercase
/// hex>`.
///
/// A `Digest` is parsed, not computed — [`Digest::parse`] and
/// [`Digest::sha256_from_hex`] validate hex an adapter already produced by
/// hashing bytes (or read off a registry response). There is deliberately no
/// way to hash inside `ks-core`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest {
    algorithm: &'static str,
    hex: String,
}

impl Digest {
    /// Parses `algorithm:hex`. Only `sha256` (64 hex digits) and `sha512`
    /// (128) are known, and the digits must be lowercase.
    pub fn parse(text: &str) -> Result<Digest, DigestError> {
        let Some((name, hex)) = text.split_once(':') else {
            return Err(DigestError::MissingSeparator);
        };
        let algorithm = match name {
            "sha256" => "sha256",
            "sha512" => "sha512",
            other => return Err(DigestError::UnknownAlgorithm { algorithm: other.to_string() }),
        };
        let expected = if algorithm == "sha512" { 128 } else { 64 };
        if hex.len() != expected || !is_lower_hex(hex) {
            return Err(DigestError::InvalidHex { algorithm, expected });
        }
        Ok(Digest { algorithm, hex: hex.to_string() })
    }

    /// Wraps the hex of an already-computed SHA-256 digest — the helper
    /// adapters use after hashing bytes themselves. Validates; does not hash.
    pub fn sha256_from_hex(hex: &str) -> Result<Digest, DigestError> {
        if hex.len() == 64 && is_lower_hex(hex) {
            Ok(Digest { algorithm: "sha256", hex: hex.to_string() })
        } else {
            Err(DigestError::InvalidHex { algorithm: "sha256", expected: 64 })
        }
    }

    /// The algorithm, `sha256` or `sha512`.
    pub fn algorithm(&self) -> &'static str {
        self.algorithm
    }

    /// The lowercase hex digits, without the algorithm prefix.
    pub fn hex(&self) -> &str {
        &self.hex
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm, self.hex)
    }
}

fn is_lower_hex(hex: &str) -> bool {
    hex.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Why a [`Digest`] refused to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestError {
    /// No `algorithm:hex` separator.
    MissingSeparator,
    /// An algorithm other than `sha256` or `sha512`.
    UnknownAlgorithm {
        /// The unsupported algorithm.
        algorithm: String,
    },
    /// Not exactly the right number of *lowercase* hex digits for the
    /// algorithm.
    InvalidHex {
        /// The algorithm the hex was offered under.
        algorithm: &'static str,
        /// How many lowercase hex digits it needs.
        expected: usize,
    },
}

impl fmt::Display for DigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DigestError::MissingSeparator => {
                f.write_str("a digest must look like `sha256:<hex>` or `sha512:<hex>`")
            }
            DigestError::UnknownAlgorithm { algorithm } => {
                write!(f, "digest algorithm {algorithm:?} is not supported (sha256, sha512)")
            }
            DigestError::InvalidHex { algorithm, expected } => {
                write!(f, "a {algorithm} digest is exactly {expected} lowercase hex digits")
            }
        }
    }
}

impl std::error::Error for DigestError {}

/// How an [`ImageRef`] points at content: a mutable tag, or a pinned digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reference {
    /// A mutable tag, e.g. `latest`.
    Tag(String),
    /// A pinned content digest.
    Digest(Digest),
}

/// A repository plus the reference within it, e.g.
/// `registry.example:5000/team/app:1.2` or `…@sha256:…`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRef {
    repository: String,
    reference: Reference,
}

impl ImageRef {
    /// An explicit repository/reference pair, for references built in code.
    pub fn new(repository: impl Into<String>, reference: Reference) -> ImageRef {
        ImageRef { repository: repository.into(), reference }
    }

    /// Parses `repo[:tag][@digest]`.
    ///
    /// The tag split is the last `:` whose tail contains no `/`, so a
    /// registry host port (`host:5000/repo:tag`) is never mistaken for a tag.
    /// A bare repository defaults to `latest`. When both a tag and a digest
    /// are present the digest wins: it pins the content, the tag is
    /// decoration.
    pub fn parse(text: &str) -> Result<ImageRef, ImageRefError> {
        let (repo_part, digest) = match text.split_once('@') {
            Some((repo, digest)) => {
                (repo, Some(Digest::parse(digest).map_err(ImageRefError::InvalidDigest)?))
            }
            None => (text, None),
        };
        if repo_part.is_empty() {
            return Err(ImageRefError::Empty);
        }
        let (repository, tag) = match repo_part.rsplit_once(':') {
            // A colon whose tail holds a `/` is the host's port, not a tag;
            // an empty tail (`repo:`) is a mistake, not a default.
            Some((_, "")) => return Err(ImageRefError::EmptyTag),
            Some((repository, tag)) if !tag.contains('/') => (repository, Some(tag)),
            _ => (repo_part, None),
        };
        let reference = match digest {
            Some(digest) => Reference::Digest(digest),
            None => Reference::Tag(tag.unwrap_or("latest").to_string()),
        };
        Ok(ImageRef { repository: repository.to_string(), reference })
    }

    /// The repository, host (with port, if any) and path included.
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// The reference within the repository.
    pub fn reference(&self) -> &Reference {
        &self.reference
    }

    /// The tag, if the reference is one.
    pub fn tag(&self) -> Option<&str> {
        match &self.reference {
            Reference::Tag(tag) => Some(tag),
            Reference::Digest(_) => None,
        }
    }

    /// The digest, if the reference is one.
    pub fn digest(&self) -> Option<&Digest> {
        match &self.reference {
            Reference::Digest(digest) => Some(digest),
            Reference::Tag(_) => None,
        }
    }
}

impl fmt::Display for ImageRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.reference {
            Reference::Tag(tag) => write!(f, "{}:{tag}", self.repository),
            Reference::Digest(digest) => write!(f, "{}@{digest}", self.repository),
        }
    }
}

/// Why an [`ImageRef`] refused to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageRefError {
    /// The empty string.
    Empty,
    /// The tag part is empty (`repo:`).
    EmptyTag,
    /// The `@digest` part did not parse.
    InvalidDigest(DigestError),
}

impl fmt::Display for ImageRefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImageRefError::Empty => f.write_str("an image reference must not be empty"),
            ImageRefError::EmptyTag => {
                f.write_str("the tag in an image reference must not be empty")
            }
            ImageRefError::InvalidDigest(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ImageRefError {}

/// What a registry (or builder) says about stored content, exactly as a
/// distribution response hands it over. The digest always comes from the
/// response — callers never compute it themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    /// The content's media type, e.g. `application/vnd.oci.image.manifest.v1+json`.
    pub media_type: String,
    /// The content's digest, as the registry reported it.
    pub digest: Digest,
    /// The content's size in bytes.
    pub size: u64,
    /// Free-form annotations.
    pub annotations: BTreeMap<String, String>,
}

/// The in-memory content of an OCI image layout, ready to push.
///
/// Deliberately bytes, not a path: an on-disk layout would force filesystem
/// I/O into every `Registry` adapter and fake. The caller — usually right
/// after `ImageBuilder::build` produced a layout — reads the directory and
/// hands over the exact manifest bytes plus the blobs the manifest
/// references; the registry digests the bytes itself and never trusts a
/// caller-supplied digest.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OciLayoutContents {
    /// The manifest's media type.
    pub media_type: String,
    /// The exact manifest bytes; the pushed digest is their hash.
    pub manifest: Vec<u8>,
    /// The blobs the manifest references, exact bytes.
    pub blobs: Vec<Vec<u8>>,
}

/// An artifact to push with `Registry::push_artifact`: an SBOM, a provenance
/// statement, a run log — anything packaged as an OCI artifact.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ArtifactUpload {
    /// The manifest media type to package the artifact as.
    pub media_type: String,
    /// The artifact type, e.g. `application/vnd.example.sbom+json`.
    pub artifact_type: String,
    /// The artifact's blobs (layers), exact bytes.
    pub blobs: Vec<Vec<u8>>,
    /// Annotations for the artifact manifest.
    pub annotations: BTreeMap<String, String>,
    /// The digest the artifact is *for* (the image it describes), if any.
    pub subject: Option<Digest>,
}

/// Why a `Registry` call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// The repository has no such tag or digest.
    NotFound {
        /// The repository that was consulted.
        repository: String,
        /// The tag or digest that was not found, as a string.
        reference: String,
    },
    /// The adapter's credentials do not allow this operation.
    Unauthorized {
        /// The repository that refused.
        repository: String,
    },
    /// Bytes returned did not hash to the digest they were served under —
    /// the response was corrupted, or the adapter is not checking.
    DigestMismatch {
        /// The digest the content was addressed by.
        expected: Digest,
        /// The digest the content actually hashed to.
        actual: Digest,
    },
    /// The registry backend itself failed (network, auth, …).
    Backend {
        /// What went wrong, safe to print.
        message: String,
    },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryError::NotFound { repository, reference } => {
                write!(f, "registry {repository} has no {reference}")
            }
            RegistryError::Unauthorized { repository } => {
                write!(f, "not authorized against registry repository {repository:?}")
            }
            RegistryError::DigestMismatch { expected, actual } => {
                write!(f, "content served as {expected} actually hashes to {actual}")
            }
            RegistryError::Backend { message } => write!(f, "registry backend failed: {message}"),
        }
    }
}

impl std::error::Error for RegistryError {}

/// The `Registry` port: an OCI distribution adapter, addressed per repository.
///
/// Content-addressing is the contract: **the digest always comes from the
/// registry response**, and adapters must verify that pulled bytes hash to
/// the digest they were requested under, failing with
/// [`RegistryError::DigestMismatch`] otherwise.
pub trait Registry: Send + Sync {
    /// Resolves a reference to the digest the repository currently serves for
    /// it: tags are looked up, digests are checked for existence.
    fn resolve<'a>(&'a self, image: &'a ImageRef) -> BoxFuture<'a, Result<Digest, RegistryError>>;

    /// Pushes an OCI layout into `repository`; returns the descriptor the
    /// registry stored it under.
    fn push_layout<'a>(
        &'a self,
        repository: &'a str,
        layout: &'a OciLayoutContents,
    ) -> BoxFuture<'a, Result<Descriptor, RegistryError>>;

    /// Pushes an artifact (SBOM, provenance, run log …) into `repository`,
    /// linked to `subject` if one is set so `referrers` can find it.
    fn push_artifact<'a>(
        &'a self,
        repository: &'a str,
        upload: &'a ArtifactUpload,
    ) -> BoxFuture<'a, Result<Descriptor, RegistryError>>;

    /// Pulls the bytes stored under `digest`, verifying they hash to it.
    fn pull<'a>(
        &'a self,
        repository: &'a str,
        digest: &'a Digest,
    ) -> BoxFuture<'a, Result<Vec<u8>, RegistryError>>;

    /// The descriptors of artifacts whose subject is `digest`.
    fn referrers<'a>(
        &'a self,
        repository: &'a str,
        digest: &'a Digest,
    ) -> BoxFuture<'a, Result<Vec<Descriptor>, RegistryError>>;

    /// Whether `repository` holds `digest`: `Ok(false)` only when the
    /// repository genuinely does not have it. Authorization and backend
    /// failures propagate as errors rather than masquerading as an empty
    /// repository — existence is not leaked by lying, and an unauthorized
    /// caller is told so, not shown a blank shelf.
    fn exists<'a>(
        &'a self,
        repository: &'a str,
        digest: &'a Digest,
    ) -> BoxFuture<'a, Result<bool, RegistryError>>;

    /// Points `tag` at `digest` within `repository` — which is also what
    /// makes `resolve` testable.
    fn tag<'a>(
        &'a self,
        repository: &'a str,
        tag: &'a str,
        digest: &'a Digest,
    ) -> BoxFuture<'a, Result<(), RegistryError>>;
}

/// Where a build may keep the work it has already done.
///
/// Adapters map this onto their backend; the three values are the ones
/// BuildKit itself offers, and nothing here promises a cache a step has
/// not verified (see [`Registry::exists`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BuildCache {
    /// Keep the cache in a registry, so it survives a fresh runner.
    Registry,
    /// Keep the cache on the machine running the build.
    #[default]
    Local,
    /// Build with no cache at all.
    None,
}

impl BuildCache {
    /// The spelling a workflow uses for this mode.
    pub fn as_str(&self) -> &'static str {
        match self {
            BuildCache::Registry => "registry",
            BuildCache::Local => "local",
            BuildCache::None => "none",
        }
    }

    /// Parses the spelling a workflow uses; `Err` carries what it was offered.
    pub fn parse(text: &str) -> Result<BuildCache, String> {
        match text {
            "registry" => Ok(BuildCache::Registry),
            "local" => Ok(BuildCache::Local),
            "none" => Ok(BuildCache::None),
            other => Err(other.to_string()),
        }
    }
}

impl fmt::Display for BuildCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The secrets one build mounts, keyed by the mount name the Dockerfile
/// asks for — BuildKit's `RUN --mount=type=secret,id=<name>`.
///
/// These are mounts, never [`args`](BuildRequest::args): a build arg is
/// recorded in the image history and in the provenance attestation, so a
/// secret passed as one is a secret baked into the artifact. Values arrive
/// as [`SecretValue`]s, which have no `Display`, no `Clone` and a `Debug`
/// that prints `***`; the only way to read one is
/// [`with_bytes`](SecretValue::with_bytes). For the same reason a
/// `BuildRequest` is deliberately not `Clone`: a request cannot be copied
/// without copying the secrets it carries.
#[derive(Default)]
pub struct BuildSecrets {
    mounts: BTreeMap<String, SecretValue>,
}

impl BuildSecrets {
    /// Creates an empty set of mounts.
    pub fn new() -> BuildSecrets {
        BuildSecrets { mounts: BTreeMap::new() }
    }

    /// Mounts `value` under `name`, returning whatever it replaced.
    pub fn insert(&mut self, name: impl Into<String>, value: SecretValue) -> Option<SecretValue> {
        self.mounts.insert(name.into(), value)
    }

    /// The value mounted under `name`.
    pub fn get(&self, name: &str) -> Option<&SecretValue> {
        self.mounts.get(name)
    }

    /// Whether nothing is mounted.
    pub fn is_empty(&self) -> bool {
        self.mounts.is_empty()
    }

    /// The mount names, sorted.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.mounts.keys().map(String::as_str)
    }

    /// The `(name, value)` mounts, sorted by name.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &SecretValue)> {
        self.mounts.iter().map(|(name, value)| (name.as_str(), value))
    }
}

/// Names and never values, exactly as
/// [`SecretBundle`](crate::ports::secrets::SecretBundle) does it: a request
/// is logged, and a log line must not become a way to read a secret.
impl fmt::Debug for BuildSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BuildSecrets").field("mounts", &self.names().collect::<Vec<_>>()).finish()
    }
}

/// A request to build an image from a build context.
#[derive(Debug, Default)]
pub struct BuildRequest {
    /// The build context directory.
    pub context: PathBuf,
    /// The Dockerfile within (or relative to) the context.
    pub dockerfile: PathBuf,
    /// Build args. Public by name, opaque by content: everything a build
    /// needs to know is here, and the only private field is the secrets.
    pub args: BTreeMap<String, String>,
    /// Platforms to build for, e.g. `linux/amd64`. More than one produces an
    /// OCI image index, so the digest a build reports addresses the index.
    pub platforms: Vec<String>,
    /// A specific stage to build, if any.
    pub target: Option<String>,
    /// The repository to push to, if the output should be pushed at all.
    pub push_to: Option<String>,
    /// Secrets mounted into the build. Never build args — see
    /// [`BuildSecrets`].
    pub secrets: BuildSecrets,
    /// Where the builder may keep the work it has already done.
    pub cache: BuildCache,
    /// Whether to produce an SBOM alongside the image. An adapter that
    /// cannot is free to ignore it; the digest it reports says nothing
    /// about one either way, so a caller that needs an artifact asks the
    /// registry for referrers.
    pub sbom: bool,
}

/// What a build produced. Content, never a tag: tagging is a `Registry`
/// concern (`Registry::tag`), the builder only names what the bytes are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildOutput {
    /// A local OCI layout: where it was written, and the manifest descriptor.
    OciLayout {
        /// The layout directory the adapter wrote.
        path: PathBuf,
        /// The image manifest, as the builder computed it.
        manifest: Descriptor,
    },
    /// The image was pushed: where it landed, and the digest the registry
    /// reported.
    PushedImage {
        /// The repository the image was pushed to.
        repository: String,
        /// The manifest digest, from the registry response.
        digest: Digest,
    },
}

/// Why a `build` failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    /// The request itself is unusable (missing context, unknown platform…).
    InvalidRequest {
        /// What is wrong, safe to print.
        reason: String,
    },
    /// The build ran and failed (compile error, failing stage…).
    Failed {
        /// What failed, safe to print.
        reason: String,
    },
    /// Building succeeded but pushing did not.
    Push {
        /// The repository the push was attempted against.
        repository: String,
        /// What the registry reported, safe to print.
        message: String,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildError::InvalidRequest { reason } => write!(f, "invalid build request: {reason}"),
            BuildError::Failed { reason } => write!(f, "image build failed: {reason}"),
            BuildError::Push { repository, message } => {
                write!(f, "push to {repository} failed: {message}")
            }
        }
    }
}

impl std::error::Error for BuildError {}

/// The `ImageBuilder` port: turns a build context into image content.
///
/// A build returns content — an OCI layout on disk, or a digest after a push
/// — never a tag: the same request must always yield the same content, and a
/// tag would pretend otherwise.
pub trait ImageBuilder: Send + Sync {
    /// Builds `request`.
    fn build<'a>(
        &'a self,
        request: &'a BuildRequest,
    ) -> BoxFuture<'a, Result<BuildOutput, BuildError>>;
}

/// The identity a `Signer` signs as: a keyless (Sigstore-style) identity
/// certified by an issuer, or a named key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerIdentity {
    /// A keyless identity: `subject` as certified by `issuer` (e.g. a
    /// Fulcio certificate for the workflow's OIDC token).
    Keyless {
        /// The OIDC issuer that certified the subject.
        issuer: String,
        /// The certified subject (workflow, runner…).
        subject: String,
    },
    /// A named key held by the signer.
    Key {
        /// The key's id, as verifiers resolve it.
        key_id: String,
    },
}

/// What is being signed: content already addressed by digest, or raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignPayload {
    /// Content addressed by digest (an image, a block).
    Digest(Digest),
    /// Raw bytes (an SBOM attestation, a run-log entry).
    Bytes(Vec<u8>),
}

/// A signature over a [`SignPayload`], carrying the identity it claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// The signature bytes, in the signer's own format.
    pub bytes: Vec<u8>,
    /// The identity the signature is from.
    pub identity: SignerIdentity,
}

/// Why signing or verifying failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    /// The payload and signature do not belong together.
    Invalid {
        /// What is wrong, safe to print.
        reason: String,
    },
    /// The signing backend itself failed (key unavailable, TSA down…).
    Backend {
        /// What went wrong, safe to print.
        message: String,
    },
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignError::Invalid { reason } => write!(f, "invalid signature: {reason}"),
            SignError::Backend { message } => write!(f, "signing backend failed: {message}"),
        }
    }
}

impl std::error::Error for SignError {}

/// The `Signer` port: produces verifiable supply-chain signatures bound to an
/// identity. Images, SBOM attestations, run-log entries and blocks are all
/// signed through this one port.
///
/// This is *not* the same concept as Cratefield's HMAC `Signer`: that one
/// authenticates messages with a shared secret key; this one produces
/// signatures a third party can verify against a public [`SignerIdentity`].
pub trait Signer: Send + Sync {
    /// The identity this signer signs as.
    fn identity(&self) -> SignerIdentity;

    /// Signs `payload` as [`Signer::identity`].
    fn sign<'a>(&'a self, payload: &'a SignPayload) -> BoxFuture<'a, Result<Signature, SignError>>;

    /// Verifies `signature` over `payload`, returning the identity it was
    /// signed as — which need not be this signer's own. [`SignError::Invalid`]
    /// when the payload and the signature do not belong together.
    fn verify<'a>(
        &'a self,
        payload: &'a SignPayload,
        signature: &'a Signature,
    ) -> BoxFuture<'a, Result<SignerIdentity, SignError>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA256_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const SHA512_HEX: &str = concat!(
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    );

    #[test]
    fn digests_parse_known_algorithms_and_display_canonically() {
        let sha256 = Digest::parse(&format!("sha256:{SHA256_HEX}")).expect("canonical sha256");
        assert_eq!((sha256.algorithm(), sha256.hex()), ("sha256", SHA256_HEX));
        assert_eq!(sha256.to_string(), format!("sha256:{SHA256_HEX}"));
        let sha512 = Digest::parse(&format!("sha512:{SHA512_HEX}")).expect("canonical sha512");
        assert_eq!((sha512.algorithm(), sha512.hex().len()), ("sha512", 128));
        assert_eq!(Digest::sha256_from_hex(SHA256_HEX), Ok(sha256));
    }

    #[test]
    fn digests_reject_missing_separators_unknown_algorithms_and_bad_hex() {
        let hex = "a".repeat(64);
        assert!(matches!(Digest::parse("sha256"), Err(DigestError::MissingSeparator)));
        assert!(matches!(
            Digest::parse(&format!("md5:{hex}")),
            Err(DigestError::UnknownAlgorithm { .. })
        ));
        // Wrong length, uppercase, and sha256-length hex under sha512.
        assert!(matches!(
            Digest::parse(&format!("sha256:{hex}a")),
            Err(DigestError::InvalidHex { .. })
        ));
        assert!(matches!(
            Digest::parse(&format!("sha256:{}", hex.to_uppercase())),
            Err(DigestError::InvalidHex { .. })
        ));
        assert!(matches!(
            Digest::parse(&format!("sha512:{hex}")),
            Err(DigestError::InvalidHex { .. })
        ));
        assert!(Digest::sha256_from_hex("nothex").is_err());
    }

    #[test]
    fn image_refs_split_repositories_from_references_across_host_ports() {
        let tagged = ImageRef::parse("team/app:1.2").expect("tagged");
        assert_eq!((tagged.repository(), tagged.tag()), ("team/app", Some("1.2")));

        // The registry host may carry a port; it belongs to the repository.
        let ported = ImageRef::parse("registry.example:5000/team/app:1.2").expect("ported");
        assert_eq!(
            (ported.repository(), ported.tag()),
            ("registry.example:5000/team/app", Some("1.2"))
        );
        let host_port_only = ImageRef::parse("registry.example:5000/team/app").expect("untagged");
        assert_eq!(host_port_only.tag(), Some("latest"), "bare repositories default to latest");

        let pinned = ImageRef::parse(&format!("registry.example:5000/app@sha256:{SHA256_HEX}"))
            .expect("digest ref");
        assert_eq!(pinned.digest().map(Digest::hex), Some(SHA256_HEX));
        assert_eq!(pinned.to_string(), format!("registry.example:5000/app@sha256:{SHA256_HEX}"));

        assert!(matches!(ImageRef::parse(""), Err(ImageRefError::Empty)));
        assert!(matches!(ImageRef::parse("repo:"), Err(ImageRefError::EmptyTag)));
        assert!(matches!(
            ImageRef::parse("repo@sha256:short"),
            Err(ImageRefError::InvalidDigest(_))
        ));
    }
}
