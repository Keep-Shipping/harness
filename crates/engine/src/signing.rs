//! Signing an image digest and attaching the signature where anyone can find
//! it ([#61](https://github.com/Keep-Shipping/harness/issues/61)).
//!
//! Two rules make a signature mean something. It must **say who signed** — a
//! keyless [`SignerIdentity::Keyless`] (the CI workflow's issuer and subject)
//! or a person's [`SignerIdentity::Key`], never an anonymous "it was signed";
//! and it must be **bound to the digest**, so a signature copied from one image
//! onto another verifies for nothing.
//!
//! Both are structural here, not advisory: the payload carries the repository
//! and the digest ([`simple_signing_payload`]), the signature rides in the
//! annotations of an OCI referrer pushed under the image, and
//! [`verify_signed`] rebuilds that payload from the digest it was asked about
//! rather than trusting what the registry serves.

use std::collections::BTreeMap;
use std::fmt;

use ks_core::ports::run_context::{ActorKind, RunContext};
use ks_core::ports::supply_chain::{
    ArtifactUpload, Descriptor, Digest, Registry, SignPayload, Signature, Signer, SignerIdentity,
};
use ks_core::step::{Port, StepError, StepLog};

/// The manifest media type a signature referrer is packaged as.
const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

/// The artifact type cosign gives a signature manifest.
const ARTIFACT_TYPE: &str = "application/vnd.dev.cosign.artifact.sig.v1+json";

/// Where the base64 signature bytes ride, as cosign puts them.
const SIGNATURE: &str = "dev.cosignproject.cosign/signature";

/// Which kind of identity produced the signature: [`KEY`] or [`KEYLESS`].
const IDENTITY_KIND: &str = "dev.keepshipping.signature/identity-kind";

/// The key's id, when the identity is a key.
const KEY_ID: &str = "dev.keepshipping.signature/key-id";

/// The OIDC issuer, when the identity is keyless.
const ISSUER: &str = "dev.keepshipping.signature/issuer";

/// The certified subject, when the identity is keyless.
const SUBJECT: &str = "dev.keepshipping.signature/subject";

/// Whether this signature was made off CI.
const LOCAL: &str = "dev.keepshipping.signature/local";

/// The [`IDENTITY_KIND`] value for a key identity.
const KEY: &str = "key";
/// The [`IDENTITY_KIND`] value for a keyless identity.
const KEYLESS: &str = "keyless";

/// The cosign *simple signing* payload for `repository` at `digest`: the exact
/// bytes a signature must cover, and exactly what [`verify_signed`] rebuilds.
///
/// Key order is fixed here rather than left to a map's iteration order, so the
/// payload — and therefore every signature over it — is byte-for-byte
/// deterministic for a given `(repository, digest)`. The two interpolated values
/// are JSON-escaped, so a repository or digest can never break the document.
pub fn simple_signing_payload(repository: &str, digest: &Digest) -> Vec<u8> {
    let repository = serde_json::to_string(repository).expect("a string always encodes");
    let digest = serde_json::to_string(&digest.to_string()).expect("a string always encodes");
    format!(
        "{{\"critical\":{{\"identity\":{{\"docker-reference\":{repository}}},\
         \"image\":{{\"docker-manifest-digest\":{digest}}},\
         \"type\":\"cosign container image signature\"}},\"optional\":null}}"
    )
    .into_bytes()
}

/// A signature that was pushed *and* read back and verified: what
/// `oci.image`'s `signed` output reports, and what the run log names.
///
/// The field is redundant with the type — there is no way to hold a `Signed`
/// without having verified — and it is here because a caller writes it straight
/// into an output value and a boolean nobody can observe is a boolean nobody
/// checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    /// Who signed, as verified off the registry.
    pub identity: SignerIdentity,
    /// Whether this was a local signature: a key held by whoever ran the
    /// workflow, not a CI workflow identity.
    pub local: bool,
    /// Always `true`; see the note on the type.
    pub signed: bool,
}

/// Signs `digest` and attaches the signature to it as a referrer, then reads it
/// back and verifies it.
///
/// Nothing is reported signed until the signature comes back off the registry
/// and the signer confirms it: a push that fails, a registry that forgets the
/// referrer and a signature that no longer verifies all return `Err`, so a
/// caller can never turn "we tried" into `signed: true`.
///
/// `local` is what the caller believes about where the run is — see
/// [`is_local`] for how the harness decides.
pub async fn sign_and_attach(
    signer: &dyn Signer,
    registry: &dyn Registry,
    repository: &str,
    digest: &Digest,
    local: bool,
) -> Result<Signed, StepError> {
    let payload = simple_signing_payload(repository, digest);
    let signature = signer.sign(&SignPayload::Bytes(payload.clone())).await.map_err(|error| {
        StepError::Port { port: Port::Signer, message: format!("signing {digest} failed: {error}") }
    })?;
    let upload = ArtifactUpload {
        media_type: MANIFEST.to_string(),
        artifact_type: ARTIFACT_TYPE.to_string(),
        blobs: vec![payload],
        annotations: annotations(&signature.identity, &signature.bytes, local),
        subject: Some(digest.clone()),
    };
    registry.push_artifact(repository, &upload).await.map_err(|error| StepError::Port {
        port: Port::Registry,
        message: format!("attaching a signature to {digest} failed: {error}"),
    })?;

    let identity = signer.identity();
    let referrers =
        registry.referrers(repository, digest).await.map_err(|error| StepError::Port {
            port: Port::Registry,
            message: format!("reading back the signature on {digest} failed: {error}"),
        })?;
    // Readback, not memory: the descriptor below is the one the registry serves
    // for this digest, so a push that stored nothing — or stored something else
    // — is caught here rather than in someone else's deploy.
    for descriptor in &referrers {
        let Some(stored) = signature_of(descriptor) else { continue };
        let payload = SignPayload::Bytes(simple_signing_payload(repository, digest));
        if let Ok(verified) = signer.verify(&payload, &stored).await
            && verified == identity
        {
            return Ok(Signed { identity, local, signed: true });
        }
    }
    Err(StepError::Port {
        port: Port::Signer,
        message: format!(
            "the signature attached to {digest} did not read back as {}, so it is not signed",
            identity_text(&identity)
        ),
    })
}

/// Checks that `digest` carries a signature made as `expected`, returning the
/// identity that verified.
///
/// Only referrers that carry a cosign signature are considered, so an SBOM or a
/// provenance statement attached to the same image is never mistaken for one.
/// The payload is rebuilt from `repository` and `digest` — a signature over a
/// different image's payload does not verify, which is what stops a valid
/// signature being copied from one digest to another.
///
/// The three refusals are kept distinct because they call for different fixes:
/// nothing to verify, a signature that does not hold, and a signature by
/// somebody else.
pub async fn verify_signed(
    signer: &dyn Signer,
    registry: &dyn Registry,
    repository: &str,
    digest: &Digest,
    expected: &SignedBy,
) -> Result<SignerIdentity, StepError> {
    let referrers =
        registry.referrers(repository, digest).await.map_err(|error| StepError::Port {
            port: Port::Registry,
            message: format!("reading the signatures on {digest} failed: {error}"),
        })?;
    let payload = SignPayload::Bytes(simple_signing_payload(repository, digest));
    let mut signatures = 0;
    let mut other: Option<SignerIdentity> = None;
    for descriptor in &referrers {
        let Some(stored) = signature_of(descriptor) else { continue };
        signatures += 1;
        match signer.verify(&payload, &stored).await {
            Ok(verified) if &verified == expected.identity() => return Ok(verified),
            Ok(verified) => {
                if other.is_none() {
                    other = Some(verified);
                }
            }
            Err(_) => {}
        }
    }
    if signatures == 0 {
        return Err(StepError::Failed(format!("{digest} is unsigned")));
    }
    match other {
        Some(verified) => Err(StepError::Failed(format!(
            "{digest} is signed by {}, not by {expected}",
            identity_text(&verified)
        ))),
        None => Err(StepError::Failed(format!("the signature on {digest} does not verify"))),
    }
}

/// An identity as it is written in a `signed_by` matcher — `key:alice`, or
/// `<subject> from <issuer>`.
///
/// [`SignerIdentity`] has no `Display` of its own: the port type stays free of
/// presentation so an adapter is never forced to have an opinion about how an
/// identity reads. This is that opinion, in one place, so a refusal and a log
/// line name the same signer the same way.
pub fn identity_text(identity: &SignerIdentity) -> String {
    match identity {
        SignerIdentity::Key { key_id } => format!("key:{key_id}"),
        SignerIdentity::Keyless { issuer, subject } => format!("{subject} from {issuer}"),
    }
}

/// The identity a deploy step will only ship behind, as written in
/// `signed_by` / `verify:`.
///
/// ```
/// use ks_engine::signing::SignedBy;
///
/// assert_eq!(SignedBy::parse("key:alice").unwrap().to_string(), "key:alice");
/// assert_eq!(
///     SignedBy::parse("signed-by repo:Keep-Shipping/harness from https://issuer.example")
///         .unwrap()
///         .to_string(),
///     "repo:Keep-Shipping/harness from https://issuer.example",
/// );
/// ```
///
/// # Grammar
///
/// - `key:<key-id>` — a named key. The key id must not be empty.
/// - `<subject> from <issuer>` — a keyless identity, cosign's
///   `--certificate-identity` and `--certificate-oidc-issuer`. Both halves are
///   required and neither may be empty: half an identity is not an identity, and
///   matching a subject from any issuer is how a signature gets accepted from
///   somewhere it should not be trusted.
/// - an optional `signed-by ` prefix, so a deploy step's
///   `verify: "signed-by key:alice"` can be handed straight in.
///
/// The split is on the *last* ` from `, so a subject that contains the words
/// still parses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedBy(SignerIdentity);

impl SignedBy {
    /// Parses an identity matcher; see the type's grammar.
    pub fn parse(text: &str) -> Result<SignedBy, SignedByError> {
        if text.trim().is_empty() {
            return Err(SignedByError::Empty);
        }
        // An optional `signed-by ` prefix — a deploy step's `verify:` value
        // carries it — is stripped here, with the leading whitespace around the
        // input. The rest is kept as written: the space on either side of
        // ` from ` is what makes an empty subject or issuer, so trimming it
        // away would turn a clear refusal into a vague "unrecognised" one.
        let text = text
            .trim_start()
            .strip_prefix("signed-by")
            .map(|rest| rest.trim_start())
            .unwrap_or(text);
        if let Some(key_id) = text.trim().strip_prefix("key:") {
            let key_id = key_id.trim();
            if key_id.is_empty() {
                return Err(SignedByError::MissingKeyId);
            }
            return Ok(SignedBy(SignerIdentity::Key { key_id: key_id.to_string() }));
        }
        let Some((subject, issuer)) = text.rsplit_once(" from ") else {
            return Err(SignedByError::Unrecognised);
        };
        let (subject, issuer) = (subject.trim(), issuer.trim());
        if subject.is_empty() {
            return Err(SignedByError::MissingSubject);
        }
        if issuer.is_empty() {
            return Err(SignedByError::MissingIssuer);
        }
        Ok(SignedBy(SignerIdentity::Keyless {
            issuer: issuer.to_string(),
            subject: subject.to_string(),
        }))
    }

    /// The identity a signature must have been made as.
    pub fn identity(&self) -> &SignerIdentity {
        &self.0
    }
}

impl fmt::Display for SignedBy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&identity_text(&self.0))
    }
}

/// Why a `signed_by` matcher refused to parse. Every message says what the
/// grammar wants, because a matcher is written by hand in a workflow file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedByError {
    /// Nothing to match on.
    Empty,
    /// `key:` with no key id after it.
    MissingKeyId,
    /// Neither `key:<key-id>` nor `<subject> from <issuer>`.
    Unrecognised,
    /// `<subject> from <issuer>` with no subject.
    MissingSubject,
    /// `<subject> from <issuer>` with no issuer.
    MissingIssuer,
}

impl fmt::Display for SignedByError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignedByError::Empty => f.write_str(
                "a signed-by matcher must be `key:<key-id>` or `<subject> from <issuer>`",
            ),
            SignedByError::MissingKeyId => f.write_str("`key:` must be followed by a key id"),
            SignedByError::Unrecognised => f.write_str(
                "a signed-by matcher must be `key:<key-id>` or `<subject> from <issuer>`",
            ),
            SignedByError::MissingSubject => f.write_str("` from ` must have a subject before it"),
            SignedByError::MissingIssuer => {
                f.write_str("a keyless signed-by matcher must name the issuer after ` from `")
            }
        }
    }
}

impl std::error::Error for SignedByError {}

/// Whether a signature from `identity` made here is a *local* one.
///
/// The [`RunContext`] port is the only thing that knows, and a step only sees it
/// when it declared it: an actor that is [`ActorKind::Ci`] signed as the
/// workflow, anything else signed as a person at a laptop. Without the port
/// there is nothing to ask, so the identity answers for itself — a keyless
/// identity exists only because CI certified it, and a key is a person's.
pub fn is_local(identity: &SignerIdentity, run_context: Option<&dyn RunContext>) -> bool {
    match run_context.map(|context| context.actor().kind) {
        Some(ActorKind::Ci) => false,
        Some(_) => true,
        None => matches!(identity, SignerIdentity::Key { .. }),
    }
}

/// Writes the one log line a signature produces: who signed, and whether this
/// was a local signature. Call it after [`sign_and_attach`] succeeds.
pub fn log_signature(log: &StepLog, signed: &Signed) {
    let local = if signed.local { " (local signature)" } else { "" };
    log.info(
        &format!("signed as {}{local}", identity_text(&signed.identity)),
        &[("signed", "true"), ("local", if signed.local { "true" } else { "false" })],
    );
}

/// The annotations a signature referrer carries: the bytes cosign reads, and
/// the identity the harness needs to say who signed without pulling the blob.
fn annotations(
    identity: &SignerIdentity,
    signature: &[u8],
    local: bool,
) -> BTreeMap<String, String> {
    let mut annotations = BTreeMap::new();
    annotations.insert(SIGNATURE.to_string(), base64_encode(signature));
    annotations.insert(
        IDENTITY_KIND.to_string(),
        match identity {
            SignerIdentity::Key { .. } => KEY.to_string(),
            SignerIdentity::Keyless { .. } => KEYLESS.to_string(),
        },
    );
    if let SignerIdentity::Key { key_id } = identity {
        annotations.insert(KEY_ID.to_string(), key_id.clone());
    }
    if let SignerIdentity::Keyless { issuer, subject } = identity {
        annotations.insert(ISSUER.to_string(), issuer.clone());
        annotations.insert(SUBJECT.to_string(), subject.clone());
    }
    annotations.insert(LOCAL.to_string(), local.to_string());
    annotations
}

/// The signature a referrer descriptor carries, or `None` when it is not a
/// signature, or is one whose annotations do not describe a whole signature and
/// identity.
fn signature_of(descriptor: &Descriptor) -> Option<Signature> {
    let bytes = base64_decode(descriptor.annotations.get(SIGNATURE)?)?;
    let identity = match descriptor.annotations.get(IDENTITY_KIND)?.as_str() {
        KEY => SignerIdentity::Key { key_id: descriptor.annotations.get(KEY_ID)?.clone() },
        KEYLESS => SignerIdentity::Keyless {
            issuer: descriptor.annotations.get(ISSUER)?.clone(),
            subject: descriptor.annotations.get(SUBJECT)?.clone(),
        },
        _ => return None,
    };
    Some(Signature { bytes, identity })
}

/// The standard base64 alphabet; hand-rolled because a signature annotation is
/// the one place a new dependency would have to be earned.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `bytes` as standard base64 with padding.
fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let group = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let bits = (u32::from(group[0]) << 16) | (u32::from(group[1]) << 8) | u32::from(group[2]);
        out.push(ALPHABET[(bits >> 18) as usize & 63] as char);
        out.push(ALPHABET[(bits >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(bits >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[bits as usize & 63] as char } else { '=' });
    }
    out
}

/// Standard base64 back to bytes, or `None` for anything that is not base64.
/// Padding is optional on the way in; nothing else about the encoding is
/// forgiven.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(text.len() / 4 * 3);
    let mut held = 0u32;
    let mut bits = 0u32;
    for byte in text.bytes() {
        if byte == b'=' {
            break;
        }
        let value = ALPHABET.iter().position(|candidate| *candidate == byte)? as u32;
        held = (held << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((held >> bits) as u8);
        }
    }
    Some(bytes)
}
