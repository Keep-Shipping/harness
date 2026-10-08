//! Attestations: the in-toto statements a run signs and pushes beside an image
//! ([#63](https://github.com/Keep-Shipping/harness/issues/63)).
//!
//! **Provenance** ([`provenance`]) says what built this image; **SBOM**
//! ([`sbom`]) wraps a document some generator already produced, which is *not*
//! this module's job — BuildKit and syft own the format, the builder hands the
//! bytes over. Both become an in-toto v1 [`Statement`], both are signed the same
//! way, and both end up as a DSSE envelope pushed with the image digest as its
//! `subject`, so [`Registry::referrers`] lists them against the image.
//!
//! What gets signed is the DSSE pre-authentication encoding of the statement's
//! exact bytes, never a re-serialization of it. Those bytes are canonical —
//! every object's keys sorted, as the run log sorts them (`canonical_value` in
//! `ks-cli`) — so a signature does not depend on the order keys went in.

use std::collections::BTreeMap;
use std::fmt;

use ks_core::ports::supply_chain::{
    ArtifactUpload, Digest, DigestError, Registry, RegistryError, SignError, SignPayload, Signer,
    SignerIdentity,
};
use serde_json::{Value, json};

/// The type every statement here declares.
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
/// SLSA v1 build provenance.
pub const SLSA_PROVENANCE: &str = "https://slsa.dev/provenance/v1";
/// An SPDX document, whatever version the generator wrote.
pub const SPDX_DOCUMENT: &str = "https://spdx.dev/Document";
/// The payload type a statement is signed under.
pub const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
/// The media type an envelope carries, as artifact type and layer alike: OCI 1.1
/// allows one artifact type per push, so it cannot name the predicate.
pub const DSSE_ENVELOPE: &str = "application/vnd.dsse.envelope.v1+json";
/// The annotation recording the envelope's `predicateType`, so a referrers
/// listing can filter provenance from SBOM. in-toto's key, not cosign's.
pub const PREDICATE_TYPE_ANNOTATION: &str = "in-toto.io/predicate-type";
/// The build type an `oci.image` provenance statement declares — a URI, under
/// the only domain the project owns.
pub const OCI_IMAGE_BUILD_TYPE: &str =
    "https://github.com/Keep-Shipping/harness/buildtypes/oci-image/v1";

/// The thing a statement is *about*: one image, named and hashed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    /// What the subject is called — the image reference, tag and all.
    pub name: String,
    /// The sha256 of its manifest (or index) bytes, hex without the prefix.
    pub sha256: String,
}

impl Subject {
    /// The subject an image digest is, under the reference it was pushed as.
    /// Only sha256: it is the algorithm in-toto's `digest` map names an image
    /// under, and the algorithm [`attach`] links the pushed artifact by.
    pub fn image(name: impl Into<String>, digest: &Digest) -> Result<Subject, DigestError> {
        if digest.algorithm() != "sha256" {
            return Err(DigestError::UnknownAlgorithm {
                algorithm: digest.algorithm().to_string(),
            });
        }
        Ok(Subject { name: name.into(), sha256: digest.hex().to_string() })
    }
}

/// An in-toto v1 [`Statement`]. The wire format's `subject` list holds one
/// entry: one build produces one image.
#[derive(Debug, Clone, PartialEq)]
pub struct Statement {
    /// What kind of predicate this is, by URI.
    pub predicate_type: String,
    /// The image the predicate is about.
    pub subject: Subject,
    /// The predicate itself, already JSON.
    pub predicate: Value,
}

impl Statement {
    /// A statement about `subject`, carrying `predicate`.
    pub fn new(subject: Subject, predicate_type: &str, predicate: Value) -> Statement {
        Statement { predicate_type: predicate_type.to_string(), subject, predicate }
    }

    /// The statement as JSON.
    #[must_use]
    pub fn to_value(&self) -> Value {
        json!({
            "_type": STATEMENT_TYPE,
            "subject": [
                {"name": self.subject.name, "digest": {"sha256": self.subject.sha256}},
            ],
            "predicateType": self.predicate_type,
            "predicate": self.predicate,
        })
    }

    /// The statement as the exact text that gets signed.
    #[must_use]
    pub fn to_canonical(&self) -> String {
        canonical(&self.to_value())
    }

    /// The statement as the exact bytes that get signed and wrapped.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_canonical().into_bytes()
    }
}

/// What the run knows about the build it is attesting to.
#[derive(Debug, Clone, PartialEq)]
pub struct Provenance {
    /// The step that built the image.
    pub step: String,
    /// The run the build belongs to.
    pub run: String,
    /// The commit the source was at.
    pub commit: String,
    /// The ref the commit was on, e.g. `refs/heads/main`.
    pub git_ref: String,
    /// The sha256 of the `ship.ks` file, hex without the prefix.
    pub file_sha256: String,
    /// The pinned builder's id, as the adapter names it.
    pub builder_id: String,
    /// The Keep Shipping version that built this, so a verifier can tell a predicate written by
    /// one release from one written by another.
    pub version: String,
    /// The build type's own parameters, resolved and *non-secret*: which base, which context,
    /// which args, which platforms. A verifier needs these to know whether this image is what
    /// this Dockerfile was supposed to produce; it is the caller's job to leave out anything
    /// secret, because this module signs whatever it is handed
    /// ([#114](https://github.com/Keep-Shipping/harness/issues/114)).
    pub inputs: Value,
}

/// SLSA v1 provenance for an image build. `externalParameters` is whatever the
/// build type defines, and this build type is `oci.image`; the commit is the
/// *resolved dependency*, since it is what the ref resolved to.
#[must_use]
pub fn provenance(subject: Subject, build: &Provenance) -> Statement {
    let predicate = json!({
        "buildDefinition": {
            "buildType": OCI_IMAGE_BUILD_TYPE,
            "externalParameters": {
                "step": build.step,
                "shipFile": {"sha256": build.file_sha256},
                "source": {"gitRef": build.git_ref},
                "inputs": build.inputs,
            },
            "resolvedDependencies": [{
                "uri": format!("git+{}", build.git_ref),
                "digest": {"gitCommit": build.commit},
            }],
        },
        "runDetails": {
            "builder": {"id": build.builder_id, "version": {"keepshipping": build.version}},
            "metadata": {"invocationId": build.run},
        },
    });
    Statement::new(subject, SLSA_PROVENANCE, predicate)
}

/// The statement wrapping an SPDX document a generator produced: parsed, not
/// embedded as a string, so the statement stays one document a verifier walks.
pub fn sbom(subject: Subject, document: &[u8]) -> Result<Statement, AttestError> {
    let predicate = serde_json::from_slice(document)?;
    Ok(Statement::new(subject, SPDX_DOCUMENT, predicate))
}

/// One signature over an envelope's payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeSignature {
    /// The id a verifier resolves the key under: a named key's own name, or a
    /// keyless identity's `issuer#subject` — both halves, so neither can be
    /// borrowed.
    pub keyid: String,
    /// The signature bytes, standard base64.
    pub sig: String,
}

/// A DSSE envelope: a payload type, the statement as base64, and signatures
/// over the [`pae`] of the two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Always [`DSSE_PAYLOAD_TYPE`] here.
    pub payload_type: String,
    /// The statement's canonical bytes, standard base64.
    pub payload: String,
    /// One entry per signature; one here.
    pub signatures: Vec<EnvelopeSignature>,
}

impl Envelope {
    /// The envelope as JSON, canonical for the same reason the statement is.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        canonical(&json!({
            "payloadType": self.payload_type,
            "payload": self.payload,
            "signatures": self.signatures.iter()
                .map(|s| json!({"keyid": s.keyid, "sig": s.sig}))
                .collect::<Vec<Value>>(),
        }))
        .into_bytes()
    }
}

/// The DSSE pre-authentication encoding of `body` under `payload_type`:
/// `DSSEv1 <len(type)> <type> <len(body)> <body>`. The type is part of what is
/// signed, so a statement cannot be replayed as something else.
#[must_use]
pub fn pae(payload_type: &str, body: &str) -> String {
    format!("DSSEv1 {} {payload_type} {} {body}", payload_type.len(), body.len())
}

/// Signs `statement` as `signer` and returns the envelope, signed over the
/// [`pae`] of the statement's canonical bytes and carrying those same bytes.
pub async fn sign(signer: &dyn Signer, statement: &Statement) -> Result<Envelope, SignError> {
    let body = statement.to_canonical();
    let pae = pae(DSSE_PAYLOAD_TYPE, &body);
    let signature = signer.sign(&SignPayload::Bytes(pae.into_bytes())).await?;
    let keyid = match &signature.identity {
        SignerIdentity::Key { key_id } => key_id.clone(),
        SignerIdentity::Keyless { issuer, subject } => format!("{issuer}#{subject}"),
    };
    Ok(Envelope {
        payload_type: DSSE_PAYLOAD_TYPE.to_string(),
        payload: base64(body.as_bytes()),
        signatures: vec![EnvelopeSignature { keyid, sig: base64(&signature.bytes) }],
    })
}

/// Signs `statement` and pushes the envelope into `repository` with the image
/// digest as its `subject`, returning the digest the registry stored it under.
pub async fn attach(
    registry: &dyn Registry,
    repository: &str,
    signer: &dyn Signer,
    subject: &Subject,
    statement: &Statement,
) -> Result<Digest, AttestError> {
    let envelope = sign(signer, statement).await?;
    let mut annotations = BTreeMap::new();
    annotations.insert(PREDICATE_TYPE_ANNOTATION.to_string(), statement.predicate_type.clone());
    let upload = ArtifactUpload {
        media_type: DSSE_ENVELOPE.to_string(),
        artifact_type: DSSE_ENVELOPE.to_string(),
        blobs: vec![envelope.to_bytes()],
        annotations,
        subject: Some(Digest::sha256_from_hex(&subject.sha256)?),
    };
    Ok(registry.push_artifact(repository, &upload).await?.digest)
}

/// Why building or attaching an attestation failed. The port errors are reused
/// as they are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestError {
    /// The signature could not be made or checked.
    Sign(SignError),
    /// The envelope could not be pushed.
    Registry(RegistryError),
    /// The subject's `sha256` is not a digest the image could be addressed by.
    Digest(DigestError),
    /// The SBOM document was not JSON.
    Sbom {
        /// What the parser said, safe to print.
        reason: String,
    },
}

impl From<SignError> for AttestError {
    fn from(error: SignError) -> Self {
        AttestError::Sign(error)
    }
}

impl From<RegistryError> for AttestError {
    fn from(error: RegistryError) -> Self {
        AttestError::Registry(error)
    }
}

impl From<DigestError> for AttestError {
    fn from(error: DigestError) -> Self {
        AttestError::Digest(error)
    }
}

impl From<serde_json::Error> for AttestError {
    fn from(error: serde_json::Error) -> Self {
        AttestError::Sbom { reason: error.to_string() }
    }
}

impl fmt::Display for AttestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttestError::Sign(error) => write!(f, "{error}"),
            AttestError::Registry(error) => write!(f, "{error}"),
            AttestError::Digest(error) => write!(f, "attestation subject: {error}"),
            AttestError::Sbom { reason } => write!(f, "the SBOM document is not JSON: {reason}"),
        }
    }
}

impl std::error::Error for AttestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AttestError::Sign(error) => Some(error),
            AttestError::Registry(error) => Some(error),
            AttestError::Digest(error) => Some(error),
            AttestError::Sbom { .. } => None,
        }
    }
}

/// The standard base64 alphabet, and nothing else: DSSE says standard base64,
/// and a URL-safe encoder would produce envelopes no verifier accepts.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding, written out rather than depended on: the
/// workspace has no base64 crate.
pub fn base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let byte = |index: usize| chunk.get(index).copied().unwrap_or(0);
        let bits = (u32::from(byte(0)) << 16) | (u32::from(byte(1)) << 8) | u32::from(byte(2));
        let sextet = |index: usize| ALPHABET[((bits >> (18 - 6 * index)) & 0x3f) as usize] as char;
        out.push(sextet(0));
        out.push(sextet(1));
        out.push(if chunk.len() > 1 { sextet(2) } else { '=' });
        out.push(if chunk.len() > 2 { sextet(3) } else { '=' });
    }
    out
}

/// JSON with every object's keys sorted by hand: `serde_json`'s `Map` follows
/// the `preserve_order` feature, which another crate in a workspace build may
/// turn on, and a statement whose bytes depend on that verifies on one machine
/// only.
fn canonical(value: &Value) -> String {
    match value {
        Value::Object(entry) => {
            let mut keys: Vec<&String> = entry.keys().collect();
            keys.sort_unstable();
            let body: Vec<String> = keys
                .into_iter()
                .map(|key| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("a string key serializes"),
                        canonical(&entry[key])
                    )
                })
                .collect();
            format!("{{{}}}", body.join(","))
        }
        Value::Array(items) => {
            let body: Vec<String> = items.iter().map(canonical).collect();
            format!("[{}]", body.join(","))
        }
        scalar => serde_json::to_string(scalar).expect("a json value serializes"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_rfc_4648_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        // The alphabet's own last symbols: `+` and `/`, not the URL-safe `-` and `_`.
        assert_eq!(base64(&[0xfb, 0xff]), "+/8=");
    }
}
