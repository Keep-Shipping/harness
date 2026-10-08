//! The signature over a log's tip, and the keyring that checks it — the half of
//! tamper-evidence a hash chain cannot give, read off the runner's sidecar
//! ([#112](https://github.com/Keep-Shipping/harness/issues/112)).
//!
//! The chain catches an edited entry, a deleted one and two swapped. It cannot
//! catch truncating entries off the end — the prefix left behind is still a good
//! chain — nor a writer that recomputes the chain as it goes, which is
//! self-consistent and simply not the run that happened. Both need a signature
//! over the tip, made from outside the writer. `crates/cli`'s `seal` makes it;
//! this checks it, over the identical wire format and the identical signed bytes.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature as EdSignature, Verifier, VerifyingKey};
use ks_core::ports::supply_chain::SignerIdentity;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The suffix a run's seals file carries on the runner's side. Re-exported here
/// so the hosted module and the CLI name it in one place.
pub const SEALS_SUFFIX: &str = ".seals.jsonl";

/// The `artifactType` a signed run log is pushed under, so a referrer listing
/// finds it exactly as it finds an SBOM.
pub const RUN_LOG_ARTIFACT_TYPE: &str = "application/vnd.keepshipping.run-log.v1";

/// The run the log belongs to, on the artifact manifest.
pub const RUN_ANNOTATION: &str = "io.keepshipping.run-log.run";

/// The head the last seal covers, so a referrer listing reads without the log.
pub const HEAD_ANNOTATION: &str = "io.keepshipping.run-log.head";

/// The bytes a seal signs. Domain-separated and line-oriented, so the same text
/// can never be read as a signature over anything else this project signs.
/// Reproduced byte for byte from `crates/cli`'s `seal_payload`, which is the whole
/// of the compatibility the issue rests on — and which is why `repo` is not
/// among them; see the crate docs.
pub fn seal_payload(run: &str, seq: u64, head: &str) -> Vec<u8> {
    format!("keepshipping run-log seal v1\nrun {run}\nseq {seq}\nhead {head}\n").into_bytes()
}

/// One signature over one entry's head: the runner's sidecar line, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seal {
    /// The head the seal covers — that entry's `hash`.
    pub head: String,
    /// The run the seal is about.
    pub run: String,
    /// The `seq` of the entry this seal covers.
    pub seq: u64,
    /// The identity the signature claims.
    pub identity: SignerIdentity,
    /// The signature bytes.
    pub signature: Vec<u8>,
}

impl Seal {
    /// The line the runner stores a seal as: sorted keys, one object, no spaces
    /// — `{"head":…,"identity":…,"run":…,"seq":…,"signature":…}`, with the
    /// signature as lowercase hex.
    pub fn to_line(&self) -> String {
        let identity = match &self.identity {
            SignerIdentity::Key { key_id } => format!("{{\"key\":{}}}", quoted(key_id)),
            SignerIdentity::Keyless { issuer, subject } => {
                format!("{{\"issuer\":{},\"subject\":{}}}", quoted(issuer), quoted(subject))
            }
        };
        format!(
            "{{\"head\":{},\"identity\":{},\"run\":{},\"seq\":{},\"signature\":{}}}",
            quoted(&self.head),
            identity,
            quoted(&self.run),
            self.seq,
            quoted(&hex(&self.signature))
        )
    }

    /// Reads a sidecar line back. The same shape `to_line` writes, including the
    /// lowercase-only hex: a signature has exactly one spelling on disk, so two
    /// spellings cannot both pass.
    pub fn parse(line: &str) -> Result<Seal, String> {
        let value: Value =
            serde_json::from_str(line).map_err(|e| format!("not a JSON object ({e})"))?;
        let object = value.as_object().ok_or("not a JSON object")?;
        let field = |object: &serde_json::Map<String, Value>, key: &str| {
            object.get(key).and_then(Value::as_str).map(str::to_string).ok_or_else(|| missing(key))
        };
        let text = |key: &str| field(object, key);
        let identity =
            object.get("identity").and_then(Value::as_object).ok_or_else(|| missing("identity"))?;
        let keyless = |key: &str| {
            field(identity, key).map_err(|_| format!("the seal names neither a key nor {key}"))
        };
        let identity = match identity.get("key") {
            Some(_) => SignerIdentity::Key { key_id: field(identity, "key")? },
            None => {
                SignerIdentity::Keyless { issuer: keyless("issuer")?, subject: keyless("subject")? }
            }
        };
        Ok(Seal {
            head: text("head")?,
            run: text("run")?,
            seq: object.get("seq").and_then(Value::as_u64).ok_or_else(|| missing("seq"))?,
            identity,
            signature: unhex(&text("signature")?)?,
        })
    }

    /// The key id the seal claims, when it claims a key at all. A hosted keyring
    /// has no issuer to resolve a keyless identity against, so it refuses those
    /// rather than waving them through.
    pub fn key_id(&self) -> Option<&str> {
        match &self.identity {
            SignerIdentity::Key { key_id } => Some(key_id),
            SignerIdentity::Keyless { .. } => None,
        }
    }
}

/// What a field the line does not have is called.
fn missing(key: &str) -> String {
    format!("the seal has no `{key}`")
}

fn quoted(text: &str) -> String {
    serde_json::to_string(text).expect("a string serializes")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Hex to bytes, or why it is not hex. ASCII first: the slices below are byte
/// offsets, and a non-ASCII character would be cut in half rather than reported.
/// Lowercase only, so a signature has one spelling on disk.
fn unhex(text: &str) -> Result<Vec<u8>, String> {
    if !text.is_ascii() {
        return Err("the signature is not hexadecimal".to_string());
    }
    if !text.len().is_multiple_of(2) {
        return Err(format!("the signature is {} characters, not whole bytes", text.len()));
    }
    (0..text.len())
        .step_by(2)
        .map(|at| {
            let pair = &text[at..at + 2];
            if pair.bytes().any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte)) {
                return Err(format!("`{pair}` is not lowercase hex"));
            }
            u8::from_str_radix(pair, 16).map_err(|_| format!("`{pair}` is not hex"))
        })
        .collect()
}

/// `ed25519:` plus the first 16 hex characters of sha256 over the public key —
/// the id a verifier resolves. The same derivation as `crates/cli`'s
/// `local_key::identity_of`, so a key registered locally and a key registered
/// here name the same identity.
pub fn identity_of(public: &[u8; 32]) -> String {
    let hash = hex(&Sha256::digest(public));
    format!("ed25519:{}", &hash[..16])
}

/// The keys a hosted viewer will accept a seal under, by key id.
#[derive(Debug, Clone, Default)]
pub struct TrustedKeys(BTreeMap<String, VerifyingKey>);

impl TrustedKeys {
    /// An empty keyring.
    pub fn new() -> TrustedKeys {
        TrustedKeys(BTreeMap::new())
    }

    /// Adds a public key, from 64 hex characters. Uppercase is fine on input —
    /// this is an operator pasting a key, not a signature on disk — so the decode
    /// is the lenient one `crates/cli`'s `local_key::decode32` uses.
    pub fn insert(&mut self, public_hex: &str) -> Result<(), KeyError> {
        let bytes = decode32(public_hex)?;
        let id = identity_of(&bytes);
        self.0.insert(id, key_of(&bytes)?);
        Ok(())
    }

    /// Adds a public key under a key id the caller names rather than one derived
    /// from it, which is how a keyring loaded from configuration is populated:
    /// an id is a label someone typed, and it can be wrong.
    ///
    /// Nothing is weakened by it — [`TrustedKeys::verify`] re-derives the id from
    /// the key and refuses any pair where the two disagree — but it is the only
    /// way to reach that check, so this is where the mismatch is introduced
    /// rather than something [`TrustedKeys::insert`] could ever produce.
    pub fn insert_under(&mut self, key_id: &str, public_hex: &str) -> Result<(), KeyError> {
        let bytes = decode32(public_hex)?;
        self.0.insert(key_id.to_string(), key_of(&bytes)?);
        Ok(())
    }

    /// Checks a seal against the keyring. In order: a keyless identity is refused
    /// (a hosted keyring knows named keys, not issuers); the key id must be
    /// trusted; the signature must be 64 bytes; the key id must actually derive
    /// from the public key it names, so a substituted id is caught before any
    /// signature is looked at; and only then is the signature verified over the
    /// exact [`seal_payload`] bytes.
    pub fn verify(&self, seal: &Seal) -> Result<(), SealRefusal> {
        let Some(key_id) = seal.key_id() else {
            let SignerIdentity::Keyless { subject, issuer } = &seal.identity else {
                unreachable!("key_id is None only for a keyless identity")
            };
            return Err(SealRefusal::Keyless { subject: subject.clone(), issuer: issuer.clone() });
        };
        let verifying =
            self.0.get(key_id).ok_or_else(|| SealRefusal::UntrustedKey(key_id.to_string()))?;
        let bytes: [u8; 64] = seal
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| SealRefusal::BadSignature { found: seal.signature.len() })?;
        let derived = identity_of(&verifying.to_bytes());
        if derived != key_id {
            return Err(SealRefusal::SubstitutedKey { key_id: key_id.to_string(), derived });
        }
        verifying
            .verify(
                &seal_payload(&seal.run, seal.seq, &seal.head),
                &EdSignature::from_bytes(&bytes),
            )
            .map_err(|error| SealRefusal::DoesNotVerify(error.to_string()))
    }

    /// The key ids the keyring trusts, in order.
    pub fn ids(&self) -> impl Iterator<Item = &String> {
        self.0.keys()
    }
}

/// Why a seal is not what it claims. Every variant is a sentence a reader of a
/// hosted page can be shown, since these are the refusals that decide whether a
/// run's badge reads `verified`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealRefusal {
    /// The seal names a keyless identity, which a hosted keyring cannot resolve.
    Keyless {
        /// The certified subject the seal names.
        subject: String,
        /// The issuer that certified it.
        issuer: String,
    },
    /// The key id is not one this keyring trusts.
    UntrustedKey(String),
    /// The signature is not a 64-byte ed25519 signature.
    BadSignature {
        /// How many bytes it was.
        found: usize,
    },
    /// The key id does not derive from the public key it names, so the id was
    /// substituted and the lookup above matched the wrong key.
    SubstitutedKey {
        /// The id the seal claims.
        key_id: String,
        /// The id that public key actually derives.
        derived: String,
    },
    /// The signature does not verify under the named key. This is the refusal a
    /// hash chain cannot produce: a writer who recomputes the whole chain leaves
    /// a perfectly good chain, and only a signature from outside the writer says
    /// otherwise.
    DoesNotVerify(String),
}

impl std::fmt::Display for SealRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SealRefusal::Keyless { subject, issuer } => write!(
                f,
                "a hosted keyring can only check named keys, and this seal is {subject} from {issuer}"
            ),
            SealRefusal::UntrustedKey(key_id) => write!(f, "no trusted key `{key_id}`"),
            SealRefusal::BadSignature { found } => {
                write!(f, "an ed25519 signature is 64 bytes, got {found}")
            }
            SealRefusal::SubstitutedKey { key_id, derived } => write!(
                f,
                "the key id `{key_id}` is not what that key derives — that key is `{derived}`"
            ),
            SealRefusal::DoesNotVerify(message) => {
                write!(f, "the signature does not verify ({message})")
            }
        }
    }
}

/// Why a public key could not be registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// The hex is not 32 bytes of a key.
    Malformed {
        /// What is wrong, safe to print.
        message: String,
    },
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::Malformed { message } => write!(f, "not a usable public key: {message}"),
        }
    }
}

/// 32 bytes from 64 hex characters, whitespace around the text allowed. Uppercase
/// is accepted: this decodes an operator's paste, not a signature on disk.
fn decode32(text: &str) -> Result<[u8; 32], KeyError> {
    let malformed = |message: String| KeyError::Malformed { message };
    let text = text.trim();
    if !text.is_ascii() {
        return Err(malformed("not ascii".to_string()));
    }
    if text.len() != 64 {
        return Err(malformed(format!("expected 64 hex characters, got {}", text.len())));
    }
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| malformed(format!("not hex: {}", &text[index * 2..index * 2 + 2])))?;
    }
    Ok(bytes)
}

/// The verifying key for 32 decoded bytes.
fn key_of(bytes: &[u8; 32]) -> Result<VerifyingKey, KeyError> {
    VerifyingKey::from_bytes(bytes).map_err(|error| KeyError::Malformed {
        message: format!("not an ed25519 public key ({error})"),
    })
}
