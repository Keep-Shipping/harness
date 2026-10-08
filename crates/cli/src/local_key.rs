//! A local ed25519 key implementing the `Signer` port (the signed run log,
//! [#112](https://github.com/Keep-Shipping/harness/issues/112)).
//!
//! Two types, because signing and verifying do not need the same half of a
//! key: [`LocalKey`] holds a [`SigningKey`] and can sign; [`TrustedKey`] holds
//! only a [`VerifyingKey`] and can verify. Both are a real cryptographic
//! signature — unlike `ks_testing::supply_chain::FakeSigner`, whose
//! signature is a hash — so a signature made here verifies anywhere the
//! 32-byte public key is published.
//!
//! Keys live in plain files of 64 hex characters: the private file is the
//! 32-byte seed, the public file the 32-byte public key. [`SIGNING_KEY_ENV`]
//! names the private file, so a CI job can point `keepshipping log seal` at a
//! key it has mounted without a flag.

use std::fmt;
use std::path::Path;

use ed25519_dalek::{Signature as EdSignature, Signer as _, SigningKey, Verifier, VerifyingKey};
use ks_core::ports::BoxFuture;
use ks_core::ports::supply_chain::{SignError, SignPayload, Signature, Signer, SignerIdentity};
use sha2::{Digest, Sha256};

/// The environment variable naming the private key file `log seal` signs
/// with.
pub const SIGNING_KEY_ENV: &str = "KEEPSHIPPING_SIGNING_KEY";

/// Hex characters in an ed25519 seed or public key: 32 bytes.
const HEX_LEN: usize = 64;

/// Why a key file or hex string is not an ed25519 key.
#[derive(Debug)]
pub enum KeyError {
    /// The text is not 64 hex characters, or the bytes are not a key.
    Malformed {
        /// What was being read: a seed or a public key.
        what: &'static str,
        /// What is wrong, safe to print.
        message: String,
    },
    /// The file could not be read.
    Io {
        /// The file.
        path: String,
        /// What went wrong, safe to print.
        message: String,
    },
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::Malformed { what, message } => {
                write!(f, "malformed ed25519 {what}: {message}")
            }
            KeyError::Io { path, message } => write!(f, "reading key file {path}: {message}"),
        }
    }
}

impl std::error::Error for KeyError {}

/// A signing key: the private half, held as a 32-byte seed.
pub struct LocalKey {
    signing: SigningKey,
    identity: SignerIdentity,
}

impl LocalKey {
    /// A signing key from a 32-byte seed as 64 hex characters.
    pub fn from_seed_hex(seed_hex: &str) -> Result<LocalKey, KeyError> {
        let seed = decode32(seed_hex, "seed")?;
        Ok(LocalKey { signing: SigningKey::from_bytes(&seed), identity: identity_of(&seed, true) })
    }

    /// Reads a key file: the seed as hex, surrounding whitespace allowed.
    pub fn read(path: impl AsRef<Path>) -> Result<LocalKey, KeyError> {
        LocalKey::from_seed_hex(&read_hex(path)?)
    }

    /// The matching public key, as 64 hex characters. Only the tests read it: `--key` takes a
    /// file a person or a CI job wrote elsewhere.
    #[cfg(test)]
    pub fn public_hex(&self) -> String {
        hex(&self.signing.verifying_key().to_bytes())
    }

    /// The verify-only half of this key.
    pub fn trusted(&self) -> TrustedKey {
        TrustedKey { verifying: self.signing.verifying_key(), identity: self.identity.clone() }
    }
}

/// The seed is a secret: `Debug` names the key, never its bytes.
impl fmt::Debug for LocalKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalKey").field("identity", &self.identity).finish_non_exhaustive()
    }
}

impl Signer for LocalKey {
    fn identity(&self) -> SignerIdentity {
        self.identity.clone()
    }

    fn sign<'a>(&'a self, payload: &'a SignPayload) -> BoxFuture<'a, Result<Signature, SignError>> {
        let signature = self.signing.sign(&payload_bytes(payload));
        Box::pin(std::future::ready(Ok(Signature {
            bytes: signature.to_bytes().to_vec(),
            identity: self.identity.clone(),
        })))
    }

    fn verify<'a>(
        &'a self,
        payload: &'a SignPayload,
        signature: &'a Signature,
    ) -> BoxFuture<'a, Result<SignerIdentity, SignError>> {
        Box::pin(std::future::ready(verify_with(
            &self.signing.verifying_key(),
            &self.identity,
            payload,
            signature,
        )))
    }
}

/// A verify-only key: the public half, safe to publish and to keep next to
/// the run logs it authenticates.
pub struct TrustedKey {
    verifying: VerifyingKey,
    identity: SignerIdentity,
}

impl TrustedKey {
    /// A verifying key from a 32-byte public key as 64 hex characters.
    pub fn from_public_hex(public_hex: &str) -> Result<TrustedKey, KeyError> {
        let bytes = decode32(public_hex, "public key")?;
        let verifying = VerifyingKey::from_bytes(&bytes).map_err(|error| KeyError::Malformed {
            what: "public key",
            message: error.to_string(),
        })?;
        Ok(TrustedKey { identity: identity_of(&verifying.to_bytes(), false), verifying })
    }

    /// Reads a key file: the public key as hex, whitespace allowed. A private
    /// key file also works — most seeds are not points on the curve, so the
    /// public half is used instead.
    pub fn read(path: impl AsRef<Path>) -> Result<TrustedKey, KeyError> {
        let text = read_hex(path)?;
        match TrustedKey::from_public_hex(&text) {
            Ok(key) => Ok(key),
            Err(_) => Ok(LocalKey::from_seed_hex(&text)?.trusted()),
        }
    }

    fn identity_key_id(&self) -> String {
        match &self.identity {
            SignerIdentity::Key { key_id } => key_id.clone(),
            other => format!("{other:?}"),
        }
    }
}

impl fmt::Debug for TrustedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustedKey").field("identity", &self.identity).finish_non_exhaustive()
    }
}

impl Signer for TrustedKey {
    fn identity(&self) -> SignerIdentity {
        self.identity.clone()
    }

    /// A verify-only key has no private half; signing with it is a
    /// [`SignError::Backend`], not a broken signature.
    fn sign<'a>(
        &'a self,
        _payload: &'a SignPayload,
    ) -> BoxFuture<'a, Result<Signature, SignError>> {
        Box::pin(std::future::ready(Err(SignError::Backend {
            message: format!(
                "{} is a verify-only key: it has no private half",
                self.identity_key_id()
            ),
        })))
    }

    fn verify<'a>(
        &'a self,
        payload: &'a SignPayload,
        signature: &'a Signature,
    ) -> BoxFuture<'a, Result<SignerIdentity, SignError>> {
        Box::pin(std::future::ready(verify_with(
            &self.verifying,
            &self.identity,
            payload,
            signature,
        )))
    }
}

/// Verifies `signature` over `payload`: the identity it claims must be the
/// key's own, and the signature must check out under that key. The two
/// failures are reported apart — a signature moved between identities is a
/// different problem from a forged one.
fn verify_with(
    verifying: &VerifyingKey,
    identity: &SignerIdentity,
    payload: &SignPayload,
    signature: &Signature,
) -> Result<SignerIdentity, SignError> {
    if &signature.identity != identity {
        return Err(SignError::Invalid {
            reason: format!(
                "signature claims {:?}, but this key is {identity:?}",
                signature.identity
            ),
        });
    }
    let bytes: [u8; 64] =
        signature.bytes.as_slice().try_into().map_err(|_| SignError::Invalid {
            reason: format!("an ed25519 signature is 64 bytes, got {}", signature.bytes.len()),
        })?;
    verifying.verify(&payload_bytes(payload), &EdSignature::from_bytes(&bytes)).map_err(
        |error| SignError::Invalid {
            reason: format!("ed25519 signature does not verify under {identity:?}: {error}"),
        },
    )?;
    Ok(signature.identity.clone())
}

/// The bytes an ed25519 signature covers: a digest by its canonical string,
/// raw bytes as-is. The same choice `FakeSigner` makes, so the two agree on
/// what a digest payload means.
fn payload_bytes(payload: &SignPayload) -> Vec<u8> {
    match payload {
        SignPayload::Digest(digest) => digest.to_string().into_bytes(),
        SignPayload::Bytes(bytes) => bytes.clone(),
    }
}

/// `ed25519:` plus the first 16 hex characters of sha256 over the public key —
/// the id a verifier resolves. A seed is hashed through to its public key
/// first, so a private and a public key file name the same identity.
fn identity_of(public: &[u8; 32], is_seed: bool) -> SignerIdentity {
    let public =
        if is_seed { SigningKey::from_bytes(public).verifying_key().to_bytes() } else { *public };
    let hash = hex(&Sha256::digest(public));
    SignerIdentity::Key { key_id: format!("ed25519:{}", &hash[..16]) }
}

/// 32 bytes from 64 hex characters, whitespace around the text allowed.
fn decode32(text: &str, what: &'static str) -> Result<[u8; 32], KeyError> {
    let malformed = |message: String| KeyError::Malformed { what, message };
    let text = text.trim();
    if !text.is_ascii() {
        return Err(malformed("not ascii".to_string()));
    }
    if text.len() != HEX_LEN {
        return Err(malformed(format!("expected {HEX_LEN} hex characters, got {}", text.len())));
    }
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| malformed(format!("not hex: {}", &text[index * 2..index * 2 + 2])))?;
    }
    Ok(bytes)
}

/// Bytes as lowercase hex.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_hex(path: impl AsRef<Path>) -> Result<String, KeyError> {
    let path = path.as_ref();
    std::fs::read_to_string(path).map_err(|error| KeyError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ks_core::ports::supply_chain::Digest;
    use ks_testing::{block_on, supply_chain::signer_conformance};

    const SEED_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

    fn key() -> LocalKey {
        LocalKey::from_seed_hex(SEED_HEX).expect("a canonical seed")
    }

    fn digest_payload() -> SignPayload {
        SignPayload::Digest(
            Digest::parse(&format!("sha256:{}", "cd".repeat(32))).expect("canonical"),
        )
    }

    #[test]
    fn passes_the_signer_conformance_kit() {
        block_on(signer_conformance(&key()));
    }

    #[test]
    fn a_fresh_signature_verifies_to_its_own_identity() {
        block_on(async {
            let key = key();
            let payload = SignPayload::Bytes(b"run log".to_vec());
            let signature = key.sign(&payload).await.expect("sign");
            assert_eq!(signature.bytes.len(), 64, "an ed25519 signature is 64 bytes");
            assert_eq!(key.verify(&payload, &signature).await.expect("verify"), key.identity());
        });
    }

    /// Digest payloads sign over their canonical string, as `FakeSigner`
    /// reads them too.
    #[test]
    fn digest_payloads_sign_over_their_canonical_string() {
        block_on(async {
            let key = key();
            let payload = digest_payload();
            let signature = key.sign(&payload).await.expect("sign");
            assert!(key.verify(&payload, &signature).await.is_ok());
        });
    }

    /// The four ways a signature stops being this key's signature over this
    /// payload: the payload moved, the key behind it moved, the identity it
    /// claims moved, or the bytes did not survive the round trip.
    #[test]
    fn nothing_else_verifies() {
        block_on(async {
            let key = key();
            let payload = SignPayload::Bytes(b"run log".to_vec());
            let signature = key.sign(&payload).await.expect("sign");

            let tampered = SignPayload::Bytes(b"run log!".to_vec());
            assert!(matches!(
                key.verify(&tampered, &signature).await,
                Err(SignError::Invalid { .. })
            ));

            let other = LocalKey::from_seed_hex(&"11".repeat(32)).expect("a canonical seed");
            let theirs = other.sign(&payload).await.expect("sign");
            // The same identity claimed over the wrong key: a forgery.
            let forged = Signature { bytes: theirs.bytes, identity: key.identity() };
            assert!(matches!(key.verify(&payload, &forged).await, Err(SignError::Invalid { .. })));

            let mut relabelled = signature.clone();
            relabelled.identity =
                SignerIdentity::Key { key_id: "ed25519:0000000000000000".to_string() };
            assert!(matches!(
                key.verify(&payload, &relabelled).await,
                Err(SignError::Invalid { .. })
            ));

            let mut truncated = signature;
            truncated.bytes.truncate(32);
            assert!(matches!(
                key.verify(&payload, &truncated).await,
                Err(SignError::Invalid { .. })
            ));
        });
    }

    #[test]
    fn a_trusted_key_verifies_from_the_public_hex() {
        block_on(async {
            let key = key();
            let trusted = TrustedKey::from_public_hex(&key.public_hex()).expect("public key");
            assert_eq!(trusted.identity(), key.identity(), "a key file names the same id");
            let payload = SignPayload::Bytes(b"run log".to_vec());
            let signature = key.sign(&payload).await.expect("sign");
            assert_eq!(trusted.verify(&payload, &signature).await.expect("verify"), key.identity());
        });
    }

    #[test]
    fn a_verify_only_key_cannot_sign() {
        block_on(async {
            let key = key();
            let trusted = TrustedKey::from_public_hex(&key.public_hex()).expect("public key");
            assert!(matches!(
                trusted.sign(&SignPayload::Bytes(b"run log".to_vec())).await,
                Err(SignError::Backend { .. })
            ));
        });
    }

    #[test]
    fn keys_round_trip_through_files() {
        let dir =
            std::env::temp_dir().join(format!("keepshipping-local-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let seed_path = dir.join("signing.key");
        let public_path = dir.join("signing.pub");
        std::fs::write(&seed_path, format!("{SEED_HEX}\n")).expect("write seed");
        let key = LocalKey::read(&seed_path).expect("read seed");
        std::fs::write(&public_path, key.public_hex()).expect("write public key");
        let trusted = TrustedKey::read(&public_path).expect("read public key");
        assert_eq!(trusted.identity(), key.identity());
        // The private file also opens as a trusted key, through its public half.
        assert_eq!(
            TrustedKey::read(&seed_path).expect("read seed as trusted").identity(),
            key.identity()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn bad_hex_and_wrong_lengths_are_errors() {
        assert!(LocalKey::from_seed_hex("zz").is_err(), "wrong length");
        assert!(LocalKey::from_seed_hex(&"zz".repeat(32)).is_err(), "not hex");
        assert!(TrustedKey::from_public_hex(&"00".repeat(31)).is_err(), "31 bytes");
        assert!(LocalKey::read("/nonexistent/ks-signing.key").is_err(), "missing file");
    }

    #[test]
    fn debug_never_prints_the_seed() {
        let key = key();
        let rendered = format!("{key:?}");
        assert!(!rendered.contains(SEED_HEX), "the seed must not leak: {rendered}");
    }
}
