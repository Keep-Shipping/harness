//! The stored Cloudflare token's encryption: AES-256-GCM, with the key
//! derived from `HARNESS_SECRET` by HKDF-SHA256 under the fixed info string
//! [`INFO`]. Each write draws a fresh random 96-bit nonce; the info string
//! doubles as the AEAD associated data, so a ciphertext sealed for another
//! purpose will not open here. A wrong secret, a flipped bit, or a swapped
//! nonce all fail the tag check and read back as "not connected".

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use hkdf::Hkdf;
use sha2::Sha256;

/// HKDF info and AEAD associated data: the key's purpose and version.
pub const INFO: &[u8] = b"ks-console/cloudflare-token/v1";

/// [`INFO`] for the optional deploy token (rollbacks): its own key, so a
/// read token's ciphertext never opens as a deploy token or the reverse.
pub const DEPLOY_INFO: &[u8] = b"ks-console/cloudflare-deploy-token/v1";

/// The GCM nonce length: 96 bits.
pub const NONCE_LEN: usize = 12;

/// A sealed token as stored: both parts base64, nonce and ciphertext apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub nonce: String,
    pub ciphertext: String,
}

/// Why sealing or opening failed. Carries no key or plaintext material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// The secret is empty, or the key could not be derived.
    Key,
    /// The OS random source was unavailable.
    Random,
    /// The stored parts are not base64 of the expected shape.
    Malformed,
    /// The tag did not verify: wrong secret, altered data, or wrong nonce.
    Open,
}

fn cipher(secret: &str, info: &[u8]) -> Result<Aes256Gcm, SealError> {
    if secret.is_empty() {
        return Err(SealError::Key);
    }
    let hkdf = Hkdf::<Sha256>::new(None, secret.as_bytes());
    let mut key = [0u8; 32];
    hkdf.expand(info, &mut key).map_err(|_| SealError::Key)?;
    Aes256Gcm::new_from_slice(&key).map_err(|_| SealError::Key)
}

/// Seals `plaintext` under `secret` with a fresh random nonce.
pub fn seal(secret: &str, plaintext: &str) -> Result<Sealed, SealError> {
    seal_for(INFO, secret, plaintext)
}

/// [`seal`] under another purpose's key ([`DEPLOY_INFO`]).
pub fn seal_for(info: &[u8], secret: &str, plaintext: &str) -> Result<Sealed, SealError> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| SealError::Random)?;
    seal_with_nonce_for(info, secret, plaintext, &nonce)
}

/// [`seal`] with the nonce supplied: the randomness is the caller's, so
/// tests can pin it. Never reuse a nonce under one key.
pub fn seal_with_nonce(
    secret: &str,
    plaintext: &str,
    nonce: &[u8; NONCE_LEN],
) -> Result<Sealed, SealError> {
    seal_with_nonce_for(INFO, secret, plaintext, nonce)
}

fn seal_with_nonce_for(
    info: &[u8],
    secret: &str,
    plaintext: &str,
    nonce: &[u8; NONCE_LEN],
) -> Result<Sealed, SealError> {
    let cipher = cipher(secret, info)?;
    let nonce = Nonce::try_from(&nonce[..]).map_err(|_| SealError::Malformed)?;
    let ciphertext = cipher
        .encrypt(&nonce, Payload { msg: plaintext.as_bytes(), aad: info })
        .map_err(|_| SealError::Open)?;
    let engine = base64::engine::general_purpose::STANDARD;
    Ok(Sealed { nonce: engine.encode(nonce), ciphertext: engine.encode(ciphertext) })
}

/// Opens a stored token. Any failure is an error; nothing is ever returned
/// partially decrypted.
pub fn open(secret: &str, sealed: &Sealed) -> Result<String, SealError> {
    open_for(INFO, secret, sealed)
}

/// [`open`] under another purpose's key ([`DEPLOY_INFO`]).
pub fn open_for(info: &[u8], secret: &str, sealed: &Sealed) -> Result<String, SealError> {
    let engine = base64::engine::general_purpose::STANDARD;
    let nonce = engine.decode(&sealed.nonce).map_err(|_| SealError::Malformed)?;
    if nonce.len() != NONCE_LEN {
        return Err(SealError::Malformed);
    }
    let ciphertext = engine.decode(&sealed.ciphertext).map_err(|_| SealError::Malformed)?;
    let cipher = cipher(secret, info)?;
    let nonce = Nonce::try_from(&nonce[..]).map_err(|_| SealError::Malformed)?;
    let plaintext = cipher
        .decrypt(&nonce, Payload { msg: &ciphertext, aad: info })
        .map_err(|_| SealError::Open)?;
    String::from_utf8(plaintext).map_err(|_| SealError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-harness-secret-0123456789";
    const TOKEN: &str = "cf-token-AbC_123-example";
    const NONCE: [u8; NONCE_LEN] = [7; NONCE_LEN];

    #[test]
    fn a_sealed_token_opens_back_to_itself() {
        let sealed = seal(SECRET, TOKEN).expect("seal");
        assert_eq!(open(SECRET, &sealed).expect("open"), TOKEN);
        assert!(!sealed.ciphertext.contains(TOKEN), "plaintext must not be stored");
    }

    #[test]
    fn every_write_draws_a_fresh_nonce() {
        let first = seal(SECRET, TOKEN).expect("seal");
        let second = seal(SECRET, TOKEN).expect("seal");
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
    }

    #[test]
    fn a_wrong_secret_does_not_open() {
        let sealed = seal(SECRET, TOKEN).expect("seal");
        assert_eq!(open("another-secret", &sealed), Err(SealError::Open));
    }

    #[test]
    fn an_altered_ciphertext_is_rejected() {
        let sealed = seal_with_nonce(SECRET, TOKEN, &NONCE).expect("seal");
        let engine = base64::engine::general_purpose::STANDARD;
        let mut bytes = engine.decode(&sealed.ciphertext).expect("base64");
        bytes[0] ^= 0x01;
        let tampered = Sealed { nonce: sealed.nonce.clone(), ciphertext: engine.encode(bytes) };
        assert_eq!(open(SECRET, &tampered), Err(SealError::Open));
    }

    #[test]
    fn a_swapped_nonce_is_rejected() {
        let sealed = seal_with_nonce(SECRET, TOKEN, &NONCE).expect("seal");
        let other = seal_with_nonce(SECRET, TOKEN, &[9; NONCE_LEN]).expect("seal");
        let swapped = Sealed { nonce: other.nonce, ciphertext: sealed.ciphertext };
        assert_eq!(open(SECRET, &swapped), Err(SealError::Open));
    }

    #[test]
    fn a_truncated_tag_is_rejected() {
        let sealed = seal_with_nonce(SECRET, TOKEN, &NONCE).expect("seal");
        let engine = base64::engine::general_purpose::STANDARD;
        let mut bytes = engine.decode(&sealed.ciphertext).expect("base64");
        bytes.truncate(bytes.len() - 1);
        let short = Sealed { nonce: sealed.nonce, ciphertext: engine.encode(bytes) };
        assert_eq!(open(SECRET, &short), Err(SealError::Open));
    }

    #[test]
    fn a_nonce_of_the_wrong_length_is_malformed() {
        let sealed = seal_with_nonce(SECRET, TOKEN, &NONCE).expect("seal");
        let engine = base64::engine::general_purpose::STANDARD;
        let short = Sealed { nonce: engine.encode([1u8; 8]), ciphertext: sealed.ciphertext };
        assert_eq!(open(SECRET, &short), Err(SealError::Malformed));
    }

    #[test]
    fn an_empty_secret_seals_nothing() {
        assert_eq!(seal("", TOKEN), Err(SealError::Key));
    }

    #[test]
    fn the_key_is_pinned_to_its_info_string() {
        // Same secret and nonce, different info would be a different key:
        // the vector below fails if INFO or the derivation ever changes.
        let sealed = seal_with_nonce(SECRET, TOKEN, &NONCE).expect("seal");
        let hkdf = Hkdf::<Sha256>::new(None, SECRET.as_bytes());
        let mut key = [0u8; 32];
        hkdf.expand(b"ks-console/cloudflare-token/other", &mut key).expect("expand");
        let other = Aes256Gcm::new_from_slice(&key).expect("key");
        let engine = base64::engine::general_purpose::STANDARD;
        let ciphertext = engine.decode(&sealed.ciphertext).expect("base64");
        assert!(
            other
                .decrypt(
                    &Nonce::try_from(&NONCE[..]).expect("nonce"),
                    Payload { msg: &ciphertext, aad: INFO }
                )
                .is_err()
        );
    }

    #[test]
    fn a_read_token_never_opens_as_a_deploy_token_or_the_reverse() {
        let read = seal_with_nonce(SECRET, TOKEN, &NONCE).unwrap();
        assert_eq!(open_for(DEPLOY_INFO, SECRET, &read), Err(SealError::Open));
        let deploy = seal_for(DEPLOY_INFO, SECRET, TOKEN).unwrap();
        assert_eq!(open(SECRET, &deploy), Err(SealError::Open));
        assert_eq!(open_for(DEPLOY_INFO, SECRET, &deploy).as_deref(), Ok(TOKEN));
    }
}
