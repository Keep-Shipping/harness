//! The [`BlocksIndex`] port: metadata about an org's published blocks
//! ([#149](https://github.com/Keep-Shipping/harness/issues/149)).
//!
//! The hosted blocks index is *metadata only*: for every block it holds the
//! name, the published versions, each version's content [`Digest`], the
//! publisher's [`SignerIdentity`] and the signature status, plus the README.
//! It never stores block contents — content lives in the org's registry,
//! addressed by digest, and the index only says where to look.
//!
//! The index is populated index-side: by pulling metadata from the org's
//! registry over an [`HttpClient`](super::http::HttpClient), or by the
//! announcement a `blocks publish --announce` sends. Consumers — `blocks
//! search` today, resolution of block references later — only ever see this
//! port, so a local cache or a mirror answers the same calls as the hosted
//! service.

use super::BoxFuture;
use super::supply_chain::{Digest, SignerIdentity};
use std::fmt;

/// What to look for in a [`BlocksIndex`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockQuery {
    /// Free text matched against block names and READMEs, as the index
    /// defines. Never empty when it reaches the index — callers trim first.
    pub text: String,
    /// The most entries the caller wants; the index may cap it further.
    pub limit: u32,
}

/// Whether the index holds a verified signature for a block version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureStatus {
    /// The index verified a signature over the version's digest.
    Signed,
    /// The version carries no signature the index could verify.
    Unsigned,
}

impl SignatureStatus {
    /// The lowercase wire and display form.
    pub fn as_str(&self) -> &'static str {
        match self {
            SignatureStatus::Signed => "signed",
            SignatureStatus::Unsigned => "unsigned",
        }
    }
}

impl fmt::Display for SignatureStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One published version of a block: metadata only — the content itself is
/// not here and never will be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockVersion {
    /// The version as the publisher named it.
    pub version: String,
    /// The digest the version's content is addressed by in the registry.
    pub digest: Digest,
    /// Whether the index holds a verified signature for this digest.
    pub signature: SignatureStatus,
}

/// The metadata of one published block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockEntry {
    /// The block's name, as published (e.g. `acme/rollout`).
    pub name: String,
    /// The identity the block is published as.
    pub publisher: SignerIdentity,
    /// The block's README. First line is the synopsis; may be empty.
    pub readme: String,
    /// The published versions, newest first as the index serves them.
    pub versions: Vec<BlockVersion>,
}

/// Why a [`BlocksIndex`] call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlocksIndexError {
    /// The index itself failed: transport, policy refusal, an HTTP error
    /// status. What the backend reported, safe to print.
    Backend {
        /// What went wrong, safe to print.
        message: String,
    },
    /// The index answered, but the answer is not a valid index response.
    InvalidResponse {
        /// What is wrong with it, safe to print.
        reason: String,
    },
}

impl fmt::Display for BlocksIndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlocksIndexError::Backend { message } => write!(f, "blocks index failed: {message}"),
            BlocksIndexError::InvalidResponse { reason } => {
                write!(f, "blocks index response is invalid: {reason}")
            }
        }
    }
}

impl std::error::Error for BlocksIndexError {}

/// The `BlocksIndex` port: search an org's block metadata.
///
/// An empty result is a normal answer — `Ok(vec![])` — not an error.
/// Transport and policy refusals surface as [`BlocksIndexError::Backend`];
/// an answer that violates the metadata contract is
/// [`BlocksIndexError::InvalidResponse`], never a silently emptied list.
pub trait BlocksIndex: Send + Sync {
    /// Searches the index for `query`.
    fn search<'a>(
        &'a self,
        query: &'a BlockQuery,
    ) -> BoxFuture<'a, Result<Vec<BlockEntry>, BlocksIndexError>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: ?Sized + Send + Sync>() {}

    #[test]
    fn the_blocks_index_trait_is_dyn_compatible() {
        assert_send_sync::<dyn BlocksIndex>();
    }

    #[test]
    fn signature_statuses_display_as_their_wire_form() {
        assert_eq!(SignatureStatus::Signed.to_string(), "signed");
        assert_eq!(SignatureStatus::Unsigned.as_str(), "unsigned");
    }

    #[test]
    fn index_errors_display_actionably() {
        let backend = BlocksIndexError::Backend { message: "503".to_string() }.to_string();
        assert!(backend.contains("blocks index") && backend.contains("503"), "{backend}");
        let invalid =
            BlocksIndexError::InvalidResponse { reason: "no name".to_string() }.to_string();
        assert!(invalid.contains("invalid") && invalid.contains("no name"), "{invalid}");
    }

    /// An entry round-trips its pieces; nothing in it is block *content* —
    /// only digests that point at content held elsewhere.
    #[test]
    fn entries_carry_metadata_only() {
        let hex = "a".repeat(64);
        let entry = BlockEntry {
            name: "acme/rollout".to_string(),
            publisher: SignerIdentity::Key { key_id: "2026-q3".to_string() },
            readme: "Rolls out a build.".to_string(),
            versions: vec![BlockVersion {
                version: "1.2.0".to_string(),
                digest: Digest::parse(&format!("sha256:{hex}")).expect("digest"),
                signature: SignatureStatus::Signed,
            }],
        };
        assert_eq!(entry.versions[0].digest.algorithm(), "sha256");
        assert_eq!(entry.publisher, SignerIdentity::Key { key_id: "2026-q3".to_string() });
    }
}
