//! The [`BlockSource`] port: block content, addressed by digest
//! ([#56](https://github.com/Keep-Shipping/harness/issues/56)).
//!
//! [`BlocksIndex`](super::blocks::BlocksIndex) is the other half of block
//! distribution and says so itself: it holds *metadata only* — names,
//! versions, digests, signature status — and never block content. Content
//! lives wherever the publishing tool put it, and this port is how a run gets
//! it. The two answer different questions and neither can answer the other's:
//! an index knows `acme/web-service` has a `3.1.0`, a source knows what those
//! bytes are.
//!
//! What this port deliberately does *not* do:
//!
//! - **It does not decide where blocks come from.** ADR 0011 settles that a
//!   workflow consumes an OCI artifact and that the cache is content-addressed
//!   on disk, but the git and OCI adapters are [#79](https://github.com/Keep-Shipping/harness/issues/79)
//!   and later. This trait is the shape they will implement; nothing here
//!   opens a socket or reads a cache directory.
//! - **It does not resolve versions for `check`.** ADR 0011 is explicit that
//!   `check` and `run` "read the digest and never resolve a version", and that
//!   `check` is "offline by construction, not by convention". So
//!   [`resolve`](BlockSource::resolve)
//!   and [`list_versions`](BlockSource::list_versions) exist for the *online*
//!   commands — `blocks update`, `blocks fetch`, `blocks publish` — and
//!   [`ResolvedBlock`] is what those write into `ship.lock`. Once a lock file
//!   exists, nothing in the offline path calls this port at all.
//! - **It does not define version-constraint semantics.** [`VersionReq`]
//!   carries the constraint string exactly as `ship.ks` spells it (`@3.1`,
//!   `@3.1.0`, `@^3`) and refuses only the one thing ADR 0011 refuses. Whether
//!   `@3` means the highest `3.x` or a prerelease-aware range is deliberately
//!   left to [#79](https://github.com/Keep-Shipping/harness/issues/79), so
//!   nothing here pretends to a `semver` the port does not have.
//! - **It does not verify signatures or authenticate.**
//!   [`fetch`](BlockSource::fetch) reports the [`SignatureStatus`] it found;
//!   deciding whether that status is acceptable
//!   is `check`'s job (fail-closed, per ADR 0011), not the adapter's.

use std::fmt;

use super::BoxFuture;
use super::blocks::{BlockVersion, SignatureStatus};
use super::supply_chain::Digest;

/// The version constraint a block reference carries, exactly as written in
/// `ship.ks`: `@3.1`, `@3.1.0`, `@^3`.
///
/// A newtype over the string, not a parsed range. ADR 0011 leaves the
/// semantics of a constraint to [#79](https://github.com/Keep-Shipping/harness/issues/79),
/// and inventing a partial parser here would be a decision made by omission:
/// an adapter written against a range type would silently inherit whatever
/// this crate guessed — and notably this type is therefore **not**
/// [`Ord`]: ordering the raw constraint text would make `"3.10" < "3.9"`,
/// which is a lexicographic accident of the spelling rather than a fact about
/// versions, and a caller that sorted constraints would silently be sorting
/// strings. The one thing that *is* decided is what
/// [`VersionReq::new`] refuses — the empty string, because ADR 0011 says "a
/// block with no `@` at all is the one failure we refuse rather than default:
/// there is no `latest` for a block, because the whole pitch is that a
/// repository pins".
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VersionReq {
    text: String,
}

impl VersionReq {
    /// Wraps the constraint as written after the `@`, refusing the empty string
    /// and anything that is only whitespace — `"  "` is as much a reference
    /// with no version as `""` is, and accepting it would be a way for the one
    /// failure ADR 0011 refuses to arrive blank.
    ///
    /// Surrounding whitespace is otherwise left in place in what is stored: this
    /// is the file's text (`" 3.1 "` stays as written), and an adapter that
    /// wants it trimmed trims it. Only the *emptiness* check looks at the
    /// trimmed form.
    pub fn new(text: &str) -> Result<VersionReq, VersionReqError> {
        if text.trim().is_empty() {
            return Err(VersionReqError::Empty);
        }
        Ok(VersionReq { text: text.to_string() })
    }

    /// The constraint, as written.
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for VersionReq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "@{}", self.text)
    }
}

/// Why a [`VersionReq`] was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionReqError {
    /// The constraint was empty — the reference carried no `@`, which ADR 0011
    /// refuses rather than defaulting to a latest version.
    Empty,
}

impl fmt::Display for VersionReqError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VersionReqError::Empty => {
                write!(f, "a block reference needs a version (there is no `latest` for a block)")
            }
        }
    }
}

impl std::error::Error for VersionReqError {}

/// What one block reference resolved to: a name, the version the constraint
/// selected, and the digest that version's content is addressed by.
///
/// The digest is the point. A [`ResolvedBlock`] is what `blocks update` writes
/// into `ship.lock`, and `check` and `run` read that digest and never resolve
/// a version — so this type is produced online and consumed as a pin, not
/// re-derived on every run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedBlock {
    /// The block's name, as referenced (e.g. `acme/web-service`).
    pub name: String,
    /// The version the constraint selected, as the source names it.
    pub version: String,
    /// The digest the content is addressed by.
    pub digest: Digest,
}

/// What [`BlockSource::fetch`] returns: the definition and the signature.
///
/// Not the implementation bytes. ADR 0011 splits a block artifact into a small
/// layer carrying the typed interface and a larger one carrying the code; this
/// port is the interface side, which is what a consumer needs to call a block
/// and what `check` type-checks a use of. The digest is carried alongside so
/// the caller can verify what it got against the pin it asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockPackage {
    /// The block's name, as published.
    pub name: String,
    /// The version this package is.
    pub version: String,
    /// The digest the content is addressed by — the one `fetch` was called with.
    pub digest: Digest,
    /// The block's typed interface: what it takes in and what it produces.
    pub definition: BlockDefinition,
    /// Whether the source holds a verified signature for `digest`.
    pub signature: SignatureStatus,
}

/// A block's typed interface, as ADR 0011's small artifact layer carries it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BlockDefinition {
    /// A one-line synopsis of what the block does.
    pub summary: String,
    /// The block's inputs, in declaration order.
    pub inputs: Vec<BlockField>,
    /// The block's outputs, in declaration order.
    pub outputs: Vec<BlockField>,
}

/// One field of a [`BlockDefinition`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockField {
    /// The field's name, as the block declares it.
    pub name: String,
    /// The field's type, as the block's own vocabulary spells it.
    ///
    /// A `String`, not an enum of types this crate knows. The block's type
    /// vocabulary is the *publisher's*, and it grows: an adapter must be free
    /// to carry a type this build has never heard of and let `check` diagnose
    /// it, rather than be unable to represent the block at all. Constraining
    /// the spelling here would move the block contract into this crate
    /// without saying so.
    pub type_name: String,
    /// Whether a step that uses this block must supply the field.
    pub required: bool,
}

/// Why a [`BlockSource`] call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockSourceError {
    /// The backend itself failed: transport, credentials, a registry that
    /// refused. What the backend reported, safe to print.
    Backend {
        /// What went wrong, safe to print.
        message: String,
    },
    /// Nothing is published at the reference that was asked for. A constraint
    /// that matches nothing is this too — there is no `latest` to fall back to.
    ///
    /// The reference is whatever the method was addressed by: a block name for
    /// [`resolve`](BlockSource::resolve) and
    /// [`list_versions`](BlockSource::list_versions), a digest for
    /// [`fetch`](BlockSource::fetch). It is called `reference` rather than
    /// `name` because `fetch` is addressed by digest and has no name to
    /// report, and an error that claimed a digest was a name would be an
    /// adapter echoing back a field that does not apply to the call.
    NotFound {
        /// The reference that was asked for — the block name or the digest, as
        /// asked, so a caller can tell which lookup missed.
        reference: String,
    },
    /// The bytes fetched did not hash to the digest they were requested under,
    /// or a served version's digest disagreed with the one asked for. The
    /// fail-closed rule ADR 0011 states for images, applied to blocks.
    DigestMismatch {
        /// The digest that was asked for.
        expected: Digest,
        /// The digest the content actually is.
        actual: Digest,
    },
}

impl fmt::Display for BlockSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockSourceError::Backend { message } => write!(f, "block source failed: {message}"),
            BlockSourceError::NotFound { reference } => {
                write!(f, "no published block at {reference}")
            }
            BlockSourceError::DigestMismatch { expected, actual } => {
                write!(f, "block content is {actual}, not the {expected} that was asked for")
            }
        }
    }
}

impl std::error::Error for BlockSourceError {}

/// The `BlockSource` port: resolve block references and fetch block content.
///
/// An empty answer from [`list_versions`](BlockSource::list_versions) is a
/// normal answer — `Ok(vec![])`, not an error — because a block with no
/// published version yet is a fact, not a failure. Everything that *is* a
/// failure says which of the three things went wrong: the backend
/// ([`Backend`](BlockSourceError::Backend)), the reference
/// ([`NotFound`](BlockSourceError::NotFound)) or the bytes
/// ([`DigestMismatch`](BlockSourceError::DigestMismatch)).
pub trait BlockSource: Send + Sync {
    /// Resolves `name` at `version_req` to the version and digest it pins.
    fn resolve<'a>(
        &'a self,
        name: &'a str,
        version_req: &'a VersionReq,
    ) -> BoxFuture<'a, Result<ResolvedBlock, BlockSourceError>>;

    /// Fetches the definition and signature of the content at `digest`.
    fn fetch<'a>(
        &'a self,
        digest: &'a Digest,
    ) -> BoxFuture<'a, Result<BlockPackage, BlockSourceError>>;

    /// Lists the published versions of `name`, newest first as the source
    /// serves them.
    ///
    /// This is the [`BlockVersion`] record the
    /// [`BlocksIndex`](super::blocks::BlocksIndex) holds, reused rather than
    /// re-declared: a content source and an index describe the same releases,
    /// and two version structs that agreed by convention would be a way for a
    /// pin and a listing to drift apart. An index lists what an org *published*;
    /// a source lists what it can *serve* — the record is the same, and which
    /// one answers is the adapter's business.
    fn list_versions<'a>(
        &'a self,
        name: &'a str,
    ) -> BoxFuture<'a, Result<Vec<BlockVersion>, BlockSourceError>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: ?Sized + Send + Sync>() {}

    #[test]
    fn the_block_source_trait_is_dyn_compatible() {
        assert_send_sync::<dyn BlockSource>();
    }

    #[test]
    fn version_requirements_display_with_the_at_the_file_spells() {
        for text in ["3.1", "3.1.0", "^3"] {
            let req = VersionReq::new(text).expect("a constraint with something after the @");
            assert_eq!(req.as_str(), text);
            assert_eq!(req.to_string(), format!("@{text}"));
        }
    }

    #[test]
    fn a_reference_with_no_version_is_refused_rather_than_defaulted() {
        assert_eq!(VersionReq::new(""), Err(VersionReqError::Empty));
        // Whitespace is not a version either, and the blank reference is the
        // same failure with a different spelling.
        assert_eq!(VersionReq::new("   "), Err(VersionReqError::Empty));
        assert_eq!(VersionReq::new("\t \n"), Err(VersionReqError::Empty));
        let message = VersionReqError::Empty.to_string();
        assert!(message.contains("latest"), "{message}");
    }

    /// A constraint with whitespace around it is accepted and kept as written,
    /// while whitespace *only* is refused. The two are different decisions and
    /// a test that only covered one would let the other drift.
    #[test]
    fn whitespace_is_kept_but_whitespace_alone_is_refused() {
        let padded = VersionReq::new(" 3.1 ").expect("a constraint with something after the @");
        assert_eq!(padded.as_str(), " 3.1 ", "the text is the file's text");
        assert_eq!(padded.to_string(), "@ 3.1 ");
    }

    #[test]
    fn source_errors_display_actionably() {
        let backend = BlockSourceError::Backend { message: "401".to_string() }.to_string();
        assert!(backend.contains("block source") && backend.contains("401"), "{backend}");

        let missing =
            BlockSourceError::NotFound { reference: "acme/web-service".to_string() }.to_string();
        assert!(missing.contains("acme/web-service"), "{missing}");

        let hex = "a".repeat(64);
        let other = "b".repeat(64);
        let mismatch = BlockSourceError::DigestMismatch {
            expected: Digest::parse(&format!("sha256:{hex}")).expect("digest"),
            actual: Digest::parse(&format!("sha256:{other}")).expect("digest"),
        }
        .to_string();
        assert!(mismatch.contains(&format!("sha256:{other}")), "{mismatch}");
    }

    /// A fetched package round-trips both halves of what it promised: the
    /// definition it was asked for and the signature status it reported, with
    /// the digest the caller pinned still on it.
    #[test]
    fn a_package_round_trips_its_definition_and_signature() {
        let hex = "c".repeat(64);
        let digest = Digest::parse(&format!("sha256:{hex}")).expect("digest");
        let package = BlockPackage {
            name: "acme/web-service".to_string(),
            version: "3.1.0".to_string(),
            digest: digest.clone(),
            definition: BlockDefinition {
                summary: "Builds and ships a web service.".to_string(),
                inputs: vec![BlockField {
                    name: "image".to_string(),
                    type_name: "string".to_string(),
                    required: true,
                }],
                outputs: vec![BlockField {
                    name: "url".to_string(),
                    type_name: "string".to_string(),
                    required: false,
                }],
            },
            signature: SignatureStatus::Signed,
        };
        assert_eq!(package.digest, digest);
        assert_eq!(package.signature.as_str(), "signed");
        assert_eq!(package.definition.inputs[0].name, "image");
        assert!(package.definition.inputs[0].required);
        assert_eq!(package.definition.outputs[0].type_name, "string");
        assert_eq!(package.definition.summary, "Builds and ships a web service.");
    }
}
