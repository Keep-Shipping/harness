//! `ship.lock`: resolving a block reference once, and verifying what came back
//! ([#81](https://github.com/Keep-Shipping/harness/issues/81)).
//!
//! Two functions, and the split is ADR 0011's: [`update`] is *online* — it is
//! what `keepshipping blocks update` does, and the only thing that asks a
//! [`BlockSource`] what exists — and [`verify`] is the gate a run puts in front
//! of bytes it did not choose. A run does not put it there yet: nothing
//! resolves a block at run time, so [`verify`] has no production caller and the
//! wiring lands with block resolution. What exists today is the rule and the
//! refusal, fail-closed, under test.
//!
//! ```text
//!   ship.ks                update()                ship.lock
//!   acme/web-service@v3 ──────────────▶  version = "3.4.1", digest = "sha256:…"
//!
//!   check  reads the digest, offline, out of the cache
//!   run    fetch(digest) ──▶ verify(entry, package, signer, baseline) ──▶ use, or refuse
//! ```
//!
//! "Resolved once" is a rule about *repositories*, not processes: an entry the
//! lock already has is carried over untouched, so a release published tomorrow
//! does not change what today's build runs.

use std::fmt;

use ks_core::block_trust::Untrusted;
use ks_core::lock::{BlockRef, Lock, LockEntry, Version, select};
use ks_core::ports::block_source::{BlockPackage, BlockSource, BlockSourceError};
use ks_core::ports::blocks::{BlockVersion, SignatureStatus};
use ks_core::ports::policy::Baseline;
use ks_core::ports::supply_chain::{Digest, SignerIdentity};

/// Resolves `references` into a `ship.lock`, asking `source` only about the
/// ones the lock has never seen.
///
/// A reference already in `previous` — same name, same request — is carried
/// over as it stands without asking the source anything, which is what makes a
/// pin a pin: `@v3` means "the highest 3.x *when the lock was written*". A
/// reference no longer used is dropped, so the lock records what the repository
/// pins now, not a log of what it once did.
///
/// Resolution goes through [`BlockSource::list_versions`] rather than
/// [`BlockSource::resolve`] because the selection rule is this crate's
/// ([`select`]): an adapter resolving under its own rules would put a second,
/// quieter answer behind the one the lock records. A digest request names
/// content rather than a version, so it is found in the same listing by digest.
pub async fn update(
    source: &dyn BlockSource,
    references: &[BlockRef],
    previous: &Lock,
) -> Result<Lock, LockUpdateError> {
    let mut entries: Vec<LockEntry> = Vec::new();
    for reference in references {
        if let Some(entry) = previous.get(reference) {
            carried(&mut entries, entry.clone())?;
            continue;
        }
        let published = source
            .list_versions(reference.name())
            .await
            .map_err(|error| LockUpdateError::Source { reference: reference.to_string(), error })?;
        let chosen =
            select(reference.pin(), &published).ok_or_else(|| LockUpdateError::Unresolved {
                reference: reference.to_string(),
                request: reference.pin().to_string(),
                published: versions_of(&published),
            })?;
        // `select` only returns a candidate whose version it parsed, so this
        // re-check is belt and braces: what goes in the lock must be text this
        // build wrote, not a tag a source chose to spell with a newline.
        if Version::parse(&chosen.version).is_err() {
            return Err(LockUpdateError::Unresolved {
                reference: reference.to_string(),
                request: reference.pin().to_string(),
                published: versions_of(&published),
            });
        }
        carried(
            &mut entries,
            LockEntry {
                name: reference.name().to_string(),
                request: reference.pin().to_string(),
                version: chosen.version.clone(),
                digest: chosen.digest.clone(),
                // The repository a block resolved from is recorded once the
                // source can name one (#79); a first resolution has none.
                source: None,
            },
        )?;
    }
    Lock::from_entries(entries)
        .map_err(|error| LockUpdateError::Unwritable { reason: error.message().to_string() })
}

/// Adds an entry unless the same reference is already held.
///
/// The same reference listed twice in `ship.ks` is one pin with one entry, so
/// both the carried and the freshly resolved paths come through here: pushing
/// twice would leave a lock `Lock::parse` refuses as a duplicate. Two
/// *different* resolutions of one reference are a conflict, not a duplicate
/// line, and happen when a release lands between two lookups.
fn carried(entries: &mut Vec<LockEntry>, entry: LockEntry) -> Result<(), LockUpdateError> {
    if let Some(held) = entries.iter().find(|held| held.key() == entry.key()) {
        if held != &entry {
            return Err(LockUpdateError::Conflict {
                reference: entry.to_string(),
                kept: held.version.clone(),
                refused: entry.version,
            });
        }
        return Ok(());
    }
    entries.push(entry);
    Ok(())
}

/// The versions a source listed, for an error that must say what was on offer.
fn versions_of(published: &[BlockVersion]) -> Vec<String> {
    let mut versions: Vec<String> = published.iter().map(|entry| entry.version.clone()).collect();
    versions.sort();
    versions
}

/// Checks a fetched package against the pin it was resolved by — the last gate
/// before block content is used, and deliberately narrow:
///
/// - the package's digest must be the locked digest, the same fail-closed rule
///   [`Registry`](ks_core::ports::supply_chain::Registry) states for images;
/// - it must be [`SignatureStatus::Signed`] — unsigned content is refused, as
///   ADR 0011 requires for secrets and `ci-only`;
/// - and the identity behind that signature must be one
///   [`Baseline::publishers`] lists, which is what
///   [`ks_core::block_trust::verify`] decides.
///
/// The signature *status* is the adapter's statement and says nothing about
/// *who*: the [`BlockSource`] adapter has no idea what your organization's
/// publishers are ([ADR
/// 0011](https://github.com/Keep-Shipping/harness/blob/main/docs/adr/0011-block-distribution.md)),
/// so it reports signed-or-unsigned and no more. The identity therefore arrives
/// separately, from [`Signer::verify`](ks_core::ports::supply_chain::Signer::verify)
/// on the supply-chain port, and is a parameter here rather than a field on
/// [`BlockPackage`]: a package is what the adapter hands over, and folding an
/// organization's allowlist into that struct would let the thing being checked
/// declare its own verdict.
///
/// Every rule fails closed, and the identity rule is the one that matters most —
/// a compromised publisher's block clears the digest and the signature just as
/// cleanly as an honest one, and only the baseline tells the two apart.
///
/// Returns the identity the block was accepted under, so a caller records who
/// published what it is about to run. No caller does that yet — the gate is
/// defined and tested, and a run reaches it when block resolution lands.
pub fn verify(
    entry: &LockEntry,
    package: &BlockPackage,
    signer: Option<&SignerIdentity>,
    baseline: &Baseline,
) -> Result<SignerIdentity, VerifyError> {
    if package.digest != entry.digest {
        return Err(VerifyError::DigestMismatch {
            reference: entry.to_string(),
            expected: entry.digest.clone(),
            actual: package.digest.clone(),
        });
    }
    if package.signature != SignatureStatus::Signed {
        return Err(VerifyError::Unsigned {
            reference: entry.to_string(),
            digest: entry.digest.clone(),
        });
    }
    ks_core::block_trust::verify(signer, baseline)
        .map_err(|reason| VerifyError::Untrusted { reference: entry.to_string(), reason })
}

/// Why [`update`] could not write a lock.
#[derive(Debug)]
pub enum LockUpdateError {
    /// The source itself failed — transport, credentials, a registry refusal.
    Source {
        /// The reference whose lookup failed, as written.
        reference: String,
        /// What the source reported.
        error: BlockSourceError,
    },
    /// Nothing published matches the request. Says what was asked for and what
    /// *is* published, because "no match" alone leaves an operator guessing
    /// between a typo, a misspelled major and a block nobody has published.
    Unresolved {
        /// The reference that could not be resolved, as written.
        reference: String,
        /// The request that matched nothing.
        request: String,
        /// The versions the source does have, sorted.
        published: Vec<String>,
    },
    /// The same reference resolved two ways in one pass: `ship.ks` lists it
    /// twice and the source answers differently, which happens when a release
    /// lands between the two lookups.
    Conflict {
        /// The reference, as written.
        reference: String,
        /// The version the first lookup resolved to.
        kept: String,
        /// The version the second did, and which is refused.
        refused: String,
    },
    /// A resolved field cannot be written to a lock file — it holds a `"`, a
    /// `\` or a control character. The format has no escapes, so such a value
    /// could only be written as extra lines, and a lock that does not re-parse
    /// is worse than a failed update.
    Unwritable {
        /// Why the value cannot be written, safe to print.
        reason: String,
    },
}

impl fmt::Display for LockUpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LockUpdateError::Source { reference, error } => {
                write!(f, "cannot resolve {reference}: {error}")
            }
            LockUpdateError::Unresolved { reference, request, published } => {
                let offered = if published.is_empty() {
                    "nothing at all".to_string()
                } else {
                    published.join(", ")
                };
                write!(
                    f,
                    "no published version of {reference} matches `{request}` (published: {offered})"
                )
            }
            LockUpdateError::Conflict { reference, kept, refused } => {
                write!(f, "{reference} resolved twice, to different versions: {kept} and {refused}")
            }
            LockUpdateError::Unwritable { reason } => {
                write!(f, "cannot write a lock file: {reason}")
            }
        }
    }
}

impl std::error::Error for LockUpdateError {}

/// Why a package was refused before use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The package is not the content the lock pinned.
    DigestMismatch {
        /// The reference it was fetched for, as written.
        reference: String,
        /// The digest the lock records.
        expected: Digest,
        /// The digest the content actually is.
        actual: Digest,
    },
    /// The content carries no verified signature.
    Unsigned {
        /// The reference it was fetched for, as written.
        reference: String,
        /// The digest that is unsigned.
        digest: Digest,
    },
    /// The content is signed, but by an identity the baseline does not list.
    /// Signatures from *anybody* satisfy the rule above, so this is the refusal
    /// that keeps a compromised publisher's block from being used
    /// ([#125](https://github.com/Keep-Shipping/harness/issues/125)).
    Untrusted {
        /// The reference it was fetched for, as written.
        reference: String,
        /// Why the organization does not trust it, as
        /// [`ks_core::block_trust`] words it.
        reason: Untrusted,
    },
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::DigestMismatch { reference, expected, actual } => write!(
                f,
                "{reference} was pinned at {expected}, and this content is {actual}: the pin and \
                 the bytes disagree"
            ),
            VerifyError::Unsigned { reference, digest } => write!(
                f,
                "{reference} at {digest} carries no verified signature, and an unsigned block is \
                 not used"
            ),
            VerifyError::Untrusted { reference, reason } => {
                write!(f, "{reference} is not used: {reason}")
            }
        }
    }
}

impl std::error::Error for VerifyError {}
