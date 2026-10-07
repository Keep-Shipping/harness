//! The [`StateStore`] port: where a parked run's state and its saved plans live
//! ([#42](https://github.com/Keep-Shipping/harness/issues/42)).
//!
//! A run that cannot finish in one job writes down where it got to and exits;
//! resuming is a new job that re-checks the digest binding and carries on
//! ([ADR 0005](../../../../docs/adr/0005-local-first-core-with-optional-hosted-services.md)).
//! That split needs the run's whole state to be a few blobs, so this port is a
//! blob store and nothing more — no listing, no partial update, no
//! transactions. The record's shape is the engine's (`ks_engine::state::RunState`,
//! which `ks-core` cannot link to); the store moves opaque bytes.
//!
//! Two rules: plan bytes go in **addressed by digest** (`plan-<sha256>`, and
//! the engine re-hashes what comes back), and state lives **only in storage the
//! customer owns** — there is no hosted adapter for plan bytes, ever. Adapters
//! whose backend is not the customer's own disk must encrypt at rest
//! ([#122](https://github.com/Keep-Shipping/harness/issues/122)).
//!
//! A third arrived with [#55](https://github.com/Keep-Shipping/harness/issues/55):
//! every write says how sensitive its bytes are ([`Sensitivity`]), and the store
//! *records* that. What the port does **not** do is act on it — it never
//! encrypts, never redacts, never decides where the bytes go. Recording the
//! classification is what lets an adapter that *can* do something about it do
//! something, and what lets `list` tell a caller which of a run's blobs it
//! should not print. The local adapter writes plaintext to the customer's own
//! disk and that is correct there; an adapter whose backend is not that disk
//! must encrypt [`Sensitivity::Secretish`] at rest ([#122](https://github.com/Keep-Shipping/harness/issues/122)).
//!
//! The classification is also a **ratchet**, not a label: once a key has been
//! written as [`Sensitivity::Secretish`], a later [`Sensitivity::Plain`] write
//! over that key is refused with [`StateError::Downgrade`] rather than quietly
//! dropping the classification. A caller must not be able to strip "this is a
//! secret" off data that was declared secret — not by a bug in its own
//! bookkeeping, and not by an adapter that just took the last word it was given.

use std::fmt;

use crate::ids::RunId;

use super::BoxFuture;

/// How sensitive the bytes under a key are
/// ([#55](https://github.com/Keep-Shipping/harness/issues/55)).
///
/// The port records this and nothing more. It is a statement the *caller* makes
/// about its own bytes — the store neither inspects them nor acts on the
/// classification — so that an adapter knows which of its objects must not be
/// written in the clear, and `list` can tell a reader which of a run's blobs it
/// should not print.
///
/// [`Plain`] is the honest default and covers almost everything: a run's own
/// `state.json` record is step names, digests and the actor who approved
/// something. [`Secretish`] is for bytes that describe what the customer is
/// about to do to their infrastructure — #55 names plan files, which spell out
/// every resource and argument in the change. "Secretish" rather than "Secret"
/// because the port has no way to tell it is right: a bad classification here is
/// a caller's mistake, and the honest name is the one that admits the store
/// cannot verify it.
///
/// The variants are declared least- to most-sensitive, so the derived `Ord`
/// hands a caller the higher of two classifications with `max`. That ordering is
/// offered, not relied on: the adapters shipped here (`LocalStateStore`,
/// `MemoryStateStore`) do the ratchet with an explicit `is_secretish`
/// comparison, and a third-party adapter wanting the ordering can derive or
/// match on it as it sees fit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Sensitivity {
    /// Ordinary run state: digests, step names, the parked record. Nothing here
    /// is a secret, and an adapter may store it as it stands.
    Plain,
    /// Bytes that must not be handled casually — plan files, above all. An
    /// adapter writing these anywhere but the customer's own disk encrypts them
    /// at rest ([#122](https://github.com/Keep-Shipping/harness/issues/122)).
    Secretish,
}

impl Sensitivity {
    /// Whether these bytes are [`Sensitivity::Secretish`] — the one question an
    /// adapter and a caller both actually ask, so it is a method rather than a
    /// `matches!` repeated at each site.
    pub fn is_secretish(&self) -> bool {
        matches!(self, Sensitivity::Secretish)
    }

    /// The wire and on-disk spelling, which is stable: it is what an adapter
    /// writes into its own index and what an error message names, so it cannot
    /// drift with a rename of the variant.
    pub fn as_str(&self) -> &'static str {
        match self {
            Sensitivity::Plain => "plain",
            Sensitivity::Secretish => "secretish",
        }
    }
}

impl fmt::Display for Sensitivity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What [`StateStore::list`] reports about one stored key: the key, how the
/// caller classified it, and how many bytes are under it.
///
/// Metadata only. There is no way to ask a store for a summary *of* some other
/// run's bytes without asking for that run's bytes, and no summary carries any
/// — a listing is something a caller can log, print, or hand to a human, and a
/// listing that leaked the contents it describes would defeat the point of
/// recording a sensitivity in the first place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateSummary {
    /// The key the bytes are stored under, scoped to the run that was listed.
    pub key: String,
    /// The classification the last successful [`StateStore::put`] recorded.
    pub sensitivity: Sensitivity,
    /// How many bytes are stored — the length of the value, not of any
    /// encoding an adapter applied to it.
    pub len: usize,
}

/// Why a [`StateStore`] operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateError {
    /// The key is not one [`check_key`] accepts, so writing it could escape
    /// the run's own directory.
    InvalidKey {
        /// The rejected key.
        key: String,
        /// What is wrong with it, for the message.
        reason: &'static str,
    },
    /// The write would have written [`Sensitivity::Plain`] over a key already
    /// held as [`Sensitivity::Secretish`], and was refused.
    ///
    /// This is the ratchet #55 asks for. Silently accepting it would let a
    /// caller — or a bug in one — strip a classification off data that was
    /// declared secret, and the store would have no way to notice: the bytes
    /// are unchanged, only the promise made about them. The stored bytes and
    /// their recorded sensitivity are left exactly as they were; the caller
    /// either writes [`Sensitivity::Secretish`] again, or picks a different key.
    Downgrade {
        /// The key that would have been downgraded.
        key: String,
    },
    /// The backing store could not be reached or written: a full disk, a
    /// failed upload, a revoked credential.
    Unavailable {
        /// What the adapter reported.
        message: String,
    },
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StateError::InvalidKey { key, reason } => {
                write!(f, "{key:?} is not a usable state key ({reason})")
            }
            StateError::Downgrade { key } => write!(
                f,
                "refusing to write plain bytes over {key:?}, which is already stored as \
                 secretish; store it as secretish again, or use another key"
            ),
            StateError::Unavailable { message } => {
                write!(f, "the state store is unavailable: {message}")
            }
        }
    }
}

impl std::error::Error for StateError {}

/// [`check_key`], as a predicate.
///
/// The charset is `[a-z0-9]` first and `[a-z0-9._-]` after it: no separators, no
/// `..`, no absolute paths, no surprises from a case-insensitive filesystem.
pub fn is_valid_key(key: &str) -> bool {
    check_key(key).is_ok()
}

/// [`is_valid_key`], with the rule the key broke, so an adapter can name it.
pub fn check_key(key: &str) -> Result<(), &'static str> {
    let mut characters = key.chars();
    match characters.next() {
        Some(first) if first.is_ascii_lowercase() || first.is_ascii_digit() => {}
        Some(_) => return Err("keys start with a lowercase letter or a digit"),
        None => return Err("the key is empty"),
    }
    if !characters
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
    {
        return Err("keys hold only lowercase letters, digits, `.`, `_` and `-`");
    }
    if key.contains("..") {
        return Err("keys cannot contain `..`");
    }
    Ok(())
}

/// The `StateStore` port: a per-run blob store.
///
/// Keys are scoped to a [`RunId`], so two runs cannot see each other's objects
/// however the adapter lays them out. `get` returning `Ok(None)` means "no such
/// blob" — a normal answer, not an error.
pub trait StateStore: Send + Sync {
    /// Stores `bytes` under `key` for `run`, replacing any previous object with
    /// that name, and records `sensitivity` as how they are to be treated.
    /// Writes must be atomic and durable before this resolves: a reader sees the
    /// old bytes or the new ones, and a run told it parked cannot then lose its
    /// state. The recorded sensitivity must be durable with them — a store that
    /// remembered a value's bytes but forgot that they were secretish has lost
    /// the only thing it was told about them.
    ///
    /// Fails with [`StateError::Downgrade`] rather than writing
    /// [`Sensitivity::Plain`] over a key already held as
    /// [`Sensitivity::Secretish`], and in that case writes nothing at all.
    fn put<'a>(
        &'a self,
        run: &'a RunId,
        key: &'a str,
        bytes: &'a [u8],
        sensitivity: Sensitivity,
    ) -> BoxFuture<'a, Result<(), StateError>>;

    /// Reads the object under `key` for `run`, or `Ok(None)` if there is none.
    fn get<'a>(
        &'a self,
        run: &'a RunId,
        key: &'a str,
    ) -> BoxFuture<'a, Result<Option<Vec<u8>>, StateError>>;

    /// Everything stored for `run` — metadata only, never bytes
    /// ([`StateSummary`]).
    ///
    /// **Sorted by key**, so two calls against the same state return the same
    /// order and a caller may render, diff or hash the result directly. An
    /// adapter whose backend has no inherent order must sort before returning;
    /// leaving the order down to whatever the object store happened to hand back
    /// would make a listing that changes shape between calls.
    ///
    /// A run with nothing stored is an empty vector, not an error — the same
    /// shape `get` gives a key it does not hold.
    fn list<'a>(&'a self, run: &'a RunId) -> BoxFuture<'a, Result<Vec<StateSummary>, StateError>>;

    /// Removes every key stored for `run`, and nothing belonging to any other
    /// run. This is how a finished run's state is cleaned up, so it is the one
    /// operation in the port that destroys data: it is not undoable, and a caller
    /// that still wants the bytes must not call it.
    ///
    /// Deleting a run that holds nothing — one that never parked, or was already
    /// deleted — succeeds. Cleaning up after a run that did not run is not an
    /// error; it is the normal case.
    fn delete_run<'a>(&'a self, run: &'a RunId) -> BoxFuture<'a, Result<(), StateError>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: ?Sized + Send + Sync>() {}

    #[test]
    fn the_state_store_trait_is_dyn_compatible() {
        assert_send_sync::<dyn StateStore>();
    }

    #[test]
    fn keys_are_accepted_or_refused_with_the_rule_they_broke() {
        for key in ["state.json", "plan-0", "a.b_c-d", "01h9zz"] {
            assert!(is_valid_key(key), "{key} should be valid");
        }
        // Anything that could address outside the run directory, or that a
        // case-insensitive filesystem would mangle.
        for (key, rule) in [
            ("", "empty"),
            (".hidden", "start"),
            ("State.json", "start"),
            ("a/b", "only lowercase"),
            ("dir\\file", "only lowercase"),
            ("a..b", "`..`"),
            ("naïve", "only lowercase"),
        ] {
            let refusal = check_key(key).expect_err(&format!("{key:?} must be refused"));
            assert!(refusal.contains(rule), "{key:?}: {refusal}");
        }
    }

    #[test]
    fn state_errors_display_actionably() {
        let bad =
            StateError::InvalidKey { key: "../x".to_string(), reason: "keys cannot contain `..`" };
        assert!(bad.to_string().contains("../x"), "{bad}");
        let down = StateError::Unavailable { message: "disk full".to_string() };
        assert!(down.to_string().contains("disk full"), "{down}");
        let refused = StateError::Downgrade { key: "plan-abc".to_string() };
        let message = refused.to_string();
        for fragment in ["plan-abc", "secretish", "plain"] {
            assert!(message.contains(fragment), "{fragment} missing from {message}");
        }
    }

    #[test]
    fn a_sensitivity_names_itself_and_says_whether_it_is_secretish() {
        assert!(!Sensitivity::Plain.is_secretish());
        assert!(Sensitivity::Secretish.is_secretish());
        // The spelling is what an adapter writes into its own index, so it is
        // pinned here rather than left to follow a variant rename.
        assert_eq!(Sensitivity::Plain.as_str(), "plain");
        assert_eq!(Sensitivity::Secretish.as_str(), "secretish");
        assert_eq!(Sensitivity::Secretish.to_string(), "secretish");
        // The ordering the derive offers is pinned here so a future reordering
        // is caught. Nothing in this repo's adapters relies on it: the ratchet
        // is an explicit `is_secretish` comparison.
        assert!(Sensitivity::Secretish > Sensitivity::Plain);
    }
}
