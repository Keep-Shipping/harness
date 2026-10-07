//! The [`StateStore`] port: working data and saved plans, per run
//! ([#55](https://github.com/Keep-Shipping/harness/issues/55)).
//!
//! Not everything a run produces is an audit record. The [run log](super::run_log)
//! is append-only and hash-chained; state is the other kind of storage —
//! scratch space a step writes so a later step can read it back, cached
//! outputs, saved [`SavedPlan`](super::iac::SavedPlan)s. State is overwritten
//! in place, scoped to one [`RunId`], and gone when the run is.
//!
//! # Sensitivity is an assertion, not a fact the store can check
//!
//! [`Sensitivity`] says how a caller *claims* its bytes must be treated, and
//! [`StateStore::put`] requires the claim on every call. The store cannot
//! verify it: an adapter cannot tell a secret from a logo. Misclassification
//! is a caller bug, and requiring the argument is what makes it a deliberate
//! one instead of an omission.
//!
//! The claim is not optional decoration, though, because adapters differ
//! enormously in who can read their bytes. An adapter that is *not* the
//! customer's own local storage — hosted, shared, backed by someone else's
//! disk — must encrypt [`Secretish`](Sensitivity::Secretish) values at rest.
//! Saved plan files are [`Secretish`](Sensitivity::Secretish) because a plan
//! carries whatever the infrastructure declared, including values a plan read
//! from a secret.
//!
//! # Keys are boring on purpose
//!
//! A [`StateKey`] is short, printable ASCII with no surrounding whitespace, so
//! the same key maps onto a filename, a column or an object key without an
//! escaping layer in the middle. Anything more interesting than that belongs
//! in the value, which is opaque bytes.
//!
//! # Deleting is the escape hatch, and it is not audited
//!
//! [`StateStore::delete_run`] is how an operator clears a run's working data.
//! Nothing here records that it happened, and [`RunLog`](super::run_log::RunLog)
//! will not do it for you: a step that deletes state should append its own
//! `state.deleted` event, or the audit record will show a value that quietly
//! stopped existing. The absence is stated plainly because it is a real gap,
//! not an oversight to be discovered later.

use std::fmt;

use super::BoxFuture;
use crate::ids::RunId;

/// How a value must be treated at rest, as asserted by whoever wrote it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Sensitivity {
    /// Working data anyone on the team may read: step output, caches, scratch
    /// files.
    Ordinary,
    /// Data that must be encrypted at rest by every adapter that is not the
    /// customer's own local storage: saved plan files, anything a plan read
    /// from a secret.
    ///
    /// This is the caller's assertion about the bytes, not something the
    /// store verifies — an adapter cannot tell a secret from a logo, so
    /// misclassifying is a caller bug. That is exactly why the classification
    /// is a required argument on every [`StateStore::put`] rather than an
    /// inferred property: an adapter guessing would get it wrong silently,
    /// while a caller choosing has to be there when it goes wrong.
    Secretish,
}

impl Sensitivity {
    /// Whether the value must be encrypted at rest.
    pub fn is_secretish(self) -> bool {
        match self {
            Sensitivity::Ordinary => false,
            Sensitivity::Secretish => true,
        }
    }

    /// The lowercase wire and display form.
    pub fn as_str(self) -> &'static str {
        match self {
            Sensitivity::Ordinary => "ordinary",
            Sensitivity::Secretish => "secretish",
        }
    }
}

impl fmt::Display for Sensitivity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A key under which one run stores one value.
///
/// Printable ASCII only (`0x21..=0x7e`, so no spaces at all), at most 128
/// bytes, never empty. That is narrow on purpose: the same key has to survive
/// being a filename, an object key or a column name without an escaping layer
/// in between.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StateKey(String);

impl StateKey {
    /// Validates and wraps `key`.
    ///
    /// Rejects, in this order: an empty key, one longer than 128 bytes, a
    /// leading or trailing space, and any byte outside `0x21..=0x7e` — no
    /// spaces, no control characters, no Unicode, with the offending character
    /// reported.
    ///
    /// The whitespace check comes before the byte check because a space is
    /// `0x20`, one below the allowed range, so every padded key would
    /// otherwise fail as [`NotPrintable`](InvalidStateKey::NotPrintable) and
    /// [`SurroundingWhitespace`](InvalidStateKey::SurroundingWhitespace) would
    /// name a rejection the type can never produce. The order is not about
    /// leniency — no key may hold a space anywhere — it is about telling the
    /// caller the most specific thing that is wrong.
    pub fn new(key: impl Into<String>) -> Result<StateKey, InvalidStateKey> {
        let key = key.into();
        if key.is_empty() {
            return Err(InvalidStateKey::Empty);
        }
        if key.len() > 128 {
            return Err(InvalidStateKey::TooLong { len: key.len() });
        }
        if key.starts_with(' ') || key.ends_with(' ') {
            return Err(InvalidStateKey::SurroundingWhitespace);
        }
        if let Some(character) =
            key.chars().find(|character| !matches!(character, '\u{21}'..='\u{7e}'))
        {
            return Err(InvalidStateKey::NotPrintable { character });
        }
        Ok(StateKey(key))
    }

    /// The key as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a [`StateKey`] was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidStateKey {
    /// The key was the empty string.
    Empty,
    /// The key was longer than the 128-byte limit.
    TooLong {
        /// The key's length in bytes.
        len: usize,
    },
    /// The key held a byte outside printable ASCII (`0x21..=0x7e`) — a space,
    /// a control character or a non-ASCII character.
    NotPrintable {
        /// The first character that is not printable ASCII.
        character: char,
    },
    /// The key began or ended with a space.
    SurroundingWhitespace,
}

impl fmt::Display for InvalidStateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidStateKey::Empty => write!(f, "state key is empty"),
            InvalidStateKey::TooLong { len } => {
                write!(f, "state key is {len} bytes, over the 128-byte limit")
            }
            InvalidStateKey::NotPrintable { character } => {
                write!(f, "state key contains {character:?}, which is not printable ASCII")
            }
            InvalidStateKey::SurroundingWhitespace => {
                write!(f, "state key has leading or trailing whitespace")
            }
        }
    }
}

impl std::error::Error for InvalidStateKey {}

/// What [`StateStore::list`] reports about one stored value, without its
/// bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateSummary {
    /// The key the value is stored under.
    pub key: StateKey,
    /// The sensitivity it was written under.
    pub sensitivity: Sensitivity,
    /// The value's length in bytes, so `list` never has to fetch values to
    /// show how big they are.
    pub len: usize,
}

/// Why a [`StateStore`] call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateStoreError {
    /// The store itself failed: disk, permissions, transport. What the backend
    /// reported, safe to print.
    Backend {
        /// What went wrong, safe to print.
        message: String,
    },
    /// The value exceeds what this store accepts. State is working data meant
    /// to be short; a long-lived record belongs in the
    /// [run log](super::run_log).
    TooLarge {
        /// The key whose value is too large.
        key: StateKey,
        /// The value's length in bytes.
        len: usize,
        /// The store's limit, in bytes.
        max: usize,
    },
    /// The key already holds [`Sensitivity::Secretish`] data and this `put`
    /// claims [`Sensitivity::Ordinary`]. A key's sensitivity only ever
    /// ratchets up, never down: otherwise a later `put` could quietly strip
    /// the protection off data written earlier.
    WouldDowngrade {
        /// The key whose sensitivity would drop.
        key: StateKey,
        /// The sensitivity it is stored under today.
        from: Sensitivity,
        /// The sensitivity this `put` claims.
        to: Sensitivity,
    },
}

impl fmt::Display for StateStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StateStoreError::Backend { message } => write!(f, "state store failed: {message}"),
            StateStoreError::TooLarge { key, len, max } => {
                write!(f, "state value for {key} is {len} bytes, over the {max}-byte limit")
            }
            StateStoreError::WouldDowngrade { key, from, to } => write!(
                f,
                "refusing to store {key} as {to}: it already holds {from} data, and sensitivity only ratchets up"
            ),
        }
    }
}

impl std::error::Error for StateStoreError {}

/// The `StateStore` port: opaque working data, namespaced by run.
///
/// # The contract
///
/// - **Namespaced by run, strictly.** State belongs to one [`RunId`]. A
///   `RunId` that is not yours is simply absent — [`get`](StateStore::get)
///   returns `Ok(None)` and the run does not appear in
///   [`list`](StateStore::list). It is never another run's data.
/// - **`put` overwrites.** Unlike the [log](super::run_log), state is working
///   data, not an audit record: writing an existing key replaces its value in
///   place. That asymmetry is the whole difference between the two ports.
/// - **Absent is not an error.** `get` returns `Ok(None)` for a key that was
///   never written.
/// - **`list` returns summaries sorted by [`StateKey`]**, ascending.
/// - **`delete_run` removes one run and nothing else.** Every other run is
///   untouched, and a run with nothing stored is not an error. Deleting is the
///   operator's escape hatch and is **not** recorded in the
///   [`RunLog`](super::run_log::RunLog) — a step that deletes state should
///   append its own `state.deleted` event so the audit record shows it.
///
/// # Adapter obligations
///
/// An adapter that is **not** local storage — hosted, shared, on someone
/// else's disk — must encrypt [`Secretish`](Sensitivity::Secretish) values at
/// rest. It must **not**
/// encrypt ordinary values in a way that leaves [`list`](StateStore::list)
/// unable to report their sensitivity: a summary's
/// [`sensitivity`](StateSummary::sensitivity) is the sensitivity the value was
/// written under, taken from adapter metadata, never something the adapter
/// works out by decrypting. An adapter that cannot enumerate without
/// decrypting every value cannot answer `list` honestly, and cannot be one.
pub trait StateStore: Send + Sync {
    /// Stores `bytes` under `key` for `run`, replacing any previous value, and
    /// records `sensitivity` as the classification of those bytes.
    fn put<'a>(
        &'a self,
        run: &'a RunId,
        key: &'a StateKey,
        bytes: &'a [u8],
        sensitivity: Sensitivity,
    ) -> BoxFuture<'a, Result<(), StateStoreError>>;

    /// Reads the value stored under `key` for `run`, or `Ok(None)` if there is
    /// none.
    fn get<'a>(
        &'a self,
        run: &'a RunId,
        key: &'a StateKey,
    ) -> BoxFuture<'a, Result<Option<Vec<u8>>, StateStoreError>>;

    /// Summarises everything stored for `run`, sorted by [`StateKey`].
    fn list<'a>(
        &'a self,
        run: &'a RunId,
    ) -> BoxFuture<'a, Result<Vec<StateSummary>, StateStoreError>>;

    /// Removes everything stored for `run`, leaving every other run untouched.
    fn delete_run<'a>(&'a self, run: &'a RunId) -> BoxFuture<'a, Result<(), StateStoreError>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: ?Sized + Send + Sync>() {}

    fn key(text: &str) -> StateKey {
        StateKey::new(text).expect("valid key")
    }

    #[test]
    fn the_state_store_trait_is_dyn_compatible() {
        assert_send_sync::<dyn StateStore>();
    }

    #[test]
    fn valid_keys_are_accepted() {
        assert_eq!(key("plan").as_str(), "plan");
        assert_eq!(key("cache/2/manifest").as_str(), "cache/2/manifest");
        assert_eq!(key(&"k".repeat(128)).as_str().len(), 128);
        // The printable-ASCII range starts at 0x21, so these are the extremes.
        assert_eq!(key("!").as_str(), "!");
        assert_eq!(key("~").as_str(), "~");
        // The allowed range starts at 0x21, so a space is not printable for
        // this purpose anywhere — interior or not.
        assert_eq!(StateKey::new("a b"), Err(InvalidStateKey::NotPrintable { character: ' ' }));
    }

    #[test]
    fn empty_and_overlong_keys_are_rejected() {
        assert_eq!(StateKey::new(""), Err(InvalidStateKey::Empty));
        assert_eq!(StateKey::new("k".repeat(129)), Err(InvalidStateKey::TooLong { len: 129 }));
    }

    #[test]
    fn non_printable_keys_are_rejected_with_the_offending_character() {
        assert_eq!(StateKey::new("café"), Err(InvalidStateKey::NotPrintable { character: 'é' }));
        assert_eq!(StateKey::new("a\tb"), Err(InvalidStateKey::NotPrintable { character: '\t' }));
        // A space is printable but not in the allowed range.
        assert_eq!(StateKey::new("a b c"), Err(InvalidStateKey::NotPrintable { character: ' ' }));
        // The first offending character is the one reported.
        assert_eq!(
            StateKey::new("ok\u{1}\u{2}"),
            Err(InvalidStateKey::NotPrintable { character: '\u{1}' })
        );
    }

    #[test]
    fn keys_are_never_padded_with_spaces() {
        assert_eq!(StateKey::new(" key"), Err(InvalidStateKey::SurroundingWhitespace));
        assert_eq!(StateKey::new("key "), Err(InvalidStateKey::SurroundingWhitespace));
    }

    #[test]
    fn invalid_state_key_errors_display_actionably() {
        assert_eq!(InvalidStateKey::Empty.to_string(), "state key is empty");
        let too_long = InvalidStateKey::TooLong { len: 200 }.to_string();
        assert!(too_long.contains("200") && too_long.contains("128"), "{too_long}");
        let not_printable = InvalidStateKey::NotPrintable { character: '\u{1}' }.to_string();
        assert!(not_printable.contains("printable ASCII"), "{not_printable}");
        let spaced = InvalidStateKey::SurroundingWhitespace.to_string();
        assert!(spaced.contains("whitespace"), "{spaced}");
    }

    #[test]
    fn sensitivity_describes_its_own_obligations() {
        assert_eq!(Sensitivity::Ordinary.as_str(), "ordinary");
        assert_eq!(Sensitivity::Secretish.as_str(), "secretish");
        assert!(!Sensitivity::Ordinary.is_secretish());
        assert!(Sensitivity::Secretish.is_secretish());
        assert_eq!(Sensitivity::Secretish.to_string(), "secretish");
        // The ordering is what "ratchets up, never down" means.
        assert!(Sensitivity::Ordinary < Sensitivity::Secretish);
    }

    #[test]
    fn state_store_errors_display_actionably() {
        let backend = StateStoreError::Backend { message: "EACCES".to_string() }.to_string();
        assert!(backend.contains("state store") && backend.contains("EACCES"), "{backend}");

        let too_large =
            StateStoreError::TooLarge { key: key("plan"), len: 9_000_000, max: 1_000_000 }
                .to_string();
        assert!(
            too_large.contains("plan")
                && too_large.contains("9000000")
                && too_large.contains("1000000"),
            "{too_large}"
        );

        let downgrade = StateStoreError::WouldDowngrade {
            key: key("deploy.token"),
            from: Sensitivity::Secretish,
            to: Sensitivity::Ordinary,
        }
        .to_string();
        assert!(
            downgrade.contains("deploy.token")
                && downgrade.contains("secretish")
                && downgrade.contains("ordinary"),
            "{downgrade}"
        );
    }

    #[test]
    fn a_summary_carries_metadata_only() {
        let summary =
            StateSummary { key: key("plan"), sensitivity: Sensitivity::Secretish, len: 4096 };
        assert_eq!(summary.key.as_str(), "plan");
        assert_eq!(summary.sensitivity, Sensitivity::Secretish);
        assert_eq!(summary.len, 4096);
    }
}
