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

use std::fmt;

use crate::ids::RunId;

use super::BoxFuture;

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
    /// that name. Writes must be atomic and durable before this resolves: a
    /// reader sees the old bytes or the new ones, and a run told it parked
    /// cannot then lose its state.
    fn put<'a>(
        &'a self,
        run: &'a RunId,
        key: &'a str,
        bytes: &'a [u8],
    ) -> BoxFuture<'a, Result<(), StateError>>;

    /// Reads the object under `key` for `run`, or `Ok(None)` if there is none.
    fn get<'a>(
        &'a self,
        run: &'a RunId,
        key: &'a str,
    ) -> BoxFuture<'a, Result<Option<Vec<u8>>, StateError>>;
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
    }
}
