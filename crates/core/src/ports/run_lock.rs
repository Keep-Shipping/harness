//! The [`RunLock`] port: mutual exclusion of runs that change one
//! (account, module) ([#175](https://github.com/Keep-Shipping/harness/issues/175)).
//!
//! Two runs that would both change `account/module` — a plan→apply workflow
//! and the nightly drift run, two applies racing on one module — must never
//! act at once. The lock is a **lease**: [`RunLock::acquire`] grants at most
//! one live lease per key, carrying an expiry and a fencing token. The expiry
//! keeps a crashed run from wedging a module forever: the lease lapses and
//! the next run takes over. The token keeps the takeover honest: it is
//! strictly increasing per key across every grant, so a run whose workflow
//! resumed after its lease expired and was taken over acts with a lower
//! token, and the resource it touches — the apply, the state write — refuses
//! it. The lock *issues* tokens; it does not enforce them. Everything a lease
//! guards must check the token it is handed against the highest one it has
//! already acted on.
//!
//! Re-acquiring while you still hold the live lease is idempotent: the same
//! lease comes back, same token, same expiry. That is the "the Worker
//! restarted mid-run and the workflow resumes" case — the resumed run asks
//! "may I proceed" and is told "you already may". Asking must not extend
//! anything; renewal is explicit ([`RunLock::renew`]). A holder whose lease
//! *expired* is a different case: re-acquiring grants a fresh lease with a
//! fresh, higher token, because the run has to earn the right to act again.
//!
//! The hosted adapter (issue #175) is a Cloudflare Durable Object per
//! (account, module) — the object's single-threaded storage makes
//! check-and-grant atomic. A local adapter can be a lockfile beside the
//! state, its mtime standing in for the expiry. Like [`RunLog`](super::run_log::RunLog)
//! this port is engine-only — a step cannot hold it, so it is not in the
//! `Port` enum and `STEP_API` does not move.

use std::fmt;
use std::time::{Duration, SystemTime};

use crate::ids::RunId;

use super::BoxFuture;

/// The resource a run lock guards: one module in one account.
///
/// Both names are validated on construction — non-empty, and no `/` inside
/// either, so the [`Display`](fmt::Display) form `account/module` is
/// unambiguous.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LockKey {
    account: String,
    module: String,
}

impl LockKey {
    /// Names the module `module` in `account` whose changing runs must not
    /// overlap. Refuses an empty name, or one containing `/`, with
    /// [`LockError::InvalidKey`].
    pub fn new(
        account: impl Into<String>,
        module: impl Into<String>,
    ) -> Result<LockKey, LockError> {
        let account = account.into();
        let module = module.into();
        if account.is_empty() {
            return Err(LockError::InvalidKey { value: account, reason: "the account is empty" });
        }
        if module.is_empty() {
            return Err(LockError::InvalidKey { value: module, reason: "the module is empty" });
        }
        for (what, name) in [("account", account.as_str()), ("module", module.as_str())] {
            if name.contains('/') {
                return Err(LockError::InvalidKey {
                    value: format!("{what} {name:?}"),
                    reason: "a name cannot contain `/`, or `account/module` would be ambiguous",
                });
            }
        }
        Ok(LockKey { account, module })
    }

    /// The account whose module is locked.
    pub fn account(&self) -> &str {
        &self.account
    }

    /// The module within the account.
    pub fn module(&self) -> &str {
        &self.module
    }
}

impl fmt::Display for LockKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.account, self.module)
    }
}

/// A lease on a [`LockKey`], as [`RunLock::acquire`] granted it.
///
/// [`token`](Lease::token) is the fencing token: strictly increasing per key
/// across every grant. A run presents it to whatever the lease guards, and
/// the resource refuses any action whose token is below the highest it has
/// already acted on — that is the whole defence against a superseded run
/// waking up and applying anyway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    /// The key this lease guards.
    pub key: LockKey,
    /// The run that holds it.
    pub holder: RunId,
    /// The fencing token, strictly increasing per key across every grant.
    pub token: u64,
    /// When the lease lapses if no [`RunLock::renew`] extends it.
    pub expires_at: SystemTime,
}

/// Why a [`RunLock`] operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockError {
    /// Another run holds the only live lease on the key.
    Held {
        /// The run that holds it.
        holder: RunId,
        /// When its lease lapses if not renewed — when to try again.
        until: SystemTime,
    },
    /// The lease is not yours any more: it expired and another run took it
    /// over, or it was released. Re-acquire before acting — acting on a lost
    /// lease is exactly what fencing tokens exist to stop.
    Lost,
    /// The lock could not be reached, or the request could not be carried
    /// out: the backing store errored or refused the request.
    Unavailable {
        /// What the adapter reported.
        message: String,
    },
    /// A [`LockKey`] was constructed with a name [`LockKey::new`] refuses;
    /// see [`LockKey::new`].
    InvalidKey {
        /// The rejected name.
        value: String,
        /// What is wrong with it, for the message.
        reason: &'static str,
    },
}

impl fmt::Display for LockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LockError::Held { holder, until } => {
                write!(f, "the lock is held by run {holder} until {until:?}; try again then")
            }
            LockError::Lost => {
                write!(
                    f,
                    "the lease is gone: it expired, was released or was taken over; \
                     re-acquire before acting"
                )
            }
            LockError::Unavailable { message } => {
                write!(f, "the run lock is unavailable: {message}")
            }
            LockError::InvalidKey { value, reason } => {
                write!(f, "{value:?} is not a usable lock name ({reason})")
            }
        }
    }
}

impl std::error::Error for LockError {}

/// The `RunLock` port: at most one live lease per (account, module), with an
/// expiry and fencing tokens. The engine holds it across the part of a run
/// that changes a module — plan through apply — and everything the run does
/// in that window carries the lease's token.
///
/// Adapters must fail with [`LockError`] rather than panicking, and must make
/// the check-and-grant in [`RunLock::acquire`] atomic: two runs asking at the
/// same moment get one lease and one [`LockError::Held`], never two leases.
pub trait RunLock: Send + Sync {
    /// Acquires the lock for `holder`, or reports who holds it.
    ///
    /// Granting rules: a key with no live lease — none at all, or an expired
    /// one — is granted to anyone, with a fresh fencing token and
    /// [`Lease::expires_at`] one `ttl` from the adapter's own clock; a live
    /// lease held by another run is [`LockError::Held`]; a live lease held by
    /// *this* holder comes back unchanged, same token and expiry, because
    /// asking may not extend anything.
    fn acquire<'a>(
        &'a self,
        key: &'a LockKey,
        holder: &'a RunId,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<Lease, LockError>>;

    /// Extends `lease` to one `ttl` from now, same token, or
    /// [`LockError::Lost`] if it is no longer the live lease on its key — it
    /// expired, was released, or a takeover re-issued the key at a higher
    /// token. Renewal never mints a token.
    fn renew<'a>(
        &'a self,
        lease: &'a Lease,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<Lease, LockError>>;

    /// Releases `lease` now, or [`LockError::Lost`] if it is no longer the
    /// live lease on its key. Releasing a lost lease never frees the newer
    /// holder's.
    fn release<'a>(&'a self, lease: &'a Lease) -> BoxFuture<'a, Result<(), LockError>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: ?Sized + Send + Sync>() {}

    #[test]
    fn the_run_lock_trait_is_dyn_compatible() {
        assert_send_sync::<dyn RunLock>();
    }

    #[test]
    fn lock_keys_reject_names_that_make_the_display_ambiguous() {
        let key = LockKey::new("platform", "network").expect("plain names are valid");
        assert_eq!(key.account(), "platform");
        assert_eq!(key.module(), "network");
        assert_eq!(key.to_string(), "platform/network");
        for (account, module, rule) in [
            ("", "network", "account is empty"),
            ("platform", "", "module is empty"),
            ("a/cct", "network", "account"),
            ("platform", "mod/ule", "module"),
        ] {
            let refusal = LockKey::new(account, module).expect_err("must be refused");
            assert!(
                matches!(refusal, LockError::InvalidKey { .. }),
                "{account:?}/{module:?} must be refused, got {refusal}"
            );
            assert!(refusal.to_string().contains(rule), "{account:?}/{module:?}: {refusal}");
        }
    }

    #[test]
    fn lock_errors_display_actionably() {
        let held = LockError::Held {
            holder: RunId::from_parts(0, 1),
            until: SystemTime::UNIX_EPOCH + Duration::from_secs(60),
        };
        let shown = held.to_string();
        assert!(shown.contains("held") && shown.contains("try again"), "{shown}");
        assert!(LockError::Lost.to_string().contains("re-acquire"), "{held}");
        let down = LockError::Unavailable { message: "durable object unreachable".to_string() };
        assert!(down.to_string().contains("durable object unreachable"), "{down}");
    }
}
