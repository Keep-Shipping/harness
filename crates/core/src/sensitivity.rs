//! How sensitive a stored blob is, so the
//! [`StateStore`](crate::ports::state_store::StateStore) port's prose policy has
//! a type behind it ([#122](https://github.com/Keep-Shipping/harness/issues/122)).
//!
//! A saved Terraform/OpenTofu plan (`.tfplan`) is a binary blob that routinely
//! carries generated passwords and provider data in cleartext. The engine parks
//! those bytes between jobs, so the policy is: **plan bytes are secretish, are
//! stored addressed by digest, and live only in storage the customer owns.** A
//! backend that is not the customer's own disk must encrypt at rest — there is
//! no hosted adapter for plan bytes, ever.
//!
//! The classification is derived from the key rather than passed alongside it
//! (see [`Sensitivity::of_key`]), and the modes are the local-disk floor an
//! adapter writes with, not a substitute for encryption elsewhere. Pure
//! computation: no I/O, so `ks-core` still compiles for `wasm32-unknown-unknown`.
//!
//! # Example
//!
//! ```
//! use ks_core::sensitivity::{PLAN_KEY_PREFIX, SENSITIVE_FILE_MODE, Sensitivity};
//!
//! let key = format!("{PLAN_KEY_PREFIX}{}", "ab".repeat(32));
//! assert_eq!(Sensitivity::of_key(&key), Sensitivity::Secretish);
//! assert_eq!(Sensitivity::of_key("state.json"), Sensitivity::Plain);
//!
//! assert_eq!(Sensitivity::Plain.to_string(), "plain");
//! assert_eq!(Sensitivity::Secretish.file_mode(), SENSITIVE_FILE_MODE);
//! assert_eq!(SENSITIVE_FILE_MODE & 0o077, 0, "not readable by group or other");
//! ```

use std::fmt;

/// The key namespace that marks a stored blob as plan bytes.
pub const PLAN_KEY_PREFIX: &str = "plan-";

/// The mode an owner-only blob is created with: read and write for the owner,
/// nothing for group or other. A floor for the customer's own disk — a backend
/// that is not local disk must encrypt at rest instead, because these bits do
/// not survive the trip through a network or an object store.
pub const SENSITIVE_FILE_MODE: u32 = 0o600;

/// The mode the directory holding a secretish blob is created with, so the names
/// inside it are not enumerable by another local user. Same caveat as
/// [`SENSITIVE_FILE_MODE`].
pub const SENSITIVE_DIR_MODE: u32 = 0o700;

/// How sensitive the bytes under a [`StateStore`](crate::ports::state_store::StateStore)
/// key are. Two levels, not a scale: there is no in-between decision to make, so
/// anything that is not a secret is treated the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sensitivity {
    /// Ordinary harness data: the parked run record, logs, rendered summaries.
    /// Safe to write under the process umask and to serve from a shared cache.
    Plain,
    /// Bytes that may carry credentials — today, saved plan files under
    /// [`PLAN_KEY_PREFIX`]. Created owner-only on local disk, and encrypted at
    /// rest by any adapter whose backend is not the customer's own disk.
    Secretish,
}

impl Sensitivity {
    /// Classifies a store key.
    ///
    /// Derived from the key rather than passed as an argument because every
    /// `put`/`get` call site and every adapter already passes a key: deriving
    /// needs no port-trait change (which would force a `STEP_API` bump and a
    /// `PINNED_PORT_CONTRACT` edit) and leaves no new call site that can forget
    /// to mark a blob.
    ///
    /// The sharp edge is worth stating plainly: a caller that names a secret
    /// blob `state.json` gets [`Sensitivity::Plain`]. This is a floor that the
    /// port's naming rule — plan bytes go in addressed by digest, so they are
    /// `plan-<sha256>` and nothing else — is what enforces, not a proof that no
    /// secret is stored under a plain name.
    pub fn of_key(key: &str) -> Sensitivity {
        if key.starts_with(PLAN_KEY_PREFIX) { Sensitivity::Secretish } else { Sensitivity::Plain }
    }

    /// The unix mode bits this level calls for. Unix modes rather than an
    /// abstract permission because this is what a filesystem takes; an adapter
    /// on a backend with no mode bits has nothing to apply it to.
    ///
    /// [`Sensitivity::Secretish`] is a requirement — write the blob with it, or
    /// tighten it afterwards. [`Sensitivity::Plain`] only names what the level
    /// needs at most: write it under the process umask rather than with these
    /// bits, so a restrictive umask is not widened.
    pub fn file_mode(self) -> u32 {
        match self {
            Sensitivity::Plain => 0o644,
            Sensitivity::Secretish => SENSITIVE_FILE_MODE,
        }
    }
}

impl fmt::Display for Sensitivity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Sensitivity::Plain => f.write_str("plain"),
            Sensitivity::Secretish => f.write_str("secretish"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plan_key_is_secretish_and_anything_else_is_plain() {
        assert_eq!(
            Sensitivity::of_key(&format!("{PLAN_KEY_PREFIX}{}", "ab".repeat(32))),
            Sensitivity::Secretish
        );
        assert_eq!(Sensitivity::of_key("state.json"), Sensitivity::Plain);
        // Only the prefix counts: a plain key that merely mentions `plan-` does
        // not become secretish, and `plan` on its own is a different namespace.
        assert_eq!(Sensitivity::of_key("plans.json"), Sensitivity::Plain);
        assert_eq!(Sensitivity::of_key("plan"), Sensitivity::Plain);
    }

    #[test]
    fn owner_only_modes_are_not_readable_by_group_or_other() {
        assert_eq!(SENSITIVE_FILE_MODE & 0o077, 0, "a secretish blob is owner-only");
        assert_eq!(SENSITIVE_DIR_MODE & 0o077, 0, "its directory is too");
        assert_eq!(Sensitivity::Secretish.file_mode(), SENSITIVE_FILE_MODE);
        assert!(Sensitivity::Plain.file_mode() & 0o777 > SENSITIVE_FILE_MODE);
    }

    #[test]
    fn a_sensitivity_displays_its_own_name() {
        assert_eq!(Sensitivity::Plain.to_string(), "plain");
        assert_eq!(Sensitivity::Secretish.to_string(), "secretish");
        assert_eq!(format!("{:?}", Sensitivity::Secretish), "Secretish");
    }
}
