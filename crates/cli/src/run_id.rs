//! Minting the id a run reports itself under.
//!
//! A [`RunId`] is a ULID: 48 bits of Unix milliseconds, then 80 bits of
//! randomness. `ks_core` encodes one but deliberately does not generate one —
//! that is a port's job ([#47](https://github.com/Keep-Shipping/harness/issues/47)),
//! and the CLI has no adapter to ask. So the CLI mixes its own: the clock it
//! already has, and the process it is running in. Two runs in the same
//! millisecond on the same machine are the only case, and the id there only
//! has to be distinct, not unpredictable.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::time::{SystemTime, UNIX_EPOCH};

use ks_core::ids::RunId;

/// A fresh run id: now, mixed with this process's own entropy.
///
/// The randomness is [`RandomState`], the standard library's per-process seed,
/// hashed together with the clock and the pid. That is enough for ids that
/// only have to be unique and sortable — not a token, and nothing that is ever
/// a credential.
pub fn mint() -> RunId {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        // A clock before the epoch is not a reason to fail a run; 0 is as
        // good a time as any for an id nobody orders by.
        .map_or(0, |d| d.as_millis() as u64);
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(millis);
    hasher.write_u32(std::process::id());
    // The nanosecond part distinguishes two runs started inside the same
    // millisecond, which the clock above rounds away.
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
    hasher.write_u32(nanos);
    RunId::from_parts(millis, hasher.finish() as u128)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minted_id_is_a_26_character_ulid() {
        let id = mint().to_string();
        assert_eq!(id.len(), 26, "{id}");
        // The first character encodes 3 bits, so a valid ULID never starts
        // with 8 or 9 — which is what makes this not just a length check.
        assert!(RunId::parse(&id).is_ok(), "{id} does not round-trip");
    }
}
