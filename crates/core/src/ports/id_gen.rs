//! The [`IdGen`] port: minting fresh [`RunId`]s.
//!
//! Kept separate from [`Clock`](super::clock::Clock) so tests can pin both:
//! a sequential fake makes run ids readable in fixtures, while a production
//! adapter encodes the current wall time and fresh randomness
//! ([`RunId::from_parts`] does the pure encoding).

use crate::ids::RunId;

/// The `IdGen` port: a source of run ids.
///
/// Every call yields a fresh, distinct id; the textual form is a canonical
/// ULID (see [`RunId`]).
pub trait IdGen: Send + Sync {
    /// Mints the next run id.
    fn run_id(&self) -> RunId;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: ?Sized + Send + Sync>() {}

    #[test]
    fn the_id_gen_trait_is_dyn_compatible() {
        assert_send_sync::<dyn IdGen>();
    }
}
