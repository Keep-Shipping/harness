//! Fake for the [`IdGen`] port: readable, sequential run ids.

use std::sync::atomic::{AtomicU64, Ordering};

use ks_core::ids::RunId;
use ks_core::ports::id_gen::IdGen;

/// An [`IdGen`] that hands out `RunId::from_parts(0, n)` for `n = 1, 2, 3, …`.
///
/// Timestamp zero keeps fixtures free of clock coupling, and the sequential
/// random part makes ids distinguishable at a glance in a run log:
/// `00000000000000000000000001`, `…02`, …
#[derive(Debug, Default)]
pub struct SequentialIdGen {
    next: AtomicU64,
}

impl SequentialIdGen {
    /// Creates a generator whose first id is `…0001`.
    pub fn new() -> SequentialIdGen {
        SequentialIdGen::default()
    }
}

impl IdGen for SequentialIdGen {
    fn run_id(&self) -> RunId {
        let n = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        RunId::from_parts(0, u128::from(n))
    }
}

/// The `IdGen` conformance kit: ids are canonical ULIDs and never repeat.
pub fn conformance(id_gen: &dyn IdGen) {
    let first = id_gen.run_id();
    let second = id_gen.run_id();
    assert_ne!(first, second, "id_gen conformance: run ids must never repeat");
    for id in [first, second] {
        let parsed = RunId::parse(id.as_str()).unwrap_or_else(|error| {
            panic!("id_gen conformance: {id} is not a valid RunId: {error}")
        });
        assert_eq!(
            parsed.as_str(),
            id.as_str(),
            "id_gen conformance: ids must round-trip canonically"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_sequential_from_one() {
        let id_gen = SequentialIdGen::new();
        for n in 1..=3u128 {
            let id = id_gen.run_id();
            assert_eq!(id.as_str(), RunId::from_parts(0, n).as_str());
        }
    }

    #[test]
    fn the_fake_passes_conformance() {
        conformance(&SequentialIdGen::new());
    }
}
