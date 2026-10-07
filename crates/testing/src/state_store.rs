//! Fake for the [`StateStore`] port: an in-memory, per-run blob store whose
//! clones share one map, plus the conformance kit every adapter must pass.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use ks_core::ids::RunId;
use ks_core::ports::BoxFuture;
use ks_core::ports::state_store::{StateError, StateStore, check_key};

/// Every run's blobs, keyed by run id then key.
type Contents = Arc<Mutex<BTreeMap<String, BTreeMap<String, Vec<u8>>>>>;

/// An in-memory [`StateStore`] — the stand-in for the local `.keepshipping/`
/// adapter in tests. `Clone` shares one store, so a test can hand the clone to
/// the "job 2" half of a resume the way a fresh process gets a fresh
/// `LocalStateStore` over the same directory. Nothing is written to disk.
///
/// ```
/// use ks_core::ids::RunId;
/// use ks_core::ports::state_store::StateStore;
/// use ks_testing::{block_on, state_store::MemoryStateStore};
///
/// let store = MemoryStateStore::new();
/// let run = RunId::from_parts(0, 1);
/// block_on(store.put(&run, "state.json", b"{}")).expect("the write lands");
/// assert_eq!(block_on(store.get(&run, "state.json")).unwrap(), Some(b"{}".to_vec()));
/// ```
#[derive(Clone, Default, Debug)]
pub struct MemoryStateStore {
    runs: Contents,
}

impl MemoryStateStore {
    /// Creates an empty store.
    pub fn new() -> MemoryStateStore {
        MemoryStateStore::default()
    }
}

/// Key failures come from the port's own validator, so a fake that accepted a
/// key would disagree with every real adapter.
fn validate(key: &str) -> Result<(), StateError> {
    check_key(key).map_err(|reason| StateError::InvalidKey { key: key.to_string(), reason })
}

impl StateStore for MemoryStateStore {
    fn put<'a>(
        &'a self,
        run: &'a RunId,
        key: &'a str,
        bytes: &'a [u8],
    ) -> BoxFuture<'a, Result<(), StateError>> {
        let result = validate(key).map(|()| {
            self.runs
                .lock()
                .expect("memory state store")
                .entry(run.to_string())
                .or_default()
                .insert(key.to_string(), bytes.to_vec());
        });
        Box::pin(std::future::ready(result))
    }

    fn get<'a>(
        &'a self,
        run: &'a RunId,
        key: &'a str,
    ) -> BoxFuture<'a, Result<Option<Vec<u8>>, StateError>> {
        let result = validate(key).map(|()| {
            self.runs.lock().expect("memory state store").get(run.as_str())?.get(key).cloned()
        });
        Box::pin(std::future::ready(result))
    }
}

/// The `StateStore` conformance kit: this fake and the local
/// `.keepshipping/runs/<id>/` one must both pass it. A round-trip, a missing key
/// as `Ok(None)`, an overwrite, two runs that cannot see each other's objects,
/// and the key rules that keep a blob inside its own run directory.
pub async fn conformance(store: &dyn StateStore) {
    let run = RunId::from_parts(1_700_000_000_000, 1);
    let other = RunId::from_parts(1_700_000_000_000, 2);
    let get = async |key: &str, run: &RunId| match store.get(run, key).await {
        Ok(found) => found,
        Err(error) => panic!("state_store conformance: get {key:?} failed: {error}"),
    };
    let put = async |key: &str, bytes: &[u8]| match store.put(&run, key, bytes).await {
        Ok(()) => {}
        Err(error) => panic!("state_store conformance: put {key:?} failed: {error}"),
    };

    for stored in [b"{\"version\":1}", b"{\"version\":2}"] {
        put("state.json", stored).await;
        assert_eq!(
            get("state.json", &run).await,
            Some(stored.to_vec()),
            "must round-trip, and a put replaces"
        );
    }
    assert_eq!(get("missing", &run).await, None, "an absent key is None, not an error");
    assert_eq!(get("state.json", &other).await, None, "keys are scoped per run");

    for bad in ["", "../escape", "dir/file", ".hidden"] {
        let written = store.put(&run, bad, b"x").await;
        assert!(
            matches!(written, Err(StateError::InvalidKey { .. })),
            "state_store conformance: {bad:?} must be refused, got {written:?}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_on;

    #[test]
    fn clones_share_one_store() {
        let run = RunId::from_parts(0, 1);
        let store = MemoryStateStore::new();
        let other_handle = store.clone();
        block_on(store.put(&run, "plan-a", b"one")).expect("the write lands");
        assert_eq!(
            block_on(other_handle.get(&run, "plan-a")).expect("the read lands"),
            Some(b"one".to_vec())
        );
    }

    #[test]
    fn the_fake_passes_conformance() {
        block_on(conformance(&MemoryStateStore::new()));
    }
}
