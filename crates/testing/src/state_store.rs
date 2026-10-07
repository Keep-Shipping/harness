//! Fake for the [`StateStore`] port: an in-memory, per-run blob store whose
//! clones share one map, plus the conformance kit every adapter must pass.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use ks_core::ids::RunId;
use ks_core::ports::BoxFuture;
use ks_core::ports::state_store::{Sensitivity, StateError, StateStore, StateSummary, check_key};

/// One stored value, with the classification its `put` recorded. No derived
/// `Debug`: `ks-testing` is published, and a store must not be a way to print
/// the secretish bytes it was handed.
#[derive(Clone)]
struct Stored {
    bytes: Vec<u8>,
    sensitivity: Sensitivity,
}

/// Every run's blobs, keyed by run id then key. Two `BTreeMap`s rather than one,
/// so `list` is sorted by the map's own order rather than by a sort the fake has
/// to remember to do — the fake must not be the reason conformance could pass a
/// store that does not sort.
type Contents = Arc<Mutex<BTreeMap<String, BTreeMap<String, Stored>>>>;

/// An in-memory [`StateStore`] — the stand-in for the local `.keepshipping/`
/// adapter in tests. `Clone` shares one store, so a test can hand the clone to
/// the "job 2" half of a resume the way a fresh process gets a fresh
/// `LocalStateStore` over the same directory. Nothing is written to disk.
///
/// `Debug` prints how much the store holds, never what: a failing assertion or
/// a `dbg!` over a fake must not put a `Secretish` plan into a CI log.
///
/// ```
/// use ks_core::ids::RunId;
/// use ks_core::ports::state_store::{Sensitivity, StateStore};
/// use ks_testing::{block_on, state_store::MemoryStateStore};
///
/// let store = MemoryStateStore::new();
/// let run = RunId::from_parts(0, 1);
/// block_on(store.put(&run, "state.json", b"{}", Sensitivity::Plain)).expect("the write lands");
/// assert_eq!(block_on(store.get(&run, "state.json")).unwrap(), Some(b"{}".to_vec()));
/// assert_eq!(format!("{store:?}"), "MemoryStateStore { runs: 1, keys: 1 }");
/// ```
#[derive(Clone, Default)]
pub struct MemoryStateStore {
    runs: Contents,
}

impl MemoryStateStore {
    /// Creates an empty store.
    pub fn new() -> MemoryStateStore {
        MemoryStateStore::default()
    }

    /// The classification recorded for `key`, or `None` if nothing is stored
    /// there. A test asserting on the ratchet directly, where [`StateStore`]
    /// deliberately offers no way to read a sensitivity back without listing.
    pub fn sensitivity_of(&self, run: &RunId, key: &str) -> Option<Sensitivity> {
        self.runs
            .lock()
            .expect("memory state store")
            .get(run.as_str())?
            .get(key)
            .map(|stored| stored.sensitivity)
    }
}

impl fmt::Debug for MemoryStateStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let runs = self.runs.lock().expect("memory state store");
        let keys: usize = runs.values().map(|held| held.len()).sum();
        f.debug_struct("MemoryStateStore").field("runs", &runs.len()).field("keys", &keys).finish()
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
        sensitivity: Sensitivity,
    ) -> BoxFuture<'a, Result<(), StateError>> {
        let result = validate(key).and_then(|()| {
            let mut runs = self.runs.lock().expect("memory state store");
            let held = runs.entry(run.to_string()).or_default();
            // The ratchet, refused before anything is written: the stored bytes
            // and their classification must both survive a refused downgrade.
            if held.get(key).is_some_and(|stored| stored.sensitivity.is_secretish())
                && !sensitivity.is_secretish()
            {
                return Err(StateError::Downgrade { key: key.to_string() });
            }
            held.insert(key.to_string(), Stored { bytes: bytes.to_vec(), sensitivity });
            Ok(())
        });
        Box::pin(std::future::ready(result))
    }

    fn get<'a>(
        &'a self,
        run: &'a RunId,
        key: &'a str,
    ) -> BoxFuture<'a, Result<Option<Vec<u8>>, StateError>> {
        let result = validate(key).map(|()| {
            self.runs
                .lock()
                .expect("memory state store")
                .get(run.as_str())?
                .get(key)
                .map(|stored| stored.bytes.clone())
        });
        Box::pin(std::future::ready(result))
    }

    fn list<'a>(&'a self, run: &'a RunId) -> BoxFuture<'a, Result<Vec<StateSummary>, StateError>> {
        let result = self
            .runs
            .lock()
            .expect("memory state store")
            .get(run.as_str())
            .map(|held| {
                held.iter()
                    .map(|(key, stored)| StateSummary {
                        key: key.clone(),
                        sensitivity: stored.sensitivity,
                        len: stored.bytes.len(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        Box::pin(std::future::ready(Ok(result)))
    }

    fn delete_run<'a>(&'a self, run: &'a RunId) -> BoxFuture<'a, Result<(), StateError>> {
        let _ = self.runs.lock().expect("memory state store").remove(run.as_str());
        Box::pin(std::future::ready(Ok(())))
    }
}

/// The `StateStore` conformance kit: this fake and the local
/// `.keepshipping/runs/<id>/` one must both pass it. A round-trip, a missing key
/// as `Ok(None)`, an overwrite, two runs that cannot see each other's objects,
/// the key rules that keep a blob inside its own run directory, a recorded
/// sensitivity that `list` reports and the ratchet that refuses to drop it,
/// `list`'s sorted order, and a `delete_run` that takes exactly one run.
pub async fn conformance(store: &dyn StateStore) {
    let run = RunId::from_parts(1_700_000_000_000, 1);
    let other = RunId::from_parts(1_700_000_000_000, 2);
    let get = async |key: &str, run: &RunId| match store.get(run, key).await {
        Ok(found) => found,
        Err(error) => panic!("state_store conformance: get {key:?} failed: {error}"),
    };
    let put_as = async |key: &str, bytes: &[u8], sensitivity: Sensitivity| match store
        .put(&run, key, bytes, sensitivity)
        .await
    {
        Ok(()) => {}
        Err(error) => {
            panic!("state_store conformance: put {key:?} as {sensitivity} failed: {error}")
        }
    };
    let list = async |run: &RunId| match store.list(run).await {
        Ok(found) => found,
        Err(error) => panic!("state_store conformance: list {} failed: {error}", run.as_str()),
    };
    let sensitivity_of = |found: &[StateSummary], key: &str| {
        found
            .iter()
            .find(|summary| summary.key == key)
            .unwrap_or_else(|| panic!("state_store conformance: {key:?} is not in the listing"))
            .sensitivity
    };

    for stored in [b"{\"version\":1}", b"{\"version\":2}"] {
        put_as("state.json", stored, Sensitivity::Plain).await;
        assert_eq!(
            get("state.json", &run).await,
            Some(stored.to_vec()),
            "must round-trip, and a put replaces"
        );
    }
    assert_eq!(get("missing", &run).await, None, "an absent key is None, not an error");
    assert_eq!(get("state.json", &other).await, None, "keys are scoped per run");

    for bad in ["", "../escape", "dir/file", ".hidden"] {
        let written = store.put(&run, bad, b"x", Sensitivity::Plain).await;
        assert!(
            matches!(written, Err(StateError::InvalidKey { .. })),
            "state_store conformance: {bad:?} must be refused, got {written:?}"
        );
        // A read is refused the same way: a key `put` will not accept is not a
        // key `get` may report on either, and an adapter that let one through
        // could read out of its own run directory.
        let read = store.get(&run, bad).await;
        assert!(
            matches!(read, Err(StateError::InvalidKey { .. })),
            "state_store conformance: get {bad:?} must be refused, got {read:?}"
        );
    }

    // ---- sensitivity: recorded, reported, and a ratchet that only climbs ---
    put_as("plan-aaaa", b"a plan", Sensitivity::Secretish).await;
    let found = list(&run).await;
    assert_eq!(
        sensitivity_of(&found, "plan-aaaa"),
        Sensitivity::Secretish,
        "list must report the classification put recorded, not a default"
    );
    assert_eq!(
        found.iter().find(|s| s.key == "plan-aaaa").expect("listed").len,
        6,
        "the summary reports the stored length, and never the bytes"
    );
    assert_eq!(
        sensitivity_of(&found, "state.json"),
        Sensitivity::Plain,
        "a plain write is recorded as plain"
    );

    let downgraded = store.put(&run, "plan-aaaa", b"a different plan", Sensitivity::Plain).await;
    assert!(
        matches!(downgraded, Err(StateError::Downgrade { .. })),
        "state_store conformance: writing plain over secretish must be refused, got {downgraded:?}"
    );
    assert_eq!(
        get("plan-aaaa", &run).await,
        Some(b"a plan".to_vec()),
        "a refused downgrade must leave the stored bytes alone"
    );
    let after = list(&run).await;
    assert_eq!(
        sensitivity_of(&after, "plan-aaaa"),
        Sensitivity::Secretish,
        "a refused downgrade must leave the recorded classification alone"
    );
    // Secretish over Secretish is not a downgrade — it is the same promise again.
    put_as("plan-aaaa", b"a longer plan", Sensitivity::Secretish).await;
    assert_eq!(get("plan-aaaa", &run).await, Some(b"a longer plan".to_vec()));

    // ---- writing one key is never the reason another one is lost -----------
    // The same-key case above is the ratchet; this is the one a whole-file
    // rewrite of a shared index gets wrong. Two keys are stored, one is
    // rewritten, and the other must read back *and* still be listed as what it
    // was — an adapter that keeps one map per run and rewrites it per write
    // passes everything else in this kit and still fails here.
    put_as("plan-bbbb", b"the other plan", Sensitivity::Secretish).await;
    put_as("plan-cccc", b"a third plan", Sensitivity::Secretish).await;
    put_as("plan-cccc", b"the third plan, rewritten", Sensitivity::Secretish).await;
    assert_eq!(
        get("plan-bbbb", &run).await,
        Some(b"the other plan".to_vec()),
        "rewriting one key must not disturb another's bytes"
    );
    assert_eq!(
        sensitivity_of(&list(&run).await, "plan-bbbb"),
        Sensitivity::Secretish,
        "rewriting one key must not drop another's recorded classification"
    );

    // ---- list is sorted, so a caller may diff or hash what it returns -----
    put_as("zzz-last", b"z", Sensitivity::Plain).await;
    let found = list(&run).await;
    let keys: Vec<&str> = found.iter().map(|summary| summary.key.as_str()).collect();
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    assert_eq!(keys, sorted, "list must return its keys in sorted order");

    // ---- delete_run takes exactly one run, and is fine with an empty one ---
    store
        .put(&other, "state.json", b"{}", Sensitivity::Plain)
        .await
        .unwrap_or_else(|error| panic!("state_store conformance: put for {other}: {error}"));
    store
        .delete_run(&run)
        .await
        .unwrap_or_else(|error| panic!("state_store conformance: delete_run: {error}"));
    assert_eq!(list(&run).await, Vec::new(), "delete_run must empty exactly that run");
    assert_eq!(get("plan-aaaa", &run).await, None, "the deleted run's blobs are gone");
    assert_eq!(
        get("state.json", &other).await,
        Some(b"{}".to_vec()),
        "delete_run must not touch another run's blobs"
    );
    assert!(
        !list(&other).await.is_empty(),
        "the run that was not deleted still lists what it holds"
    );
    // Deleting a run takes what was declared about it too. A store that kept a
    // key's classification anywhere outside that run's own directory would still
    // be holding the promise after the bytes were gone, and would refuse this
    // write as a downgrade of a run that no longer exists.
    put_as("plan-aaaa", b"plain again", Sensitivity::Plain).await;
    assert_eq!(
        get("plan-aaaa", &run).await,
        Some(b"plain again".to_vec()),
        "delete_run must take the recorded classification with it, so a deleted run's keys can \
         be written plain again"
    );
    for run in [&run, &other, &RunId::from_parts(1_700_000_000_000, 999)] {
        store.delete_run(run).await.unwrap_or_else(|error| {
            panic!("state_store conformance: deleting an empty run: {error}")
        });
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
        block_on(store.put(&run, "plan-a", b"one", Sensitivity::Secretish))
            .expect("the write lands");
        assert_eq!(
            block_on(other_handle.get(&run, "plan-a")).expect("the read lands"),
            Some(b"one".to_vec())
        );
        assert_eq!(
            other_handle.sensitivity_of(&run, "plan-a"),
            Some(Sensitivity::Secretish),
            "the clone sees what the other handle recorded"
        );
    }

    #[test]
    fn a_fresh_fake_holds_nothing() {
        let run = RunId::from_parts(0, 1);
        let store = MemoryStateStore::new();
        assert_eq!(block_on(store.list(&run)).expect("list"), Vec::new());
        assert_eq!(store.sensitivity_of(&run, "plan-a"), None);
        assert!(block_on(store.delete_run(&run)).is_ok(), "deleting an unknown run is fine");
    }

    #[test]
    fn a_refused_downgrade_leaves_both_the_bytes_and_the_classification() {
        let run = RunId::from_parts(0, 2);
        let store = MemoryStateStore::new();
        block_on(store.put(&run, "plan-a", b"secret", Sensitivity::Secretish)).expect("put");
        assert_eq!(
            block_on(store.put(&run, "plan-a", b"plain", Sensitivity::Plain)).expect_err("refused"),
            StateError::Downgrade { key: "plan-a".to_string() }
        );
        assert_eq!(block_on(store.get(&run, "plan-a")).expect("get"), Some(b"secret".to_vec()));
        assert_eq!(store.sensitivity_of(&run, "plan-a"), Some(Sensitivity::Secretish));
    }

    #[test]
    fn the_fake_passes_conformance() {
        block_on(conformance(&MemoryStateStore::new()));
    }
}
