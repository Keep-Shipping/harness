//! Fake for the [`StateStore`] port: working data per run, in memory, with the
//! sensitivity ratchet and a size limit.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use ks_core::ids::RunId;
use ks_core::ports::BoxFuture;
use ks_core::ports::state_store::{
    Sensitivity, StateKey, StateStore, StateStoreError, StateSummary,
};

/// The default cap on a single stored value: 1 MiB.
///
/// State is working data meant to be short — step scratch, caches, saved
/// plans. A long-lived record belongs in the [run log](ks_core::ports::run_log),
/// so the store refuses to become one. Change it per test with
/// [`max_value_bytes`](FakeStateStore::max_value_bytes).
pub const MAX_VALUE_BYTES: usize = 1024 * 1024;

/// What the fake holds, keyed by run then key.
#[derive(Default)]
struct StoreState {
    /// run → key → (sensitivity it was written under, the bytes).
    runs: BTreeMap<RunId, BTreeMap<StateKey, (Sensitivity, Vec<u8>)>>,
    /// Set by [`failing`](FakeStateStore::failing): every call fails with it.
    failure: Option<String>,
    /// The per-value size limit, in bytes.
    max_value_bytes: usize,
}

/// A [`StateStore`] held entirely in process memory, one `BTreeMap` per run.
///
/// It models the port's working-data semantics — overwrite in place, absent
/// is `Ok(None)`, one run's keys invisible to another, the sensitivity
/// ratchet, [`delete_run`](StateStore::delete_run) touching exactly one run —
/// and refuses a value over [`MAX_VALUE_BYTES`], because state is working
/// data meant to be short.
///
/// ```
/// use ks_core::ids::RunId;
/// use ks_core::ports::state_store::{Sensitivity, StateKey, StateStore, StateStoreError};
/// use ks_testing::{block_on, state_store::FakeStateStore};
///
/// let store = FakeStateStore::new();
/// let run = RunId::from_parts(1_700_000_000_000, 7);
/// let plan = StateKey::new("plan").expect("printable key");
/// block_on(store.put(&run, &plan, b"{}", Sensitivity::Secretish)).expect("put");
/// assert_eq!(
///     block_on(store.get(&run, &plan)).expect("get"),
///     Some(b"{}".to_vec())
/// );
///
/// // Sensitivity only ratchets up: an Ordinary write over Secretish data is
/// // refused, and the old bytes are still there.
/// match block_on(store.put(&run, &plan, b"tampered", Sensitivity::Ordinary)) {
///     Err(StateStoreError::WouldDowngrade { .. }) => {}
///     other => panic!("expected WouldDowngrade, got {other:?}"),
/// }
/// assert_eq!(store.sensitivity_of(&run, &plan), Some(Sensitivity::Secretish));
/// ```
///
/// # What this fake does not model
///
/// - **Encryption at rest.** `Secretish` bytes sit in plain `Vec<u8>` in the
///   process heap, exactly as written. The fake is **not** a model for a real
///   adapter's encryption, and [`conformance`] asserts nothing about it — an
///   adapter that is not the customer's own local storage must encrypt
///   `Secretish` at rest, and only that adapter can be tested for it.
/// - **Durability, sharing and concurrency.** Nothing survives the process,
///   nothing is shared between processes, and the mutex makes every call
///   atomic within one test.
pub struct FakeStateStore {
    state: Mutex<StoreState>,
}

impl Default for FakeStateStore {
    fn default() -> FakeStateStore {
        FakeStateStore {
            state: Mutex::new(StoreState {
                max_value_bytes: MAX_VALUE_BYTES,
                ..StoreState::default()
            }),
        }
    }
}

impl FakeStateStore {
    /// Creates an empty store with the default [`MAX_VALUE_BYTES`] limit.
    pub fn new() -> FakeStateStore {
        FakeStateStore::default()
    }

    /// Scripts every call to fail with [`StateStoreError::Backend`].
    pub fn failing(mut self, message: impl Into<String>) -> Self {
        self.lock_mut().failure = Some(message.into());
        self
    }

    /// Caps a single value at `max` bytes instead of [`MAX_VALUE_BYTES`].
    pub fn max_value_bytes(mut self, max: usize) -> Self {
        self.lock_mut().max_value_bytes = max;
        self
    }

    /// The runs holding at least one key, sorted.
    pub fn runs(&self) -> Vec<RunId> {
        self.lock().runs.keys().cloned().collect()
    }

    /// The sensitivity `run`'s `key` was written under, if it is stored.
    pub fn sensitivity_of(&self, run: &RunId, key: &StateKey) -> Option<Sensitivity> {
        self.lock().runs.get(run)?.get(key).map(|(sensitivity, _)| *sensitivity)
    }

    fn lock(&self) -> MutexGuard<'_, StoreState> {
        self.state.lock().expect("fake state store")
    }

    fn lock_mut(&mut self) -> &mut StoreState {
        self.state.get_mut().expect("fake state store")
    }

    fn backend(state: &StoreState) -> Option<StateStoreError> {
        state.failure.clone().map(|message| StateStoreError::Backend { message })
    }
}

impl StateStore for FakeStateStore {
    fn put<'a>(
        &'a self,
        run: &'a RunId,
        key: &'a StateKey,
        bytes: &'a [u8],
        sensitivity: Sensitivity,
    ) -> BoxFuture<'a, Result<(), StateStoreError>> {
        let result = {
            let mut state = self.lock();
            if let Some(error) = FakeStateStore::backend(&state) {
                Err(error)
            } else if bytes.len() > state.max_value_bytes {
                Err(StateStoreError::TooLarge {
                    key: key.clone(),
                    len: bytes.len(),
                    max: state.max_value_bytes,
                })
            } else {
                let stored = state.runs.entry(run.clone()).or_default();
                let held = stored.get(key).map(|(held, _)| *held);
                // Sensitivity ratchets up and never down: a later write cannot
                // quietly strip the classification off bytes written earlier.
                if held == Some(Sensitivity::Secretish) && sensitivity == Sensitivity::Ordinary {
                    Err(StateStoreError::WouldDowngrade {
                        key: key.clone(),
                        from: Sensitivity::Secretish,
                        to: Sensitivity::Ordinary,
                    })
                } else {
                    let effective = match held {
                        Some(Sensitivity::Secretish) => Sensitivity::Secretish,
                        _ => sensitivity,
                    };
                    stored.insert(key.clone(), (effective, bytes.to_vec()));
                    Ok(())
                }
            }
        };
        Box::pin(std::future::ready(result))
    }

    fn get<'a>(
        &'a self,
        run: &'a RunId,
        key: &'a StateKey,
    ) -> BoxFuture<'a, Result<Option<Vec<u8>>, StateStoreError>> {
        let result = {
            let state = self.lock();
            match FakeStateStore::backend(&state) {
                Some(error) => Err(error),
                None => {
                    Ok(state.runs.get(run).and_then(|keys| keys.get(key)).map(|(_, b)| b.clone()))
                }
            }
        };
        Box::pin(std::future::ready(result))
    }

    fn list<'a>(
        &'a self,
        run: &'a RunId,
    ) -> BoxFuture<'a, Result<Vec<StateSummary>, StateStoreError>> {
        let result = {
            let state = self.lock();
            match FakeStateStore::backend(&state) {
                Some(error) => Err(error),
                None => {
                    // BTreeMap iteration is already ascending by StateKey.
                    Ok(state
                        .runs
                        .get(run)
                        .map(|keys| {
                            keys.iter()
                                .map(|(key, (sensitivity, bytes))| StateSummary {
                                    key: key.clone(),
                                    sensitivity: *sensitivity,
                                    len: bytes.len(),
                                })
                                .collect()
                        })
                        .unwrap_or_default())
                }
            }
        };
        Box::pin(std::future::ready(result))
    }

    fn delete_run<'a>(&'a self, run: &'a RunId) -> BoxFuture<'a, Result<(), StateStoreError>> {
        let result = {
            let mut state = self.lock();
            match FakeStateStore::backend(&state) {
                Some(error) => Err(error),
                None => {
                    // Absent is not an error: deleting a run with nothing
                    // stored is the same as deleting nothing.
                    state.runs.remove(run);
                    Ok(())
                }
            }
        };
        Box::pin(std::future::ready(result))
    }
}

/// The `StateStore` conformance kit: every adapter — [`FakeStateStore`] here,
/// real adapters later
/// ([#55](https://github.com/Keep-Shipping/harness/issues/55)) — must pass
/// this.
///
/// `run` and `other` must be two run ids nothing else in the test is using;
/// the kit writes under both, so give it ids of its own when sharing a store
/// across suites.
///
/// Checks, in order: an absent key reads `Ok(None)` rather than an error;
/// `put`/`get` round-trips the exact bytes, including empty and non-UTF-8
/// ones; one run's keys are invisible in another run's `list`; `list` is
/// sorted by key and reports each key's sensitivity and byte length; the
/// sensitivity ratchet refuses `Ordinary` over `Secretish` and leaves the old
/// bytes in place; the *same* sensitivity overwrites in place, keeping one
/// entry; and `delete_run` removes exactly one run — twice is still `Ok`.
///
/// This kit says nothing about encryption at rest. It runs against a
/// `&dyn StateStore`, and [`FakeStateStore`] stores `Secretish` bytes in
/// plaintext, so asserting it here would be asserting something only a real
/// adapter can honour.
pub async fn conformance(store: &dyn StateStore) {
    let run = RunId::from_parts(1_700_000_000_000, 0x00c0_ffee_0000_0003);
    let other = RunId::from_parts(1_700_000_000_000, 0x00c0_ffee_0000_0004);
    let key = |text: &str| StateKey::new(text).unwrap_or_else(|error| panic!("{error}"));

    let absent = key("state.conformance.absent");
    assert_eq!(
        store.get(&run, &absent).await,
        Ok(None),
        "state store conformance: get of an absent key is Ok(None), not an error"
    );

    // Byte-exact round-trips: empty, plain ASCII, and bytes that are not
    // valid UTF-8 at all.
    for (name, bytes) in [
        ("state.conformance.empty", Vec::new()),
        ("state.conformance.text", b"a saved plan".to_vec()),
        ("state.conformance.binary", vec![0u8, 159, 146, 150]),
    ] {
        let key = key(name);
        store
            .put(&run, &key, &bytes, Sensitivity::Ordinary)
            .await
            .unwrap_or_else(|error| panic!("state store conformance: put must succeed: {error}"));
        assert_eq!(
            store.get(&run, &key).await,
            Ok(Some(bytes)),
            "state store conformance: get returns the exact bytes that were put"
        );
        assert_eq!(
            store.get(&other, &key).await,
            Ok(None),
            "state store conformance: another run's key is absent, never another run's data"
        );
        assert!(
            !store
                .list(&other)
                .await
                .expect("state store conformance: list must succeed")
                .iter()
                .any(|summary| summary.key == key),
            "state store conformance: another run's keys do not appear in its list"
        );
    }

    let alpha = key("state.conformance.a");
    let middle = key("state.conformance.m");
    let zeta = key("state.conformance.z");
    store
        .put(&run, &alpha, b"aaa", Sensitivity::Ordinary)
        .await
        .unwrap_or_else(|error| panic!("state store conformance: put must succeed: {error}"));
    store
        .put(&run, &middle, b"bb", Sensitivity::Secretish)
        .await
        .unwrap_or_else(|error| panic!("state store conformance: put must succeed: {error}"));
    store
        .put(&run, &zeta, b"c", Sensitivity::Ordinary)
        .await
        .unwrap_or_else(|error| panic!("state store conformance: put must succeed: {error}"));
    let listed = store
        .list(&run)
        .await
        .unwrap_or_else(|error| panic!("state store conformance: list must succeed: {error}"));
    let keys: Vec<&StateKey> = listed.iter().map(|summary| &summary.key).collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted, "state store conformance: list returns summaries sorted by key");
    for summary in &listed {
        let bytes = store
            .get(&run, &summary.key)
            .await
            .unwrap_or_else(|error| panic!("state store conformance: get must succeed: {error}"))
            .unwrap_or_else(|| {
                panic!("state store conformance: listed {} is readable", summary.key)
            });
        assert_eq!(
            summary.len,
            bytes.len(),
            "state store conformance: the summary's len is the value's byte length"
        );
    }
    let middle_summary =
        listed.iter().find(|summary| summary.key == middle).expect("the secretish key is listed");
    assert_eq!(
        middle_summary.sensitivity,
        Sensitivity::Secretish,
        "state store conformance: the summary reports the sensitivity the value was written under"
    );
    let alpha_summary =
        listed.iter().find(|summary| summary.key == alpha).expect("the ordinary key is listed");
    assert_eq!(
        alpha_summary.sensitivity,
        Sensitivity::Ordinary,
        "state store conformance: the summary reports the sensitivity the value was written under"
    );

    // The ratchet: a key that holds Secretish data cannot be written back as
    // Ordinary, and the refused write leaves the bytes alone.
    let token = key("state.conformance.token");
    store
        .put(&run, &token, b"x", Sensitivity::Secretish)
        .await
        .unwrap_or_else(|error| panic!("state store conformance: put must succeed: {error}"));
    match store.put(&run, &token, b"y", Sensitivity::Ordinary).await {
        Err(StateStoreError::WouldDowngrade { key: refused, from, to }) => {
            assert_eq!(refused, token, "state store conformance: WouldDowngrade names the key");
            assert_eq!(from, Sensitivity::Secretish);
            assert_eq!(to, Sensitivity::Ordinary);
        }
        other => panic!(
            "state store conformance: Ordinary over Secretish must be WouldDowngrade, got {other:?}"
        ),
    }
    assert_eq!(
        store.get(&run, &token).await,
        Ok(Some(b"x".to_vec())),
        "state store conformance: the refused downgrade must not have changed the stored value"
    );

    // Same sensitivity overwrites in place: still one entry, new bytes.
    store
        .put(&run, &alpha, b"aaaaaa", Sensitivity::Ordinary)
        .await
        .unwrap_or_else(|error| panic!("state store conformance: put must succeed: {error}"));
    assert_eq!(
        store.get(&run, &alpha).await,
        Ok(Some(b"aaaaaa".to_vec())),
        "state store conformance: put overwrites the value in place"
    );
    let listed = store
        .list(&run)
        .await
        .unwrap_or_else(|error| panic!("state store conformance: list must succeed: {error}"));
    assert_eq!(
        listed.iter().filter(|summary| summary.key == alpha).count(),
        1,
        "state store conformance: an overwritten key is still exactly one entry"
    );

    // delete_run removes one run and nothing else; doing it twice is fine.
    store.delete_run(&run).await.unwrap_or_else(|error| {
        panic!("state store conformance: delete_run must succeed: {error}")
    });
    assert_eq!(
        store.list(&run).await,
        Ok(Vec::new()),
        "state store conformance: delete_run removes the run's keys"
    );
    store
        .put(&other, &alpha, b"another run", Sensitivity::Ordinary)
        .await
        .unwrap_or_else(|error| panic!("state store conformance: put must succeed: {error}"));
    store.delete_run(&run).await.unwrap_or_else(|error| {
        panic!("state store conformance: a second delete_run must succeed: {error}")
    });
    assert_eq!(
        store.get(&other, &alpha).await,
        Ok(Some(b"another run".to_vec())),
        "state store conformance: delete_run leaves every other run untouched"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_on;

    fn run(seed: u128) -> RunId {
        RunId::from_parts(1_700_000_000_000, seed)
    }

    fn key(text: &str) -> StateKey {
        StateKey::new(text).expect("valid key")
    }

    #[test]
    fn a_fresh_fake_stores_nothing() {
        let store = FakeStateStore::new();
        let run = run(1);
        assert_eq!(block_on(store.list(&run)).expect("list"), Vec::new());
        assert_eq!(store.runs(), Vec::new());
        assert_eq!(store.sensitivity_of(&run, &key("k")), None);
    }

    #[test]
    fn values_persist_across_independent_reads() {
        let store = FakeStateStore::new();
        let run = run(2);
        block_on(store.put(&run, &key("cache"), b"hello", Sensitivity::Ordinary)).expect("put");
        // Two separate calls, each taking and releasing the mutex.
        assert_eq!(block_on(store.get(&run, &key("cache"))).expect("get"), Some(b"hello".to_vec()));
        assert_eq!(block_on(store.get(&run, &key("cache"))).expect("get"), Some(b"hello".to_vec()));
        assert_eq!(store.sensitivity_of(&run, &key("cache")), Some(Sensitivity::Ordinary));
    }

    #[test]
    fn non_utf8_secretish_bytes_round_trip_exactly() {
        let store = FakeStateStore::new();
        let run = run(3);
        let bytes = vec![0u8, 159, 146, 150];
        block_on(store.put(&run, &key("blob"), &bytes, Sensitivity::Secretish)).expect("put");
        assert_eq!(block_on(store.get(&run, &key("blob"))).expect("get"), Some(bytes));
        assert_eq!(store.sensitivity_of(&run, &key("blob")), Some(Sensitivity::Secretish));
    }

    #[test]
    fn a_refused_downgrade_leaves_the_value_alone() {
        let store = FakeStateStore::new();
        let run = run(4);
        let key = key("token");
        block_on(store.put(&run, &key, b"x", Sensitivity::Secretish)).expect("put");
        assert_eq!(
            block_on(store.put(&run, &key, b"y", Sensitivity::Ordinary)),
            Err(StateStoreError::WouldDowngrade {
                key: key.clone(),
                from: Sensitivity::Secretish,
                to: Sensitivity::Ordinary,
            })
        );
        assert_eq!(block_on(store.get(&run, &key)).expect("get"), Some(b"x".to_vec()));
        // Writing Secretish again over Secretish is not a downgrade.
        block_on(store.put(&run, &key, b"z", Sensitivity::Secretish)).expect("put");
        assert_eq!(block_on(store.get(&run, &key)).expect("get"), Some(b"z".to_vec()));
    }

    #[test]
    fn an_ordinary_write_may_be_upgraded_to_secretish() {
        let store = FakeStateStore::new();
        let run = run(5);
        let key = key("plan");
        block_on(store.put(&run, &key, b"v1", Sensitivity::Ordinary)).expect("put");
        block_on(store.put(&run, &key, b"v2", Sensitivity::Secretish))
            .expect("upgrading is allowed");
        assert_eq!(store.sensitivity_of(&run, &key), Some(Sensitivity::Secretish));
    }

    #[test]
    fn values_over_the_limit_are_refused_and_the_limit_is_inclusive() {
        let store = FakeStateStore::new().max_value_bytes(8);
        let run = run(6);
        let key = key("big");
        block_on(store.put(&run, &key, b"12345678", Sensitivity::Ordinary)).expect("at the limit");
        assert_eq!(
            block_on(store.put(&run, &key, b"123456789", Sensitivity::Ordinary)),
            Err(StateStoreError::TooLarge { key: key.clone(), len: 9, max: 8 })
        );
        assert_eq!(block_on(store.get(&run, &key)).expect("get"), Some(b"12345678".to_vec()));
        // The documented default, so a later change to it is deliberate.
        assert_eq!(MAX_VALUE_BYTES, 1024 * 1024);
        let default_store = FakeStateStore::new();
        let big = vec![b'x'; MAX_VALUE_BYTES];
        assert!(
            matches!(block_on(default_store.put(&run, &key, &big, Sensitivity::Ordinary)), Ok(())),
            "a megabyte is under the default cap, so this test's eight-byte limit is the only limit in play"
        );
    }

    #[test]
    fn delete_run_removes_exactly_one_run() {
        let store = FakeStateStore::new();
        let kept = run(7);
        let dropped = run(8);
        block_on(store.put(&kept, &key("k"), b"kept", Sensitivity::Ordinary)).expect("put");
        block_on(store.put(&dropped, &key("k"), b"dropped", Sensitivity::Ordinary)).expect("put");
        assert_eq!(store.runs(), vec![kept.clone(), dropped.clone()]);
        block_on(store.delete_run(&dropped)).expect("delete_run");
        assert_eq!(block_on(store.list(&dropped)).expect("list"), Vec::new());
        assert_eq!(block_on(store.get(&kept, &key("k"))).expect("get"), Some(b"kept".to_vec()));
        // A run with nothing stored, deleted twice, is not an error.
        block_on(store.delete_run(&dropped)).expect("a second delete_run");
        block_on(store.delete_run(&run(9))).expect("deleting an unknown run");
    }

    #[test]
    fn a_failing_fake_fails_every_method() {
        let store = FakeStateStore::new().failing("EACCES");
        let run = run(10);
        let key = key("k");
        let backend = StateStoreError::Backend { message: "EACCES".to_string() };
        assert_eq!(
            block_on(store.put(&run, &key, b"v", Sensitivity::Ordinary)),
            Err(backend.clone())
        );
        assert_eq!(block_on(store.get(&run, &key)), Err(backend.clone()));
        assert_eq!(block_on(store.list(&run)), Err(backend.clone()));
        assert_eq!(block_on(store.delete_run(&run)), Err(backend));
    }

    #[test]
    fn the_fake_passes_conformance() {
        block_on(conformance(&FakeStateStore::new()));
    }
}
