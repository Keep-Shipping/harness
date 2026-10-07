//! Behaviour of the `StateStore` fake: overwrite-in-place working data, the
//! sensitivity ratchet, per-run isolation, the size limit — plus the
//! conformance kit, run against the fake through the `dyn` trait.

use ks_core::ids::RunId;
use ks_core::ports::state_store::{Sensitivity, StateKey, StateStore, StateStoreError};
use ks_testing::block_on;
use ks_testing::state_store::{
    FakeStateStore, MAX_VALUE_BYTES, conformance as state_store_conformance,
};

fn run(seed: u128) -> RunId {
    RunId::from_parts(1_700_000_000_000, seed)
}

fn key(text: &str) -> StateKey {
    StateKey::new(text).unwrap_or_else(|error| panic!("{error}"))
}

/// Dyn-compatibility: the engine holds ports as `&dyn`.
fn _port_is_dyn_compatible(_store: &dyn StateStore) {}

#[test]
fn the_state_store_port_is_send_sync_and_dyn_compatible() {
    fn assert_send_sync<T: ?Sized + Send + Sync>() {}
    assert_send_sync::<dyn StateStore>();
    let _ = _port_is_dyn_compatible as fn(&dyn StateStore);
}

#[test]
fn the_fake_passes_its_conformance_kit_through_the_dyn_trait() {
    let store = FakeStateStore::new();
    let dynamic: &dyn StateStore = &store;
    block_on(state_store_conformance(dynamic));
}

#[test]
fn a_fresh_fake_stores_nothing() {
    let store = FakeStateStore::new();
    let run = run(1);
    assert_eq!(block_on(store.get(&run, &key("plan"))).expect("get"), None);
    assert_eq!(block_on(store.list(&run)).expect("list"), Vec::new());
    assert_eq!(store.runs(), Vec::new());
    assert_eq!(store.sensitivity_of(&run, &key("plan")), None);
}

#[test]
fn values_persist_across_independent_reads() {
    let store = FakeStateStore::new();
    let run = run(2);
    let plan = key("plan");
    block_on(store.put(&run, &plan, b"{\"resources\":[]}", Sensitivity::Secretish)).expect("put");

    // Separate calls, each taking and releasing the fake's mutex: what one
    // step wrote is what a later step reads back.
    assert_eq!(
        block_on(store.get(&run, &plan)).expect("get"),
        Some(b"{\"resources\":[]}".to_vec())
    );
    assert_eq!(
        block_on(store.get(&run, &plan)).expect("get"),
        Some(b"{\"resources\":[]}".to_vec())
    );
    assert_eq!(store.sensitivity_of(&run, &plan), Some(Sensitivity::Secretish));
}

#[test]
fn non_utf8_secretish_bytes_round_trip_exactly() {
    let store = FakeStateStore::new();
    let run = run(3);
    let blob = key("cache/blob");
    let bytes = vec![0u8, 159, 146, 150];
    block_on(store.put(&run, &blob, &bytes, Sensitivity::Secretish)).expect("put");
    assert_eq!(
        block_on(store.get(&run, &blob)).expect("get"),
        Some(bytes.clone()),
        "the fake stores opaque bytes, so non-UTF-8 survives untouched"
    );
    assert_eq!(block_on(store.list(&run)).expect("list")[0].len, bytes.len());
}

#[test]
fn one_runs_state_is_invisible_to_another() {
    let store = FakeStateStore::new();
    let mine = run(4);
    let yours = run(5);
    let plan = key("plan");
    block_on(store.put(&mine, &plan, b"{}", Sensitivity::Ordinary)).expect("put");

    assert_eq!(block_on(store.get(&yours, &plan)).expect("get"), None);
    assert_eq!(block_on(store.list(&yours)).expect("list"), Vec::new());
    assert_eq!(store.runs(), vec![mine.clone()]);
}

#[test]
fn a_refused_downgrade_is_reported_and_the_value_is_unchanged() {
    let store = FakeStateStore::new();
    let run = run(6);
    let token = key("deploy.token");
    block_on(store.put(&run, &token, b"x", Sensitivity::Secretish)).expect("put");

    match block_on(store.put(&run, &token, b"y", Sensitivity::Ordinary)) {
        Err(StateStoreError::WouldDowngrade { key: refused, from, to }) => {
            assert_eq!(refused, token);
            assert_eq!(from, Sensitivity::Secretish);
            assert_eq!(to, Sensitivity::Ordinary);
        }
        other => panic!("an Ordinary write over Secretish data must be refused, got {other:?}"),
    }
    assert_eq!(
        block_on(store.get(&run, &token)).expect("get"),
        Some(b"x".to_vec()),
        "the refused write must leave the stored bytes alone"
    );
    assert_eq!(store.sensitivity_of(&run, &token), Some(Sensitivity::Secretish));
}

#[test]
fn putting_the_same_sensitivity_overwrites_in_place() {
    let store = FakeStateStore::new();
    let run = run(7);
    let output = key("outputs");
    block_on(store.put(&run, &output, b"first", Sensitivity::Ordinary)).expect("put");
    block_on(store.put(&run, &output, b"second, longer", Sensitivity::Ordinary)).expect("put");

    assert_eq!(
        block_on(store.get(&run, &output)).expect("get"),
        Some(b"second, longer".to_vec()),
        "state is working data, not an audit record: put replaces"
    );
    let listed = block_on(store.list(&run)).expect("list");
    assert_eq!(listed.len(), 1, "an overwritten key is still exactly one entry");
    assert_eq!(listed[0].len, "second, longer".len(), "the summary reports the new bytes' length");
}

#[test]
fn values_over_the_limit_are_refused_and_values_under_it_are_not() {
    let store = FakeStateStore::new();
    let run = run(8);
    let big = key("big");
    let at_limit = vec![b'x'; MAX_VALUE_BYTES];

    block_on(store.put(&run, &big, &at_limit, Sensitivity::Ordinary))
        .expect("a value at the limit is accepted");
    let over = vec![b'x'; MAX_VALUE_BYTES + 1];
    assert_eq!(
        block_on(store.put(&run, &big, &over, Sensitivity::Ordinary)),
        Err(StateStoreError::TooLarge {
            key: big.clone(),
            len: MAX_VALUE_BYTES + 1,
            max: MAX_VALUE_BYTES
        })
    );
    assert_eq!(
        block_on(store.get(&run, &big)).expect("get"),
        Some(at_limit),
        "the refused value must not have replaced the stored one"
    );

    // A smaller store makes the same rule testable without a megabyte of heap.
    let small = FakeStateStore::new().max_value_bytes(4);
    block_on(small.put(&run, &big, b"1234", Sensitivity::Ordinary)).expect("at the limit is fine");
    assert!(matches!(
        block_on(small.put(&run, &big, b"12345", Sensitivity::Ordinary)),
        Err(StateStoreError::TooLarge { len: 5, max: 4, .. })
    ));
}

#[test]
fn delete_run_clears_one_run_and_a_second_delete_is_fine() {
    let store = FakeStateStore::new();
    let kept = run(9);
    let dropped = run(10);
    block_on(store.put(&kept, &key("k"), b"kept", Sensitivity::Ordinary)).expect("put");
    block_on(store.put(&dropped, &key("k"), b"dropped", Sensitivity::Secretish)).expect("put");

    block_on(store.delete_run(&dropped)).expect("delete_run");
    assert_eq!(block_on(store.list(&dropped)).expect("list"), Vec::new());
    assert_eq!(block_on(store.get(&dropped, &key("k"))).expect("get"), None);
    assert_eq!(block_on(store.get(&kept, &key("k"))).expect("get"), Some(b"kept".to_vec()));
    block_on(store.delete_run(&dropped)).expect("deleting an already-empty run is not an error");
    block_on(store.delete_run(&run(11))).expect("deleting an unknown run is not an error");
}

#[test]
fn a_failing_fake_fails_all_four_methods() {
    let store = FakeStateStore::new().failing("EACCES");
    let run = run(12);
    let key = key("k");
    let backend = StateStoreError::Backend { message: "EACCES".to_string() };
    assert_eq!(block_on(store.put(&run, &key, b"v", Sensitivity::Ordinary)), Err(backend.clone()));
    assert_eq!(block_on(store.get(&run, &key)), Err(backend.clone()));
    assert_eq!(block_on(store.list(&run)), Err(backend.clone()));
    assert_eq!(block_on(store.delete_run(&run)), Err(backend));
}
