//! Behaviour of the `StateStore` fake: overwrite-in-place working data, the
//! sensitivity ratchet, per-run isolation, deterministic listings — plus the
//! conformance kit, run against the fake through the `dyn` trait.

use ks_core::ids::RunId;
use ks_core::ports::state_store::{Sensitivity, StateError, StateStore};
use ks_testing::block_on;
use ks_testing::state_store::{MemoryStateStore, conformance as state_store_conformance};

fn run(seed: u128) -> RunId {
    RunId::from_parts(1_700_000_000_000, seed)
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
    let store = MemoryStateStore::new();
    let dynamic: &dyn StateStore = &store;
    block_on(state_store_conformance(dynamic));
}

#[test]
fn a_fresh_fake_stores_nothing() {
    let store = MemoryStateStore::new();
    let run = run(1);
    assert_eq!(block_on(store.get(&run, "plan")).expect("get"), None);
    assert_eq!(block_on(store.list(&run)).expect("list"), Vec::new());
    assert_eq!(store.sensitivity_of(&run, "plan"), None);
}

#[test]
fn values_persist_across_independent_reads() {
    let store = MemoryStateStore::new();
    let run = run(2);
    block_on(store.put(&run, "plan", b"{\"resources\":[]}", Sensitivity::Secretish)).expect("put");

    // Separate calls, each taking and releasing the fake's mutex: what one
    // step wrote is what a later step reads back.
    assert_eq!(
        block_on(store.get(&run, "plan")).expect("get"),
        Some(b"{\"resources\":[]}".to_vec())
    );
    assert_eq!(
        block_on(store.get(&run, "plan")).expect("get"),
        Some(b"{\"resources\":[]}".to_vec())
    );
    assert_eq!(store.sensitivity_of(&run, "plan"), Some(Sensitivity::Secretish));
}

#[test]
fn non_utf8_secretish_bytes_round_trip_exactly() {
    let store = MemoryStateStore::new();
    let run = run(3);
    let bytes = vec![0u8, 159, 146, 150];
    block_on(store.put(&run, "cache.blob", &bytes, Sensitivity::Secretish)).expect("put");
    assert_eq!(
        block_on(store.get(&run, "cache.blob")).expect("get"),
        Some(bytes.clone()),
        "the fake stores opaque bytes, so non-UTF-8 survives untouched"
    );
    assert_eq!(block_on(store.list(&run)).expect("list")[0].len, bytes.len());
}

#[test]
fn one_runs_state_is_invisible_to_another() {
    let store = MemoryStateStore::new();
    let mine = run(4);
    let yours = run(5);
    block_on(store.put(&mine, "plan", b"{}", Sensitivity::Plain)).expect("put");

    assert_eq!(block_on(store.get(&yours, "plan")).expect("get"), None);
    assert_eq!(block_on(store.list(&yours)).expect("list"), Vec::new());
}

#[test]
fn a_refused_downgrade_is_reported_and_the_value_is_unchanged() {
    let store = MemoryStateStore::new();
    let run = run(6);
    block_on(store.put(&run, "deploy.token", b"x", Sensitivity::Secretish)).expect("put");

    assert_eq!(
        block_on(store.put(&run, "deploy.token", b"y", Sensitivity::Plain)).expect_err("refused"),
        StateError::Downgrade { key: "deploy.token".to_string() }
    );
    assert_eq!(
        block_on(store.get(&run, "deploy.token")).expect("get"),
        Some(b"x".to_vec()),
        "the refused write must leave the stored bytes alone"
    );
    assert_eq!(store.sensitivity_of(&run, "deploy.token"), Some(Sensitivity::Secretish));
}

#[test]
fn putting_the_same_sensitivity_overwrites_in_place() {
    let store = MemoryStateStore::new();
    let run = run(7);
    block_on(store.put(&run, "outputs", b"first", Sensitivity::Plain)).expect("put");
    block_on(store.put(&run, "outputs", b"second, longer", Sensitivity::Plain)).expect("put");

    assert_eq!(
        block_on(store.get(&run, "outputs")).expect("get"),
        Some(b"second, longer".to_vec()),
        "state is working data, not an audit record: put replaces"
    );
    let listed = block_on(store.list(&run)).expect("list");
    assert_eq!(listed.len(), 1, "an overwritten key is still exactly one entry");
    assert_eq!(listed[0].len, "second, longer".len(), "the summary reports the new bytes' length");
}

#[test]
fn a_listing_is_sorted_and_carries_only_metadata() {
    let store = MemoryStateStore::new();
    let run = run(8);
    for key in ["zebra", "alpha", "middle", "beta"] {
        block_on(store.put(&run, key, b"v", Sensitivity::Plain)).expect("put");
    }
    let listed = block_on(store.list(&run)).expect("list");
    let keys: Vec<&str> = listed.iter().map(|summary| summary.key.as_str()).collect();
    assert_eq!(
        keys,
        ["alpha", "beta", "middle", "zebra"],
        "list is sorted, whatever order it was written in"
    );
    // Listing twice against unchanged state gives the same answer, so a caller
    // may diff or hash it.
    assert_eq!(listed, block_on(store.list(&run)).expect("list"));
}

#[test]
fn delete_run_clears_one_run_and_a_second_delete_is_fine() {
    let store = MemoryStateStore::new();
    let kept = run(9);
    let dropped = run(10);
    block_on(store.put(&kept, "k", b"kept", Sensitivity::Plain)).expect("put");
    block_on(store.put(&dropped, "k", b"dropped", Sensitivity::Secretish)).expect("put");

    block_on(store.delete_run(&dropped)).expect("delete_run");
    assert_eq!(block_on(store.list(&dropped)).expect("list"), Vec::new());
    assert_eq!(block_on(store.get(&dropped, "k")).expect("get"), None);
    assert_eq!(block_on(store.get(&kept, "k")).expect("get"), Some(b"kept".to_vec()));
    block_on(store.delete_run(&dropped)).expect("deleting an already-empty run is not an error");
    block_on(store.delete_run(&run(11))).expect("deleting an unknown run is not an error");
}

#[test]
fn a_bad_key_is_refused_before_anything_is_stored() {
    let store = MemoryStateStore::new();
    let run = run(12);
    for bad in ["../escape", "dir/file", ".sensitivity.json"] {
        assert!(
            matches!(
                block_on(store.put(&run, bad, b"v", Sensitivity::Plain)),
                Err(StateError::InvalidKey { .. })
            ),
            "{bad:?} must be refused: a key cannot name the store's own bookkeeping"
        );
        // A read is refused the same way, so a caller cannot use `get` to reach
        // what `put` would not let it write.
        assert!(
            matches!(block_on(store.get(&run, bad)), Err(StateError::InvalidKey { .. })),
            "get {bad:?} must be refused, not answered"
        );
    }
    assert_eq!(block_on(store.list(&run)).expect("list"), Vec::new());
}

#[test]
fn rewriting_one_key_leaves_another_keys_bytes_and_classification_alone() {
    let store = MemoryStateStore::new();
    let run = run(13);
    block_on(store.put(&run, "plan-one", b"the first plan", Sensitivity::Secretish)).expect("put");
    block_on(store.put(&run, "plan-two", b"the second plan", Sensitivity::Secretish)).expect("put");
    block_on(store.put(&run, "plan-two", b"the second plan, rewritten", Sensitivity::Secretish))
        .expect("put");

    assert_eq!(
        block_on(store.get(&run, "plan-one")).expect("get"),
        Some(b"the first plan".to_vec()),
        "writing a different key must not disturb this one's bytes"
    );
    assert_eq!(store.sensitivity_of(&run, "plan-one"), Some(Sensitivity::Secretish));
    let listed = block_on(store.list(&run)).expect("list");
    assert_eq!(listed.len(), 2, "both keys are still listed");
    assert_eq!(
        listed.iter().find(|s| s.key == "plan-one").expect("listed").sensitivity,
        Sensitivity::Secretish,
        "a whole-run rewrite must not drop a key it did not touch"
    );
}

#[test]
fn a_same_key_downgrade_is_refused_and_the_stored_bytes_are_untouched() {
    let store = MemoryStateStore::new();
    let run = run(14);
    block_on(store.put(&run, "plan-race", b"the secret plan", Sensitivity::Secretish))
        .expect("put");

    assert_eq!(
        block_on(store.put(&run, "plan-race", b"plain bytes", Sensitivity::Plain))
            .expect_err("refused"),
        StateError::Downgrade { key: "plan-race".to_string() }
    );
    assert_eq!(
        block_on(store.get(&run, "plan-race")).expect("get"),
        Some(b"the secret plan".to_vec()),
        "the refused write must not touch what is already under the key"
    );
    assert_eq!(store.sensitivity_of(&run, "plan-race"), Some(Sensitivity::Secretish));
}

#[test]
fn delete_run_takes_the_classification_with_it() {
    let store = MemoryStateStore::new();
    let run = run(15);
    block_on(store.put(&run, "plan-gone", b"a secret plan", Sensitivity::Secretish)).expect("put");
    block_on(store.delete_run(&run)).expect("delete_run");

    // The promise was made about a run that no longer exists, so writing the
    // same key plain afterwards is a fresh write, not a downgrade.
    block_on(store.put(&run, "plan-gone", b"ordinary state", Sensitivity::Plain))
        .expect("a deleted run's keys can be written plain again");
    assert_eq!(
        block_on(store.get(&run, "plan-gone")).expect("get"),
        Some(b"ordinary state".to_vec())
    );
    assert_eq!(store.sensitivity_of(&run, "plan-gone"), Some(Sensitivity::Plain));
}

#[test]
fn debug_reports_what_the_store_holds_and_never_what_it_holds_it_as() {
    let store = MemoryStateStore::new();
    let run = run(16);
    block_on(store.put(&run, "plan-ada", b"s3cr3t-plan-bytes", Sensitivity::Secretish))
        .expect("put");

    let shown = format!("{store:?}");
    assert_eq!(shown, "MemoryStateStore { runs: 1, keys: 1 }", "counts only");
    assert!(
        !shown.contains("s3cr3t") && !shown.contains("secretish"),
        "a Debug of the fake must not become a way to print secretish bytes into a log: {shown}"
    );
}
