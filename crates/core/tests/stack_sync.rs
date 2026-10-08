//! The vendored `built_with.json` against the published Factory Zero registry.
//!
//! The product fetches nothing at run time, so the one way its "built with"
//! data can go stale is a registry the venture edits without re-vendoring.
//! `KS_STACK_SYNC=1 cargo test -p ks-core --test stack_sync` fetches the
//! registry with `curl` and fails on any drift — a changed field, a reordered
//! use, a status flip — as a readable diff. Unset (the case in
//! `cargo test --workspace`) the network half prints that it was skipped and
//! returns, the same gating `blocks_registry.rs` uses for its registries.
//! `KS_STACK_SYNC_URL` overrides the URL, so the failure mode itself can be
//! exercised offline.

use ks_core::built_with;

/// The registry entry this venture vendors.
const VENTURE_ID: &str = "FZ-012";

/// A corrupted or hand-mangled vendor fails even with no network: the bytes
/// must at least be the registry entry's shape before anything compares them.
#[test]
fn the_vendored_copy_is_the_fz_012_entry() {
    let vendored: serde_json::Value = serde_json::from_str(built_with::venture_json())
        .expect("vendored built_with.json is not valid JSON");
    assert_eq!(vendored["id"], VENTURE_ID, "the vendored entry is not {VENTURE_ID}");
    assert_eq!(vendored["name"], "Keep Shipping");
    // And the hand-rolled parser the product itself reads through agrees.
    assert_eq!(built_with::venture().id, VENTURE_ID);
}

#[test]
fn the_vendored_copy_matches_the_published_registry() {
    if std::env::var_os("KS_STACK_SYNC").is_none() {
        println!("skipping the stack sync check: KS_STACK_SYNC is unset");
        return;
    }
    let url =
        std::env::var("KS_STACK_SYNC_URL").unwrap_or_else(|_| built_with::REGISTRY_URL.to_string());
    let published = fetch(&url);

    let entry = published["ventures"]
        .as_array()
        .expect("the registry's `ventures` is an array")
        .iter()
        .find(|venture| venture["id"] == VENTURE_ID)
        .unwrap_or_else(|| {
            panic!("{VENTURE_ID} (Keep Shipping) is missing from the published registry ({url})")
        })
        .clone();

    // Values, not the typed struct: a field the parser does not know yet is
    // drift all the same. Both sides go back through the same pretty printer,
    // so the diff reads line by line.
    let vendored: serde_json::Value =
        serde_json::from_str(built_with::venture_json()).expect("vendored built_with.json parses");
    assert_eq!(
        serde_json::to_string_pretty(&vendored).expect("serialises"),
        serde_json::to_string_pretty(&entry).expect("serialises"),
        "the vendored built_with.json has drifted from {url}; re-vendor the {VENTURE_ID} entry"
    );

    // And the parsed shape the product renders from is the published one, so
    // the hand-rolled parser cannot be dropping or mangling a field the raw
    // comparison above would excuse.
    let venture = built_with::venture();
    assert_eq!(Some(venture.name.as_str()), entry.get("name").and_then(|v| v.as_str()));
    assert_eq!(Some(venture.site.as_str()), entry.get("site").and_then(|v| v.as_str()));
    assert_eq!(Some(venture.page.as_str()), entry.get("page").and_then(|v| v.as_str()));
    let uses = entry["uses"].as_array().expect("the published `uses` is an array");
    assert_eq!(venture.uses.len(), uses.len(), "the parsed `uses` count is not the published one");
    for (use_, published) in venture.uses.iter().zip(uses) {
        let reason = "the parsed use is not the published one";
        assert_eq!(
            Some(use_.id.as_str()),
            published.get("id").and_then(|v| v.as_str()),
            "{reason}"
        );
        assert_eq!(
            Some(use_.name.as_str()),
            published.get("name").and_then(|v| v.as_str()),
            "{reason}"
        );
        assert_eq!(
            Some(use_.url.as_str()),
            published.get("url").and_then(|v| v.as_str()),
            "{reason}"
        );
        assert_eq!(
            Some(use_.status.as_str()),
            published.get("status").and_then(|v| v.as_str()),
            "{reason}"
        );
    }
}

/// The registry as `serde_json::Value`, fetched with curl — the tool is here
/// in dev sandboxes and CI, and pulling a client into ks-core's dev graph for
/// one check would not earn its keep. Only runs when explicitly enabled, so a
/// failure says how to opt out.
fn fetch(url: &str) -> serde_json::Value {
    let output = std::process::Command::new("curl")
        .args(["-sS", "--max-time", "30", "-f", url])
        .output()
        .expect("curl itself could not be run");
    if !output.status.success() {
        panic!(
            "the published registry ({url}) was unreachable: {} {} — this check only runs with \
             KS_STACK_SYNC set; unset it to skip",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("the published registry ({url}) is not valid JSON: {error}"))
}
