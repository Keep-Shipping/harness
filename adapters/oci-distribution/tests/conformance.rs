//! The registry conformance kit against **real** registries
//! ([#60](https://github.com/Keep-Shipping/harness/issues/60)).
//!
//! `KS_OCI_CONFORMANCE_REGISTRIES` is a comma-separated list of registry hosts,
//! e.g. `localhost:5000,localhost:5001`. Unset — the case in
//! `cargo test --workspace` — the test prints that it was skipped and returns,
//! so the ordinary test run stays service-free (ADR 0002).
//!
//! The registries CI runs this against, and the features each one exercises,
//! are listed in `docs/REGISTRIES.md`.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use ks_cli::http_client::TcpHttpClient;
use ks_core::ports::http::HttpPolicy;
use ks_oci_distribution::OciDistribution;
use ks_testing::block_on;
use ks_testing::supply_chain::registry_conformance;

/// Pushes of a conformance run are small, but a registry answers a lot of
/// things; 16 MiB of response headroom keeps a manifest or an index from
/// tripping the cap.
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[test]
fn the_registry_conformance_kit_passes_on_every_configured_registry() {
    let Ok(configured) = std::env::var("KS_OCI_CONFORMANCE_REGISTRIES") else {
        println!("skipping the registry conformance run: KS_OCI_CONFORMANCE_REGISTRIES is unset");
        return;
    };
    let registries: Vec<String> = configured
        .split(',')
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .map(str::to_string)
        .collect();
    assert!(!registries.is_empty(), "KS_OCI_CONFORMANCE_REGISTRIES is set but empty");

    // The hosts the registries live on, port stripped: that is what the
    // client's allowlist matches.
    let hosts: BTreeSet<String> = registries
        .iter()
        .map(|host| host.split(':').next().unwrap_or(host).to_ascii_lowercase())
        .collect();
    let client = Arc::new(TcpHttpClient::new(HttpPolicy {
        allowed_hosts: hosts,
        timeout: Duration::from_secs(60),
        max_response_bytes: MAX_RESPONSE_BYTES,
    }));
    // These are local, plain-http registries: naming them insecure is what
    // tells the adapter to use `http:` rather than `https:`.
    let registry = OciDistribution::new(client).with_insecure_hosts(registries.clone());

    for host in &registries {
        let repository = format!("{host}/conformance/app");
        println!("running the registry conformance kit against {repository}");
        block_on(registry_conformance(&registry, &repository));
        println!("{repository}: conformance passed");
    }
}
