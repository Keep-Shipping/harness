//! The Helm conformance kit against a **real** cluster and a **real** `helm`
//! binary ([#74](https://github.com/Keep-Shipping/harness/issues/74)).
//!
//! # What it would do
//!
//! With `KS_HELM_CONFORMANCE=1` set, this installs a real chart on a real
//! cluster through [`HelmCli`], exercises the whole [`Cluster`] port against it
//! — an atomic install, an upgrade, `rollout`/`health` polling, a `rollback` to
//! the first revision — and uninstalls the release afterwards. It is the only
//! test that proves the adapter's argv is what Helm actually accepts, which no
//! amount of asserting on a fake runner can: a flag Helm rejects, a `--set`
//! value Helm parses differently than expected, or a `--namespace` in the wrong
//! place only fails against the real thing.
//!
//! # Why it is opt-in
//!
//! CI here has no cluster and no `helm` on `PATH`, and the acceptance criterion
//! — install and upgrade a chart pushed by `oci.artifact` on kind — is run by
//! hand, or in a job that stands a cluster up first. Unset, the case in
//! `cargo test --workspace`, this test prints that it was skipped and returns,
//! so the ordinary test run stays service-free (ADR 0002). It never fails
//! because the environment is absent.
//!
//! # Running it
//!
//! ```text
//! KS_HELM_CONFORMANCE=1 \
//! KS_HELM_CONTEXT=kind-kind \
//! KS_HELM_CHART=oci://localhost:5000/conformance/chart \
//! KS_HELM_VALUES=./examples/chart/values.yaml \
//! cargo test -p ks-helm-cli --test conformance -- --nocapture
//! ```
//!
//! `KS_HELM_CHART` is the acceptance criterion's shape: a chart published by
//! `oci.artifact`, named by digest where the registry can be asked for one.

use ks_core::ports::cluster::{Chart, ChartUpgrade, Cluster, ClusterError, Revision, Values};
use ks_core::ports::health::{Health, HealthReport};
use ks_helm_cli::HelmCli;
use ks_testing::block_on;

/// The kubeconfig context the conformance run drives.
const DEFAULT_CONTEXT: &str = "kind-kind";
/// The namespace the conformance release is installed into.
const DEFAULT_NAMESPACE: &str = "ks-helm-conformance";
/// The release name the conformance run installs.
const RELEASE: &str = "conformance";

/// The namespace the run installs into, so the request and the uninstall at the
/// end agree on one value.
fn namespace() -> String {
    std::env::var("KS_HELM_NAMESPACE").unwrap_or_else(|_| DEFAULT_NAMESPACE.to_string())
}

/// The adapter the run drives, built from the environment.
fn adapter() -> HelmCli {
    let context = std::env::var("KS_HELM_CONTEXT").unwrap_or_else(|_| DEFAULT_CONTEXT.to_string());
    let mut adapter = HelmCli::try_new(context).expect("a context").with_namespace(namespace());
    if let Ok(kubeconfig) = std::env::var("KS_HELM_KUBECONFIG") {
        adapter = adapter.with_kubeconfig(kubeconfig);
    }
    adapter
}

/// The chart the run installs: an OCI reference, as `oci.artifact` publishes it.
///
/// The `oci://` scheme is stripped — `ImageRef` names a repository, and the
/// adapter re-adds the scheme when it builds the URL.
fn chart() -> Chart {
    let Ok(chart) = std::env::var("KS_HELM_CHART") else {
        panic!("KS_HELM_CHART must name the chart to install, as an oci:// reference");
    };
    // `Chart::oci` would refuse a tag, and that is the rule a step follows. This
    // builds the variant directly so a run started by hand can still point at
    // `oci://host/name:1.2.3`; the adapter renders it the same way and, as ever,
    // never emits `--version` for any OCI reference, digest or tag.
    Chart::Oci(
        ks_core::ports::supply_chain::ImageRef::parse(
            chart.strip_prefix("oci://").unwrap_or(&chart),
        )
        .expect("KS_HELM_CHART must be `oci://host/name[:tag][@sha256:…]`"),
    )
}

#[test]
fn a_chart_installs_upgrades_and_rolls_back_on_a_real_cluster() {
    let Ok(conformance) = std::env::var("KS_HELM_CONFORMANCE") else {
        println!("skipping the helm conformance run: KS_HELM_CONFORMANCE is unset");
        return;
    };
    assert!(
        conformance == "1" || conformance.eq_ignore_ascii_case("true"),
        "KS_HELM_CONFORMANCE is set but is not 1: {conformance:?}"
    );

    let adapter = adapter();
    let request = ChartUpgrade::new(RELEASE, chart())
        .expect("a named release")
        .with_namespace(namespace())
        .with_values(Values::new(
            std::env::var("KS_HELM_VALUES").unwrap_or_else(|_| "replicaCount: 1\n".to_string()),
        ))
        .with_set("conformance.run", RELEASE);

    // The release does not exist yet, so there is no observation — and silence
    // is not health. That is the first thing the port promises and the first
    // thing this run checks.
    let before: HealthReport = block_on(adapter.health(RELEASE)).expect("a report either way");
    println!("before install: {} ({:?})", before.state(), before.reason());
    assert_eq!(before.state(), Health::NoData, "a release that is not there has no observation");
    assert!(matches!(block_on(adapter.rollout(RELEASE)), Err(ClusterError::NotFound { .. })));

    // Install. `--atomic` means this either settles or leaves nothing behind.
    let installed = block_on(adapter.upgrade(&request)).expect("the chart installs");
    println!("installed: revision {} {}", installed.revision(), installed.state());
    assert!(installed.revision() >= Revision::new(1));
    assert_eq!(installed.state(), Health::Healthy, "an atomic install settles or fails");

    // Upgrade the same release to the same chart, with a different override —
    // the port's install and upgrade are one operation.
    let upgraded =
        block_on(adapter.upgrade(&request.clone().with_set("conformance.run", "second")))
            .expect("the chart upgrades");
    println!("upgraded: revision {} {}", upgraded.revision(), upgraded.state());
    assert!(
        upgraded.revision() > installed.revision(),
        "an upgrade is a new revision, not the same one: {} -> {}",
        installed.revision(),
        upgraded.revision()
    );

    // Read-only views agree with each other.
    let rollout = block_on(adapter.rollout(RELEASE)).expect("the release is there");
    let health = block_on(adapter.health(RELEASE)).expect("the release is there");
    assert_eq!(rollout.revision(), upgraded.revision());
    assert_eq!(health.state(), Health::Healthy);
    assert!(health.reason().is_some(), "helm's own description is carried through");

    // Roll back to the revision the install produced. The port names a revision
    // explicitly, so the run does too.
    let rolled =
        block_on(adapter.rollback(RELEASE, installed.revision())).expect("the release rolls back");
    println!("rolled back to revision {} {}", rolled.revision(), rolled.state());
    assert!(rolled.revision() > installed.revision(), "a rollback is a new revision too");
    assert_eq!(block_on(adapter.health(RELEASE)).expect("a report").state(), Health::Healthy);

    // A revision this run never produced is not one the cluster retains.
    assert!(matches!(
        block_on(adapter.rollback(RELEASE, Revision::new(9_999))),
        Err(ClusterError::RevisionUnknown { .. })
    ));

    // `apply` is refused rather than shelled out to `kubectl`.
    let manifests =
        [ks_core::ports::cluster::Manifest::new("Deployment/api", b"kind: Deployment".to_vec())
            .expect("non-empty")];
    assert!(matches!(block_on(adapter.apply(&manifests)), Err(ClusterError::Apply { .. })));

    // Tidy up. `helm uninstall` is not a port method, so it is run directly and
    // only here: the conformance run must not leave a release behind on
    // somebody's kind cluster.
    let output = std::process::Command::new("helm")
        .args(["uninstall", RELEASE, "--namespace", &namespace()])
        .output();
    match output {
        Ok(output) if output.status.success() => println!("uninstalled {RELEASE}"),
        Ok(output) => println!(
            "could not uninstall {RELEASE}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(error) => println!("could not run `helm uninstall`: {error}"),
    }
}
