//! Behaviour of the deploy-target fakes: scripted health transitions through
//! a rollout, the errors each port promises for its failure cases, the pinned
//! host key, and the pin-a-step-cannot-trust.
//!
//! Each port's fake is driven the way a step would drive a real target —
//! apply then wait, publish then shift, probe until settled — and each ends
//! with the port's conformance kit and a `dyn` check, so the same kit can be
//! pointed at a real adapter unchanged.

use std::path::PathBuf;
use std::time::Duration;

use ks_core::ports::cluster::{
    Chart, ChartUpgrade, Cluster, ClusterError, Manifest, Revision, Rollout, Values,
};
use ks_core::ports::function_host::{
    Artifact, FunctionHost, FunctionHostError, TrafficSplit, Version,
};
use ks_core::ports::health::{Health, HealthReport};
use ks_core::ports::remote_shell::{Command, CommandResult, Probe, RemoteShell, ShellError};
use ks_testing::block_on;
use ks_testing::cluster::{ClusterCall, FakeCluster, conformance as cluster_conformance};
use ks_testing::function_host::{
    FakeFunctionHost, FunctionHostCall, VERSION_OVERRIDE_HEADER,
    conformance as function_conformance,
};
use ks_testing::remote_shell::{
    DEFAULT_FINGERPRINT, FAILING_PROGRAM, FakeRemoteShell, OK_PROGRAM, REBUILT_HOST_KEY, ShellCall,
    UNANSWERABLE_PROBE, conformance as shell_conformance,
};

/// The workload every cluster test applies.
const WORKLOAD: &str = "Deployment/api";

fn manifest() -> Manifest {
    Manifest::new(WORKLOAD, b"kind: Deployment").expect("the test manifest is well formed")
}

fn artifact() -> Artifact {
    Artifact::new("oci://registry/api:v7", Some("sha256:abc123".to_string()))
        .expect("the test artifact is well formed")
}

fn command(program: &str) -> Command {
    Command::new(program, vec!["--flag".to_string()], Duration::from_secs(30))
        .expect("the test command is well formed")
}

fn probe(command_line: &str) -> Probe {
    Probe::new(command_line).expect("the test probe is well formed")
}

fn version(id: &str) -> Version {
    Version::new(id).expect("the test version id is not empty")
}

/// The release upgrade the cluster fake is asked for: a named release from a
/// chart on disk, rendered with its own values.
fn upgrade() -> ChartUpgrade {
    ChartUpgrade::new("api", Chart::path("./charts/api").expect("a chart path"))
        .expect("a named release")
        .with_namespace("production")
        .with_values(Values::new("replicas: 2"))
}

fn all_of(version: &Version) -> TrafficSplit {
    TrafficSplit::new(version.clone(), 100).expect("all of it is in range")
}

/// A local file this test creates, so the shell fake's one existence check
/// never depends on a path that exists only on some machines — `/etc/*` is
/// absent from a distroless image. The second value removes the file on drop.
fn a_local_file(name: &str) -> (PathBuf, TempFile) {
    let path =
        std::env::temp_dir().join(format!("ks-testing-deploy-{}-{name}", std::process::id()));
    std::fs::write(&path, b"payload the fake never reads\n").expect("the temp dir is writable");
    (path.clone(), TempFile(path))
}

/// Removes the file an [`a_local_file`] call created.
struct TempFile(PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn a_workload_walks_its_scripted_health_transition_and_then_holds() {
    let cluster = FakeCluster::new().with_health_script([
        Health::Progressing,
        Health::Progressing,
        Health::Healthy,
    ]);

    // Before the apply the cluster has observed nothing, and silence must not
    // pass a healthy gate (#52).
    let silent = block_on(cluster.health(WORKLOAD)).expect("a report, not an error");
    assert_eq!(silent.state(), Health::NoData);
    assert!(!silent.satisfies(Health::Healthy));
    assert!(!silent.satisfies(Health::Failed), "NoData is not a failure either");

    block_on(cluster.apply(&[manifest()])).expect("the manifests are accepted");

    // A waiter polls: two polls see Progressing, then it settles.
    let polled: Vec<Health> =
        (0..3).map(|_| block_on(cluster.health(WORKLOAD)).expect("a report").state()).collect();
    assert_eq!(polled, vec![Health::Progressing, Health::Progressing, Health::Healthy]);
    // And it holds at the last state rather than falling off the end of the
    // script, so a slow waiter sees the same answer.
    assert_eq!(block_on(cluster.health(WORKLOAD)).expect("a report").state(), Health::Healthy);
    assert_eq!(block_on(cluster.health(WORKLOAD)).expect("a report").reason(), None);

    // A degraded target keeps a waiter polling: it is not settled.
    let degraded = FakeCluster::new().with_health_script([Health::Degraded]);
    block_on(degraded.apply(&[manifest()])).expect("the manifests are accepted");
    let report = block_on(degraded.health(WORKLOAD)).expect("a report");
    assert_eq!(report.state(), Health::Degraded);
    assert!(!report.state().is_settled());
    assert!(!report.satisfies(Health::Healthy));
}

#[test]
fn each_workload_walks_its_own_health_script() {
    let cluster = FakeCluster::new().with_health_script([Health::Progressing, Health::Healthy]);
    let web = Manifest::new("Deployment/web", b"kind: Deployment").expect("well formed");
    block_on(cluster.apply(&[manifest(), web])).expect("the manifests are accepted");

    // Polling `Deployment/api` to a settled answer must not hand
    // `Deployment/web` a rollout it never walked: a shared cursor would report
    // `Healthy` on web's first poll, silently skipping the whole rollout.
    assert_eq!(
        (0..2)
            .map(|_| block_on(cluster.health(WORKLOAD)).expect("a report").state())
            .collect::<Vec<_>>(),
        vec![Health::Progressing, Health::Healthy]
    );
    assert_eq!(
        block_on(cluster.health("Deployment/web")).expect("a report").state(),
        Health::Progressing
    );
}

#[test]
fn a_rejected_apply_never_reports_a_workload_as_healthy() {
    let cluster = FakeCluster::new().with_manifest_error(ClusterError::Apply {
        message: "admission webhook denied the request".to_string(),
    });
    let applied = block_on(cluster.apply(&[manifest()]));
    assert_eq!(
        applied,
        Err(ClusterError::Apply { message: "admission webhook denied the request".to_string() }),
        "an admission failure is Apply, with the api server's own wording"
    );
    // Nothing was accepted, so there is nothing to observe — and silence is
    // not a green deploy.
    let report = block_on(cluster.health(WORKLOAD)).expect("a report, not an error");
    assert_eq!(report.state(), Health::NoData);
    assert!(!report.satisfies(Health::Healthy));
}

#[test]
fn a_rollback_names_its_revision_and_never_substitutes_the_running_one() {
    let cluster = FakeCluster::new()
        .with_rollback_revision(Revision::new(4))
        .with_rollout(WORKLOAD, Rollout::new(Revision::new(5), Health::Healthy));
    block_on(cluster.apply(&[manifest()])).expect("the manifests are accepted");

    let rolled =
        block_on(cluster.rollback(WORKLOAD, Revision::new(4))).expect("revision 4 is retained");
    assert_eq!(rolled.revision(), Revision::new(4));

    // Revision 5 is what is running now, and asking for it back still fails:
    // the fake retains only what the test told it to, and a rollback to the
    // wrong revision is worse than none (#52).
    assert_eq!(
        block_on(cluster.rollback(WORKLOAD, Revision::new(5))),
        Err(ClusterError::RevisionUnknown { revision: Revision::new(5) })
    );
}

#[test]
fn the_cluster_records_every_call_oldest_first() {
    let cluster = FakeCluster::new();
    let request = upgrade();
    block_on(cluster.apply(&[manifest()])).expect("the manifests are accepted");
    block_on(cluster.rollout(WORKLOAD)).expect("a rollout");
    block_on(cluster.health(WORKLOAD)).expect("a report");
    block_on(cluster.upgrade(&request)).expect("an upgrade");
    block_on(cluster.rollback(WORKLOAD, Revision::new(1))).expect("a rollback");
    assert_eq!(
        cluster.calls(),
        vec![
            ClusterCall::Apply { names: vec![WORKLOAD.to_string()] },
            ClusterCall::Rollout { name: WORKLOAD.to_string() },
            ClusterCall::Health { name: WORKLOAD.to_string() },
            ClusterCall::Upgrade { request: upgrade() },
            ClusterCall::Rollback { name: WORKLOAD.to_string(), revision: Revision::new(1) },
        ],
        "the recorded upgrade is the whole request, not just the release name"
    );
    // And the request that came out is the one that went in: the release, the
    // chart it came from and the namespace it was told to deploy into.
    let ClusterCall::Upgrade { request: recorded } = &cluster.calls()[3] else {
        panic!("expected an upgrade call");
    };
    assert_eq!(recorded.release(), "api");
    assert_eq!(recorded.chart().as_path(), Some("./charts/api"));
    assert_eq!(recorded.namespace(), Some("production"));
    // `handle` is a read of the adapter's identity: a method, never a call
    // against the cluster, so it does not appear in the vector above.
    assert_eq!(cluster.handle().context(), "fake-context");
}

#[test]
fn a_probe_walks_its_scripted_transition_and_unscripted_probes_are_silent() {
    let shell = FakeRemoteShell::new().with_probe_script(
        "curl -fsS localhost:8080/healthz",
        [Health::Progressing, Health::Degraded, Health::Healthy],
    );

    let unknown =
        block_on(shell.probe(&probe(UNANSWERABLE_PROBE))).expect("a report, not an error");
    assert_eq!(unknown.state(), Health::NoData);
    assert!(!unknown.satisfies(Health::Healthy), "silence is not health");

    let healthz = probe("curl -fsS localhost:8080/healthz");
    let states: Vec<Health> =
        (0..4).map(|_| block_on(shell.probe(&healthz)).expect("a report").state()).collect();
    assert_eq!(
        states,
        vec![Health::Progressing, Health::Degraded, Health::Healthy, Health::Healthy]
    );
}

#[test]
fn a_failed_command_is_an_error_and_a_copy_reports_its_bytes() {
    let shell = FakeRemoteShell::new()
        .with_command_result("uname", CommandResult::new("Linux\n", ""))
        .with_copy_bytes(12_288);

    let result = block_on(shell.run(&command("uname"))).expect("the command is scripted");
    assert_eq!(result.stdout(), "Linux\n");
    assert_eq!(result.stderr(), "");

    let failed = block_on(shell.run(&command(FAILING_PROGRAM)));
    assert!(
        matches!(&failed, Err(ShellError::Command { status, .. }) if *status != 0),
        "a nonzero exit is ShellError::Command, never an Ok carrying a status, got {failed:?}"
    );

    // A source the test itself created: the fake's one filesystem read must not
    // depend on a path that exists only on some machines.
    let (local, _cleanup) = a_local_file("deploy-copy");
    let copied = block_on(shell.copy(&local, "/tmp/hostname"))
        .expect("the local file this test created exists");
    assert_eq!(copied.bytes(), 12_288);
    assert!(
        block_on(shell.copy(&local.with_extension("absent"), "/tmp/nope")).is_err(),
        "a truncated transfer is an error, not a shorter Copied"
    );
}

#[test]
fn a_pinned_host_key_mismatch_stops_every_call_on_the_host() {
    let shell = FakeRemoteShell::new()
        .with_rejected_host_key(DEFAULT_FINGERPRINT)
        .with_probe_script(OK_PROGRAM, [Health::Healthy]);
    let expected = ShellError::HostKeyMismatch {
        expected: DEFAULT_FINGERPRINT.to_string(),
        got: REBUILT_HOST_KEY.to_string(),
    };
    let (local, _cleanup) = a_local_file("deploy-rejected-copy");
    assert_eq!(block_on(shell.run(&command(OK_PROGRAM))), Err(expected.clone()));
    assert_eq!(block_on(shell.copy(&local, "/tmp/hostname")), Err(expected.clone()));
    assert_eq!(block_on(shell.probe(&probe(OK_PROGRAM))), Err(expected));

    // The pin is checked on every connect, so a scripted healthy probe still
    // never ran: the connection did not open.
    assert_eq!(
        shell.calls(),
        vec![
            ShellCall::Run { program: OK_PROGRAM.to_string() },
            ShellCall::Copy { to: "/tmp/hostname".to_string() },
            ShellCall::Probe { command: OK_PROGRAM.to_string() },
        ]
    );
}

#[test]
fn a_published_version_is_cold_until_traffic_reaches_it() {
    let host = FakeFunctionHost::new();
    let v1 = block_on(host.publish(&artifact())).expect("the artifact publishes");
    let v2 = block_on(host.publish(&artifact())).expect("the second artifact publishes");
    assert_eq!((v1.id(), v2.id()), ("v1", "v2"));

    // Real, but cold: never run, so never healthy — and a different error from
    // a version the host has never heard of.
    assert_eq!(
        block_on(host.health(&v1)),
        Err(FunctionHostError::NoTraffic { version: "v1".to_string() })
    );
    assert_eq!(
        block_on(host.health(&version("v999"))),
        Err(FunctionHostError::UnknownVersion { version: "v999".to_string() })
    );

    block_on(host.shift(&TrafficSplit::new(v2.clone(), 10).expect("ten percent")))
        .expect("the split is accepted");
    let report = block_on(host.health(&v2)).expect("a report");
    assert_eq!(report.state(), Health::Healthy);
    assert_eq!(report.reason(), None);
    // A 10% shift is still traffic, so v1 stays cold and v2 is serving.
    assert!(matches!(block_on(host.health(&v1)), Err(FunctionHostError::NoTraffic { .. })));
}

#[test]
fn a_smoke_check_through_the_pin_can_be_told_which_version_answered() {
    let detectable = FakeFunctionHost::new().with_pin_detectable(true);
    let v1 = block_on(detectable.publish(&artifact())).expect("v1 publishes");
    let v2 = block_on(detectable.publish(&artifact())).expect("v2 publishes");
    assert!(detectable.pin_is_detectable());

    // The pin names the version the step published, in the Workers header.
    let pin = detectable.pinned(&v2);
    assert_eq!(pin.version(), &v2);
    assert_eq!(pin.url(), None);
    assert_eq!(pin.headers(), [(VERSION_OVERRIDE_HEADER.to_string(), "api=\"v2\"".to_string())]);
    // Two pins for two versions are two different requests, so the response
    // can be attributed to one of them.
    assert_ne!(detectable.pinned(&v1).headers(), detectable.pinned(&v2).headers());

    // The undetectable host is the dangerous one: the pin still looks right,
    // but nothing says which version served the request, so a step that only
    // checks for a 200 would smoke-test the old code and pass.
    let undetectable = FakeFunctionHost::new().with_pin_detectable(false);
    assert!(!undetectable.pin_is_detectable());
    let first = block_on(undetectable.publish(&artifact())).expect("the artifact publishes");
    let pin = undetectable.pinned(&first);
    assert_eq!(pin.version(), &first);
    assert_eq!(pin.headers()[0].1, "api=\"v1\"");
}

#[test]
fn rollback_returns_where_traffic_was_and_pre_warming_never_fails_a_deploy() {
    let host = FakeFunctionHost::new().with_split(all_of(&version("v1")));
    let v2 = block_on(host.publish(&artifact())).expect("v2 publishes");
    block_on(host.shift(&all_of(&v2))).expect("the split is accepted");
    assert_eq!(host.current_split(), Some(v2.clone()));

    block_on(host.keep_warm(&v2, 3)).expect("a host that cannot pre-warm still succeeds");
    assert_eq!(host.warm_versions(), 3);

    // No version argument: the host knows where traffic was, and the run log
    // records where it actually went.
    assert_eq!(block_on(host.rollback()), Ok(version("v1")));
    assert_eq!(host.current_split(), Some(version("v1")));

    // And it is convergent: a cleanup step or a retry after the rollback
    // reports the same version again, rather than the one just abandoned.
    assert_eq!(block_on(host.rollback()), Ok(version("v1")));
    assert_eq!(block_on(host.rollback()), Ok(version("v1")));
    assert_eq!(host.current_split(), Some(version("v1")));
}

#[test]
fn the_function_host_records_every_call_oldest_first() {
    let host = FakeFunctionHost::new();
    let v1 = block_on(host.publish(&artifact())).expect("v1 publishes");
    block_on(host.shift(&all_of(&v1))).expect("the split is accepted");
    block_on(host.health(&v1)).expect("a report");
    block_on(host.keep_warm(&v1, 2)).expect("pre-warm");
    let _ = host.pinned(&v1);
    let _ = host.pin_is_detectable();
    block_on(host.rollback()).expect("a rollback");
    assert_eq!(
        host.calls(),
        vec![
            FunctionHostCall::Publish {
                uri: "oci://registry/api:v7".to_string(),
                digest: Some("sha256:abc123".to_string()),
            },
            FunctionHostCall::Shift { version: "v1".to_string(), percent: 100 },
            FunctionHostCall::Health { version: "v1".to_string() },
            FunctionHostCall::KeepWarm { version: "v1".to_string(), count: 2 },
            FunctionHostCall::Pinned { version: "v1".to_string() },
            FunctionHostCall::PinIsDetectable,
            FunctionHostCall::Rollback,
        ]
    );
    // A `Debug` of the fake is counts only: an artifact uri can quote a deploy
    // log, and a panic message must not carry one.
    let debug = format!("{host:?}");
    assert!(debug.contains("published: 1"), "{debug}");
    assert!(!debug.contains("oci://"), "{debug}");
}

#[test]
fn a_healthy_report_carries_no_reason_when_the_target_says_nothing() {
    // The scripted states a fake answers with are bare `HealthReport::new`s,
    // so a step's waiting log shows the state alone; a test that wants the
    // target's own wording scripts one.
    let cluster = FakeCluster::new();
    block_on(cluster.apply(&[manifest()])).expect("the manifests are accepted");
    let bare: HealthReport = block_on(cluster.health(WORKLOAD)).expect("a report");
    assert_eq!(bare, HealthReport::new(Health::Healthy));

    let explained = FakeCluster::new().with_health_reports([HealthReport::with_reason(
        Health::Degraded,
        "2 of 5 replicas ready",
    )]);
    block_on(explained.apply(&[manifest()])).expect("the manifests are accepted");
    let explained = block_on(explained.health(WORKLOAD)).expect("a report");
    assert_eq!(explained.state(), Health::Degraded);
    assert_eq!(explained.reason(), Some("2 of 5 replicas ready"));
}

#[test]
fn the_cluster_fake_passes_conformance_and_is_dyn_compatible() {
    let cluster = FakeCluster::new().with_health_script([Health::Progressing, Health::Healthy]);
    block_on(cluster_conformance(&cluster, WORKLOAD, &manifest()));

    fn assert_send_sync<T: ?Sized + Send + Sync>() {}
    assert_send_sync::<dyn Cluster>();
    let dynamic: &dyn Cluster = &cluster;
    assert_eq!(dynamic.handle().context(), "fake-context");
}

#[test]
fn the_remote_shell_fake_passes_conformance_and_is_dyn_compatible() {
    let shell = FakeRemoteShell::new();
    block_on(shell_conformance(&shell));

    fn assert_send_sync<T: ?Sized + Send + Sync>() {}
    assert_send_sync::<dyn RemoteShell>();
    let dynamic: &dyn RemoteShell = &shell;
    assert_eq!(dynamic.host().user(), "deploy");
}

#[test]
fn the_function_host_fake_passes_conformance_and_is_dyn_compatible() {
    let host = FakeFunctionHost::new();
    block_on(function_conformance(&host));

    fn assert_send_sync<T: ?Sized + Send + Sync>() {}
    assert_send_sync::<dyn FunctionHost>();
    let dynamic: &dyn FunctionHost = &host;
    // The dangerous default: this host says nothing about which version
    // answered a pinned request, so a step must check the response itself.
    assert!(!dynamic.pin_is_detectable());
}
