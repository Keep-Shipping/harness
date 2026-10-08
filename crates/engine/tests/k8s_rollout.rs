//! What a rollout owes the cluster before anything is applied
//! ([#73](https://github.com/Keep-Shipping/harness/issues/73)).
//!
//! The contract is in the refusals and the rollback: a tag and an unpinned
//! sidecar never reach the API server, and a workload that does not settle goes
//! back to the revision it was on — or the run says there was nothing to go
//! back to.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ks_core::harness::Harness;
use ks_core::ports::clock::Clock;
use ks_core::ports::cluster::{Cluster, ClusterError, Revision, Rollout};
use ks_core::ports::health::{Health, HealthReport};
use ks_core::ports::script_host::Value;
use ks_core::ports::secrets::Redactor;
use ks_core::step::{
    CancellationToken, Inputs, LogRecord, LogSink, Outputs, Port, Ports, StepError, StepKind,
};
use ks_engine::k8s_rollout::K8sRollout;
use ks_engine::run::run_step;
use ks_testing::block_on;
use ks_testing::clock::FakeClock;
use ks_testing::cluster::{ClusterCall, FakeCluster};
use ks_testing::step::RecordingSink;

/// The manifest every scenario starts from: one Deployment, one container, no
/// namespace, and a tag nobody should let reach a cluster.
const DEPLOYMENT: &str = "\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      containers:
        - name: api
          image: ghcr.io/acme/api:latest
";

/// A digest for `repository`, shaped like the ones a registry hands out.
fn digest(repository: &str) -> String {
    format!("{repository}@sha256:{}", "a".repeat(64))
}

/// The harness a scenario runs in.
fn compose(cluster: Arc<FakeCluster>, clock: Arc<FakeClock>) -> Harness {
    Harness::builder()
        .ports(
            Ports::default()
                .with_clock(Arc::clone(&clock) as Arc<dyn Clock>)
                .with_cluster(Arc::clone(&cluster) as Arc<dyn Cluster>),
        )
        .step(K8sRollout)
        .build()
        .expect("the composition is valid")
}

/// One scenario: manifests in a scratch directory, a cluster, a clock, a sink.
struct Case {
    at: PathBuf,
    cluster: Arc<FakeCluster>,
    clock: Arc<FakeClock>,
    sink: Arc<RecordingSink>,
}

impl Case {
    /// A scenario whose scratch directory holds `manifest` as `deployment.yaml`.
    fn new(cluster: FakeCluster, manifest: &str) -> Case {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let at = std::env::temp_dir().join(format!("ks-rollout-{}-{unique}", std::process::id()));
        let _ = std::fs::remove_dir_all(&at);
        std::fs::create_dir_all(&at).expect("the scratch directory can be created");
        std::fs::write(at.join("deployment.yaml"), manifest).expect("the manifest can be written");
        Case {
            at,
            cluster: Arc::new(cluster),
            clock: Arc::new(FakeClock::new()),
            sink: Arc::new(RecordingSink::new()),
        }
    }

    /// The cluster almost every scenario needs: a `Deployment/api` on
    /// `revision`, and the states it settles through.
    fn on_revision(revision: u32, states: impl IntoIterator<Item = Health>) -> FakeCluster {
        FakeCluster::new()
            .with_rollout(
                "Deployment/api",
                Rollout::new(Revision::new(revision), Health::Progressing),
            )
            .with_rollback_revision(Revision::new(revision))
            .with_health_script(states)
    }

    /// The shared inputs: a cluster to deploy to and the manifests to deploy.
    fn inputs(&self) -> Inputs {
        let mut inputs = Inputs::new();
        inputs.insert("to".to_string(), Value::from("prod"));
        inputs.insert("manifests".to_string(), Value::from(self.at.display().to_string()));
        inputs
    }

    /// [`Case::inputs`] with the Deployment's image pinned.
    fn pinned(&self) -> Inputs {
        let mut inputs = self.inputs();
        inputs.insert("image".to_string(), Value::from(digest("ghcr.io/acme/api")));
        inputs
    }

    /// Runs `k8s.rollout` over `inputs`, leaving everything it did in `self`.
    fn drive(&self, inputs: Inputs) -> Result<Outputs, StepError> {
        let harness = compose(Arc::clone(&self.cluster), Arc::clone(&self.clock));
        block_on(run_step(
            &harness,
            "k8s.rollout",
            inputs,
            CancellationToken::new(),
            Arc::clone(&self.sink) as Arc<dyn LogSink>,
            Arc::new(Redactor::new()),
        ))
    }

    /// Every line the run logged: message and fields, so a test can ask what it
    /// said rather than only what it titled it.
    fn said(&self) -> String {
        let record = |record: &LogRecord| {
            let fields = record
                .fields
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join(" ");
            format!("{} {fields}", record.message)
        };
        self.sink.records().iter().map(record).collect::<Vec<_>>().join("\n")
    }

    /// The cluster calls the run made, in order.
    fn calls(&self) -> Vec<String> {
        self.cluster
            .calls()
            .into_iter()
            .map(|call| match call {
                ClusterCall::Apply { names } => format!("apply {names:?}"),
                ClusterCall::Rollout { name } => format!("rollout {name}"),
                ClusterCall::Health { name } => format!("health {name}"),
                ClusterCall::Rollback { name, revision } => {
                    format!("rollback {name} to {revision}")
                }
                other => format!("{other:?}"),
            })
            .collect()
    }
}

impl Drop for Case {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.at);
    }
}

#[test]
fn a_pinned_image_reaches_the_cluster_and_the_reason_is_logged() {
    let cluster = FakeCluster::new()
        .with_health_reports([HealthReport::with_reason(Health::Healthy, "4/4 pods healthy")]);
    let case = Case::new(cluster, DEPLOYMENT);
    let mut inputs = case.pinned();
    inputs.insert("namespace".to_string(), Value::from("prod"));
    let outputs = case.drive(inputs).expect("the rollout settles");
    assert_eq!(outputs.len(), 0, "a rollout owes nothing it did not declare");
    // The previous revision is read before the apply, so a rollback has one.
    assert_eq!(
        case.calls(),
        vec!["rollout Deployment/api", r#"apply ["Deployment/api"]"#, "health Deployment/api"]
    );
    let log = case.said();
    assert!(log.contains("4/4 pods healthy"), "{log}");
    assert!(log.contains(&digest("ghcr.io/acme/api")), "{log}");
    assert!(!log.contains("latest"), "{log}");
}

#[test]
fn a_tag_is_never_applied() {
    let case = Case::new(FakeCluster::new(), DEPLOYMENT);
    let mut inputs = case.inputs();
    inputs.insert("image".to_string(), Value::from("ghcr.io/acme/api:1.2"));

    let refused = case.drive(inputs).expect_err("a tag is not a pin");
    assert!(
        matches!(&refused, StepError::InvalidInput { field, reason }
            if field == "image" && reason.contains("is a tag")),
        "{refused}"
    );
    assert_eq!(case.calls(), Vec::<String>::new(), "nothing reached the cluster");
}

#[test]
fn an_unpinned_sidecar_is_never_applied() {
    let manifest = format!("{DEPLOYMENT}        - name: sidecar\n          image: nginx:1.25\n");
    let case = Case::new(FakeCluster::new(), &manifest);

    let refused = case.drive(case.pinned()).expect_err("a sidecar nobody pinned");
    assert!(
        matches!(&refused, StepError::InvalidInput { reason, .. } if reason.contains("nginx:1.25")),
        "{refused}"
    );
    assert_eq!(case.calls(), Vec::<String>::new(), "nothing reached the cluster");
}

#[test]
fn a_workload_that_fails_is_rolled_back_to_the_revision_the_cluster_had() {
    let cluster = Case::on_revision(3, []).with_health_reports([HealthReport::with_reason(
        Health::Failed,
        "1/4 pods ready (CrashLoopBackOff)",
    )]);
    let case = Case::new(cluster, DEPLOYMENT);

    let failed = case.drive(case.pinned()).expect_err("a crash loop settles failed");
    assert!(
        matches!(&failed, StepError::Failed(message)
            if message.contains("CrashLoopBackOff") && message.contains("revision 3")),
        "{failed}"
    );
    assert_eq!(
        case.calls(),
        vec![
            "rollout Deployment/api",
            r#"apply ["Deployment/api"]"#,
            "health Deployment/api",
            "rollback Deployment/api to 3",
        ],
        "one poll settles it: a failed rollout is not waited out"
    );
    assert_eq!(case.clock.sleeps(), Vec::<Duration>::new(), "no deadline is spent on a failure");
}

#[test]
fn a_rollout_that_never_settles_times_out_and_rolls_back() {
    let case = Case::new(Case::on_revision(4, [Health::Progressing]), DEPLOYMENT);
    let mut inputs = case.pinned();
    inputs
        .insert("wait".to_string(), Value::List(vec![Value::from("healthy"), Value::from("20s")]));

    let failed = case.drive(inputs).expect_err("20s is not long enough");
    assert!(
        matches!(&failed, StepError::Failed(message)
            if message.contains("within 20s")
                && message.contains("rolled back Deployment/api to revision 4")),
        "{failed}"
    );
    assert_eq!(
        case.clock.elapsed_since_start(),
        Duration::from_secs(20),
        "the step waits out the deadline it was given, polling as it goes"
    );
    assert_eq!(case.calls().last().map(String::as_str), Some("rollback Deployment/api to 4"));
}

#[test]
fn rollback_none_leaves_the_rollout_in_place_and_says_so() {
    let case = Case::new(Case::on_revision(2, [Health::Progressing]), DEPLOYMENT);
    let mut inputs = case.pinned();
    inputs.insert("rollback".to_string(), Value::from("none"));
    inputs.insert("wait".to_string(), Value::List(vec![Value::from("healthy"), Value::from("6s")]));

    let failed = case.drive(inputs).expect_err("nothing settles here either");
    assert!(
        matches!(&failed, StepError::Failed(m) if m.contains("rollback is disabled")),
        "{failed}"
    );
    assert_eq!(
        case.calls().last().map(String::as_str),
        Some("health Deployment/api"),
        "a disabled rollback makes no rollback call"
    );
    assert!(case.said().contains("rollback is disabled"));
}

#[test]
fn a_first_deploy_has_nothing_to_roll_back_to() {
    let case = Case::new(FakeCluster::new().with_health_script([Health::Failed]), DEPLOYMENT);

    let failed = case.drive(case.pinned()).expect_err("the first deploy still fails");
    assert!(
        matches!(&failed, StepError::Failed(m) if m.contains("no earlier revision")),
        "{failed}"
    );
    assert_eq!(
        case.calls(),
        vec!["rollout Deployment/api", r#"apply ["Deployment/api"]"#, "health Deployment/api"],
        "a workload the cluster never had is not rolled back to nothing"
    );
}

/// An apply that fails part way has still changed something: the workloads that
/// had a previous revision are put back before the failure is reported.
#[test]
fn an_apply_that_fails_rolls_back_what_it_had_already_changed() {
    let cluster =
        Case::on_revision(7, [Health::Healthy]).with_manifest_error(ClusterError::Apply {
            message: "admission webhook denied it".to_string(),
        });
    let case = Case::new(cluster, DEPLOYMENT);

    let refused = case.drive(case.pinned()).expect_err("the API server said no");
    assert!(
        matches!(&refused, StepError::Port { port: Port::Cluster, message }
            if message.contains("admission webhook denied it")
                && message.contains("Deployment/api could not be rolled back to 7")),
        "the rollback that was attempted, and what became of it, is in the error: {refused}"
    );
    assert_eq!(
        case.calls(),
        vec![
            "rollout Deployment/api",
            r#"apply ["Deployment/api"]"#,
            "rollback Deployment/api to 7"
        ]
    );
}

/// `verify:` is an input, so it is defaulted like the rest: a rollout that
/// names no identity verifies nothing, and needs neither a registry nor a
/// signer — which is what lets a composition without either still build
/// ([#113](https://github.com/Keep-Shipping/harness/issues/113)). The refusals
/// themselves live in `deploy_verify.rs`, against a real digest.
#[test]
fn an_empty_verify_is_the_default_and_verifies_nothing() {
    let schema = K8sRollout.schema();
    let verify = schema.inputs.iter().find(|field| field.name == "verify");
    assert_eq!(
        verify.and_then(|field| field.default.clone()),
        Some(Value::from("")),
        "empty means no verification"
    );
    assert_eq!(K8sRollout.optional(), [Port::Registry, Port::Signer], "the ports are optional");
    assert!(
        !K8sRollout.requires().contains(&Port::Signer),
        "a deploy is not blocked by having no signer"
    );
}
