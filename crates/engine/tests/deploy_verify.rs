//! What a deploy owes before it ships an image nobody signed
//! ([#113](https://github.com/Keep-Shipping/harness/issues/113)).
//!
//! The contract is one sentence: **a deploy ships a digest only when the
//! identity its workflow named signed that digest.** Everything here is that
//! sentence in both directions — a keyless identity the workflow named accepts
//! its own workflow's signature, and the same deploy refuses a signature made by
//! a *different* workflow, without ever having reached the cluster.
//!
//! Two things are proved beyond the refusals, because either could be quietly
//! wrong: the refusal lands **before** the apply (a check that ran after the
//! cluster was touched would catch the wrong signature far too late), and a run
//! with **no `verify:`** is untouched by any of this — it needs neither a
//! registry nor a signer, which is what makes those ports optional rather than
//! required.
//!
//! [`FakeSigner`]'s MAC is not real cryptography — it is
//! `sha256(identity bytes ‖ payload bytes)`, a deterministic stand-in so a test
//! can assert on identity binding. The contract under test is the one a real
//! adapter has to meet: a signature verifies as the identity it was made as,
//! and nothing else does.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use ks_core::harness::Harness;
use ks_core::ports::clock::Clock;
use ks_core::ports::cluster::{Cluster, Revision, Rollout};
use ks_core::ports::health::{Health, HealthReport};
use ks_core::ports::remote_shell::{Host, HostKey, RemoteShell};
use ks_core::ports::script_host::Value;
use ks_core::ports::secrets::Redactor;
use ks_core::ports::supply_chain::{Digest, OciLayoutContents, Registry, Signer};
use ks_core::step::{
    CancellationToken, Inputs, LogRecord, LogSink, Outputs, Port, Ports, StepError,
};
use ks_engine::k8s_rollout::K8sRollout;
use ks_engine::run::run_step;
use ks_engine::signing::sign_and_attach;
use ks_engine::vm_deploy::VmDeploy;
use ks_testing::block_on;
use ks_testing::clock::FakeClock;
use ks_testing::cluster::{ClusterCall, FakeCluster};
use ks_testing::remote_shell::FakeRemoteShell;
use ks_testing::step::RecordingSink;
use ks_testing::supply_chain::{FakeRegistry, FakeSigner};

/// The repository the rollout's manifests run, and the artifact `vm.deploy`
/// ships — one image, so one digest has to satisfy both steps.
const REPOSITORY: &str = "ghcr.io/acme/api";

/// A real image manifest, so the digest under test is a real SHA-256.
const MANIFEST: &[u8] = b"{\"schemaVersion\":2,\"config\":{}}";

/// The keyless issuer CI hands a workflow's identity out under.
const ISSUER: &str = "https://token.actions.githubusercontent.com";

/// This repository's own release workflow, as a keyless identity names it: the
/// subject is the workflow file, the issuer is who certified it.
const RELEASE_WORKFLOW: &str =
    "https://github.com/acme/api/.github/workflows/release.yml@refs/heads/main";

/// A *different* workflow on the same repository — same issuer, other file. A
/// deploy that accepted this one would accept anything the repository's CI ever
/// signs, which is not what `verify:` asked for.
const OTHER_WORKFLOW: &str =
    "https://github.com/acme/api/.github/workflows/nightly.yml@refs/heads/main";

/// The identity of [`RELEASE_WORKFLOW`], as a `verify:` value spells it.
fn verify_release() -> String {
    format!("signed-by {RELEASE_WORKFLOW} from {ISSUER}")
}

/// The manifest the rollout applies: one Deployment, one container, one tag
/// nobody should let reach a cluster.
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

/// The host the fleet deploy reaches.
const HOST: &str = "a.example";

/// The key `HOST` presents, as a pinned `host_key` input spells it.
const HOST_KEY: &str = "SHA256:a";

/// The one host the fleet is, pinned the way an operator pins it.
fn host() -> Host {
    Host::new(
        HOST,
        22,
        "deploy",
        HostKey::new("ssh-ed25519", HOST_KEY).expect("a well-formed host key"),
    )
    .expect("a well-formed host")
}

/// One scenario: a pushed image, a cluster, a shell, and a sink. Every test
/// signs the image itself, so what distinguishes them is who signed it and what
/// the workflow claimed.
struct Case {
    at: PathBuf,
    registry: Arc<FakeRegistry>,
    digest: Digest,
    cluster: Arc<FakeCluster>,
    shell: Arc<FakeRemoteShell>,
    sink: Arc<RecordingSink>,
}

impl Case {
    /// A scenario with the image pushed and nothing signed yet.
    fn new() -> Case {
        let registry = Arc::new(FakeRegistry::new());
        let digest = block_on(registry.push_layout(
            REPOSITORY,
            &OciLayoutContents {
                media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
                manifest: MANIFEST.to_vec(),
                blobs: vec![b"layer".to_vec()],
            },
        ))
        .expect("the image push succeeds")
        .digest;

        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let at = std::env::temp_dir().join(format!("ks-verify-{}-{unique}", std::process::id()));
        let _ = std::fs::remove_dir_all(&at);
        std::fs::create_dir_all(&at).expect("the scratch directory can be created");
        std::fs::write(at.join("deployment.yaml"), DEPLOYMENT)
            .expect("the manifest can be written");

        Case {
            at,
            registry,
            digest,
            cluster: Arc::new(
                FakeCluster::new()
                    .with_rollout(
                        "Deployment/api",
                        Rollout::new(Revision::new(1), Health::Progressing),
                    )
                    .with_health_reports([HealthReport::new(Health::Healthy)]),
            ),
            // The configured host, so the fleet deploy reaches it directly rather than
            // through a `connect` the fake would have to resolve to a peer.
            shell: Arc::new(FakeRemoteShell::new().with_host(host())),
            sink: Arc::new(RecordingSink::new()),
        }
    }

    /// Signs the pushed image as `signer`, and hands back the signer as the
    /// port takes it — one identity signs and verifies, which is the normal case
    /// (one key, or one CI workflow).
    fn sign(&self, signer: FakeSigner) -> Arc<dyn Signer> {
        block_on(sign_and_attach(&signer, &*self.registry, REPOSITORY, &self.digest, false))
            .expect("the signature attaches");
        Arc::new(signer)
    }

    /// `k8s.rollout` with the supply-chain ports `sign`ed in.
    fn rollout(&self, signer: Option<Arc<dyn Signer>>) -> Harness {
        let mut ports = Ports::default()
            .with_clock(Arc::new(FakeClock::new()) as Arc<dyn Clock>)
            .with_cluster(Arc::clone(&self.cluster) as Arc<dyn Cluster>);
        if let Some(signer) = signer {
            ports = ports
                .with_registry(Arc::clone(&self.registry) as Arc<dyn Registry>)
                .with_signer(signer);
        }
        Harness::builder().ports(ports).step(K8sRollout).build().expect("the composition is valid")
    }

    /// `vm.deploy` with the supply-chain ports `sign`ed in.
    fn fleet(&self, signer: Arc<dyn Signer>) -> Harness {
        ks_engine::steps::builtin_types()
            .into_iter()
            .fold(
                Harness::builder().ports(
                    Ports::default()
                        .with_clock(Arc::new(FakeClock::new()) as Arc<dyn Clock>)
                        .with_remote_shell(Arc::clone(&self.shell) as Arc<dyn RemoteShell>)
                        .with_registry(Arc::clone(&self.registry) as Arc<dyn Registry>)
                        .with_signer(signer),
                ),
                |builder, def| builder.type_def(def),
            )
            .step(VmDeploy)
            .build()
            .expect("the composition is valid")
    }

    /// The rollout's inputs, pinned to this scenario's digest.
    fn rollout_inputs(&self) -> Inputs {
        let mut inputs = Inputs::new();
        inputs.insert("to".to_string(), Value::from("prod"));
        inputs.insert("manifests".to_string(), Value::from(self.at.display().to_string()));
        inputs.insert("image".to_string(), Value::from(self.reference()));
        inputs
    }

    /// `vm.deploy`'s inputs: one pinned host and the artifact it ships.
    fn deploy_inputs(&self) -> Inputs {
        let mut inputs = Inputs::new();
        inputs.insert(
            "hosts".to_string(),
            Value::List(vec![Value::Map(BTreeMap::from([
                ("address".to_string(), Value::from(HOST)),
                ("host_key".to_string(), Value::from(HOST_KEY)),
            ]))]),
        );
        inputs.insert("image".to_string(), Value::from(self.reference()));
        inputs
    }

    /// The digest-pinned reference this scenario's signatures are attached to.
    fn reference(&self) -> String {
        format!("{REPOSITORY}@{}", self.digest)
    }

    /// Every line the run logged.
    fn said(&self) -> String {
        let record = |record: &LogRecord| {
            let fields = record
                .fields
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>();
            format!("{} {}", record.message, fields.join(" "))
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
                other => format!("{other:?}"),
            })
            .collect()
    }

    /// Whether the manifests ever reached the API server.
    fn applied(&self) -> bool {
        self.calls().iter().any(|call| call.starts_with("apply"))
    }
}

impl Drop for Case {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.at);
    }
}

/// Runs `kind` over `inputs` in `harness`, keeping whatever it said.
fn drive(
    harness: &Harness,
    kind: &'static str,
    inputs: Inputs,
    sink: Arc<RecordingSink>,
) -> Result<Outputs, StepError> {
    block_on(run_step(
        harness,
        kind,
        inputs,
        CancellationToken::new(),
        sink as Arc<dyn LogSink>,
        Arc::new(Redactor::new()),
    ))
}

/// The workflow named the identity that signed, so the rollout ships.
#[test]
fn a_rollout_ships_an_image_the_named_workflow_signed() {
    let case = Case::new();
    let signer = case.sign(FakeSigner::keyless(ISSUER, RELEASE_WORKFLOW));
    let harness = case.rollout(Some(signer));
    let mut inputs = case.rollout_inputs();
    inputs.insert("verify".to_string(), Value::from(verify_release()));

    drive(&harness, "k8s.rollout", inputs, Arc::clone(&case.sink)).expect("the rollout settles");

    assert!(case.applied(), "the rollout went through: {:?}", case.calls());
    let log = case.said();
    assert!(log.contains("is signed by"), "{log}");
    assert!(log.contains(RELEASE_WORKFLOW), "{log}");
}

/// **The acceptance criterion**: a digest signed by a different workflow is
/// refused, the error names both identities, and the cluster was never applied
/// to — the refusal is worth nothing if the manifests already landed.
#[test]
fn a_rollout_refuses_a_digest_signed_by_a_different_workflow() {
    let case = Case::new();
    // Signed on CI, but by `nightly.yml`, not by the workflow `verify:` names.
    let signer = case.sign(FakeSigner::keyless(ISSUER, OTHER_WORKFLOW));
    let harness = case.rollout(Some(signer));
    let mut inputs = case.rollout_inputs();
    inputs.insert("verify".to_string(), Value::from(verify_release()));

    let refused =
        drive(&harness, "k8s.rollout", inputs, Arc::clone(&case.sink)).expect_err("wrong workflow");

    let message = refused.to_string();
    assert!(message.contains(OTHER_WORKFLOW), "the signer is named: {message}");
    assert!(message.contains(RELEASE_WORKFLOW), "the expected identity is named: {message}");
    assert_eq!(
        case.calls(),
        Vec::<String>::new(),
        "nothing reached the cluster: a refusal after the apply would be too late"
    );
}

/// Nothing signed the image at all, so there is nothing to check against.
#[test]
fn a_rollout_refuses_an_unsigned_image() {
    let case = Case::new();
    let harness = case.rollout(Some(Arc::new(FakeSigner::keyless(ISSUER, RELEASE_WORKFLOW))));
    let mut inputs = case.rollout_inputs();
    inputs.insert("verify".to_string(), Value::from(verify_release()));

    let refused =
        drive(&harness, "k8s.rollout", inputs, Arc::clone(&case.sink)).expect_err("unsigned");
    assert!(refused.to_string().contains("is unsigned"), "{refused}");
    assert_eq!(case.calls(), Vec::<String>::new(), "nothing reached the cluster");
}

/// No `verify:` at all: the ports really are optional, and a rollout that asks
/// for nothing behaves exactly as it did before this step had the input.
#[test]
fn a_rollout_with_no_verify_needs_no_signer() {
    let case = Case::new();
    let harness = case.rollout(None);

    drive(&harness, "k8s.rollout", case.rollout_inputs(), Arc::clone(&case.sink))
        .expect("an unsigned image is nobody's business unless the workflow says so");
    assert!(case.applied(), "the rollout went through: {:?}", case.calls());
    assert!(!case.said().contains("is signed by"), "nothing was verified");
}

/// A matcher the grammar does not cover is the workflow's mistake, and it is
/// named as such rather than reaching the registry.
#[test]
fn a_verify_value_that_does_not_parse_is_refused_as_an_input() {
    let case = Case::new();
    let harness = case.rollout(Some(Arc::new(FakeSigner::keyless(ISSUER, RELEASE_WORKFLOW))));

    for asked in ["nonsense", "signed-by", "signed-by key:"] {
        let mut inputs = case.rollout_inputs();
        inputs.insert("verify".to_string(), Value::from(asked));
        let refused = drive(&harness, "k8s.rollout", inputs, Arc::clone(&case.sink))
            .expect_err("half an identity is not an identity");
        assert!(
            matches!(&refused, StepError::InvalidInput { field, .. } if field == "verify"),
            "`{asked}` is the input that is wrong: {refused}"
        );
    }
    assert_eq!(case.calls(), Vec::<String>::new(), "nothing reached the cluster");
}

/// A named key works as well as a keyless identity: `key:alice` against an
/// image signed by somebody else's key is the same refusal.
#[test]
fn a_rollout_refuses_a_digest_signed_by_another_key() {
    let case = Case::new();
    let signer = case.sign(FakeSigner::with_key("bob"));
    let harness = case.rollout(Some(signer));
    let mut inputs = case.rollout_inputs();
    inputs.insert("verify".to_string(), Value::from("signed-by key:alice"));

    let refused = drive(&harness, "k8s.rollout", inputs, Arc::clone(&case.sink))
        .expect_err("bob is not alice");
    let message = refused.to_string();
    assert!(message.contains("key:bob") && message.contains("key:alice"), "{message}");
    assert_eq!(case.calls(), Vec::<String>::new(), "nothing reached the cluster");
}

/// `vm.deploy` ships the artifact the named identity signed, the same way
/// `k8s.rollout` does — the shared helper is one rule, not two.
#[test]
fn a_fleet_deploy_ships_an_image_the_named_workflow_signed() {
    let case = Case::new();
    let signer = case.sign(FakeSigner::keyless(ISSUER, RELEASE_WORKFLOW));
    let harness = case.fleet(signer);
    let mut inputs = case.deploy_inputs();
    inputs.insert("verify".to_string(), Value::from(verify_release()));

    drive(&harness, "vm.deploy", inputs, Arc::clone(&case.sink)).expect("the deploy runs");
    assert!(case.said().contains("is signed by"), "{}", case.said());
}

/// And the refusal, before a host is reached: an artifact signed by another
/// workflow is not the one this deploy was asked to ship.
#[test]
fn a_fleet_deploy_refuses_a_digest_signed_by_a_different_workflow() {
    let case = Case::new();
    let signer = case.sign(FakeSigner::keyless(ISSUER, OTHER_WORKFLOW));
    let harness = case.fleet(signer);
    let mut inputs = case.deploy_inputs();
    inputs.insert("verify".to_string(), Value::from(verify_release()));

    let refused =
        drive(&harness, "vm.deploy", inputs, Arc::clone(&case.sink)).expect_err("wrong workflow");
    let message = refused.to_string();
    assert!(message.contains(OTHER_WORKFLOW), "the signer is named: {message}");
    assert!(message.contains(RELEASE_WORKFLOW), "the expected identity is named: {message}");
    assert!(case.shell.calls().is_empty(), "no host was reached: {:?}", case.shell.calls());
}

/// A `verify:` with no signer behind it is a failed run, not a skipped check:
/// the ports are optional so a composition *builds*, never so a `verify:` can go
/// unverified.
#[test]
fn a_verify_with_no_registry_in_the_composition_is_refused() {
    let case = Case::new();
    let harness = case.rollout(None);
    let mut inputs = case.rollout_inputs();
    inputs.insert("verify".to_string(), Value::from("signed-by key:alice"));

    let refused = drive(&harness, "k8s.rollout", inputs, Arc::clone(&case.sink))
        .expect_err("there is nobody to read the signature with");
    assert!(
        matches!(&refused, StepError::Port { port, message } if *port == Port::Registry
            && message.contains("no registry was provided")),
        "{refused}"
    );
    assert_eq!(case.calls(), Vec::<String>::new(), "nothing reached the cluster");
}
