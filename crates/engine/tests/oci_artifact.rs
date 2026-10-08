//! End to end: `oci.artifact` run through [`run_step`] over `ks-testing` fakes — a Helm chart
//! pushed in the Helm OCI layout and then installed by digest through the `Cluster` port, an
//! SBOM attached to an image digest and found again by `referrers`, a signed artifact whose
//! signature is stored beside it, and the inputs the step refuses.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ks_core::harness::Harness;
use ks_core::ports::cluster::{Chart, ChartUpgrade, Cluster};
use ks_core::ports::script_host::{Value, ValueType};
use ks_core::ports::secrets::Redactor;
use ks_core::ports::supply_chain::{
    Digest, ImageRef, OciLayoutContents, Registry, SignPayload, Signature, Signer, SignerIdentity,
};
use ks_core::step::{CancellationToken, Inputs, LogRecord, LogSink, Outputs, Ports, TypeDef};
use ks_engine::oci_artifact::OciArtifactStep;
use ks_engine::run::run_step;
use ks_testing::cluster::{ClusterCall, FakeCluster};
use ks_testing::supply_chain::{FakeRegistry, FakeSigner};
use ks_testing::{block_on, clock::FakeClock};

/// The repository charts and artifacts are pushed to.
const REPOSITORY: &str = "registry.example/charts/app";

/// A temp directory that deletes itself on drop, so no test can forget.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> TempDir {
        let path = std::env::temp_dir()
            .join(format!("keepshipping-oci-artifact-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("make temp dir");
        TempDir(path)
    }

    /// Writes `contents` as `name` and hands back the path to pass as a `files` entry.
    fn file(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, contents).expect("the artifact file is written");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A [`LogSink`] that keeps every record, for assertions.
#[derive(Default)]
struct RecordingSink {
    records: Mutex<Vec<LogRecord>>,
}

impl RecordingSink {
    fn records(&self) -> Vec<LogRecord> {
        self.records.lock().expect("recording sink").clone()
    }
}

impl LogSink for RecordingSink {
    fn record(&self, record: LogRecord) {
        self.records.lock().expect("recording sink").push(record);
    }
}

/// The composition: a fake registry, a fake signer and a fake cluster, plus the step itself.
struct Fixture {
    harness: Harness,
    registry: Arc<FakeRegistry>,
    cluster: Arc<FakeCluster>,
    signer: Arc<FakeSigner>,
    sink: Arc<RecordingSink>,
}

impl Fixture {
    /// Runs `oci.artifact` with `inputs`.
    fn push(&self, inputs: Inputs) -> Result<Outputs, ks_core::step::StepError> {
        block_on(run_step(
            &self.harness,
            "oci.artifact",
            inputs,
            CancellationToken::new(),
            Arc::clone(&self.sink) as Arc<dyn LogSink>,
            Arc::new(Redactor::new()),
        ))
    }

    /// Runs `oci.artifact` with `inputs`, expecting success.
    fn pushed(&self, inputs: Inputs) -> Outputs {
        self.push(inputs).expect("the artifact pushes")
    }

    /// The manifest bytes the registry stored under `digest`.
    fn manifest(&self, digest: &Digest) -> String {
        let bytes = block_on(self.registry.pull(REPOSITORY, digest)).expect("the manifest pulls");
        String::from_utf8(bytes).expect("a manifest is utf-8")
    }
}

fn fixture() -> Fixture {
    let registry = Arc::new(FakeRegistry::new());
    let cluster = Arc::new(FakeCluster::new());
    let signer = Arc::new(FakeSigner::with_key("test-key"));
    let sink = Arc::new(RecordingSink::default());
    let ports = Ports::default()
        .with_clock(Arc::new(FakeClock::new()))
        .with_registry(Arc::clone(&registry) as Arc<dyn Registry>)
        .with_signer(Arc::clone(&signer) as Arc<dyn Signer>)
        .with_cluster(Arc::clone(&cluster) as Arc<dyn Cluster>);
    Fixture { harness: harness(ports), registry, cluster, signer, sink }
}

/// A harness with the step and the named types its schema uses.
fn harness(ports: Ports) -> Harness {
    let string_type =
        |name: &'static str, doc: &'static str| TypeDef { name, base: ValueType::String, doc };
    Harness::builder()
        .ports(ports)
        .type_def(string_type("oci.Digest", "an OCI content digest (`sha256:…`)"))
        .type_def(string_type("oci.Tag", "a mutable OCI tag (`repository:tag`)"))
        .type_def(string_type("oci.Ref", "a pinned OCI reference (`repository@digest`)"))
        .step_arc(Arc::new(OciArtifactStep))
        .build()
        .expect("the fixture composition is valid")
}

/// A `files` list of one path.
fn files(path: &Path) -> Value {
    Value::List(vec![Value::from(path.to_string_lossy().into_owned())])
}

/// The inputs for a Helm chart at `path`, pushed to `tag` in [`REPOSITORY`].
fn chart_inputs(path: &Path, tag: &str) -> Inputs {
    let mut inputs = Inputs::new();
    inputs.insert("files".to_string(), files(path));
    inputs.insert("type".to_string(), Value::from("helm"));
    inputs.insert("push".to_string(), Value::from(format!("{REPOSITORY}:{tag}")));
    inputs
}

/// One string output of a run.
fn output(outputs: &Outputs, name: &str) -> String {
    match outputs.get(name) {
        Some(Value::String(text)) => text.clone(),
        other => panic!("the step returns a {name}, got {other:?}"),
    }
}

/// An image digest already in [`REPOSITORY`] — the thing an SBOM describes.
/// Referrers are per-repository, so the artifact has to land beside the image.
fn pushed_image(registry: &FakeRegistry) -> Digest {
    block_on(registry.push_layout(
        REPOSITORY,
        &OciLayoutContents {
            media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            manifest: b"an image manifest".to_vec(),
            blobs: vec![b"a layer".to_vec()],
        },
    ))
    .expect("the image pushes")
    .digest
}

#[test]
fn a_helm_chart_pushes_in_the_helm_oci_layout_and_the_ref_is_what_an_install_takes() {
    let scratch = TempDir::new("helm");
    let chart = scratch.file("app-1.0.0.tgz", b"a gzipped chart tarball");
    let f = fixture();

    let outputs = f.pushed(chart_inputs(&chart, "1.0.0"));

    let digest = output(&outputs, "digest");
    let reference = output(&outputs, "ref");
    assert_eq!(
        reference,
        format!("{REPOSITORY}@{digest}"),
        "the ref is repo@digest, never the tag"
    );

    // The manifest is a Helm chart's: Helm's config media type as the
    // artifactType, Helm's chart-content media type as the layer's.
    let digest = Digest::parse(&digest).expect("the digest is canonical");
    let manifest = f.manifest(&digest);
    assert!(
        manifest.contains(r#""artifactType":"application/vnd.cncf.helm.config.v1+json""#),
        "{manifest}"
    );
    assert!(
        manifest.contains(r#""io.keepshipping.artifact.layerMediaType":"application/vnd.cncf.helm.chart.content.v1.tar+gzip""#),
        "{manifest}"
    );
    assert!(
        manifest.contains(r#""org.opencontainers.image.title":"app-1.0.0.tgz""#),
        "a single-file artifact is named by its file: {manifest}"
    );

    // The chart's bytes are in the registry, the tag points at the manifest,
    // and resolving the tag gives the same digest — the registry's own answer.
    assert!(
        f.registry.stored_digests(REPOSITORY).contains(&digest),
        "the chart landed in the repository"
    );
    let tagged = block_on(
        f.registry.resolve(&ImageRef::parse(&format!("{REPOSITORY}:1.0.0")).expect("a tag")),
    )
    .expect("the tag resolves");
    assert_eq!(tagged, digest);

    // Installing: there is no `k8s.rollout` step yet (#74), so this calls the
    // Cluster port directly to show what such a step would pass — the `ref` this
    // step returned, which carries the digest, not the mutable tag.
    let release = ImageRef::parse(&reference).expect("the ref parses");
    assert_eq!(release.digest(), Some(&digest), "a release takes a pinned digest");
    let request = ChartUpgrade::new("app", Chart::oci(release.clone()).expect("a pinned chart"))
        .expect("a named release");
    let _rollout = block_on(f.cluster.upgrade(&request)).expect("the chart installs");
    assert_eq!(
        f.cluster.calls(),
        vec![ClusterCall::Upgrade { request: request.clone() }],
        "the install names the repo@digest, through the Cluster port"
    );
    assert_eq!(request.chart().reference(), Some(&release), "the chart is the pinned ref");

    let record = f
        .sink
        .records()
        .into_iter()
        .find(|record| record.message == "pushed artifact")
        .expect("the step logged the push");
    assert_eq!(record.step, "oci.artifact");
    assert!(record.fields.contains(&("ref".to_string(), reference.clone())), "{:?}", record.fields);
}

#[test]
fn an_artifact_with_a_subject_is_listed_by_referrers() {
    let scratch = TempDir::new("sbom");
    let sbom = scratch.file("api.spdx.json", br#"{"spdxVersion":"SPDX-2.3"}"#);
    let f = fixture();

    // The image the SBOM describes, pushed to the same repository — referrers
    // are looked up per repository.
    let image = pushed_image(&f.registry);

    let mut inputs = Inputs::new();
    inputs.insert("files".to_string(), files(&sbom));
    inputs.insert("type".to_string(), Value::from("spdx"));
    inputs.insert("push".to_string(), Value::from(format!("{REPOSITORY}:sbom-1")));
    inputs.insert("subject".to_string(), Value::from(image.to_string()));
    let outputs = f.pushed(inputs);

    let referrers = block_on(f.registry.referrers(REPOSITORY, &image)).expect("referrers answer");
    let artifact = referrers
        .iter()
        .find(|descriptor| descriptor.digest.to_string() == output(&outputs, "digest"))
        .expect("the SBOM is a referrer of the image it describes");
    assert_eq!(artifact.media_type, "application/vnd.oci.image.manifest.v1+json");

    // The manifest really carries the subject link — that is what makes it a
    // referrer rather than an unrelated blob that happens to be nearby.
    let digest = Digest::parse(&output(&outputs, "digest")).expect("the digest is canonical");
    let manifest = block_on(f.registry.pull(REPOSITORY, &digest)).expect("the SBOM pulls");
    let manifest = String::from_utf8(manifest).expect("a manifest is utf-8");
    assert!(manifest.contains(&format!(r#""digest":"{image}""#)), "{manifest}");
    assert!(manifest.contains(r#""artifactType":"application/spdx+json""#), "{manifest}");
}

#[test]
fn sign_true_stores_a_verifiable_signature_as_a_referrer() {
    let scratch = TempDir::new("sign");
    let bundle = scratch.file("policy.rego", b"package policy\n");
    let f = fixture();

    let mut inputs = Inputs::new();
    inputs.insert("files".to_string(), files(&bundle));
    inputs.insert("type".to_string(), Value::from("application/vnd.keepshipping.policy"));
    inputs.insert("push".to_string(), Value::from(format!("{REPOSITORY}:policy-1")));
    inputs.insert("sign".to_string(), Value::from(true));
    let outputs = f.pushed(inputs);

    // The signature is not just computed and dropped: it is stored beside the
    // artifact, as a referrer of it, so a verifier finds it the same way it
    // finds an SBOM.
    let digest = Digest::parse(&output(&outputs, "digest")).expect("the digest is canonical");
    let referrers = block_on(f.registry.referrers(REPOSITORY, &digest)).expect("referrers answer");
    let stored = referrers
        .iter()
        .find(|descriptor| {
            descriptor.annotations.get("io.keepshipping.signature.payload")
                == Some(&digest.to_string())
        })
        .expect("the signature is a referrer of the artifact it signs");
    // Its layer is the signature bytes themselves.
    let manifest = f.manifest(&stored.digest);
    let layers = manifest
        .split_once(r#""layers":[{"#)
        .and_then(|(_, layers)| layers.split_once(r#""digest":"sha256:"#))
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(digest, _)| digest)
        .expect("the signature manifest has one layer naming a digest");
    let bytes = block_on(
        f.registry.pull(REPOSITORY, &Digest::parse(&format!("sha256:{layers}")).expect("a digest")),
    )
    .expect("the signature layer pulls");

    // Rebuilt from the annotations the descriptor carries, the stored bytes
    // verify against the signer the step was given — and against nothing else.
    let key_id = stored
        .annotations
        .get("io.keepshipping.signature.keyId")
        .expect("the signature names the key that made it")
        .clone();
    let signature = Signature { bytes, identity: SignerIdentity::Key { key_id } };
    assert_eq!(
        block_on(f.signer.verify(&SignPayload::Digest(digest.clone()), &signature))
            .expect("the stored signature verifies"),
        f.signer.identity()
    );
    let other = SignPayload::Digest(
        Digest::parse(&format!("sha256:{}", "0".repeat(64))).expect("a digest"),
    );
    assert!(
        block_on(f.signer.verify(&other, &signature)).is_err(),
        "the stored signature does not verify over a different digest"
    );
}

#[test]
fn sign_without_a_signer_is_refused_rather_than_pushed_unsigned() {
    let scratch = TempDir::new("nosigner");
    let bundle = scratch.file("policy.rego", b"package policy\n");
    let registry = Arc::new(FakeRegistry::new());
    let ports = Ports::default()
        .with_clock(Arc::new(FakeClock::new()))
        .with_registry(Arc::clone(&registry) as Arc<dyn Registry>);

    let mut inputs = Inputs::new();
    inputs.insert("files".to_string(), files(&bundle));
    inputs.insert("type".to_string(), Value::from("application/vnd.keepshipping.policy"));
    inputs.insert("push".to_string(), Value::from(format!("{REPOSITORY}:policy-1")));
    inputs.insert("sign".to_string(), Value::from(true));
    let error = block_on(run_step(
        &harness(ports),
        "oci.artifact",
        inputs,
        CancellationToken::new(),
        Arc::new(RecordingSink::default()) as Arc<dyn LogSink>,
        Arc::new(Redactor::new()),
    ))
    .expect_err("signing needs a signer");

    assert!(error.to_string().contains("Signer"), "the error names the missing port: {error}");
    assert!(
        registry.stored_digests(REPOSITORY).is_empty(),
        "a run that cannot sign refuses before it publishes anything"
    );
}

#[test]
fn bad_inputs_are_refused_before_anything_is_pushed() {
    let scratch = TempDir::new("bad");
    let present = scratch.file("chart.tgz", b"a chart");
    let missing = scratch.0.join("gone.tgz");

    // A `push` that names a digest rather than a tag.
    let f = fixture();
    let mut inputs = chart_inputs(&present, "1.0.0");
    inputs
        .insert("push".to_string(), Value::from(format!("{REPOSITORY}@sha256:{}", "a".repeat(64))));
    let error = f.push(inputs).expect_err("a digest is not a tag");
    assert!(matches!(
        error,
        ks_core::step::StepError::InvalidInput { field, .. } if field == "push"
    ));
    assert!(f.registry.stored_digests(REPOSITORY).is_empty(), "nothing was pushed");

    // A `push` with no tag of its own — `ImageRef::parse` would call it
    // `latest`, publishing under a name the run never chose.
    let f = fixture();
    let mut inputs = chart_inputs(&present, "1.0.0");
    inputs.insert("push".to_string(), Value::from(REPOSITORY));
    let error = f.push(inputs).expect_err("a bare repository is not a tag");
    assert!(matches!(
        error,
        ks_core::step::StepError::InvalidInput { field, .. } if field == "push"
    ));
    assert!(f.registry.stored_digests(REPOSITORY).is_empty(), "nothing was pushed");

    // An unknown artifact type, and one that is not a media type at all.
    let f = fixture();
    let mut inputs = chart_inputs(&present, "1.0.0");
    inputs.insert("type".to_string(), Value::from("chart"));
    let error = f.push(inputs).expect_err("`chart` is not a type the step knows");
    assert!(matches!(
        error,
        ks_core::step::StepError::InvalidInput { field, .. } if field == "type"
    ));

    // A file that is not there.
    let f = fixture();
    let error = f.push(chart_inputs(&missing, "1.0.0")).expect_err("the chart is missing");
    assert!(error.to_string().contains("cannot read file"), "the error says which file: {error}");
    assert!(f.registry.stored_digests(REPOSITORY).is_empty(), "nothing was pushed");

    // `files` is required, and the harness says so before the step reads a byte.
    let f = fixture();
    let mut inputs = Inputs::new();
    inputs.insert("type".to_string(), Value::from("helm"));
    inputs.insert("push".to_string(), Value::from(format!("{REPOSITORY}:1.0.0")));
    let error = f.push(inputs).expect_err("files is required");
    assert!(matches!(
        error,
        ks_core::step::StepError::InvalidInput { field, .. } if field == "files"
    ));
}

#[test]
fn the_step_is_registered_as_a_builtin_with_the_schema_it_declares() {
    let steps = ks_engine::steps::builtin_steps();
    let artifact = steps
        .iter()
        .find(|step| step.name() == "oci.artifact")
        .expect("oci.artifact is a built-in step");

    let schema = artifact.schema();
    let inputs: Vec<&str> = schema.inputs.iter().map(|field| field.name).collect();
    assert_eq!(inputs, vec!["files", "type", "push", "subject", "sign"]);
    let outputs: Vec<&str> = schema.outputs.iter().map(|field| field.name).collect();
    assert_eq!(outputs, vec!["digest", "ref"]);
    assert_eq!(artifact.requires(), &[ks_core::step::Port::Registry]);
    assert_eq!(artifact.optional(), &[ks_core::step::Port::Signer]);
}
