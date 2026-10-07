//! The built-in `oci.image` step over the `ks-testing` fakes: the outputs it owes, the digest it
//! confirms with the registry, the secrets it never leaks, an index for a multi-platform build,
//! what signing needs, and a cache that follows the context and nothing else.
//!
//! The checker side — that `image: build.tag` is still refused for an `oci.Digest` input — is
//! covered by `crates/core/tests/check.rs::type_mismatch_hints_the_output_with_the_wanted_type`
//! and its snapshot. What is proved here is that the step and the catalog agree, so the two
//! cannot drift.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use ks_core::Catalog;
use ks_core::harness::{Harness, HarnessBuilder};
use ks_core::ports::script_host::Value;
use ks_core::ports::secrets::Redactor;
use ks_core::ports::supply_chain::{
    BuildCache, Digest, ImageBuilder, ImageRef, OciLayoutContents, Reference, Registry, Signer,
};
use ks_core::step::{
    CacheInput, Caching, CancellationToken, Inputs, LogSink, Outputs, Port, Ports, StepError,
    StepKind,
};
use ks_engine::cache::{CacheOutcome, DirCache, cache_key, run_step_cached};
use ks_engine::oci_image::{NAME, OciImage};
use ks_engine::run::run_step;
use ks_testing::block_on;
use ks_testing::clock::FakeClock;
use ks_testing::step::{RecordingSink, StepCase, step_conformance};
use ks_testing::supply_chain::{FakeImageBuilder, FakeRegistry, FakeSigner};

/// The repository the fixture pushes to.
const REPOSITORY: &str = "ghcr.io/acme/api";
/// A tag that is not `latest`, so a test cannot pass by accident.
const TAG: &str = "v1.2.3";
/// A synthetic secret: CONTRIBUTING forbids committing anything that looks like a real one.
const SECRET: &str = "not-a-real-npm-token";
/// The index media type a multi-platform build has to report.
const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";

/// The composition `oci.image` needs: the built-in types its schema names, and the step itself.
fn harness_for(ports: Ports) -> HarnessBuilder {
    ks_engine::steps::builtin_types()
        .into_iter()
        .fold(Harness::builder().ports(ports), |builder, def| builder.type_def(def))
        .step_arc(Arc::new(OciImage))
}

/// A directory under the system temp dir, removed when this goes out of scope.
struct Scratch(PathBuf);

impl Scratch {
    fn new(kind: &str) -> Scratch {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let unique = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("ks-oci-{}-{kind}-{unique}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("the scratch directory can be created");
        Scratch(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The composition, the fakes and the directories one test drives.
struct Fixture {
    harness: Harness,
    registry: Arc<FakeRegistry>,
    builder: Arc<FakeImageBuilder>,
    sink: Arc<RecordingSink>,
    context: PathBuf,
    /// Both directories, so they outlive the paths the tests assert against.
    scratch: Vec<Scratch>,
}

/// A fixture whose builder pushes into the fixture's own registry, with no signer.
fn fixture() -> Fixture {
    fixture_with(FakeImageBuilder::new(), None)
}

/// As [`fixture`], with a builder scripted some other way and an optional signer.
fn fixture_with(builder: FakeImageBuilder, signer: Option<FakeSigner>) -> Fixture {
    let context = Scratch::new("context");
    std::fs::write(context.0.join("Dockerfile"), "FROM scratch\n")
        .expect("the Dockerfile is written");
    let cache_root = Scratch::new("cache");

    let registry = Arc::new(FakeRegistry::new());
    let builder = Arc::new(builder.pushing_into(Arc::clone(&registry)));
    let mut ports = Ports::default()
        .with_clock(Arc::new(FakeClock::new()))
        .with_registry(Arc::clone(&registry) as Arc<dyn Registry>)
        .with_image_builder(Arc::clone(&builder) as Arc<dyn ImageBuilder>);
    if let Some(signer) = signer {
        ports = ports.with_signer(Arc::new(signer) as Arc<dyn Signer>);
    }
    Fixture {
        harness: harness_for(ports).build().expect("the composition is valid"),
        registry,
        builder,
        sink: Arc::new(RecordingSink::new()),
        context: context.0.clone(),
        scratch: vec![context, cache_root],
    }
}

impl Fixture {
    /// A Dockerfile in this fixture's context, and `push` as the image reference. The Dockerfile
    /// is named absolutely so the context the step works out is this fixture's directory rather
    /// than whatever the test binary's working directory happens to be.
    fn case(&self) -> Inputs {
        let mut inputs = Inputs::new();
        inputs.insert("from".to_string(), Value::from(self.dockerfile_text()));
        inputs.insert(
            "context".to_string(),
            Value::from(self.context.to_string_lossy().into_owned()),
        );
        inputs.insert("push".to_string(), Value::from(format!("{REPOSITORY}:{TAG}")));
        inputs
    }

    /// The same case with one secret mounted under `npm`.
    fn case_with_secret(&self) -> Inputs {
        let mut inputs = self.case();
        inputs.insert(
            "secrets".to_string(),
            Value::Map(BTreeMap::from([("npm".to_string(), Value::from(SECRET))])),
        );
        inputs
    }

    fn dockerfile_text(&self) -> String {
        self.context.join("Dockerfile").to_string_lossy().into_owned()
    }

    /// This fixture's composition with one port swapped, for the tests about what the registry
    /// says rather than what the builder claims.
    fn with_port(&self, f: impl FnOnce(Ports) -> Ports) -> Harness {
        harness_for(f(self.harness.ports().clone())).build().expect("a composition")
    }
}

/// The `&str` under `name`.
fn text<'a>(outputs: &'a Outputs, name: &str) -> &'a str {
    match outputs.get(name) {
        Some(Value::String(text)) => text,
        other => panic!("the step returns a {name}, got {other:?}"),
    }
}

/// The strings under `name`.
fn list(outputs: &Outputs, name: &str) -> Vec<String> {
    match outputs.get(name) {
        Some(Value::List(items)) => items
            .iter()
            .map(|item| match item {
                Value::String(text) => text.clone(),
                other => panic!("a string, got {other:?}"),
            })
            .collect(),
        other => panic!("the step returns a list {name}, got {other:?}"),
    }
}

/// Runs the step against `harness`, keeping whatever it said.
fn drive(harness: &Harness, inputs: Inputs, sink: Arc<dyn LogSink>) -> Result<Outputs, StepError> {
    block_on(run_step(
        harness,
        NAME,
        inputs,
        CancellationToken::new(),
        sink,
        Arc::new(Redactor::new()),
    ))
}

/// As [`drive`], against the fixture's own composition, panicking on failure.
fn build(fixture: &Fixture, inputs: Inputs) -> Outputs {
    drive(&fixture.harness, inputs, Arc::clone(&fixture.sink) as Arc<dyn LogSink>)
        .unwrap_or_else(|error| panic!("the step runs: {error}"))
}

/// Every message and field the fixture's sink kept, flattened for a leak assertion.
fn logged(fixture: &Fixture) -> Vec<String> {
    let mut lines = Vec::new();
    for record in fixture.sink.records() {
        lines.push(record.message);
        lines.extend(record.fields.into_iter().map(|(name, value)| format!("{name}={value}")));
    }
    lines
}

#[test]
fn the_outputs_are_the_registrys_digest_the_pinned_ref_and_the_pushed_tag() {
    let fixture = fixture();
    let outputs = build(&fixture, fixture.case());

    // The registry is what says what it stored: the builder pushed a manifest, and this is the
    // hash of those bytes.
    let digest = Digest::parse(text(&outputs, "digest")).expect("a canonical digest");
    assert!(
        block_on(fixture.registry.exists(REPOSITORY, &digest)).expect("the registry answers"),
        "{digest} must be in {REPOSITORY}"
    );
    assert_eq!(text(&outputs, "ref"), format!("{REPOSITORY}@{digest}"));
    assert_eq!(text(&outputs, "tag"), format!("{REPOSITORY}:{TAG}"));
    assert_eq!(text(&outputs, "sbom"), "", "no port produces an SBOM yet");
    assert_eq!(outputs.get("signed"), Some(&Value::from(false)), "no `sign: true`");

    // The tag the step applied is the one the reference now resolves to.
    let tagged = ImageRef::new(REPOSITORY, Reference::Tag(TAG.to_string()));
    assert_eq!(block_on(fixture.registry.resolve(&tagged)).expect("the tag resolves"), digest);

    // What the builder was handed is what the step declared, not what it improvised — and every
    // input left out arrived as the default its schema names.
    let request = &fixture.builder.requests()[0];
    assert_eq!(request.context, fixture.context);
    assert_eq!(request.dockerfile, fixture.context.join("Dockerfile"));
    assert_eq!(request.push_to.as_deref(), Some(REPOSITORY));
    assert_eq!(list(&outputs, "platforms"), request.platforms);
    assert_eq!(request.platforms.len(), 1, "the host's platform");
    assert!(request.platforms[0].starts_with("linux/"), "got {:?}", request.platforms);
    assert_eq!(request.cache, BuildCache::Local, "the default cache");
    assert_eq!(request.target, None, "no stage was named");
    assert!(!request.sbom, "no SBOM was asked for");
    assert_eq!(request.args, BTreeMap::new(), "no args");
    assert_eq!(request.secrets, Vec::<String>::new(), "nothing mounted");
}

/// Omitting `context` means the Dockerfile's own directory — the fallback is the issue's
/// `path = dirname(from)`, and a `.` default would have been a different directory entirely.
#[test]
fn an_omitted_context_is_the_dockerfiles_own_directory() {
    let fixture = fixture();
    let mut inputs = Inputs::new();
    inputs.insert("from".to_string(), Value::from("sub/Dockerfile"));
    inputs.insert("push".to_string(), Value::from(format!("{REPOSITORY}:{TAG}")));
    assert!(!inputs.contains_key("context"), "the case really does omit context");

    let outputs = build(&fixture, inputs.clone());
    assert_eq!(text(&outputs, "tag"), format!("{REPOSITORY}:{TAG}"), "the build ran");

    let request = &fixture.builder.requests()[0];
    assert_eq!(request.context, PathBuf::from("sub"), "dirname(from), not `.`");
    assert_eq!(request.dockerfile, PathBuf::from("sub/Dockerfile"));

    // The resolved directory is also what the key covers: a Dockerfile inside its own context is
    // hashed by the context walk, so it must not be asked for twice.
    assert_eq!(
        OciImage.caching(&inputs),
        Caching::Keyed(vec![CacheInput::File(PathBuf::from("sub"))]),
        "the cache key covers the resolved context"
    );
}

#[test]
fn the_step_passes_the_conformance_kit() {
    let fixture = fixture();
    let mut inputs = fixture.case_with_secret();
    inputs.insert(
        "args".to_string(),
        Value::Map(BTreeMap::from([("VERSION".to_string(), Value::from("1.2.3"))])),
    );
    // `StepCase::with_secret` names a `Value::String` input, and a secret mounted into a build
    // arrives as a map, so the kit's own leak check cannot be aimed at this step's `secrets`.
    // [`secrets_reach_the_builder_as_mounts_and_leave_no_trace_in_the_image_or_the_log`] does
    // that instead, against a redactor that has never seen the value.
    block_on(step_conformance(&fixture.harness, StepCase::new(NAME, inputs)));
}

#[test]
fn secrets_reach_the_builder_as_mounts_and_leave_no_trace_in_the_image_or_the_log() {
    let fixture = fixture();
    build(&fixture, fixture.case_with_secret());

    // Mounted, never an arg: a build arg is recorded in the image history, so a secret passed as
    // one is a secret baked into the artifact.
    let request = &fixture.builder.requests()[0];
    assert_eq!(request.secrets, ["npm".to_string()], "the mount reached the builder");
    assert!(
        !request.args.values().any(|value| value.contains(SECRET)),
        "a secret passed as a build arg is baked in: {:?}",
        request.args
    );

    // Not one byte of the value is in anything the registry stored.
    for digest in fixture.registry.stored_digests(REPOSITORY) {
        let bytes = block_on(fixture.registry.pull(REPOSITORY, &digest)).expect("stored content");
        assert!(!String::from_utf8_lossy(&bytes).contains(SECRET), "{digest} carries the secret");
    }

    // And none in the log, though the redactor here has never seen it — the step is not relying
    // on redaction to keep a value out of its own output.
    let lines = logged(&fixture);
    assert!(lines.iter().any(|line| line.contains("npm")), "the mount names are logged");
    assert!(
        !lines.iter().any(|line| line.contains(SECRET)),
        "the secret reached the log: {lines:?}"
    );
}

#[test]
fn a_multi_platform_build_reports_the_digest_of_an_image_index() {
    let fixture = fixture();
    let mut inputs = fixture.case();
    inputs.insert(
        "platforms".to_string(),
        Value::List(vec![Value::from("linux/amd64"), Value::from("linux/arm64")]),
    );
    let outputs = build(&fixture, inputs);

    assert_eq!(list(&outputs, "platforms"), ["linux/amd64", "linux/arm64"]);
    let digest = Digest::parse(text(&outputs, "digest")).expect("a canonical digest");
    let index = String::from_utf8(
        block_on(fixture.registry.pull(REPOSITORY, &digest)).expect("the index is stored"),
    )
    .expect("an index is text");
    assert!(index.contains(OCI_INDEX), "the digest must address an index, got {index}");
}

#[test]
fn the_digest_is_the_registrys_or_the_step_fails() {
    // Absent: the builder pushed into a registry the step cannot see, so there is nowhere to tag.
    let absent = fixture();
    let empty = Arc::new(FakeRegistry::new());
    let harness =
        absent.with_port(|ports| ports.with_registry(Arc::clone(&empty) as Arc<dyn Registry>));
    let error = drive(&harness, absent.case(), Arc::new(RecordingSink::new()) as Arc<dyn LogSink>)
        .expect_err("an unconfirmed digest is not an output");
    assert!(matches!(error, StepError::Port { .. }), "{error}");

    // Disagreed: two manifests the registry really holds, the tag pointing at the first, and a
    // builder reporting the second. What the tag resolves to wins, and the difference is the error.
    let disagreed = fixture();
    let tagged = seed(&disagreed.registry, "{\"tagged\"}");
    let claimed = seed(&disagreed.registry, "{\"claimed\"}");
    block_on(disagreed.registry.tag(REPOSITORY, TAG, &tagged)).expect("the tag can be applied");
    let lying = Arc::new(FakeImageBuilder::new().claiming(claimed.clone()));
    let harness = disagreed
        .with_port(|ports| ports.with_image_builder(Arc::clone(&lying) as Arc<dyn ImageBuilder>));

    let error =
        drive(&harness, disagreed.case(), Arc::new(RecordingSink::new()) as Arc<dyn LogSink>)
            .expect_err("a builder that misreports is caught");
    match &error {
        StepError::Failed(reason) => {
            assert!(reason.contains(&claimed.to_string()), "the claimed digest: {reason}");
            assert!(reason.contains(&tagged.to_string()), "what the registry holds: {reason}");
        }
        other => panic!("a mismatch, not a transport failure: {other:?}"),
    }
}

/// Pushes a layout and returns the digest the registry stored it under, so a test has content to
/// point a tag at.
fn seed(registry: &FakeRegistry, manifest: &str) -> Digest {
    let contents = OciLayoutContents {
        media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
        manifest: manifest.as_bytes().to_vec(),
        blobs: Vec::new(),
    };
    block_on(registry.push_layout(REPOSITORY, &contents)).expect("a push succeeds").digest
}

#[test]
fn signing_needs_a_signer_and_a_signer_is_used() {
    let unsigned = fixture();
    let mut inputs = unsigned.case();
    inputs.insert("sign".to_string(), Value::from(true));
    let error = build_err(&unsigned, inputs).expect_err("signing needs a signer");
    assert!(
        matches!(&error, StepError::Port { port, .. } if *port == Port::Signer),
        "a clear port error, got {error}"
    );
    assert!(error.to_string().contains("sign: true"), "{error}");

    let signed = fixture_with(FakeImageBuilder::new(), Some(FakeSigner::keyless("iss", "sub")));
    let mut inputs = signed.case();
    inputs.insert("sign".to_string(), Value::from(true));
    assert_eq!(
        build(&signed, inputs).get("signed"),
        Some(&Value::from(true)),
        "a signer was provided, so it signed"
    );
}

/// [`build`], keeping the error rather than panicking on it.
fn build_err(fixture: &Fixture, inputs: Inputs) -> Result<Outputs, StepError> {
    drive(&fixture.harness, inputs, Arc::clone(&fixture.sink) as Arc<dyn LogSink>)
}

#[test]
fn the_cache_follows_the_context_and_a_secret_never_joins_it() {
    let fixture = fixture();
    let store = DirCache::new(&fixture.scratch[1].0);
    let run = || {
        block_on(run_step_cached(
            &fixture.harness,
            NAME,
            fixture.case(),
            CancellationToken::new(),
            Arc::clone(&fixture.sink) as Arc<dyn LogSink>,
            Arc::new(Redactor::new()),
            &store,
        ))
        .expect("the step runs")
    };

    assert!(matches!(run().1, CacheOutcome::Miss { .. }));
    assert_eq!(fixture.builder.requests().len(), 1);

    let (outputs, hit) = run();
    let evidence = match &hit {
        CacheOutcome::Hit { evidence, .. } => evidence.clone(),
        other => panic!("nothing changed, so the work is skipped: {other:?}"),
    };
    assert!(evidence.starts_with("sha256:"), "{evidence}");
    assert_eq!(fixture.builder.requests().len(), 1, "the builder ran once");

    // The image the key names is the evidence a skip rests on; garbage-collect it and the next run
    // has to build again.
    let digest = Digest::parse(text(&outputs, "digest")).expect("a canonical digest");
    fixture.registry.delete(REPOSITORY, &digest);
    assert!(matches!(run().1, CacheOutcome::Stale { .. }));
    assert_eq!(fixture.builder.requests().len(), 2, "the builder ran again");

    // A changed context is a different key, decided without running the step.
    // `Caching::Keyed` holds the paths the key covers; `cache_key` is what
    // hashes them — so it is what a content change shows up in.
    let key_of = |inputs: &Inputs| match OciImage.caching(inputs) {
        Caching::Keyed(declared) => {
            cache_key(&OciImage, inputs, &declared).expect("the context is readable")
        }
        Caching::Never => panic!("a build without secrets is cacheable"),
    };
    let before = key_of(&fixture.case());
    std::fs::write(fixture.context.join("Dockerfile"), "FROM alpine\n")
        .expect("the context changes");
    assert_ne!(before, key_of(&fixture.case()), "a changed context is a different key");

    // A run that mounts a secret does not take part at all: the key is computed over the resolved
    // inputs, and the value behind the mount is one of them — it would be hashed into a digest
    // that is logged on every miss and written to disk.
    assert!(
        matches!(OciImage.caching(&fixture.case_with_secret()), Caching::Never),
        "a build that mounts secrets must not be keyed by a digest of them"
    );
}

/// The parity check: the checker and the executable must agree, or a workflow the checker blesses
/// may not run, and one it refuses may be fine. The comparison runs against what
/// `Catalog::from_harness` derives from the [`StepKind`] itself — the mapping the harness applies
/// when a composition is built.
#[test]
fn the_catalog_entry_and_the_step_schema_are_the_same_contract() {
    let harness = fixture().harness;
    let from_harness = Catalog::from_harness(&harness).expect("the catalog builds");
    let step = from_harness.step(NAME).expect("built in");
    let builtin = Catalog::builtin();
    let catalog = builtin.step(NAME).expect("built in");
    assert_eq!(step.inputs, catalog.inputs, "the inputs drifted");
    assert_eq!(step.outputs, catalog.outputs, "the outputs drifted");
}
