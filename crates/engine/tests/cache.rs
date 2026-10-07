//! End to end: a cacheable `oci.image`-like step run twice through [`run_step_cached`] over
//! `ks-testing` fakes — the second run skips and says why, a deleted image turns the hit into a
//! rebuild, a changed context misses, a step that does not opt in always runs, and a corrupt
//! entry is a miss rather than an error.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ks_core::harness::Harness;
use ks_core::ports::BoxFuture;
use ks_core::ports::script_host::{Value, ValueType};
use ks_core::ports::secrets::Redactor;
use ks_core::ports::supply_chain::{BuildOutput, BuildRequest, Digest, ImageBuilder, Registry};
use ks_core::step::{
    ActionClass, ActionKind, CacheCheck, CacheInput, Caching, CancellationToken, Field, Inputs,
    LogRecord, LogSink, Outputs, Port, Ports, StepCtx, StepError, StepKind, StepSchema, TypeDef,
    TypeRef, Version,
};
use ks_engine::cache::{CacheOutcome, DirCache, StepCache, run_step_cached};
use ks_testing::supply_chain::{FakeImageBuilder, FakeRegistry};
use ks_testing::{block_on, clock::FakeClock};

/// The repository the sample step pushes to — where the cached digest has to still be.
const REPOSITORY: &str = "ghcr.io/acme/api";

/// The `oci.image`-like step: builds an image from a context directory and pushes it, as the
/// hero file's `build: oci.image` step would. Its work is a pure function of the context and the
/// inputs, so it opts into the cache — and checks the pushed image is still there before letting
/// itself be skipped.
struct BuildImageStep;

impl StepKind for BuildImageStep {
    fn name(&self) -> &'static str {
        "oci.image"
    }

    fn version(&self) -> Version {
        Version::new(1, 0, 0)
    }

    fn schema(&self) -> StepSchema {
        StepSchema {
            doc: "Builds an image from a build context and pushes it.",
            inputs: vec![
                Field::new("context", TypeRef::Named("path"), "the build context directory"),
                Field::new(
                    "push",
                    TypeRef::Builtin(ValueType::String),
                    "the repository to push to",
                )
                .with_default(Value::from(REPOSITORY)),
                Field::new("sign", TypeRef::Builtin(ValueType::Bool), "whether to sign the image")
                    .with_default(Value::from(false)),
            ],
            outputs: vec![
                Field::new("digest", TypeRef::Named("oci.Digest"), "the pushed manifest digest"),
                Field::new("tag", TypeRef::Builtin(ValueType::String), "the tag that was applied"),
                Field::new("signed", TypeRef::Builtin(ValueType::Bool), "whether it was signed"),
            ],
        }
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::ImageBuilder, Port::Registry]
    }

    fn action(&self, _inputs: &Inputs) -> ActionClass {
        ActionClass::new(ActionKind::Build)
    }

    /// The build context is the whole input: hashing it is what makes "unchanged" provable.
    fn caching(&self, inputs: &Inputs) -> Caching {
        match inputs.get("context") {
            Some(Value::String(context)) => {
                Caching::Keyed(vec![CacheInput::File(PathBuf::from(context))])
            }
            _ => Caching::Never,
        }
    }

    /// Cached outputs are only worth returning if the image they name is still in the registry:
    /// a GC'd image means the step must run again.
    fn verify_cached<'a>(
        &'a self,
        ctx: StepCtx,
        outputs: &'a Outputs,
    ) -> BoxFuture<'a, Result<CacheCheck, StepError>> {
        Box::pin(async move {
            let Some(Value::String(digest)) = outputs.get("digest") else {
                return Ok(CacheCheck::Stale("the entry carries no digest".to_string()));
            };
            let digest = Digest::parse(digest).map_err(|error| StepError::InvalidOutput {
                field: "digest".to_string(),
                reason: error.to_string(),
            })?;
            let registry = ctx.ports().registry().ok_or_else(|| StepError::Port {
                port: Port::Registry,
                message: "no registry was provided".to_string(),
            })?;
            let exists = registry.exists(REPOSITORY, &digest).await.map_err(|error| {
                StepError::Port { port: Port::Registry, message: error.to_string() }
            })?;
            Ok(if exists {
                CacheCheck::Valid(format!("{digest} present in {REPOSITORY}"))
            } else {
                CacheCheck::Stale(format!("{digest} no longer in {REPOSITORY}"))
            })
        })
    }

    fn run(&self, ctx: StepCtx, inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>> {
        Box::pin(async move {
            let builder = ctx.ports().image_builder().ok_or_else(|| StepError::Port {
                port: Port::ImageBuilder,
                message: "no image builder was provided".to_string(),
            })?;
            let text = |name: &str| match inputs.get(name) {
                Some(Value::String(text)) => text.clone(),
                _ => String::new(),
            };
            let context = PathBuf::from(text("context"));
            let built = builder
                .build(&BuildRequest {
                    dockerfile: context.join("Dockerfile"),
                    context,
                    args: Default::default(),
                    platforms: vec!["linux/amd64".to_string()],
                    target: None,
                    push_to: Some(text("push")),
                })
                .await
                .map_err(|error| StepError::Failed(error.to_string()))?;
            let digest = match built {
                BuildOutput::PushedImage { digest, .. } => digest,
                BuildOutput::OciLayout { manifest, .. } => manifest.digest,
            };
            let mut outputs = Outputs::new();
            outputs.insert("digest".to_string(), Value::from(digest.to_string()));
            outputs.insert("tag".to_string(), Value::from(text("push")));
            outputs.insert(
                "signed".to_string(),
                Value::from(matches!(inputs.get("sign"), Some(Value::Bool(true)))),
            );
            Ok(outputs)
        })
    }
}

/// A step that takes the default [`Caching::Never`] — it runs every time, whatever the cache holds.
struct AlwaysRunsStep;

impl StepKind for AlwaysRunsStep {
    fn name(&self) -> &'static str {
        "sample.always"
    }

    fn version(&self) -> Version {
        Version::new(0, 1, 0)
    }

    fn schema(&self) -> StepSchema {
        StepSchema { doc: "Runs every time.", inputs: vec![], outputs: vec![] }
    }

    fn requires(&self) -> &'static [Port] {
        &[]
    }

    fn action(&self, _inputs: &Inputs) -> ActionClass {
        ActionClass::new(ActionKind::Other)
    }

    fn run(&self, _ctx: StepCtx, _inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>> {
        Box::pin(std::future::ready(Ok(Outputs::new())))
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

    /// The fields of the first record with this message.
    fn fields_of(&self, message: &str) -> Vec<(String, String)> {
        self.records()
            .iter()
            .find(|record| record.message == message)
            .unwrap_or_else(|| panic!("no record with message {message:?}"))
            .fields
            .clone()
    }
}

impl LogSink for RecordingSink {
    fn record(&self, record: LogRecord) {
        self.records.lock().expect("recording sink").push(record);
    }
}

/// A scratch directory under the system temp dir, removed when it goes out of scope.
struct Scratch(PathBuf);

impl Scratch {
    /// A fresh, empty directory named after `kind`, unique to this process.
    fn new(kind: &str) -> Scratch {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let unique = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("ks-cache-{}-{kind}-{unique}", std::process::id()));
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

/// The composition plus the fakes and scratch directories one test drives.
struct Fixture {
    harness: Harness,
    registry: Arc<FakeRegistry>,
    builder: Arc<FakeImageBuilder>,
    sink: Arc<RecordingSink>,
    context: PathBuf,
    /// Held so the directory outlives the paths the tests assert against.
    _scratch: Vec<Scratch>,
}

impl Fixture {
    /// Writes or overwrites one file in the build context.
    fn write_context(&self, name: &str, contents: &str) {
        std::fs::write(self.context.join(name), contents).expect("the context file can be written");
    }

    fn inputs(&self) -> Inputs {
        let mut inputs = Inputs::new();
        inputs.insert(
            "context".to_string(),
            Value::from(self.context.to_string_lossy().into_owned()),
        );
        inputs
    }

    fn cache(&self) -> DirCache {
        DirCache::new(&self._scratch[1].0)
    }

    /// Runs `name` through [`run_step_cached`] against this fixture's cache and log sink.
    fn drive(&self, name: &str, inputs: Inputs) -> (Outputs, CacheOutcome) {
        block_on(run_step_cached(
            &self.harness,
            name,
            inputs,
            CancellationToken::new(),
            Arc::clone(&self.sink) as Arc<dyn LogSink>,
            Arc::new(Redactor::new()),
            &self.cache(),
        ))
        .expect("the step runs")
    }

    /// Runs `oci.image`, the step whose build this fixture's context feeds.
    fn build(&self) -> (Outputs, CacheOutcome) {
        self.drive("oci.image", self.inputs())
    }
}

fn fixture() -> Fixture {
    let context = Scratch::new("context");
    std::fs::write(context.0.join("Dockerfile"), "FROM scratch\n")
        .expect("the Dockerfile can be written");
    let cache_root = Scratch::new("cache");

    let registry = Arc::new(FakeRegistry::new());
    let builder =
        Arc::new(FakeImageBuilder::new().pushing_into(Arc::clone(&registry) as Arc<FakeRegistry>));
    let sink = Arc::new(RecordingSink::default());
    let ports = Ports::default()
        .with_clock(Arc::new(FakeClock::new()))
        .with_registry(Arc::clone(&registry) as Arc<dyn Registry>)
        .with_image_builder(Arc::clone(&builder) as Arc<dyn ImageBuilder>);
    let harness = Harness::builder()
        .ports(ports)
        .type_def(TypeDef {
            name: "oci.Digest",
            base: ValueType::String,
            doc: "an OCI content digest (`sha256:...`)",
        })
        .step_arc(Arc::new(BuildImageStep))
        .step_arc(Arc::new(AlwaysRunsStep))
        .build()
        .expect("the fixture composition is valid");

    Fixture {
        harness,
        registry,
        builder,
        sink,
        context: context.0.clone(),
        _scratch: vec![context, cache_root],
    }
}

/// The digest a run's outputs carry, as text.
fn digest_of(outputs: &Outputs) -> String {
    match outputs.get("digest") {
        Some(Value::String(digest)) => digest.clone(),
        other => panic!("the step returns a digest, got {other:?}"),
    }
}

/// The digest stored in the cache entry under `key`, parsed.
fn digest_in(f: &Fixture, key: &str) -> Digest {
    let entry = f.cache().get(key).expect("the entry decodes");
    Digest::parse(&digest_of(&entry)).expect("the cached digest is canonical")
}

/// The key of an outcome, for the assertion that it is a miss.
fn miss_key(outcome: &CacheOutcome) -> String {
    match outcome {
        CacheOutcome::Miss { key } => key.clone(),
        other => panic!("expected a miss, got {other:?}"),
    }
}

#[test]
fn a_second_run_with_unchanged_inputs_skips_the_build_and_says_why() {
    let f = fixture();
    let (first, outcome) = f.build();
    let key = miss_key(&outcome);
    assert_eq!(f.builder.requests().len(), 1, "one build so far");

    let (second, outcome) = f.build();
    assert_eq!(second, first, "the cached outputs come back unchanged");
    let CacheOutcome::Hit { key: hit_key, evidence } = outcome else {
        panic!("the second run should hit, got {outcome:?}");
    };
    assert_eq!(hit_key, key, "the same key, found this time");
    assert!(hit_key.starts_with("sha256:"), "the key is a rendered digest: {hit_key}");
    assert_eq!(f.builder.requests().len(), 1, "the builder ran once: the work was skipped");

    let digest = digest_of(&first);
    assert_eq!(evidence, format!("{digest} present in {REPOSITORY}"));
    let fields = f.sink.fields_of("step skipped");
    assert_eq!(fields[0], ("reason".to_string(), "cache hit: inputs unchanged".to_string()));
    assert_eq!(fields[1], ("key".to_string(), key));
    assert_eq!(fields[2], ("evidence".to_string(), evidence));
}

#[test]
fn deleting_the_image_from_the_registry_turns_the_hit_into_a_rebuild() {
    let f = fixture();
    let key = miss_key(&f.build().1);

    let (_, outcome) = f.build();
    assert!(matches!(outcome, CacheOutcome::Hit { .. }), "the image is still there: {outcome:?}");

    let digest = digest_in(&f, &key);
    f.registry.delete(REPOSITORY, &digest);

    let (rebuilt, outcome) = f.build();
    let CacheOutcome::Stale { key: stale_key, evidence } = outcome else {
        panic!("a deleted image must rebuild, got {outcome:?}");
    };
    assert_eq!(stale_key, key, "the same key, now stale");
    assert_eq!(evidence, format!("{digest} no longer in {REPOSITORY}"));
    assert_eq!(f.builder.requests().len(), 2, "the builder ran again");
    assert_eq!(digest_of(&rebuilt), digest.to_string(), "the same context, the same digest");

    let stale = f.sink.fields_of("cache entry stale");
    assert_eq!(stale[0], ("key".to_string(), key.clone()));
    assert_eq!(stale[1], ("evidence".to_string(), evidence));
    assert_eq!(f.sink.fields_of("rebuilding")[0], ("key".to_string(), key));
}

#[test]
fn changing_a_file_in_the_build_context_misses() {
    let f = fixture();
    f.build();
    f.write_context("app.txt", "one thing");
    let key = miss_key(&f.build().1);

    f.write_context("app.txt", "another thing");
    let changed = miss_key(&f.build().1);
    assert_ne!(changed, key, "a changed context hashes to a different key");
    assert_eq!(f.builder.requests().len(), 3, "three builds: nothing was skipped");
}

#[test]
fn a_step_that_does_not_opt_in_always_runs() {
    let f = fixture();
    f.build();
    for _ in 0..2 {
        let (outputs, outcome) = f.drive("sample.always", Inputs::new());
        assert_eq!(outputs, Outputs::new());
        assert_eq!(outcome, CacheOutcome::Uncacheable, "the default never caches");
    }
    let entries = std::fs::read_dir(&f._scratch[1].0).expect("the cache root exists");
    assert_eq!(entries.count(), 1, "only the cacheable step wrote an entry");
}

#[test]
fn a_corrupt_cache_entry_is_a_miss_not_an_error() {
    let f = fixture();
    let key = miss_key(&f.build().1);

    let entry = f.cache().entry_path(&key);
    std::fs::write(&entry, b"\x00\x01not a cache entry").expect("the entry can be corrupted");

    miss_key(&f.build().1);
    assert_eq!(f.builder.requests().len(), 2, "the step ran again rather than trusting garbage");
}
