//! End to end: a sample step kind composed with `Harness::builder()` over `ks-testing` fakes
//! and run through [`run_step`] — outputs, defaults, the input-computed action class,
//! redaction, port restriction and cancellation.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use ks_core::harness::Harness;
use ks_core::ports::BoxFuture;
use ks_core::ports::run_context::NetworkScope;
use ks_core::ports::script_host::{Value, ValueType};
use ks_core::ports::secrets::{Redactor, SecretValue};
use ks_core::ports::supply_chain::{Digest, ImageRef, OciLayoutContents, Registry};
use ks_core::step::{
    ActionClass, ActionKind, CancellationToken, Field, Inputs, LogLevel, LogRecord, LogSink,
    Outputs, Port, Ports, StepCapabilities, StepCtx, StepError, StepKind, StepSchema, TypeDef,
    TypeRef, Version,
};
use ks_engine::run::run_step;
use ks_testing::supply_chain::{FakeRegistry, FakeSigner};
use ks_testing::{block_on, clock::FakeClock, secrets::FakeSecrets};

/// The first `&str` input under `name`; inputs arrive prepared, so a wrong type never reaches
/// a step.
fn text<'a>(inputs: &'a Inputs, name: &str) -> &'a str {
    match inputs.get(name) {
        Some(Value::String(text)) => text,
        _ => "",
    }
}

/// The sample step: resolves an image's digest through the `Registry` port and logs through
/// the redacting logger. `credential` stands in for a resolved secret the engine registered
/// with the run's redactor.
struct RolloutStep;

impl StepKind for RolloutStep {
    fn name(&self) -> &'static str {
        "sample.rollout"
    }

    fn version(&self) -> Version {
        Version::new(1, 2, 0)
    }

    fn schema(&self) -> StepSchema {
        StepSchema {
            doc: "Rolls an already-pushed image out to an environment.",
            inputs: vec![
                Field::new("image", TypeRef::Builtin(ValueType::String), "image to roll out"),
                Field::new(
                    "env",
                    TypeRef::Builtin(ValueType::String),
                    "the environment being deployed to, e.g. `prod`",
                ),
                Field::new(
                    "credential",
                    TypeRef::Builtin(ValueType::String),
                    "registry credential; registered with the run's redactor",
                )
                .with_default(Value::from("")),
                Field::new("tag", TypeRef::Builtin(ValueType::String), "tag to apply")
                    .with_default(Value::from("latest")),
            ],
            outputs: vec![
                Field::new(
                    "digest",
                    TypeRef::Named("digest"),
                    "the digest the reference resolves to",
                ),
                Field::new("tag", TypeRef::Builtin(ValueType::String), "the tag that was applied"),
            ],
        }
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::Registry]
    }

    fn optional(&self) -> &'static [Port] {
        &[Port::Signer]
    }

    /// `deploy` in `prod` is a different approval than in `dev`, so the class is computed from
    /// the (already prepared) inputs.
    fn action(&self, inputs: &Inputs) -> ActionClass {
        ActionClass::new(ActionKind::Deploy).in_env(text(inputs, "env"))
    }

    fn capabilities(&self) -> StepCapabilities {
        StepCapabilities {
            network: NetworkScope::Hosts(BTreeSet::from(["registry.example".to_string()])),
            ..StepCapabilities::default()
        }
    }

    fn run(&self, ctx: StepCtx, inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>> {
        Box::pin(async move {
            let Some(registry) = ctx.ports().registry() else {
                return Err(StepError::Port {
                    port: Port::Registry,
                    message: "no registry was provided".to_string(),
                });
            };
            let image = ImageRef::parse(text(&inputs, "image")).map_err(|error| {
                StepError::InvalidInput { field: "image".to_string(), reason: error.to_string() }
            })?;
            let digest = registry.resolve(&image).await.map_err(|error| StepError::Port {
                port: Port::Registry,
                message: error.to_string(),
            })?;
            let digest_text = digest.to_string();
            let (env, credential) = (text(&inputs, "env"), text(&inputs, "credential"));
            ctx.log().info(
                &format!("rolling out {image} to {env} with credential {credential}"),
                &[("digest", digest_text.as_str()), ("credential", credential)],
            );
            let mut outputs = Outputs::new();
            outputs.insert("digest".to_string(), Value::from(digest_text));
            outputs.insert("tag".to_string(), Value::from(text(&inputs, "tag")));
            Ok(outputs)
        })
    }
}

/// A step that records which ports its context actually holds.
struct SpyStep {
    observed: Arc<Mutex<Vec<Port>>>,
}

impl StepKind for SpyStep {
    fn name(&self) -> &'static str {
        "sample.spy"
    }

    fn version(&self) -> Version {
        Version::new(0, 1, 0)
    }

    fn schema(&self) -> StepSchema {
        StepSchema { doc: "Records the ports its context holds.", inputs: vec![], outputs: vec![] }
    }

    fn requires(&self) -> &'static [Port] {
        &[]
    }

    fn optional(&self) -> &'static [Port] {
        &[Port::Signer]
    }

    fn action(&self, _inputs: &Inputs) -> ActionClass {
        ActionClass::new(ActionKind::Other)
    }

    fn run(&self, ctx: StepCtx, _inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>> {
        Box::pin(async move {
            self.observed.lock().expect("spy").extend(ctx.ports().provided());
            Ok(Outputs::new())
        })
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

/// The composition: a fake registry seeded with `app:v1`, a fake clock, plus ports the sample
/// step did *not* declare (to prove the restriction).
struct Fixture {
    harness: Harness,
    sink: Arc<RecordingSink>,
    digest: Digest,
    observed: Arc<Mutex<Vec<Port>>>,
}

impl Fixture {
    /// Runs `name` through [`run_step`] against this fixture's log sink.
    fn drive<'a>(
        &'a self,
        name: &'a str,
        inputs: Inputs,
        cancel: CancellationToken,
        redactor: Arc<Redactor>,
    ) -> BoxFuture<'a, Result<Outputs, StepError>> {
        Box::pin(run_step(
            &self.harness,
            name,
            inputs,
            cancel,
            Arc::clone(&self.sink) as Arc<dyn LogSink>,
            redactor,
        ))
    }
}

fn fixture() -> Fixture {
    let registry = Arc::new(FakeRegistry::new());
    let descriptor = block_on(registry.push_layout(
        "app",
        &OciLayoutContents {
            media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            manifest: b"sample manifest".to_vec(),
            blobs: vec![b"layer".to_vec()],
        },
    ))
    .expect("the push succeeds");
    block_on(registry.tag("app", "v1", &descriptor.digest)).expect("the tag lands");

    let sink = Arc::new(RecordingSink::default());
    let observed = Arc::new(Mutex::new(Vec::new()));
    let ports = Ports::default()
        .with_clock(Arc::new(FakeClock::new()))
        .with_registry(Arc::clone(&registry) as Arc<dyn Registry>)
        .with_signer(Arc::new(FakeSigner::with_key("test-key")))
        .with_secrets(Arc::new(FakeSecrets::new()));
    let harness = Harness::builder()
        .ports(ports)
        .type_def(TypeDef {
            name: "digest",
            base: ValueType::String,
            doc: "an OCI content digest (`sha256:...`)",
        })
        .step_arc(Arc::new(RolloutStep))
        .step_arc(Arc::new(SpyStep { observed: Arc::clone(&observed) }))
        .build()
        .expect("the fixture composition is valid");
    Fixture { harness, sink, digest: descriptor.digest, observed }
}

#[test]
fn runs_a_step_end_to_end() {
    let f = fixture();
    let mut redactor = Redactor::new();
    redactor.register(&SecretValue::new(b"s3cr3t-token".to_vec()));
    let redactor = Arc::new(redactor);

    let mut inputs = Inputs::new();
    inputs.insert("image".to_string(), Value::from("app:v1"));
    inputs.insert("env".to_string(), Value::from("prod"));
    inputs.insert("credential".to_string(), Value::from("s3cr3t-token"));

    let outputs = block_on(f.drive(
        "sample.rollout",
        inputs,
        CancellationToken::new(),
        Arc::clone(&redactor),
    ))
    .expect("the step runs");

    assert_eq!(outputs.get("digest"), Some(&Value::from(f.digest.to_string())));
    assert_eq!(outputs.get("tag"), Some(&Value::from("latest")), "the default tag is applied");

    let records = f.sink.records();
    // The engine logged the action class computed from the inputs: deploy in prod.
    assert!(records.iter().any(|record| record.level == LogLevel::Info
        && record.fields == vec![("action".to_string(), "deploy prod".to_string())]));
    // The step's own record went out redacted — message and fields alike.
    let record = records
        .iter()
        .find(|record| record.step == "sample.rollout" && record.message.starts_with("rolling"))
        .expect("the step logged");
    assert!(!record.message.contains("s3cr3t-token"), "{}", record.message);
    assert!(record.message.contains("***"), "{}", record.message);
    let credential = record.fields.iter().find(|(name, _)| name == "credential").expect("field");
    assert_eq!(credential.1, "***");
    let digest_field = record.fields.iter().find(|(name, _)| name == "digest").expect("field");
    assert_eq!(digest_field.1, f.digest.to_string());
}

#[test]
fn a_step_only_sees_the_ports_it_declared() {
    let f = fixture();
    block_on(run_step(
        &f.harness,
        "sample.spy",
        Inputs::new(),
        CancellationToken::new(),
        Arc::new(RecordingSink::default()) as Arc<dyn LogSink>,
        Arc::new(Redactor::new()),
    ))
    .expect("the spy runs");
    // The harness provides Clock, Registry, Signer and Secrets; the spy declared only the
    // Signer, so that is all its context holds.
    assert_eq!(*f.observed.lock().expect("spy"), vec![Port::Signer]);
}

#[test]
fn a_run_cancelled_before_start_is_cancelled() {
    let f = fixture();
    let cancel = CancellationToken::new();
    cancel.cancel();
    let error =
        block_on(f.drive("sample.rollout", Inputs::new(), cancel, Arc::new(Redactor::new())))
            .expect_err("the run was cancelled");
    assert_eq!(error, StepError::Cancelled);
    assert!(f.sink.records().is_empty(), "a cancelled step never logs");
}

#[test]
fn an_unknown_step_is_rejected_before_anything_logs() {
    let f = fixture();
    let error = block_on(f.drive(
        "nope.step",
        Inputs::new(),
        CancellationToken::new(),
        Arc::new(Redactor::new()),
    ))
    .expect_err("no step has this name");
    assert_eq!(error, StepError::UnknownStep("nope.step".to_string()));
    assert!(f.sink.records().is_empty(), "nothing is logged before the rejection");
}
