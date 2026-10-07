//! The step conformance kit through the public API: the sample step passes it, and three
//! deliberately-broken steps prove it can fail — a kit that only ever passes is a kit that
//! proves nothing.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use ks_core::harness::Harness;
use ks_core::ids::StepId;
use ks_core::ports::BoxFuture;
use ks_core::ports::script_host::{Value, ValueType};
use ks_core::ports::secrets::SecretRef;
use ks_core::step::{
    ActionClass, ActionKind, Field, Inputs, LogLevel, LogRecord, LogSink, Outputs, Port, Ports,
    StepCtx, StepError, StepKind, StepSchema, TypeRef, Version,
};
use ks_testing::block_on;
use ks_testing::clock::FakeClock;
use ks_testing::secrets::FakeSecrets;
use ks_testing::step::{RecordingSink, StepCase, step_conformance, text};

/// A harness carrying one step, the clock every composition must provide, and a `Secrets` port
/// so a step that declares one can compose at all. What the fake scripts or withholds is the
/// caller's business; the kit supplies its own resolver for the secret pass.
fn harness_over(step: impl StepKind) -> Harness {
    Harness::builder()
        .ports(
            Ports::default()
                .with_clock(Arc::new(FakeClock::new()))
                .with_secrets(Arc::new(FakeSecrets::new())),
        )
        .step(step)
        .build()
        .expect("the composition is valid")
}

/// Runs `case` against `step` and returns the message of the panic it produced.
fn rejection(step: impl StepKind, case: StepCase) -> String {
    let harness = harness_over(step);
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        block_on(step_conformance(&harness, case))
    }));
    let payload = caught.expect_err("the kit must reject a non-conforming step");
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|text| (*text).to_string()))
        .expect("a conformance panic carries a string message")
}

/// Declares an output of type `number` and returns a string, so the outputs check must catch it.
struct MistypedOutputs;

impl StepKind for MistypedOutputs {
    fn name(&self) -> &'static str {
        "bad.mistyped"
    }

    fn version(&self) -> Version {
        Version::new(1, 0, 0)
    }

    fn schema(&self) -> StepSchema {
        StepSchema {
            doc: "Returns a string under a declared numeric output.",
            inputs: vec![],
            outputs: vec![Field::new(
                "count",
                TypeRef::Builtin(ValueType::Number),
                "supposed to be a number",
            )],
        }
    }

    fn requires(&self) -> &'static [Port] {
        &[]
    }

    fn action(&self, _inputs: &Inputs) -> ActionClass {
        ActionClass::new(ActionKind::Other)
    }

    fn run(&self, _ctx: StepCtx, _inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>> {
        let mut outputs = Outputs::new();
        outputs.insert("count".to_string(), Value::from("not a number"));
        Box::pin(std::future::ready(Ok(outputs)))
    }
}

/// Counts its own runs, so the same inputs cannot give the same outputs twice.
struct Counting {
    runs: Arc<AtomicU64>,
}

impl StepKind for Counting {
    fn name(&self) -> &'static str {
        "bad.counting"
    }

    fn version(&self) -> Version {
        Version::new(1, 0, 0)
    }

    fn schema(&self) -> StepSchema {
        StepSchema {
            doc: "Returns how many times it has run, so it is not idempotent.",
            inputs: vec![],
            outputs: vec![Field::new(
                "count",
                TypeRef::Builtin(ValueType::Number),
                "how many runs have happened",
            )],
        }
    }

    fn requires(&self) -> &'static [Port] {
        &[]
    }

    fn action(&self, _inputs: &Inputs) -> ActionClass {
        ActionClass::new(ActionKind::Other)
    }

    fn run(&self, _ctx: StepCtx, _inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>> {
        let runs = self.runs.fetch_add(1, Ordering::SeqCst);
        let mut outputs = Outputs::new();
        outputs.insert("count".to_string(), Value::from(runs as f64));
        Box::pin(std::future::ready(Ok(outputs)))
    }
}

/// Which channel a [`Leaky`] step leaks through: one per sink/error site the kit checks, so a
/// change to the kit that stops catching one of them fails a test rather than passing quietly.
#[derive(Clone, Copy)]
enum Channel {
    /// The log message — the record it is logged on stays otherwise clean.
    Message,
    /// A field value — the message it is logged alongside stays clean.
    Field,
    /// A `StepError` — nothing reaches the sink at all.
    Error,
}

/// Resolves the case's secret and leaks it down one chosen channel, so each of the kit's leak
/// sites is pinned in turn rather than only the first one a leaky step would trip.
struct Leaky {
    name: &'static str,
    reference: SecretRef,
    channel: Channel,
}

impl StepKind for Leaky {
    fn name(&self) -> &'static str {
        self.name
    }

    fn version(&self) -> Version {
        Version::new(1, 0, 0)
    }

    fn schema(&self) -> StepSchema {
        StepSchema {
            doc: "Resolves a secret through the Secrets port and leaks it down one channel.",
            inputs: vec![
                Field::new(
                    "token",
                    TypeRef::Builtin(ValueType::String),
                    "a token standing in for a resolved secret",
                )
                .with_default(Value::from("")),
            ],
            outputs: vec![Field::new(
                "message",
                TypeRef::Builtin(ValueType::String),
                "the echoed message",
            )],
        }
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::Secrets]
    }

    fn action(&self, _inputs: &Inputs) -> ActionClass {
        ActionClass::new(ActionKind::Other)
    }

    fn run(&self, ctx: StepCtx, inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>> {
        let reference = self.reference.clone();
        let (name, channel) = (self.name, self.channel);
        Box::pin(async move {
            let resolved = match ctx.ports().secrets() {
                Some(secrets) => secrets.resolve(&reference, &StepId::new(name)).await.ok(),
                None => None,
            };
            let mut outputs = Outputs::new();
            outputs.insert("message".to_string(), Value::from(text(&inputs, "token")));
            if let Some(value) = resolved {
                let shown = value.with_bytes(|bytes| String::from_utf8_lossy(bytes).into_owned());
                match channel {
                    Channel::Message => {
                        // The field is carried too, exactly as a self-resolving step would log
                        // it: the message assertion fires first, so this arm pins the message
                        // channel and never reaches the field value below it.
                        ctx.log().info(&format!("resolved {shown}"), &[("token", shown.as_str())]);
                    }
                    Channel::Field => {
                        ctx.log().info("resolved a token", &[("token", shown.as_str())]);
                    }
                    Channel::Error => {
                        return Err(StepError::Failed(format!("vault refused {shown}")));
                    }
                }
            }
            Ok(outputs)
        })
    }
}

/// The needle every leaking step below hands the kit: a synthetic sample, and what no
/// rejection message may contain.
const NEEDLE: &str = "not-a-real-token";

/// A case for a step registered as `name` whose `token` input is the needle and is marked as the
/// secret it must never leak.
fn secret_case(name: &'static str) -> StepCase {
    let mut inputs = Inputs::new();
    inputs.insert("token".to_string(), Value::from(NEEDLE));
    StepCase::new(name, inputs).with_secret("token", NEEDLE)
}

#[test]
fn a_rejection_never_prints_the_secret_it_reports() {
    // Each of these is rejected — the assertion is that it is still rejected *quietly*. A panic
    // message that quotes the record, the error or the outputs it is reporting lands in the same
    // test output and CI log the check exists to protect, so leaking the needle there is the
    // defect, not a cosmetic detail.

    let message = rejection(
        Leaky {
            name: "bad.self-resolving",
            reference: SecretRef::new("env", "deploy-token"),
            channel: Channel::Message,
        },
        secret_case("bad.self-resolving"),
    );
    assert!(
        message.contains("logged the secret in the message"),
        "a leak in the log message is still caught, got {message:?}"
    );
    assert!(!message.contains(NEEDLE), "the rejection must not quote the secret, got {message:?}");

    let field = rejection(
        Leaky {
            name: "bad.leaky-field",
            reference: SecretRef::new("env", "deploy-token"),
            channel: Channel::Field,
        },
        secret_case("bad.leaky-field"),
    );
    assert!(
        field.contains("logged the secret as the value"),
        "a leak in a field value is still caught, got {field:?}"
    );
    assert!(!field.contains(NEEDLE), "the rejection must not quote the secret, got {field:?}");

    let error = rejection(
        Leaky {
            name: "bad.leaky-error",
            reference: SecretRef::new("env", "deploy-token"),
            channel: Channel::Error,
        },
        secret_case("bad.leaky-error"),
    );
    assert!(
        error.contains("StepError::Failed"),
        "a leak in an error message is still caught, got {error:?}"
    );
    assert!(!error.contains(NEEDLE), "the rejection must not quote the secret, got {error:?}");
}

#[test]
fn the_kit_never_passes_vacuously() {
    let mistyped = rejection(MistypedOutputs, StepCase::new("bad.mistyped", Inputs::new()));
    assert!(
        mistyped.contains("the returned outputs must match the declared schema"),
        "a mistyped output must be caught against the outputs contract, got {mistyped:?}"
    );

    // Nothing about `Counting` hides it any more: its schema declares no input at all, so the
    // first pass and the re-run differ only in what the step kept to itself, and the idempotency
    // check is what stops it.
    let counting = rejection(
        Counting { runs: Arc::new(AtomicU64::new(0)) },
        StepCase::new("bad.counting", Inputs::new()),
    );
    assert!(
        counting.contains("re-running with the same inputs must produce the same outputs"),
        "a step that counts its runs must be caught against the idempotency contract, got {counting:?}"
    );

    // The secret check, proven not to be vacuous: this step declares `Port::Secrets`, resolves
    // the case's secret itself, and logs it. Only the secret pass can catch it — every other
    // pass runs the same code against a resolver that resolves nothing.
    let leaking = rejection(
        Leaky {
            name: "bad.self-resolving",
            reference: SecretRef::new("env", "deploy-token"),
            channel: Channel::Message,
        },
        secret_case("bad.self-resolving"),
    );
    assert!(
        leaking.contains("logged the secret in the message"),
        "a step that resolves its own secret and logs it must be caught, got {leaking:?}"
    );
}

/// Declares one output, returns it, and returns a *second* output whose key is the secret it was
/// handed. The values are innocuous, so only the key is at fault — and `check_outputs` reports an
/// undeclared key by naming it, which is why the kit's rejection must name the variant instead.
struct SecretKeyedOutput;

impl StepKind for SecretKeyedOutput {
    fn name(&self) -> &'static str {
        "bad.secret-key"
    }

    fn version(&self) -> Version {
        Version::new(1, 0, 0)
    }

    fn schema(&self) -> StepSchema {
        StepSchema {
            doc: "Returns an extra output keyed by the secret it was given.",
            inputs: vec![
                Field::new(
                    "token",
                    TypeRef::Builtin(ValueType::String),
                    "a token standing in for a resolved secret",
                )
                .with_default(Value::from("")),
            ],
            outputs: vec![Field::new(
                "message",
                TypeRef::Builtin(ValueType::String),
                "the echoed message",
            )],
        }
    }

    fn requires(&self) -> &'static [Port] {
        &[]
    }

    fn action(&self, _inputs: &Inputs) -> ActionClass {
        ActionClass::new(ActionKind::Other)
    }

    fn run(&self, _ctx: StepCtx, inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>> {
        let mut outputs = Outputs::new();
        outputs.insert("message".to_string(), Value::from("hello"));
        outputs.insert(text(&inputs, "token").to_string(), Value::from("an innocuous value"));
        Box::pin(std::future::ready(Ok(outputs)))
    }
}

#[test]
fn a_rejection_never_prints_the_secret_it_reports_as_an_output_key() {
    // `check_outputs` builds its `InvalidOutput` with `field` set to the offending output key, so
    // a step that returns the secret *as a key* puts it in the error's `Display`. The rejection
    // still has to say which contract broke, and still must not quote the key it was handed.
    let message = rejection(SecretKeyedOutput, secret_case("bad.secret-key"));
    assert!(
        message.contains("the returned outputs must match the declared schema"),
        "an undeclared output key must be caught against the outputs contract, got {message:?}"
    );
    assert!(
        !message.contains(NEEDLE),
        "the rejection must not quote the output key it is reporting, got {message:?}"
    );
}

#[test]
fn a_recording_sink_records_and_its_debug_prints_only_a_count() {
    let sink = Arc::new(RecordingSink::new());
    let logged: Arc<dyn LogSink> = Arc::clone(&sink) as Arc<dyn LogSink>;
    logged.record(LogRecord {
        step: "hello.echo".to_string(),
        level: LogLevel::Info,
        message: "a message nobody should read back".to_string(),
        fields: vec![("token".to_string(), "not-a-real-token".to_string())],
    });

    let shown = format!("{sink:?}");
    assert!(shown.contains("1"), "the count is printed: {shown}");
    assert!(!shown.contains("not-a-real-token"), "no value is printed: {shown}");
    assert!(!shown.contains("nobody should read"), "no message is printed: {shown}");
}
