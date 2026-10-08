//! Fake for the [`ScriptHost`] port: registered scripts (schema + scripted
//! outputs), the *shared* schema validation, and a record of which secret
//! names each run received — never their values.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ks_core::ports::BoxFuture;
use ks_core::ports::script_host::{
    ScriptHost, ScriptHostError, ScriptRef, StepSchema, Value, ValueType, Values,
};
use ks_core::ports::secrets::{Redactor, SecretBundle, SecretValue};
use ks_core::step::{LogSink, StepLog};

use crate::step::RecordingSink;

/// The name the conformance kit's secrets arrive under, and their value. Both live here so the
/// kit's hosts, its fixtures and its redaction assertions cannot drift apart.
const CONFORMANCE_SECRET: &str = "conformance-token";
const CONFORMANCE_TOKEN: &[u8] = b"hunter2";
/// The fixture that logs the token rather than returning it.
const LOG_SECRET_FIXTURE: &str = "log-secret";

/// What a scripted fake script computes: outputs from the validated inputs, with the step's
/// `StepLog` to log on — the two things a script process is handed and nothing else.
type ScriptFn = dyn Fn(&Values, &StepLog) -> Values + Send + Sync;

/// What a registered fake script does when [`ScriptHost::run`] reaches it,
/// after the input contract has been validated.
enum Behavior {
    /// Returns these fixed outputs (still validated against the schema).
    Outputs(Values),
    /// Computes outputs from the (already validated) inputs, logging on the
    /// step's `StepLog` like a real script's log frames do.
    Fn(Box<ScriptFn>),
    /// Simulates the process failing: exits nonzero (or never exits).
    Fail(ScriptHostError),
}

/// One registered fake script.
struct Registered {
    schema: StepSchema,
    behavior: Behavior,
}

/// A [`ScriptHost`] you script per test.
///
/// Register each script under its [`ScriptRef`] path with
/// [`with_script`](FakeScriptHost::with_script) (fixed outputs),
/// [`with_script_fn`](FakeScriptHost::with_script_fn) (computed outputs), or
/// [`with_failure`](FakeScriptHost::with_failure) (a nonzero exit). `run`
/// validates inputs and outputs with the *shared* [`StepSchema`] checks, so a
/// script misbehaving here fails exactly as it would under a real adapter,
/// and records which secret *names* it received — never values, in the
/// record or in `Debug`.
///
/// The log frames a scripted function emits go to the [`StepLog`] the run
/// hands it, so they are redacted on the way out exactly as a real script's
/// would be.
///
/// ```
/// use std::collections::BTreeMap;
/// use std::sync::Arc;
/// use ks_core::ports::script_host::{ScriptHost, ScriptRef, StepSchema, ValueType, Value};
/// use ks_core::ports::secrets::{Redactor, SecretBundle};
/// use ks_core::step::{LogSink, StepLog};
/// use ks_testing::{block_on, script_host::FakeScriptHost, step::RecordingSink};
///
/// let mut schema = StepSchema::default();
/// schema.inputs.insert("name".to_string(), ValueType::String);
/// schema.outputs.insert("greeting".to_string(), ValueType::String);
/// let mut outputs: BTreeMap<String, Value> = BTreeMap::new();
/// outputs.insert("greeting".to_string(), Value::from("hello, app"));
/// let host = FakeScriptHost::new().with_script(
///     &ScriptRef::new("scripts/greet.ts"),
///     schema,
///     outputs,
/// );
/// let sink = Arc::new(RecordingSink::new());
/// let log = StepLog::new("app.greet", Arc::new(Redactor::new()), Arc::clone(&sink) as Arc<dyn LogSink>);
/// let greeting = block_on(host.run(
///     &ScriptRef::new("scripts/greet.ts"),
///     &BTreeMap::from([("name".to_string(), Value::from("app"))]),
///     &SecretBundle::new(),
///     &log,
/// )).expect("the scripted script runs");
/// assert_eq!(greeting["greeting"], Value::from("hello, app"));
/// ```
#[derive(Default)]
pub struct FakeScriptHost {
    scripts: Mutex<BTreeMap<PathBuf, Registered>>,
    /// Secret names seen by each run, in order, duplicates included.
    secret_names: Mutex<Vec<String>>,
    /// Every script `run` was asked for, oldest first.
    runs: Mutex<Vec<ScriptRef>>,
}

impl FakeScriptHost {
    /// Creates a fake with no registered scripts; any `run` fails with
    /// [`ScriptHostError::Protocol`] until scripts are registered.
    pub fn new() -> FakeScriptHost {
        FakeScriptHost::default()
    }

    /// Registers `script` with `schema` and fixed `outputs` — the outputs the
    /// script would write to stdout. They are still validated against the
    /// schema, so scripted bugs surface as typed errors.
    pub fn with_script(
        mut self,
        script: &ScriptRef,
        schema: StepSchema,
        outputs: Values,
    ) -> FakeScriptHost {
        self.register(script, schema, Behavior::Outputs(outputs));
        self
    }

    /// Registers `script` with `schema` and outputs computed from the
    /// (already validated) inputs. The closure also gets the step's
    /// [`StepLog`], so a test can script the log frames a real script emits
    /// — including ones built from a secret — and watch them come out
    /// redacted, which is the contract the fourth `run` argument carries.
    pub fn with_script_fn(
        mut self,
        script: &ScriptRef,
        schema: StepSchema,
        outputs: impl Fn(&Values, &StepLog) -> Values + Send + Sync + 'static,
    ) -> FakeScriptHost {
        self.register(script, schema, Behavior::Fn(Box::new(outputs)));
        self
    }

    /// Registers `script` that fails like a real process: `exit_code` of
    /// `None` means it never exited. Input validation still runs first — a
    /// script that was never legally invoked cannot have failed.
    pub fn with_failure(
        mut self,
        script: &ScriptRef,
        schema: StepSchema,
        exit_code: Option<i32>,
        message: impl Into<String>,
    ) -> FakeScriptHost {
        self.register(
            script,
            schema,
            Behavior::Fail(ScriptHostError::ScriptFailed { exit_code, message: message.into() }),
        );
        self
    }

    /// Registers the [`fixtures`] — every conformance scenario runs against
    /// this fake out of the box.
    pub fn with_fixtures(self) -> FakeScriptHost {
        let mut fake = self;
        for fixture in fixtures() {
            let script = ScriptRef::new(fixture_path(fixture.name));
            // `log-secret` is the one fixture whose *behaviour* is on the log rather than on
            // stdout: it logs the token the run handed it and returns nothing. Every other
            // fixture is a fixed stdout object.
            fake = if fixture.name == LOG_SECRET_FIXTURE {
                fake.with_script_fn(&script, fixture.schema, |_inputs, log| {
                    log.info(
                        &format!("connecting with {}", String::from_utf8_lossy(CONFORMANCE_TOKEN)),
                        &[("token", &String::from_utf8_lossy(CONFORMANCE_TOKEN))],
                    );
                    Values::new()
                })
            } else {
                fake.with_script(&script, fixture.schema, fixture.returns)
            };
        }
        fake
    }

    fn register(&mut self, script: &ScriptRef, schema: StepSchema, behavior: Behavior) {
        self.scripts
            .lock()
            .expect("fake script host registry")
            .insert(script.path().to_path_buf(), Registered { schema, behavior });
    }

    /// Every secret name handed to `run`, oldest first, duplicates included.
    /// Names only — the values are not stored anywhere on the fake.
    pub fn received_secret_names(&self) -> Vec<String> {
        self.secret_names.lock().expect("fake script host secrets").clone()
    }

    /// Every script `run` was asked for, oldest first.
    pub fn runs(&self) -> Vec<ScriptRef> {
        self.runs.lock().expect("fake script host runs").clone()
    }
}

impl fmt::Debug for FakeScriptHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeScriptHost")
            .field("scripts", &self.scripts.lock().expect("fake script host registry").len())
            .field(
                "secret_names",
                &self.secret_names.lock().expect("fake script host secrets").len(),
            )
            .field("runs", &self.runs.lock().expect("fake script host runs").len())
            .finish()
    }
}

/// The shared `run` body: validate, execute, validate — in that order, with
/// the same [`StepSchema`] checks a real adapter must run. `log` is the
/// step's redacting logger, handed to scripted functions and ignored by the
/// fixed-output and failure behaviors, neither of which logs.
fn execute(
    registered: &Registered,
    inputs: &Values,
    log: &StepLog,
) -> Result<Values, ScriptHostError> {
    registered.schema.validate_inputs(inputs)?;
    match &registered.behavior {
        Behavior::Outputs(outputs) => {
            registered.schema.validate_outputs(outputs)?;
            Ok(outputs.clone())
        }
        Behavior::Fn(compute) => {
            let outputs = compute(inputs, log);
            registered.schema.validate_outputs(&outputs)?;
            Ok(outputs)
        }
        Behavior::Fail(error) => Err(error.clone()),
    }
}

impl ScriptHost for FakeScriptHost {
    fn schema<'a>(
        &'a self,
        script: &'a ScriptRef,
    ) -> BoxFuture<'a, Result<StepSchema, ScriptHostError>> {
        let result = self
            .scripts
            .lock()
            .expect("fake script host registry")
            .get(script.path())
            .map(|registered| registered.schema.clone())
            .ok_or_else(|| unknown_script(script));
        Box::pin(std::future::ready(result))
    }

    fn run<'a>(
        &'a self,
        script: &'a ScriptRef,
        inputs: &'a Values,
        secrets: &'a SecretBundle,
        log: &'a StepLog,
    ) -> BoxFuture<'a, Result<Values, ScriptHostError>> {
        let result = {
            let registry = self.scripts.lock().expect("fake script host registry");
            self.runs.lock().expect("fake script host runs").push(script.clone());
            for name in secrets.names() {
                self.secret_names.lock().expect("fake script host secrets").push(name.to_string());
            }
            match registry.get(script.path()) {
                Some(registered) => execute(registered, inputs, log),
                None => Err(unknown_script(script)),
            }
        };
        Box::pin(std::future::ready(result))
    }
}

fn unknown_script(script: &ScriptRef) -> ScriptHostError {
    ScriptHostError::Protocol {
        message: format!("no script registered at {}", script.path().display()),
    }
}

/// One conformance scenario: a schema, the inputs to run it with, what the
/// script writes to stdout before the host validates it (`returns`), and the
/// result [`ScriptHost::run`] must produce (`expected`).
#[derive(Debug, Clone)]
pub struct ScriptFixture {
    /// The scenario's name; adapters map it to an actual script file.
    pub name: &'static str,
    /// The script's declared contract.
    pub schema: StepSchema,
    /// The inputs to run the script with.
    pub inputs: Values,
    /// What the script returns on stdout, before schema validation.
    pub returns: Values,
    /// What `run` must produce for this fixture.
    pub expected: Result<Values, ScriptHostError>,
}

/// The `ScriptHost` conformance fixtures: a right-typed echo, a fixture
/// exercising every container and scalar type, and one scripted bug per
/// typed error — a wrong-typed output, a missing output, an undeclared
/// output, and a wrong-typed input — plus one fixture whose whole point is
/// the log: it logs the secret it was handed, as a message and as a field
/// value, and returns nothing. Real adapters (protocol settled in
/// [ADR 0009](../../../docs/adr/0009-typescript-escape-hatch-runtime.md)) map
/// each fixture to an actual script file and must reproduce
/// both its `returns` behaviour and its `expected` result; the fake maps
/// them in [`FakeScriptHost::with_fixtures`].
pub fn fixtures() -> Vec<ScriptFixture> {
    let echo_outputs = values_of(&[("greeting", "hello, conformance".into())]);
    let typed_outputs = values_of(&[
        ("tags", Value::List(vec![Value::from("web"), Value::from("app")])),
        ("labels", Value::Map(BTreeMap::from([("env".to_string(), Value::from("staging"))]))),
    ]);
    vec![
        ScriptFixture {
            name: "echo",
            schema: schema_of(&[("name", ValueType::String)], &[("greeting", ValueType::String)]),
            inputs: values_of(&[("name", "conformance".into())]),
            returns: echo_outputs.clone(),
            expected: Ok(echo_outputs),
        },
        ScriptFixture {
            name: "typed",
            schema: schema_of(
                &[("count", ValueType::Number)],
                &[("tags", ValueType::List), ("labels", ValueType::Map)],
            ),
            inputs: values_of(&[("count", Value::Number(3.0))]),
            returns: typed_outputs.clone(),
            expected: Ok(typed_outputs),
        },
        ScriptFixture {
            // Declares String, returns a Number.
            name: "wrong-type",
            schema: schema_of(&[], &[("x", ValueType::String)]),
            inputs: Values::new(),
            returns: values_of(&[("x", Value::Number(7.0))]),
            expected: Err(ScriptHostError::OutputTypeMismatch {
                name: "x".to_string(),
                expected: ValueType::String,
                found: ValueType::Number,
            }),
        },
        ScriptFixture {
            // Declares x and y, returns only x.
            name: "missing-output",
            schema: schema_of(&[], &[("x", ValueType::String), ("y", ValueType::Number)]),
            inputs: Values::new(),
            returns: values_of(&[("x", "ok".into())]),
            expected: Err(ScriptHostError::MissingOutput { name: "y".to_string() }),
        },
        ScriptFixture {
            // Returns an output it never declared.
            name: "extra-output",
            schema: schema_of(&[], &[("x", ValueType::String)]),
            inputs: Values::new(),
            returns: values_of(&[("x", "ok".into()), ("surprise", Value::Null)]),
            expected: Err(ScriptHostError::UnexpectedOutput { name: "surprise".to_string() }),
        },
        ScriptFixture {
            // Logs the secret it was handed — as the message and as a field value —
            // and returns nothing. Nothing about this is observable in the return
            // value: the kit asserts it on the log, where it must read `***`.
            name: LOG_SECRET_FIXTURE,
            schema: StepSchema::default(),
            inputs: Values::new(),
            returns: Values::new(),
            expected: Ok(Values::new()),
        },
        ScriptFixture {
            // The caller supplies a String where the script declared Number.
            name: "bad-input",
            schema: schema_of(&[("count", ValueType::Number)], &[("x", ValueType::String)]),
            inputs: values_of(&[("count", "three".into())]),
            returns: Values::new(),
            expected: Err(ScriptHostError::InputTypeMismatch {
                name: "count".to_string(),
                expected: ValueType::Number,
                found: ValueType::String,
            }),
        },
    ]
}

/// The `ScriptHost` conformance kit: every adapter must pass this.
///
/// `script_for` maps a fixture's name to the script that plays it — a path
/// under the adapter's fixture directory for real adapters, anything unique
/// for the fake. For each fixture, [`ScriptHost::schema`] must report the
/// fixture's schema and [`ScriptHost::run`] with the fixture's inputs must
/// produce the fixture's expected result. Runs carry a secret named
/// `conformance-token`; hosts must pass it to the script by file descriptor
/// and must never log it.
///
/// Every run gets a fresh [`Redactor`] holding that token, and a
/// [`StepLog`] over it the host writes its log frames
/// to — the same channel the engine hands a step. The kit then asserts the
/// whole log across the whole fixture set: the raw token appears in none of
/// it, and `***` appears, because the `log-secret` fixture's script logs the
/// secret it was handed.
pub async fn conformance(host: &dyn ScriptHost, script_for: impl Fn(&ScriptFixture) -> ScriptRef) {
    let mut secrets = SecretBundle::new();
    secrets.insert(CONFORMANCE_SECRET, SecretValue::new(CONFORMANCE_TOKEN.to_vec()));
    let mut redactor = Redactor::new();
    redactor.register(&SecretValue::new(CONFORMANCE_TOKEN.to_vec()));
    let sink = Arc::new(RecordingSink::new());
    let log = StepLog::new(
        "conformance.script",
        Arc::new(redactor),
        Arc::clone(&sink) as Arc<dyn LogSink>,
    );
    for fixture in fixtures() {
        let script = script_for(&fixture);
        let schema = host.schema(&script).await.unwrap_or_else(|error| {
            panic!("conformance: schema of {:?} failed: {error}", fixture.name)
        });
        assert_eq!(&schema, &fixture.schema, "conformance: schema mismatch for {:?}", fixture.name);
        let actual = host.run(&script, &fixture.inputs, &secrets, &log).await;
        match (&fixture.expected, actual) {
            (Ok(want), Ok(got)) => {
                assert_eq!(got, *want, "conformance: outputs of {:?}", fixture.name)
            }
            (Err(want), Err(got)) => {
                assert_eq!(got, *want, "conformance: error of {:?}", fixture.name)
            }
            (expected, actual) => {
                panic!("conformance: {:?} expected {expected:?}, got {actual:?}", fixture.name)
            }
        }
    }
    // The assertion is over the records themselves, not the count or a sample: a
    // single surviving byte of the token is the whole failure this kit exists for.
    let records = sink.records();
    let shown = format!("{records:?}");
    assert!(
        !shown.contains(std::str::from_utf8(CONFORMANCE_TOKEN).expect("the token is UTF-8")),
        "conformance: a secret reached the log: {shown}"
    );
    assert!(shown.contains("***"), "conformance: nothing was redacted at all: {shown}");
}

/// The path [`FakeScriptHost::with_fixtures`] registers each fixture under;
/// pass it to [`conformance`]'s `script_for` when testing that fake.
pub fn fixture_path(name: &str) -> String {
    format!("/ks-testing/fixtures/{name}.ts")
}

/// Builds a `Values` map from `(name, value)` pairs.
fn values_of(pairs: &[(&str, Value)]) -> Values {
    pairs.iter().map(|(name, value)| ((*name).to_string(), value.clone())).collect()
}

/// Builds a [`StepSchema`] from `(name, type)` pairs.
fn schema_of(inputs: &[(&str, ValueType)], outputs: &[(&str, ValueType)]) -> StepSchema {
    StepSchema {
        inputs: inputs.iter().map(|(name, ty)| ((*name).to_string(), *ty)).collect(),
        outputs: outputs.iter().map(|(name, ty)| ((*name).to_string(), *ty)).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_on;

    /// A logger over a redactor holding the kit's token — what a step would be handed.
    fn log_for(secret: Option<&[u8]>) -> (StepLog, Arc<RecordingSink>) {
        let mut redactor = Redactor::new();
        if let Some(bytes) = secret {
            redactor.register(&SecretValue::new(bytes.to_vec()));
        }
        let sink = Arc::new(RecordingSink::new());
        let log =
            StepLog::new("test.script", Arc::new(redactor), Arc::clone(&sink) as Arc<dyn LogSink>);
        (log, sink)
    }

    fn echo_script() -> ScriptRef {
        ScriptRef::new("scripts/greet.ts")
    }

    fn echo_host() -> FakeScriptHost {
        let mut schema = StepSchema::default();
        schema.inputs.insert("name".to_string(), ValueType::String);
        schema.outputs.insert("greeting".to_string(), ValueType::String);
        FakeScriptHost::new().with_script_fn(&echo_script(), schema, |inputs, _log| {
            let name = match inputs.get("name") {
                Some(Value::String(name)) => name.as_str(),
                _ => "stranger",
            };
            BTreeMap::from([("greeting".to_string(), Value::from(format!("hi, {name}")))])
        })
    }

    #[test]
    fn computed_outputs_see_the_validated_inputs() {
        let host = echo_host();
        let inputs = values_of(&[("name", "app".into())]);
        let (log, _) = log_for(None);
        let outputs = block_on(host.run(&echo_script(), &inputs, &SecretBundle::new(), &log))
            .expect("the fn script runs");
        assert_eq!(outputs["greeting"], Value::from("hi, app"));
    }

    #[test]
    fn a_script_logging_a_secret_is_redacted_on_the_way_out() {
        let schema = StepSchema::default();
        let host = FakeScriptHost::new().with_script_fn(&echo_script(), schema, |_inputs, log| {
            // What a script does with the value it was handed on the secret fd.
            let token = String::from_utf8_lossy(CONFORMANCE_TOKEN).to_string();
            log.info(&format!("connecting with {token}"), &[("token", &token)]);
            Values::new()
        });
        let (log, sink) = log_for(Some(CONFORMANCE_TOKEN));
        block_on(host.run(&echo_script(), &Values::new(), &SecretBundle::new(), &log))
            .expect("the fn script runs");

        let records = sink.records();
        let shown = format!("{records:?}");
        assert!(!shown.contains("hunter2"), "the raw token reached the sink: {shown}");
        // Redacted, not dropped: the frame is still there, with stars in it.
        let record = records.first().expect("the frame was recorded");
        assert_eq!(record.message, "connecting with ***");
        assert_eq!(record.fields, vec![("token".to_string(), "***".to_string())]);
    }

    #[test]
    fn unregistered_scripts_are_protocol_errors() {
        let host = FakeScriptHost::new();
        let (log, _) = log_for(None);
        let error = block_on(host.run(&echo_script(), &Values::new(), &SecretBundle::new(), &log))
            .expect_err("nothing is registered");
        assert!(matches!(error, ScriptHostError::Protocol { .. }), "{error}");
        assert!(block_on(host.schema(&echo_script())).is_err());
        // A failed lookup is still a recorded run attempt.
        assert_eq!(host.runs(), vec![echo_script()]);
    }

    #[test]
    fn the_fake_passes_conformance_through_the_trait() {
        let host = FakeScriptHost::new().with_fixtures();
        let dynamic: &dyn ScriptHost = &host;
        block_on(conformance(dynamic, |fixture| ScriptRef::new(fixture_path(fixture.name))));
    }
}
