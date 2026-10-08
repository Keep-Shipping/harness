//! Secrets and escape-hatch scripts ([#91](https://github.com/Keep-Shipping/harness/issues/91)):
//! a secret a script *logs* comes out `***` everywhere a log is read, and a secret a script
//! *returns* fails the step — the run log is one hop away from every line a step writes, so "it
//! was redacted downstream" is not a defence a script gets to rely on.
//!
//! The assertions are on the recorded text, never on a count: one surviving byte of the value is
//! the whole failure here, and a record that quietly went missing would pass a count-based check.

use std::sync::Arc;

use ks_core::harness::Harness;
use ks_core::ports::BoxFuture;
use ks_core::ports::run_log::{RunEvent, RunLog};
use ks_core::ports::script_host::{
    ScriptRef, StepSchema as ScriptSchema, Value, ValueType, Values,
};
use ks_core::ports::secrets::{Redactor, SecretBundle, SecretValue};
use ks_core::step::{
    ActionClass, ActionKind, CancellationToken, Field, Inputs, LogLevel, LogSink, Outputs, Port,
    Ports, StepCtx, StepError, StepKind, StepSchema, TypeRef, Version,
};
use ks_engine::journal::Journal;
use ks_testing::block_on;
use ks_testing::clock::FakeClock;
use ks_testing::run_log::RecordingRunLog;
use ks_testing::script_host::FakeScriptHost;
use ks_testing::step::RecordingSink;

/// The secret's name in the bundle and the value behind it.
const SECRET_NAME: &str = "db";
const SECRET_VALUE: &str = "s3cr3t-db-password";
/// The script the step runs: a path no adapter has, since the fake keys on it.
const SCRIPT_PATH: &str = "scripts/migrate.ts";
/// A string that embeds the secret rather than being it. Assembled from fragments so the source
/// carries no whole connection string that a secret scanner would — quite reasonably — flag.
const EMBEDDED: &str =
    concat!("postgres://", "app:", "s3cr3t-db-password", "@db.internal:5432/app");

/// What the scripted script does with the secret it was handed. One step kind covers every case;
/// only the script's behavior differs, which is the point — the engine cannot tell them apart.
#[derive(Clone, Copy)]
enum Behavior {
    /// Logs the revealed value as the message and as a field value, returns nothing.
    Log,
    /// Returns it verbatim as `leaked`.
    ReturnSecret,
    /// Returns a connection string that merely embeds it, as `url`.
    ReturnEmbedded,
    /// Returns an output *named* after the secret — one the step never declared, so only the
    /// secret check stands between it and an unredacted name in the error text.
    ReturnSecretNamed,
    /// Returns something of its own, containing no part of the secret.
    ReturnClean,
}

impl Behavior {
    /// What the script returns, or `None` when it only logs. A step declares exactly what its
    /// script returns: `check_outputs` and the fake's own schema check are both strict, so an
    /// extra declared output would fail the run before the secret check saw anything.
    fn returns(self) -> Option<(&'static str, Values)> {
        let one = |name: &'static str, value: Value| Some((name, values_of(&[(name, value)])));
        match self {
            Behavior::Log => None,
            Behavior::ReturnSecret => one("leaked", Value::from(SECRET_VALUE)),
            Behavior::ReturnEmbedded => one("url", Value::from(EMBEDDED)),
            Behavior::ReturnSecretNamed => {
                Some((SECRET_VALUE, values_of(&[(SECRET_VALUE, Value::from("x"))])))
            }
            Behavior::ReturnClean => one("summary", Value::from("the schema is up to date")),
        }
    }

    /// The output the *script* declares, which the fake validates against exactly as a real
    /// adapter would.
    fn script_declares(self) -> Option<Field> {
        let (name, _) = self.returns()?;
        Some(Field::new(name, TypeRef::Builtin(ValueType::String), "what the script reported back"))
    }

    /// The output the *step* declares it owes. Same, except the one named after the secret,
    /// which the step never promised — that is what makes it undeclared, and puts `check_outputs`,
    /// which names undeclared outputs in its error, in the path.
    fn step_declares(self) -> Option<Field> {
        match self {
            Behavior::ReturnSecretNamed => None,
            _ => self.script_declares(),
        }
    }
}

/// A `Values` map from `(name, value)` pairs.
fn values_of(pairs: &[(&str, Value)]) -> Values {
    pairs.iter().map(|(name, value)| ((*name).to_string(), value.clone())).collect()
}

/// A step kind that reaches the `ScriptHost` port the way a real escape-hatch step does: build a
/// [`SecretBundle`] and call `run` with `ctx.log()`, then return whatever came back.
struct ScriptStep {
    behavior: Behavior,
}

impl StepKind for ScriptStep {
    fn name(&self) -> &'static str {
        "sample.script"
    }

    fn version(&self) -> Version {
        Version::new(0, 1, 0)
    }

    fn schema(&self) -> StepSchema {
        StepSchema {
            doc: "Runs a script through the ScriptHost port.",
            inputs: vec![],
            outputs: self.behavior.step_declares().into_iter().collect(),
        }
    }

    fn action(&self, _inputs: &Inputs) -> ActionClass {
        ActionClass::new(ActionKind::Other)
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::ScriptHost]
    }

    fn run(&self, ctx: StepCtx, _inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>> {
        Box::pin(async move {
            let host = ctx.ports().script_host().ok_or(StepError::Port {
                port: Port::ScriptHost,
                message: "no script host was provided".to_string(),
            })?;
            // What the secrets pass resolves for this step, already registered with the run's
            // redactor by the time the step starts.
            let mut bundle = SecretBundle::new();
            bundle.insert(SECRET_NAME, SecretValue::new(SECRET_VALUE.as_bytes().to_vec()));
            // `ctx.log()` is the run's redacting step log: a script's frames go there, so they
            // meet the same `Redactor` a built-in step's do.
            // `redact` on the way into the error: the host's message can carry an output name
            // or a stderr tail, and a `StepError`'s text is printed unredacted.
            host.run(&ScriptRef::new(SCRIPT_PATH), &Values::new(), &bundle, ctx.log())
                .await
                .map_err(|error| StepError::Failed(ctx.log().redact(&error.to_string())))
        })
    }
}

/// The scripted script for `behavior`: it declares what the step declares, so the fake applies
/// the schema checks a real adapter would, and does whatever `behavior` says.
fn host_for(behavior: Behavior) -> FakeScriptHost {
    let mut schema = ScriptSchema::default();
    if let Some(field) = behavior.script_declares() {
        schema.outputs.insert(field.name.to_string(), ValueType::String);
    }
    let script = ScriptRef::new(SCRIPT_PATH);
    FakeScriptHost::new().with_script_fn(&script, schema, move |_inputs, log| match behavior {
        Behavior::Log => {
            log.log(
                LogLevel::Info,
                &format!("connecting with {SECRET_VALUE}"),
                &[("token", SECRET_VALUE)],
            );
            Values::new()
        }
        _ => behavior.returns().expect("a returning behavior returns").1,
    })
}

/// The harness: the step, the scripted host and a clock.
fn harness(behavior: Behavior) -> Harness {
    Harness::builder()
        .ports(
            Ports::default()
                .with_clock(Arc::new(FakeClock::new()))
                .with_script_host(Arc::new(host_for(behavior))),
        )
        .step_arc(Arc::new(ScriptStep { behavior }))
        .build()
        .expect("the fixture composition is valid")
}

/// The run's redactor, holding the one secret this run resolved.
fn redactor() -> Arc<Redactor> {
    let mut redactor = Redactor::new();
    redactor.register(&SecretValue::new(SECRET_VALUE.as_bytes().to_vec()));
    Arc::new(redactor)
}

/// `sample.script` over `sink`, through the engine's funnel.
fn drive(
    behavior: Behavior,
    sink: Arc<dyn LogSink>,
    redactor: Arc<Redactor>,
) -> Result<Outputs, StepError> {
    block_on(ks_engine::run::run_step(
        &harness(behavior),
        "sample.script",
        Inputs::new(),
        CancellationToken::new(),
        sink,
        redactor,
    ))
}

/// `drive` with a sink nobody will read.
fn run(behavior: Behavior) -> Result<Outputs, StepError> {
    drive(behavior, Arc::new(RecordingSink::new()), redactor())
}

/// A script logging a secret: redacted in the message, in the field value, and everywhere else.
#[test]
fn a_secret_a_script_logs_comes_out_redacted() {
    let sink = Arc::new(RecordingSink::new());
    drive(Behavior::Log, Arc::clone(&sink) as Arc<dyn LogSink>, redactor())
        .expect("logging a secret is not returning one");

    let records = sink.records();
    let frame = records
        .iter()
        .find(|record| record.message.contains("connecting"))
        .unwrap_or_else(|| panic!("the script's frame reached the sink: {records:?}"));
    assert_eq!(frame.message, "connecting with ***", "the message was not redacted");
    assert_eq!(
        frame.fields,
        vec![("token".to_string(), "***".to_string())],
        "the field value was not redacted"
    );
    assert!(!format!("{records:?}").contains(SECRET_VALUE), "the raw value survived in the output");
}

/// The same run through a [`Journal`], so the run log is read too. The journal records step
/// *transitions*, not log frames — it takes its own `LogSink` and its events carry output names
/// and error text — so this pins the other channel: nothing the script did leaves the value in
/// the run log either way. A stronger claim here would be false.
#[test]
fn a_secret_a_script_logs_never_reaches_the_run_log() {
    let run_log = Arc::new(RecordingRunLog::new());
    let journal = Journal::new(
        Arc::clone(&run_log) as Arc<dyn RunLog>,
        redactor(),
        ks_core::ids::RunId::from_parts(0, 1),
    );
    block_on(journal.step(
        &harness(Behavior::Log),
        "sample.script",
        Inputs::new(),
        CancellationToken::new(),
        Arc::new(RecordingSink::new()) as Arc<dyn LogSink>,
    ))
    .expect("logging a secret is not returning one");

    let events = run_log.events();
    assert!(
        !format!("{events:?}").contains(SECRET_VALUE),
        "the raw value reached the run log: {events:?}"
    );
    // It really ran, so the check above was about something.
    assert_eq!(
        events.iter().map(RunEvent::kind).collect::<Vec<_>>(),
        ["step.started", "step.finished"],
    );
}

/// A script returning a secret outright fails the step, naming the field and never the value.
#[test]
fn a_secret_a_script_returns_fails_the_step() {
    let error = run(Behavior::ReturnSecret).expect_err("the secret came back as an output");
    assert_eq!(
        error,
        StepError::InvalidOutput {
            field: "leaked".to_string(),
            reason: "contains a secret value; a step cannot return a secret".to_string()
        }
    );
    // The whole error text bypasses the redactor, so every part of it is checked.
    assert!(!error.to_string().contains(SECRET_VALUE), "{error}");
}

/// A secret merely *inside* a string is just as fatal: the value does not survive redaction
/// intact on its own either, so nothing downstream can use what the step returned.
#[test]
fn a_string_embedding_a_secret_fails_the_step_too() {
    let error = run(Behavior::ReturnEmbedded).expect_err("the secret was embedded in a string");
    let StepError::InvalidOutput { field, .. } = &error else {
        panic!("expected InvalidOutput, got {error:?}")
    };
    assert_eq!(field, "url");
    assert!(!error.to_string().contains(SECRET_VALUE), "{error}");
}

/// The check runs *before* the schema check because `check_outputs` puts an undeclared output's
/// name in its error, unredacted — a script naming an output after the secret would otherwise
/// have it read straight back out.
#[test]
fn an_output_named_after_the_secret_fails_before_the_schema_check() {
    let error = run(Behavior::ReturnSecretNamed).expect_err("the output was named after a secret");
    assert!(
        matches!(&error, StepError::InvalidOutput { reason, .. }
            if reason.contains("secret") && !reason.contains(SECRET_VALUE)),
        "{error}"
    );
    assert!(!error.to_string().contains(SECRET_VALUE), "{error}");
}

/// The check is about secrets, not about strings: an ordinary output still comes back.
#[test]
fn an_output_without_a_secret_still_comes_back() {
    let outputs = run(Behavior::ReturnClean).expect("nothing here is a secret");
    assert_eq!(outputs["summary"], Value::from("the schema is up to date"));
}
