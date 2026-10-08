//! End to end: a script-like step that leaks a resolved secret four ways — raw,
//! base64, percent-encoded and JSON-escaped — through the [`ScriptHost`] port
//! over `ks-testing` fakes, then fails with the secret in its error.
//!
//! Every sink the run writes to is asserted: the step's log lines, and the run
//! log's `step.finished` event. Nothing may carry any of the four forms, and the
//! redaction marker must actually be there — an empty record would satisfy a
//! `!contains` assertion while proving nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ks_core::harness::Harness;
use ks_core::ids::{RunId, StepId};
use ks_core::ports::run_log::{RunEvent, RunLog};
use ks_core::ports::script_host::{
    ScriptHost, ScriptRef, StepSchema as ScriptSchema, Value, ValueType,
};
use ks_core::ports::secrets::{Redactor, Secrets};
use ks_core::step::{
    ActionClass, ActionKind, CancellationToken, Field, Inputs, LogSink, Outputs, Port, Ports,
    StepCtx, StepError, StepKind, StepSchema, TypeRef, Version,
};
use ks_engine::journal::Journal;
use ks_engine::secrets::resolve_step_secrets;
use ks_testing::clock::FakeClock;
use ks_testing::run_log::RecordingRunLog;
use ks_testing::script_host::FakeScriptHost;
use ks_testing::step::RecordingSink;
use ks_testing::{block_on, secrets::FakeSecrets};

/// The secret under test, chosen so it differs in *every* encoding: a space, a
/// double quote, a slash, an `@` and a newline all survive raw but change under
/// base64, percent-encoding and JSON escaping.
const SECRET: &str = "s3cr3t \"p@ss\"/word\n+x";

/// The reference the step resolves, and the name the fake has it under.
fn reference() -> ks_core::ports::secrets::SecretRef {
    ks_core::ports::secrets::SecretRef::new("env", "deploy-token")
}

// The three encoders the step leaks through. Hand-rolled here on purpose: the
// step stands in for a real script, and reusing ks-core's (private) encoders
// would make the test agree with the implementation by construction.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0] as u32,
            *chunk.get(1).unwrap_or(&0) as u32,
            *chunk.get(2).unwrap_or(&0) as u32,
        ];
        let bits = (b[0] << 16) | (b[1] << 8) | b[2];
        out.push(ALPHABET[(bits >> 18 & 0x3F) as usize] as char);
        out.push(ALPHABET[(bits >> 12 & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(bits >> 6 & 0x3F) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[(bits & 0x3F) as usize] as char } else { '=' });
    }
    out
}

fn percent_encode(bytes: &[u8]) -> String {
    let unreserved = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~');
    let mut out = String::new();
    for byte in bytes {
        if unreserved(*byte) {
            out.push(*byte as char);
        } else {
            out.push_str(&format!("%{:02X}", byte));
        }
    }
    out
}

fn json_escape(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in bytes {
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x08 => out.push_str("\\b"),
            0x0C => out.push_str("\\f"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            b if *b < 0x20 => out.push_str(&format!("\\u00{:02x}", byte)),
            b => out.push(*b as char),
        }
    }
    out
}

/// The script-like step: it resolves a secret through the [`Secrets`] port, runs
/// its script through the [`ScriptHost`] port with that bundle, echoes the value
/// in four encodings to its log output, and then fails with the raw value in its
/// error — the worst case a step can produce.
struct EchoSecretStep;

impl StepKind for EchoSecretStep {
    fn name(&self) -> &'static str {
        "sample.echo-secret"
    }

    fn version(&self) -> Version {
        Version::new(1, 0, 0)
    }

    fn schema(&self) -> StepSchema {
        StepSchema {
            doc: "Echoes a resolved secret in every encoding, then fails.",
            inputs: vec![Field::new(
                "script",
                TypeRef::Builtin(ValueType::String),
                "path of the script to run",
            )],
            outputs: vec![Field::new(
                "greeting",
                TypeRef::Builtin(ValueType::String),
                "what the script returned",
            )],
        }
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::ScriptHost, Port::Secrets]
    }

    fn optional(&self) -> &'static [Port] {
        &[]
    }

    fn action(&self, _inputs: &Inputs) -> ActionClass {
        ActionClass::new(ActionKind::Other)
    }

    fn run(
        &self,
        ctx: StepCtx,
        inputs: Inputs,
    ) -> ks_core::ports::BoxFuture<'_, Result<Outputs, StepError>> {
        Box::pin(async move {
            let Some(secrets) = ctx.ports().secrets() else {
                return Err(StepError::Port {
                    port: Port::Secrets,
                    message: "no secrets resolver was provided".to_string(),
                });
            };
            let Some(host) = ctx.ports().script_host() else {
                return Err(StepError::Port {
                    port: Port::ScriptHost,
                    message: "no script host was provided".to_string(),
                });
            };
            let Some(Value::String(script)) = inputs.get("script").cloned() else {
                return Err(StepError::InvalidInput {
                    field: "script".to_string(),
                    reason: "missing or not a string".to_string(),
                });
            };

            // The normal resolution path: a `SecretValue` from the port, never a
            // string that happened to hold it.
            let value = secrets.resolve(&reference(), &StepId::new(self.name())).await.map_err(
                |error| StepError::Port { port: Port::Secrets, message: error.to_string() },
            )?;
            let mut bundle = ks_core::ports::secrets::SecretBundle::new();
            bundle.insert("token", value);

            // The script runs with the bundle in hand, as a real script host would.
            host.run(&ScriptRef::new(script), &BTreeMap::new(), &bundle, ctx.log()).await.map_err(
                |error| StepError::Port { port: Port::ScriptHost, message: error.to_string() },
            )?;

            // The leak, in four forms, exactly as a careless script would print them.
            let logged = bundle.get("token").expect("just inserted").with_bytes(|bytes| {
                format!(
                    "raw: {} base64: {} percent: {} json: {}",
                    String::from_utf8_lossy(bytes),
                    base64(bytes),
                    percent_encode(bytes),
                    json_escape(bytes)
                )
            });
            ctx.log().info(&logged, &[]);

            // And the failure text, which the run log carries in `step.finished`.
            let message = bundle.get("token").expect("just inserted").with_bytes(|bytes| {
                format!("could not authenticate: {}", String::from_utf8_lossy(bytes))
            });
            Err(StepError::Failed(message))
        })
    }
}

/// The four forms of the secret, none of which may reach any output.
fn leaked_forms() -> Vec<String> {
    let bytes = SECRET.as_bytes();
    vec![SECRET.to_string(), base64(bytes), percent_encode(bytes), json_escape(bytes)]
}

#[test]
fn no_form_of_the_secret_reaches_the_log_sink_or_the_run_log() {
    let resolver = Arc::new(FakeSecrets::new().with(reference(), SECRET.as_bytes().to_vec()));

    let mut schema = ScriptSchema::default();
    schema.outputs.insert("greeting".to_string(), ValueType::String);
    let script = ScriptRef::new("scripts/echo-secret.ts");
    let harness = Harness::builder()
        .ports(
            Ports::default()
                .with_clock(Arc::new(FakeClock::new()))
                .with_secrets(Arc::clone(&resolver) as Arc<dyn Secrets>)
                .with_script_host(Arc::new(FakeScriptHost::new().with_script_fn(
                    &script,
                    schema,
                    |_inputs, _log| BTreeMap::from([("greeting".to_string(), Value::from("hi"))]),
                )) as Arc<dyn ScriptHost>),
        )
        .step_arc(Arc::new(EchoSecretStep))
        .build()
        .expect("the fixture composition is valid");

    // Resolve the step's secrets the way the engine does, registering each value
    // with the run's redactor *before* the step runs.
    let mut redactor = Redactor::new();
    let bundle = block_on(resolve_step_secrets(
        resolver.as_ref(),
        &[("token".to_string(), reference())],
        &StepId::new("sample.echo-secret"),
        &mut redactor,
    ))
    .expect("the reference is scripted");
    assert!(bundle.get("token").is_some(), "the step is handed its secret");

    let sink = Arc::new(RecordingSink::new());
    let log = Arc::new(RecordingRunLog::new());
    let journal = Journal::new(
        Arc::clone(&log) as Arc<dyn RunLog>,
        Arc::new(redactor),
        RunId::from_parts(1, 0),
    );

    let mut inputs = Inputs::new();
    inputs.insert("script".to_string(), Value::from(script.path().to_str().expect("utf-8 path")));
    let error = block_on(journal.step(
        &harness,
        "sample.echo-secret",
        inputs,
        CancellationToken::new(),
        Arc::clone(&sink) as Arc<dyn LogSink>,
    ))
    .expect_err("the step fails with the secret in its message");

    // The four encodings differ from one another, so a redactor that caught only
    // one of them would still leak three.
    let forms = leaked_forms();
    let distinct: BTreeSet<&String> = forms.iter().collect();
    assert_eq!(distinct.len(), 4, "the test secret must differ across encodings: {forms:?}");

    let messages: Vec<String> =
        sink.records().iter().map(|record| record.message.clone()).collect();
    assert!(!messages.is_empty(), "the step logged something");
    assert!(
        messages.iter().any(|message| message.contains("***")),
        "the redaction marker should be visible: {messages:?}"
    );
    for form in &forms {
        for message in &messages {
            assert!(!message.contains(form.as_str()), "log sink leaked {form:?}: {message}");
        }
        for event in log.events() {
            let rendered = format!("{event:?}");
            assert!(!rendered.contains(form.as_str()), "run log leaked {form:?}: {rendered}");
        }
    }

    // The run log's `step.finished` carries the failure, so the error path is
    // covered too — redacted by the journal, not by luck.
    let finished = log
        .events()
        .into_iter()
        .find(|event| matches!(event, RunEvent::StepFinished { ok: false, .. }))
        .expect("the failed step was journalled");
    let RunEvent::StepFinished { error: logged, .. } = finished else {
        unreachable!("matched above")
    };
    let logged = logged.expect("a failed step logs why");
    assert!(!logged.contains(SECRET), "the failure text leaked the secret: {logged}");
    assert!(logged.contains("***"), "the failure text should be redacted: {logged}");

    // And the step did fail for the reason the test staged.
    assert!(matches!(&error, StepError::Failed(_)));
    assert!(error.to_string().contains("could not authenticate"), "{error}");
}
