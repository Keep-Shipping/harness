//! The step conformance kit ([#21](https://github.com/Keep-Shipping/harness/issues/21)): every
//! [`StepKind`] must pass [`step_conformance`]. It is the first kit here for a *step* rather
//! than for an adapter — a step's contract is a property of the step, not of whichever adapter
//! it happens to reach for.
//!
//! [`ks_core::harness::Harness`] already checks a run's inputs and outputs against a step's
//! declared schema, and refuses a composition whose types do not resolve or whose ports nobody
//! provides. What it cannot check is how the *step* behaves: whether two identical runs return
//! identical outputs, and what a step does with a secret it holds. Those are step-side
//! contracts, so they belong in a kit a step's own tests run.
//!
//! [`RecordingSink`] is the one piece of infrastructure the kit needs: a [`LogSink`] that keeps
//! what it is given, so "never logged a secret" is an assertion rather than a hope. It prints a
//! count, never a value, for the same reason [`Redactor`] does.
//!
//! The kit panics on violation rather than returning a `Result`: a conformance run is a test,
//! and the message naming the broken contract is the whole output.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ks_core::harness::Harness;
use ks_core::ids::StepId;
use ks_core::ports::BoxFuture;
use ks_core::ports::script_host::{Value, ValueType};
use ks_core::ports::secrets::{
    Redactor, ResolverInfo, SecretRef, SecretValue, Secrets, SecretsError,
};
use ks_core::step::{
    ActionClass, ActionKind, CancellationToken, Field, Inputs, LogRecord, LogSink, Outputs, Port,
    Ports, StepCtx, StepError, StepKind, StepLog, StepSchema, TypeRef, Version,
};

/// How long the cancelled pass may take to come back [`StepError::Cancelled`] before the kit
/// calls it stuck. The check happens before the step is started, so this bounds the engine's
/// own pre-start check, not any work the step does — generous for the same reason: it is there
/// to catch a funnel that hangs, not to measure a machine.
pub const CANCEL_BUDGET: Duration = Duration::from_millis(100);

/// A [`LogSink`] that keeps every record it is handed, in order.
///
/// `Send + Sync`, so an `Arc<RecordingSink>` is usable as the `Arc<dyn LogSink>` the engine and
/// [`step_conformance`] drive a step with. `Debug` prints the record count only — a sink holding
/// a run's log lines must not become a way to print one.
///
/// ```
/// use std::sync::Arc;
/// use ks_core::step::{LogLevel, LogRecord, LogSink};
/// use ks_testing::step::RecordingSink;
///
/// let sink = Arc::new(RecordingSink::new());
/// sink.record(LogRecord {
///     step: "hello.echo".to_string(),
///     level: LogLevel::Info,
///     message: "step started".to_string(),
///     fields: vec![("action".to_string(), "other".to_string())],
/// });
///
/// assert_eq!(sink.records().len(), 1);
/// assert_eq!(format!("{sink:?}"), "RecordingSink { records: 1 }");
/// ```
#[derive(Default)]
pub struct RecordingSink {
    records: Mutex<Vec<LogRecord>>,
}

impl RecordingSink {
    /// Creates an empty sink.
    pub fn new() -> RecordingSink {
        RecordingSink::default()
    }

    /// Every record so far, in the order it arrived.
    #[must_use]
    pub fn records(&self) -> Vec<LogRecord> {
        self.records.lock().expect("recording sink poisoned").clone()
    }
}

impl LogSink for RecordingSink {
    fn record(&self, record: LogRecord) {
        self.records.lock().expect("recording sink poisoned").push(record);
    }
}

impl fmt::Debug for RecordingSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.records.lock().expect("recording sink poisoned").len();
        f.debug_struct("RecordingSink").field("records", &count).finish()
    }
}

/// One step's conformance scenario: the step's name and the inputs it will be driven with, plus
/// what the kit must additionally know about that run.
///
/// Build one with [`StepCase::new`], then say which input is a secret
/// ([`with_secret`](StepCase::with_secret)) and, rarely, how long the cancelled pass may take
/// ([`with_cancel_budget`](StepCase::with_cancel_budget)). `Debug` prints field names and the
/// budget, never a value.
///
/// ```
/// use ks_core::ports::script_host::Value;
/// use ks_core::step::Inputs;
/// use ks_testing::step::StepCase;
///
/// let mut inputs = Inputs::new();
/// inputs.insert("token".to_string(), Value::from("not-a-real-token"));
/// let case = StepCase::new("hello.echo", inputs).with_secret("token", "not-a-real-token");
///
/// let shown = format!("{case:?}");
/// assert!(shown.contains("hello.echo"), "the step is named: {shown}");
/// assert!(shown.contains("token"), "the secret's field is named: {shown}");
/// assert!(!shown.contains("not-a-real-token"), "no value is printed: {shown}");
/// ```
#[derive(Clone)]
pub struct StepCase {
    name: &'static str,
    inputs: Inputs,
    secret: Option<(String, String)>,
    cancel_budget: Duration,
}

impl StepCase {
    /// Describes the run the kit will drive `name` with.
    ///
    /// `inputs` may be partial: a declared input the step defaults is left out and reaches the
    /// step as its default.
    #[must_use]
    pub fn new(name: &'static str, inputs: Inputs) -> StepCase {
        StepCase { name, inputs, secret: None, cancel_budget: CANCEL_BUDGET }
    }

    /// Marks the input `field`, whose value is `value`, as the secret this step must never leak.
    ///
    /// The field and the value must be in `inputs` and the value must be exactly that string, so
    /// a scenario cannot name a secret the run never actually carries; a mistyped scenario
    /// panics here, at construction, rather than quietly proving nothing. Neither panic message
    /// prints a value — not the input's and not the one named here.
    ///
    /// The kit then drives the step with a [`Secrets`] port that resolves *every* reference to
    /// this value, and a [`Redactor`] that has never seen it.
    #[must_use]
    pub fn with_secret(mut self, field: &str, value: &str) -> StepCase {
        match self.inputs.get(field) {
            Some(Value::String(found)) if found == value => {}
            Some(Value::String(_)) => panic!(
                "conformance: input {field:?} is not the string this case names as its secret"
            ),
            Some(_) => {
                panic!("conformance: input {field:?} is not a string, so it cannot be a secret")
            }
            None => panic!("conformance: no input {field:?} to mark as a secret"),
        }
        self.secret = Some((field.to_string(), value.to_string()));
        self
    }

    /// Overrides [`CANCEL_BUDGET`] for this scenario, for a funnel that is known to take more
    /// than the default to refuse a cancelled run.
    #[must_use]
    pub fn with_cancel_budget(mut self, budget: Duration) -> StepCase {
        self.cancel_budget = budget;
        self
    }
}

/// Names and never values: a `StepCase` debug output must be safe to paste into a bug report,
/// exactly as [`RecordingSink`]'s is.
impl fmt::Debug for StepCase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StepCase")
            .field("name", &self.name)
            .field("inputs", &self.inputs.keys().collect::<Vec<_>>())
            .field("secret", &self.secret.as_ref().map(|(field, _)| field.as_str()))
            .field("cancel_budget", &self.cancel_budget)
            .finish()
    }
}

/// The scenario [`HelloEcho`] is proven against: `token` carrying a synthetic secret, and
/// `message` left out so the step runs on its declared default.
///
/// The token is the string `not-a-real-token` on purpose — it is a sample, and CONTRIBUTING
/// forbids committing anything that looks like a real credential.
#[must_use]
pub fn hello_echo_case() -> StepCase {
    let mut inputs = Inputs::new();
    inputs.insert("token".to_string(), Value::from("not-a-real-token"));
    StepCase::new("hello.echo", inputs).with_secret("token", "not-a-real-token")
}

/// The sample step: echoes its `message` back, uppercased, and says whether a token was
/// handed to it.
///
/// It exists so every check the kit makes has one step that passes it and one deliberately
/// broken step that does not, or the kit proves nothing
/// ([#21](https://github.com/Keep-Shipping/harness/issues/21)). It is also the example step
/// authors copy, which is why it is written the way a step is meant to be written: the token
/// never reaches a log line, and [`step_conformance`]'s secret check is what keeps it that way.
///
/// It lives here rather than in `ks_engine`'s `builtin_steps()` because it is a sample, not a
/// product step: `docs/STEPS.md` is generated from the built-ins and drift-checked, and this
/// step is not something the harness ships.
pub struct HelloEcho;

impl HelloEcho {
    /// The step's registered name; what [`hello_echo_case`] drives.
    pub const NAME: &'static str = "hello.echo";
}

impl StepKind for HelloEcho {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn version(&self) -> Version {
        Version::new(1, 0, 0)
    }

    fn schema(&self) -> StepSchema {
        StepSchema {
            doc: "Echoes a message back, uppercased, and reports whether it was given a token.",
            inputs: vec![
                Field::new("message", TypeRef::Builtin(ValueType::String), "the text to echo")
                    .with_default(Value::from("hello")),
                Field::new(
                    "token",
                    TypeRef::Builtin(ValueType::String),
                    "a token standing in for a resolved secret; it is never logged",
                )
                .with_default(Value::from("")),
            ],
            outputs: vec![
                Field::new("message", TypeRef::Builtin(ValueType::String), "the echoed message"),
                Field::new("upper", TypeRef::Builtin(ValueType::String), "the message, uppercased"),
            ],
        }
    }

    fn requires(&self) -> &'static [Port] {
        &[]
    }

    fn optional(&self) -> &'static [Port] {
        &[]
    }

    fn action(&self, _inputs: &Inputs) -> ActionClass {
        ActionClass::new(ActionKind::Other)
    }

    fn run(&self, ctx: StepCtx, inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>> {
        Box::pin(async move {
            let (message, token) = (text(&inputs, "message"), text(&inputs, "token"));
            // Whether a token is in use is worth recording; the token is not. A field that says
            // `set` is honest about the contract and cannot leak when the log is pasted into a
            // bug report.
            let state = if token.is_empty() { "unset" } else { "set" };
            ctx.log().info(&format!("echoing {message}"), &[("token", state)]);
            let mut outputs = Outputs::new();
            outputs.insert("message".to_string(), Value::from(message));
            outputs.insert("upper".to_string(), Value::from(message.to_uppercase()));
            Ok(outputs)
        })
    }
}

/// The step conformance kit. Panics, with a message naming the broken contract, when `step`
/// violates one of:
///
/// - a step is registered under the case's name;
/// - the step runs on conforming inputs and returns exactly its declared outputs — present,
///   typed, and nothing extra;
/// - re-running with the same inputs produces the same outputs, so a step is a function of its
///   inputs and not of a counter or a clock it kept to itself;
/// - when the case marked a secret, no record the sink receives — message, field name or field
///   value — carries it. The step is driven with the secret resolvable through the `Secrets`
///   port and unknown to the redactor, which is the only way a secret can reach a sink in the
///   clear; and no error message carries it either, because a `StepError` bypasses the redactor;
/// - a run cancelled before the step started comes back [`StepError::Cancelled`] within the
///   case's budget without having logged anything.
///
/// The last one is a property of the engine's funnel rather than of the step: the run is
/// refused before the step starts, so `run` is never called. The kit keeps it, and says so,
/// because it pins documented engine behaviour.
///
/// See the module docs for what this kit does *not* claim, and [`step_conformance`] for the kit
/// itself.
pub async fn step_conformance(harness: &Harness, case: StepCase) {
    let step = harness
        .step(case.name)
        .unwrap_or_else(|| panic!("conformance: no step is registered under {:?}", case.name));
    let schema = step.schema();

    let first = drive(
        harness,
        case.name,
        case.inputs.clone(),
        CancellationToken::new(),
        Arc::new(RecordingSink::new()),
        Arc::new(Redactor::new()),
        harness.ports(),
    )
    .await;
    let first = match first {
        Ok(outputs) => outputs,
        // `drive` ends in `check_outputs`, so a mistyped output arrives as an error rather
        // than a value. Report it against the contract it broke, not the generic one — but name
        // the variant, never the text: `InvalidOutput`'s `field` is whatever output key the step
        // returned, so a step that returns the secret as a key would be quoted back here, in the
        // panic message, in the CI log this kit exists to keep it out of. The reason string is
        // built from declared field names and type names, but the variant name costs nothing and
        // leaves no path through this arm that formats the error at all.
        Err(error @ StepError::InvalidOutput { .. }) => panic!(
            "conformance: the returned outputs must match the declared schema (StepError::{})",
            error_variant(&error)
        ),
        // `StepError`'s `Display` embeds its inner string, and a step's own `Failed` message can
        // hold anything the step put there — including a secret. Name the variant, never the text.
        Err(error) => panic!(
            "conformance: the step must run on conforming inputs (StepError::{})",
            error_variant(&error)
        ),
    };
    harness
        .check_outputs(step.as_ref(), &first)
        .expect("conformance: the returned outputs must match the declared schema");
    for field in &schema.outputs {
        assert!(
            first.contains_key(field.name),
            "conformance: declared output {:?} is missing from the returned outputs",
            field.name,
        );
    }

    let again = drive(
        harness,
        case.name,
        case.inputs.clone(),
        CancellationToken::new(),
        Arc::new(RecordingSink::new()),
        Arc::new(Redactor::new()),
        harness.ports(),
    )
    .await;
    let again = match again {
        Ok(outputs) => outputs,
        Err(error) => panic!(
            "conformance: the step must run on conforming inputs (StepError::{})",
            error_variant(&error)
        ),
    };
    // The kit does not claim outputs are secret-free — a schema output may be any string, and a
    // step may legitimately echo an input — so this reports *which* fields differ and never what
    // is in them. A second run that differs prints field names, not values.
    let differing: Vec<&str> = first
        .keys()
        .chain(again.keys())
        .filter(|field| first.get(*field) != again.get(*field))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(String::as_str)
        .collect();
    assert!(
        differing.is_empty(),
        "conformance: re-running with the same inputs must produce the same outputs; the declared \
         fields {differing:?} differ between the two runs"
    );

    if let Some((_, secret)) = &case.secret {
        // Why this pass is not vacuous: the engine registers every value it resolves with the
        // redactor, so anything a step legitimately holds is scrubbed on the way to a sink. Here
        // the port hands the step the plaintext and the redactor is empty — exactly what a step
        // that resolves its own secret really gets, and so what can reach a sink in the clear.
        let step_name = case.name;
        let mut ports = harness.ports().clone();
        ports = ports.with_secrets(Arc::new(EveryReference(secret.clone().into_bytes())));
        let sink = Arc::new(RecordingSink::new());
        let outcome = drive(
            harness,
            case.name,
            case.inputs.clone(),
            CancellationToken::new(),
            Arc::clone(&sink) as Arc<dyn LogSink>,
            Arc::new(Redactor::new()),
            &ports,
        )
        .await;
        for record in sink.records() {
            // The rule these three share: a message that fires *because* a secret was found must
            // not quote the record that carried it — the panic lands in the same test output and
            // CI log the check exists to protect. What is safe is what the step's author wrote:
            // the step's name, the level, and a field name (which is exactly the thing that must
            // not *be* the secret, and naming it says which channel leaked).
            assert!(
                !record.message.contains(secret.as_str()),
                "conformance: step {step_name:?} logged the secret in the message of an {:?} record",
                record.level,
            );
            for (name, value) in &record.fields {
                assert!(
                    !name.contains(secret.as_str()),
                    "conformance: step {step_name:?} used the secret as a field name on an {:?} record",
                    record.level,
                );
                assert!(
                    !value.contains(secret.as_str()),
                    "conformance: step {step_name:?} logged the secret as the value of the {:?} field on an {:?} record",
                    name,
                    record.level,
                );
            }
        }
        // `StepError` reaches run diagnostics without passing through the redactor, so a step
        // that puts a secret in its error leaks it no matter how well the sink behaved. Its
        // `Display` embeds the inner string by construction, so the variant name is the report.
        if let Err(error) = &outcome {
            assert!(
                !error.to_string().contains(secret.as_str()),
                "conformance: step {step_name:?} returned a StepError::{} carrying the secret, and error messages bypass the redactor",
                error_variant(error),
            );
        }
    }

    let cancelled_log = Arc::new(RecordingSink::new());
    let cancel = CancellationToken::new();
    cancel.cancel();
    // Only the drive is timed: harness construction is the test's, not the funnel's.
    let started = Instant::now();
    let outcome = drive(
        harness,
        case.name,
        case.inputs.clone(),
        cancel,
        Arc::clone(&cancelled_log) as Arc<dyn LogSink>,
        Arc::new(Redactor::new()),
        harness.ports(),
    )
    .await;
    // What is under test here is the funnel, not the step: `drive` refuses a cancelled run
    // before it builds a `StepCtx`, so `run` is never called and both facts below are
    // properties of `ks_engine`'s pre-start check. `StepError::Cancelled` is documented as
    // "cancelled before the step started", so this is exactly that variant — and ADR 0100
    // leaves the mid-run outcome open ("a waker-based future is future work"), so the kit
    // deliberately asserts nothing about a step that polls mid-run.
    assert_eq!(
        outcome.err(),
        Some(StepError::Cancelled),
        "conformance: a run cancelled before the step starts must be Cancelled, not run"
    );
    assert!(
        started.elapsed() < case.cancel_budget,
        "conformance: a cancelled run took {:?}, over the {:?} budget",
        started.elapsed(),
        case.cancel_budget,
    );
    // The count, not the records: what they hold is exactly the thing a log must never be
    // printed for.
    assert!(
        cancelled_log.records().is_empty(),
        "conformance: a cancelled step must not log, got {} records",
        cancelled_log.records().len()
    );
}

/// Runs `name` from `harness` the way the engine runs it, with public `ks_core` API only.
///
/// A copy of `ks_engine::run::run_step`, line for line, with one deviation: the ports handed to
/// the step come from the `ports` argument rather than from the harness, so the secret pass can
/// supply a [`Secrets`] port the harness never had. The copy is deliberate rather than a
/// dev-dependency cycle taken advantage of: a conformance library should not depend on the
/// engine it tests, and staying on `ks-core` alone keeps `ks-testing`'s whole dependency surface
/// to `ks-core` and `sha2`. The funnel is short enough to carry a comment instead of a
/// dependency. If the engine's funnel changes, this must change with it.
async fn drive(
    harness: &Harness,
    name: &str,
    inputs: Inputs,
    cancel: CancellationToken,
    log: Arc<dyn LogSink>,
    redactor: Arc<Redactor>,
    ports: &Ports,
) -> Result<Outputs, StepError> {
    let step = harness.step(name).ok_or_else(|| StepError::UnknownStep(name.to_string()))?;
    if cancel.is_cancelled() {
        return Err(StepError::Cancelled);
    }
    let inputs = harness.prepare_inputs(step.as_ref(), inputs)?;
    let step_log = StepLog::new(name, Arc::clone(&redactor), log);
    step_log.info("step started", &[("action", step.action(&inputs).to_string().as_str())]);
    let declared: Vec<Port> = step.requires().iter().chain(step.optional()).copied().collect();
    let ctx =
        StepCtx::new(ports.restricted_to(&declared), Arc::clone(harness.clock()), cancel, step_log);
    let outputs = step.run(ctx, inputs).await?;
    harness.check_outputs(step.as_ref(), &outputs)?;
    Ok(outputs)
}

/// A [`Secrets`] port that resolves *every* reference to one value: what the secret pass hands a
/// step that reaches for the port itself. A step cannot pick a reference the kit does not
/// answer, so the value it receives is always the case's marked secret — and no redactor has ever
/// seen it.
struct EveryReference(Vec<u8>);

impl Secrets for EveryReference {
    fn resolve<'a>(
        &'a self,
        _reference: &'a SecretRef,
        _for_step: &'a StepId,
    ) -> BoxFuture<'a, Result<SecretValue, SecretsError>> {
        Box::pin(std::future::ready(Ok(SecretValue::new(self.0.clone()))))
    }

    fn describe(&self) -> ResolverInfo {
        ResolverInfo {
            name: "step-conformance".to_string(),
            backend: "ks-testing, unregistered by design".to_string(),
            available: true,
            note: Some("resolves every reference to the case's secret".to_string()),
        }
    }
}

/// The first `&str` input under `name`; inputs arrive prepared, so a wrong type never reaches a
/// step. The idiom every step reaches for to read its own inputs, public so a step's own tests
/// can use the same one.
#[must_use]
pub fn text<'a>(inputs: &'a Inputs, name: &str) -> &'a str {
    match inputs.get(name) {
        Some(Value::String(text)) => text,
        _ => "",
    }
}

/// The [`StepError`] variant's name, for a report that must not quote the error: every variant's
/// `Display` embeds its inner string, and a step's own `Failed` message can hold a secret.
fn error_variant(error: &StepError) -> &'static str {
    match error {
        StepError::UnknownStep(_) => "UnknownStep",
        StepError::InvalidInput { .. } => "InvalidInput",
        StepError::InvalidOutput { .. } => "InvalidOutput",
        StepError::Cancelled => "Cancelled",
        StepError::Port { .. } => "Port",
        StepError::Failed(_) => "Failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_on;
    use crate::clock::FakeClock;

    #[test]
    fn the_sample_step_passes_conformance() {
        let harness = Harness::builder()
            .ports(Ports::default().with_clock(Arc::new(FakeClock::new())))
            .step(HelloEcho)
            .build()
            .expect("the sample composition is valid");
        block_on(step_conformance(&harness, hello_echo_case()));
    }
}
