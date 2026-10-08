//! The run log's engine-side contract ([#46](https://github.com/Keep-Shipping/harness/issues/46)):
//! every transition emits exactly one event of the right kind, a step is bracketed by
//! `step.started` and `step.finished`, and no secret value reaches the log — redaction happens
//! before the append, not inside the adapter.

use std::sync::Arc;
use std::time::Duration;

use ks_core::harness::Harness;
use ks_core::ids::RunId;
use ks_core::ports::BoxFuture;
use ks_core::ports::run_log::{RunEvent, RunLog, RunLogError};
use ks_core::ports::script_host::{Value, ValueType};
use ks_core::ports::secrets::{Redactor, SecretValue};
use ks_core::step::{
    ActionClass, ActionKind, CancellationToken, Field, Inputs, LogSink, Outputs, Port, Ports,
    StepCtx, StepError, StepKind, StepSchema, TypeRef, Version,
};
use ks_engine::journal::Journal;
use ks_testing::clock::FakeClock;
use ks_testing::run_log::RecordingRunLog;
use ks_testing::{block_on, step::RecordingSink};

/// The fake secret the redaction assertion hangs on.
const SECRET: &str = "s3cr3t-token";
/// An output *value* the log must never carry.
const VALUE: &str = "the-output-value";
/// How long the step "works" for, on the harness clock — the duration `step.finished` reports.
const WORK: Duration = Duration::from_millis(250);

/// A step with no inputs: it works for [`WORK`] on the harness clock and returns two fixed
/// outputs, or — when `fails` is set — an error carrying that string, which is the shape a real
/// dependency failure has, where a secret ends up inside a stack trace.
struct WorkStep {
    fails: Option<&'static str>,
}

impl StepKind for WorkStep {
    fn name(&self) -> &'static str {
        "sample.work"
    }

    fn version(&self) -> Version {
        Version::new(0, 1, 0)
    }

    fn schema(&self) -> StepSchema {
        let text = TypeRef::Builtin(ValueType::String);
        StepSchema {
            doc: "Works for a while, then returns two values or fails.",
            inputs: vec![],
            outputs: vec![
                Field::new("digest", text, "a digest-shaped value"),
                Field::new("tag", text, "a tag"),
            ],
        }
    }

    fn action(&self, _inputs: &Inputs) -> ActionClass {
        ActionClass::new(ActionKind::Other)
    }

    fn requires(&self) -> &'static [Port] {
        &[]
    }

    fn run(&self, ctx: StepCtx, _inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>> {
        let fails = self.fails;
        Box::pin(async move {
            ctx.clock().sleep(WORK).await;
            if let Some(detail) = fails {
                return Err(StepError::Failed(format!("registry refused: {detail}")));
            }
            let mut outputs = Outputs::new();
            outputs.insert("digest".to_string(), Value::from(VALUE));
            outputs.insert("tag".to_string(), Value::from("v1"));
            Ok(outputs)
        })
    }
}

fn harness(fails: Option<&'static str>) -> Harness {
    Harness::builder()
        .ports(Ports::default().with_clock(Arc::new(FakeClock::new())))
        .step_arc(Arc::new(WorkStep { fails }))
        .build()
        .expect("the fixture composition is valid")
}

/// A journal over a fresh recording fake and the redactor it scrubs with.
fn journal(redactor: Redactor) -> (Journal, Arc<RecordingRunLog>, RunId) {
    let log = Arc::new(RecordingRunLog::new());
    let run = RunId::from_parts(0, 1);
    let j = Journal::new(Arc::clone(&log) as Arc<dyn RunLog>, Arc::new(redactor), run.clone());
    (j, log, run)
}

/// The usual journal: no secrets registered, so nothing is scrubbed.
fn plain() -> (Journal, Arc<RecordingRunLog>, RunId) {
    journal(Redactor::new())
}

/// A redactor holding [`SECRET`].
fn redacting() -> Redactor {
    let mut redactor = Redactor::new();
    redactor.register(&SecretValue::new(SECRET.as_bytes().to_vec()));
    redactor
}

/// Journals `sample.work` through `j` and gives back what came out.
fn work(j: &Journal, fails: Option<&'static str>) -> Result<Outputs, StepError> {
    block_on(j.step(
        &harness(fails),
        "sample.work",
        Inputs::new(),
        CancellationToken::new(),
        sink(),
    ))
}

/// A sink that accepts anything; the run log, not the step log, is under test.
fn sink() -> Arc<dyn LogSink> {
    Arc::new(RecordingSink::new())
}

fn kinds(events: &[RunEvent]) -> Vec<&'static str> {
    events.iter().map(RunEvent::kind).collect()
}

/// One transition, as a plain fn the table can drive; each returns the future the `async fn`
/// transition does, so the call site `block_on`s it.
type Transition = for<'a> fn(&'a Journal) -> BoxFuture<'a, Result<(), RunLogError>>;

/// Every non-`step.*` transition emits exactly one event, of the right kind. Each runs against a
/// fresh journal, so "exactly one" is a claim about the transition, not about what happened to
/// be in the log before it.
#[test]
fn each_transition_emits_exactly_one_event() {
    fn hashes() -> Vec<String> {
        vec!["sha256:aa".into()]
    }
    let transitions: Vec<(&str, Transition)> = vec![
        ("run.started", |j| Box::pin(j.run_started("sha256:f", "push", "ada", false))),
        ("approval.requested", |j| Box::pin(j.approval_requested("d", "tty", hashes()))),
        ("approval.granted", |j| Box::pin(j.approval_granted("d", "ada", "tty", hashes()))),
        ("approval.denied", |j| {
            Box::pin(j.approval_denied("d", "ada", "tty", hashes(), "no, not on a Friday"))
        }),
        ("approval.expired", |j| Box::pin(j.approval_expired("d", "tty", hashes()))),
        ("approval.aborted", |j| Box::pin(j.approval_aborted("d", "ada", "tty", hashes()))),
        ("approval.rejected", |j| {
            Box::pin(j.approval_rejected("d", "mallory is not on @platform", "tty", hashes()))
        }),
        ("decide.answered", |j| {
            Box::pin(j.decide_answered(
                "d",
                "model",
                "v1",
                "sha256:aa",
                "sha256:bb",
                "yes",
                0.9,
                vec![("yes".into(), 0.9)],
                0.5,
                "ok",
            ))
        }),
        ("decision.overridden", |j| {
            Box::pin(j.decision_overridden("01ARZ3NDEKTSV4RRFFQ69G5FAV", "d", "ada", "wrong"))
        }),
        ("policy.refused", |j| Box::pin(j.policy_refused(Some("d"), "no-prod"))),
        ("attestation.attached", |j| {
            Box::pin(j.attestation_attached(
                "build",
                "sha256:aa",
                "https://slsa.dev/provenance/v1",
                "sha256:bb",
            ))
        }),
        ("run.finished", |j| Box::pin(j.run_finished("ok", hashes()))),
    ];

    for (kind, transition) in transitions {
        let (j, log, run) = plain();
        block_on(transition(&j)).expect("the fake accepts the entry");
        assert_eq!(kinds(&log.events()), [kind], "{kind} emitted the wrong events");
        assert_eq!(log.entries()[0].0, run, "{kind} is filed under the right run");
    }
}

/// A step is bracketed by `step.started` and `step.finished` whatever it does — a failure is an
/// event, not an exception to the bracket. The finished event carries output *names* and a
/// duration taken from the harness's clock, never a value, and the redacted error message when it
/// failed.
#[test]
fn a_step_is_bracketed_by_started_and_finished() {
    let (j, log, _) = plain();
    assert_eq!(work(&j, None).expect("the step runs").len(), 2);
    let events = log.events();
    assert_eq!(kinds(&events), ["step.started", "step.finished"]);
    let RunEvent::StepFinished { step, ok, outputs, duration_ms, error } = &events[1] else {
        panic!("expected step.finished, got {:?}", events[1]);
    };
    assert_eq!((step.as_str(), *ok, error.as_deref()), ("sample.work", true, None));
    assert_eq!(outputs, &["digest".to_string(), "tag".to_string()], "names only, sorted");
    assert_eq!(*duration_ms, 250, "measured on the harness clock");
    assert!(!format!("{events:?}").contains(VALUE), "an output value reached the log");

    let (j, log, _) = plain();
    assert!(matches!(work(&j, Some("boom")), Err(StepError::Failed(_))));
    let RunEvent::StepFinished { ok, outputs, error, .. } = &log.events()[1] else {
        panic!("expected step.finished");
    };
    assert!(!*ok && outputs.is_empty(), "a failed step returned no outputs");
    assert!(error.as_deref().expect("the error is recorded").contains("boom"));
}

/// The redaction contract: a secret passed in through any field comes out scrubbed. The journal
/// redacts before appending, so the adapter is never handed the raw text.
#[test]
fn a_secret_value_never_reaches_the_log() {
    let (j, log, _) = journal(redacting());

    block_on(j.run_started(SECRET, "push", SECRET, true)).expect("lands");
    block_on(j.approval_granted("deploy", SECRET, SECRET, vec![SECRET.into()])).expect("lands");
    block_on(j.approval_denied("deploy", SECRET, SECRET, vec![SECRET.into()], SECRET))
        .expect("lands");
    block_on(j.approval_expired("deploy", SECRET, vec![SECRET.into()])).expect("lands");
    block_on(j.approval_aborted("deploy", SECRET, SECRET, vec![SECRET.into()])).expect("lands");
    block_on(j.approval_rejected("deploy", SECRET, SECRET, vec![SECRET.into()])).expect("lands");
    block_on(j.decide_answered(
        "deploy",
        SECRET,
        SECRET,
        SECRET,
        SECRET,
        SECRET,
        0.5,
        vec![(SECRET.into(), 0.5)],
        0.5,
        SECRET,
    ))
    .expect("lands");
    block_on(j.decision_overridden(SECRET, SECRET, SECRET, SECRET)).expect("lands");
    block_on(j.policy_refused(Some(SECRET), SECRET)).expect("lands");
    block_on(j.run_finished(SECRET, vec![SECRET.into()])).expect("lands");
    // And through a step's own error message — where a secret really arrives.
    let error = work(&j, Some(SECRET)).expect_err("the step fails");

    let shown = format!("{:?}", log.events());
    assert!(!shown.contains(SECRET), "a secret reached the run log: {shown}");
    assert!(shown.contains("***"), "it was redacted, not dropped: {shown}");
    // Only the log is scrubbed: the caller keeps its own error.
    assert!(error.to_string().contains(SECRET), "the caller keeps its own error");
}

/// A log that will not take an entry fails the run — never a silent drop. There is no `Port`
/// variant for the run log (steps never see it), so the failure is `StepError::Failed`.
#[test]
fn a_log_that_refuses_an_entry_fails_closed() {
    /// A [`RunLog`] that refuses every entry.
    struct Refusing;
    impl RunLog for Refusing {
        fn append<'a>(
            &'a self,
            _run: &'a RunId,
            _event: RunEvent,
        ) -> BoxFuture<'a, Result<(), RunLogError>> {
            Box::pin(async { Err(RunLogError::Backend { message: "no space left".into() }) })
        }
    }

    let j = Journal::new(
        Arc::new(Refusing) as Arc<dyn RunLog>,
        Arc::new(Redactor::new()),
        RunId::from_parts(0, 1),
    );
    let error = block_on(j.run_started("sha256:f", "push", "ada", false))
        .expect_err("it refuses every entry");
    assert!(error.to_string().contains("no space left"), "{error}");

    // A step never runs, because its `step.started` could not be written.
    assert!(matches!(work(&j, None), Err(StepError::Failed(_))), "the step did not run");
}
