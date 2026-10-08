//! `decide` answers a risk question about a plan, and the line it returns is
//! written by the engine from the plan rather than by the model
//! ([#104](https://github.com/Keep-Shipping/harness/issues/104)).
//!
//! The two site pull requests are the acceptance: pr #412 adds and updates
//! only and the review auto-approves, pr #418 replaces a database and the
//! review waits for a human, and the reason line has to read `high 0.91
//! replaces aws_db_instance.main` — every word checkable against the plan.

use std::collections::BTreeMap;
use std::sync::Arc;

use ks_core::auto_rule::{self, Decision};
use ks_core::harness::Harness;
use ks_core::ports::decision_model::{Answer, DecisionModel, ESCALATE, ModelProfile};
use ks_core::ports::script_host::Value;
use ks_core::ports::secrets::Redactor;
use ks_core::step::{CancellationToken, Inputs, LogSink, Outputs as StepOutputs, Ports, StepError};
use ks_engine::decide::Decide;
use ks_engine::run::run_step;
use ks_testing::block_on;
use ks_testing::clock::FakeClock;
use ks_testing::decision_model::{FakeDecisionModel, fake_profile};
use ks_testing::step::{RecordingSink, StepCase, step_conformance};

/// The site's risk step, as the fixture spells it.
const SITE: &str = include_str!("../../lang/tests/fixtures/site-decide.ks");

/// The model id the fixture pins, and the version it reports.
const MODEL: &str = "typesafe/jev";
const VERSION: &str = "2026-10-01";

/// A `FakeDecisionModel` that answers as `typesafe/jev@2026-10-01`.
fn jev() -> FakeDecisionModel {
    FakeDecisionModel::new().with_profile(ModelProfile {
        model_id: MODEL.to_string(),
        version: VERSION.to_string(),
        ..fake_profile()
    })
}

/// An answer choosing `choice` at `probability`, splitting the rest evenly over
/// the other options — the distribution a real model would report.
fn answering(options: &[&str], choice: &str, probability: f64) -> Answer {
    let rest = (1.0 - probability) / (options.len() - 1) as f64;
    let probabilities = options
        .iter()
        .map(|option| ((*option).to_string(), if *option == choice { probability } else { rest }))
        .collect();
    Answer::new(choice, probabilities, probability)
}

/// The step's inputs for `model` over a plan of `rows`, each `(address, action)`
/// spelled the way `tofu.plan` emits them.
fn inputs(model: &str, rows: &[(&str, &str)]) -> Inputs {
    let resources = rows
        .iter()
        .map(|(address, action)| {
            Value::Map(BTreeMap::from([
                ("address".to_string(), Value::from(*address)),
                ("action".to_string(), Value::from(*action)),
            ]))
        })
        .collect();
    let plan = Value::Map(BTreeMap::from([("resources".to_string(), Value::List(resources))]));
    let mut inputs = Inputs::new();
    inputs.insert("model".to_string(), Value::from(model));
    inputs.insert("ask".to_string(), Value::from("How risky is this plan?"));
    inputs.insert("input".to_string(), plan);
    let returns = ["low", "medium", "high"].into_iter().map(Value::from).collect();
    inputs.insert("returns".to_string(), Value::List(returns));
    inputs
}

/// The `destroys` count the plan in `rows` reports: `tofu` counts a
/// replacement as one destroy, and a data source read as none.
fn destroys_of(rows: &[(&str, &str)]) -> usize {
    rows.iter().filter(|(_, action)| matches!(*action, "delete" | "replace")).count()
}

/// The site's `approval` rule, `risk is low ≥ 0.95 and plan.destroys == 0`,
/// read by hand: `approval` has no runtime yet, so the decision it would make
/// is lowered here from the `decide` step's own outputs.
fn review(outputs: &StepOutputs, destroys: usize) -> Decision {
    let confidence = match outputs.get("confidence") {
        Some(Value::Number(confidence)) => *confidence,
        _ => 0.0,
    };
    let low = outputs.get("answer") == Some(&Value::from("low"));
    auto_rule::decide(low && confidence >= 0.95, destroys)
}

/// A harness running `decide`, with `model` wired when one is given.
fn harness_with(model: Option<&Arc<FakeDecisionModel>>) -> Harness {
    let mut ports = Ports::default().with_clock(Arc::new(FakeClock::new()));
    if let Some(model) = model {
        ports = ports.with_decision_model(Arc::clone(model) as Arc<dyn DecisionModel>);
    }
    Harness::builder().ports(ports).step(Decide).build().expect("the composition is valid")
}

async fn decide(
    harness: &Harness,
    inputs: Inputs,
) -> Result<(StepOutputs, Arc<RecordingSink>), StepError> {
    let sink = Arc::new(RecordingSink::default());
    let outputs = run_step(
        harness,
        "decide",
        inputs,
        CancellationToken::new(),
        Arc::clone(&sink) as Arc<dyn LogSink>,
        Arc::new(Redactor::new()),
    )
    .await?;
    Ok((outputs, sink))
}

/// The site's risk step checks, and `probabilities` is one of its outputs.
#[test]
fn the_site_risk_step_checks_and_carries_probabilities() {
    let checked = ks_core::check(&ks_lang::parse(SITE));
    assert!(checked.diagnostics.is_empty(), "{:#?}", checked.diagnostics);

    let show_probabilities = SITE.replace("risk.reason", "risk.probabilities");
    let checked = ks_core::check(&ks_lang::parse(&show_probabilities));
    assert!(
        !checked.diagnostics.iter().any(|d| format!("{:?}", d.severity) == "Error"),
        "`risk.probabilities` is a declared output: {:#?}",
        checked.diagnostics,
    );
}

/// pr #412: +1 ~1 -0, the model says `low` with confidence 0.97, and the
/// review auto-approves — because the rule holds and nothing is destroyed.
#[test]
fn a_certain_low_answer_auto_approves() {
    let model = Arc::new(
        jev().with_answer("decide", answering(&["low", "medium", "high", ESCALATE], "low", 0.97)),
    );
    let harness = harness_with(Some(&model));
    let rows = [("aws_lb.api", "create"), ("aws_ecs_service.api", "update")];

    let (outputs, _sink) =
        block_on(decide(&harness, inputs(MODEL, &rows))).expect("the model answers");

    assert_eq!(outputs.get("answer"), Some(&Value::from("low")));
    assert_eq!(outputs.get("confidence"), Some(&Value::Number(0.97)));
    assert_eq!(
        outputs.get("reason"),
        Some(&Value::from("low 0.97 1 to add · 1 to change · 0 to destroy")),
        "nothing was destroyed, so the reason is the counts",
    );
    let Some(Value::Map(probabilities)) = outputs.get("probabilities") else {
        panic!("`probabilities` is a map: {:?}", outputs.get("probabilities"));
    };
    assert_eq!(probabilities.len(), 4, "one probability per answer on offer: {probabilities:?}");
    assert_eq!(probabilities.get("low"), Some(&Value::Number(0.97)));

    // The site's `auto:` rule, read the way the engine would read it.
    assert_eq!(review(&outputs, destroys_of(&rows)), Decision::AutoApprove, "auto-approved");
}

/// pr #418: replacing the database, the model says `high` at 0.91, and the
/// review waits. The reason names the replacement — the engine's words, not
/// the model's.
#[test]
fn a_replacement_waits_for_a_human_and_names_itself() {
    let model = Arc::new(
        jev().with_answer("decide", answering(&["low", "medium", "high", ESCALATE], "high", 0.91)),
    );
    let harness = harness_with(Some(&model));
    let rows = [("aws_db_instance.main", "replace")];

    let (outputs, _sink) =
        block_on(decide(&harness, inputs(MODEL, &rows))).expect("the model answers");

    assert_eq!(outputs.get("answer"), Some(&Value::from("high")));
    assert_eq!(outputs.get("confidence"), Some(&Value::Number(0.91)));
    assert_eq!(
        outputs.get("reason"),
        Some(&Value::from("high 0.91 replaces aws_db_instance.main")),
        "every word in the reason is checkable against the plan",
    );

    // The answer is not `low`, and the replacement is one destroy.
    assert_eq!(review(&outputs, destroys_of(&rows)), Decision::AskHuman, "waiting");
}

/// `model: none` escalates without reaching for the port, so the review asks a
/// human even though the plan destroys nothing.
#[test]
fn no_model_escalates_without_asking_one() {
    let model = Arc::new(jev());
    let harness = harness_with(Some(&model));
    let rows = [("aws_lb.api", "create")];

    let (outputs, sink) =
        block_on(decide(&harness, inputs("none", &rows))).expect("`none` is not a failure");

    assert_eq!(outputs.get("answer"), Some(&Value::from(ESCALATE)));
    assert_eq!(outputs.get("confidence"), Some(&Value::Number(1.0)));
    assert_eq!(
        outputs.get("reason"),
        Some(&Value::from("escalate 1.00 no model is configured (model: none)")),
    );
    assert_eq!(
        outputs.get("probabilities"),
        Some(&Value::Map(BTreeMap::from([(ESCALATE.to_string(), Value::Number(1.0))]))),
        "certain, and about one answer only",
    );
    assert!(model.calls().is_empty(), "a `none` step must not call a model: {:?}", model.calls());
    // An escalation is not `low`, so the rule cannot hold however safe the plan.
    assert_eq!(review(&outputs, destroys_of(&rows)), Decision::AskHuman, "waiting");
    assert!(
        sink.records().iter().any(|record| record.message.contains("escalating")),
        "the log says why: {:?}",
        sink.records(),
    );
}

/// A model the file did not ask for, a version it did not pin, and no adapter
/// at all are all red steps: a decision logged against the wrong model — or
/// against nobody — is unreproducible.
#[test]
fn the_step_has_to_run_on_the_model_it_names() {
    let model = Arc::new(jev());
    let harness = harness_with(Some(&model));
    let rows = [("aws_lb.api", "create")];

    for spec in ["typesafe/other", &format!("{MODEL}@2026-10-02")] {
        let error = block_on(decide(&harness, inputs(spec, &rows))).expect_err("not the named one");
        let message = error.to_string();
        assert!(message.contains(spec), "the refusal names what was asked for: {message}");
        assert!(message.contains(MODEL) || message.contains(VERSION), "{message}");
    }

    let unwired = harness_with(None);
    let error = block_on(decide(&unwired, inputs(MODEL, &rows))).expect_err("no model is wired");
    assert!(matches!(error, StepError::Port { .. }), "{error}");
    assert!(error.to_string().contains("no decision model was provided"), "{error}");
    assert!(model.calls().is_empty(), "a mismatch is caught before the model is asked");
}

/// Anything the step cannot ask about is refused before the model is: an input
/// that is not a plan, and a `returns:` the port's own contract rejects.
#[test]
fn a_question_the_step_cannot_ask_never_reaches_the_model() {
    let model = Arc::new(jev());
    let harness = harness_with(Some(&model));
    let rows = [("aws_lb.api", "create")];
    let with_returns = |words: Vec<String>| {
        let mut inputs = inputs(MODEL, &rows);
        let returns = words.into_iter().map(Value::from).collect();
        inputs.insert("returns".to_string(), Value::List(returns));
        inputs
    };
    let not_a_plan = {
        let mut inputs = inputs(MODEL, &rows);
        inputs.insert(
            "input".to_string(),
            Value::Map(BTreeMap::from([("a".to_string(), Value::from(1.0))])),
        );
        inputs
    };
    let too_many = (0..256).map(|i| i.to_string()).collect::<Vec<_>>();

    let cases = [
        (not_a_plan, "only a plan's `changes`"),
        (with_returns(vec![ESCALATE.to_string()]), "is on offer with every question"),
        (with_returns(vec!["low".into(), "low".into()]), "appears twice"),
        (with_returns(Vec::new()), "at least one answer"),
        (with_returns(too_many), "options, at most 255"),
    ];
    for (inputs, says) in cases {
        let error = block_on(decide(&harness, inputs)).expect_err("the question cannot be asked");
        assert!(error.to_string().contains(says), "{error}");
    }
    assert!(model.calls().is_empty(), "a bad question is caught before the model is asked");
}

#[test]
fn the_decide_step_passes_the_step_conformance_kit() {
    let model = Arc::new(
        jev().with_answer("decide", answering(&["low", "medium", "high", ESCALATE], "low", 0.97)),
    );
    let harness = harness_with(Some(&model));
    let rows = [("aws_lb.api", "create"), ("aws_db_instance.main", "replace")];

    block_on(step_conformance(&harness, StepCase::new("decide", inputs(MODEL, &rows))));
}
