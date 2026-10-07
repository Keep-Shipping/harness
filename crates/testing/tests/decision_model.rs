//! Behaviour of the `DecisionModel` fakes: what they answer, what they
//! record, and that the conformance kit actually catches a misbehaving
//! adapter.

use std::collections::BTreeMap;

use ks_core::plan_summary::{Kind, Limits, PlanSummary, SummaryAttribute, SummaryEntry, Target};
use ks_core::ports::BoxFuture;
use ks_core::ports::decision_model::{
    Answer, ChoiceOption, DecisionError, DecisionModel, ESCALATE, ModelProfile, Question,
    RedactedState,
};
use ks_testing::block_on;
use ks_testing::decision_model::{FakeDecisionModel, NoneDecisionModel, conformance, fake_profile};

/// Compile-time check that `DecisionModel` is dyn-compatible.
fn assert_send_sync<T: ?Sized + Send + Sync>() {}

fn questions() -> BTreeMap<String, Question> {
    BTreeMap::from([
        (
            "deploy".to_string(),
            Question::choice(
                "Is this deploy safe to run?",
                vec![ChoiceOption::new(ESCALATE), ChoiceOption::new("approve")],
            ),
        ),
        (
            "storage".to_string(),
            Question::choice(
                "Is the storage rule correct?",
                vec![ChoiceOption::new(ESCALATE), ChoiceOption::new("reject")],
            ),
        ),
    ])
}

fn state(entries: usize) -> RedactedState {
    let summary = PlanSummary {
        risky: (0..entries)
            .map(|i| SummaryEntry {
                kind: Kind::Replace,
                address: format!("aws_instance.web_{i}"),
                attributes: vec![SummaryAttribute {
                    path: "instance_type".to_string(),
                    before: "t3.small".to_string(),
                    after: "m5.large".to_string(),
                    forces_replacement: true,
                }],
                reason: Some("instance type changed".to_string()),
            })
            .collect(),
        add: entries,
        destroy: entries,
        ..PlanSummary::default()
    };
    RedactedState::summarise(&summary, Target::Plain, &Limits::default())
}

/// A bare fake and the none adapter both escalate everything; only the none
/// adapter says so in its profile.
#[test]
fn an_unscripted_question_escalates() {
    let asked = questions();
    let scripted = Answer::certain(&asked["deploy"], "approve");
    let fake = FakeDecisionModel::new().with_answer("deploy", scripted.clone());
    let answers = block_on(fake.ask(state(1), asked.clone())).expect("the scripted answers");
    assert_eq!(answers["deploy"], scripted);
    assert_eq!(answers["storage"].choice, ESCALATE, "an unscripted question must escalate");
    assert_eq!(fake.calls().len(), 1);

    let answers =
        block_on(FakeDecisionModel::new().ask(state(1), asked.clone())).expect("answerable");
    let none = block_on(NoneDecisionModel.ask(state(1), asked)).expect("escalating is answering");
    for (label, answers) in [("fake", answers), ("none adapter", none)] {
        assert_eq!(answers.len(), 2, "{label}");
        for (id, answer) in &answers {
            assert_eq!(answer.choice, ESCALATE, "{label}/{id}");
            assert_eq!(answer.probabilities[ESCALATE], 1.0, "{label}/{id}");
            assert_eq!(answer.confidence, 1.0, "{label}/{id}: a stated answer, not a guess");
        }
    }
    assert_eq!(NoneDecisionModel.profile().max_state_bytes, 0, "it reads no state");
}

#[test]
fn a_fake_set_to_fail_fails_every_call() {
    let model = FakeDecisionModel::new().unavailable("429");
    let error = block_on(model.ask(state(0), questions())).expect_err("a model outage is an error");
    match error {
        DecisionError::Model { message } => assert_eq!(message, "429"),
        other => panic!("expected a Model error, got {other:?}"),
    }
    // The call is still recorded: a failed call is still a call.
    assert_eq!(model.calls().len(), 1);
}

#[test]
fn a_state_over_the_limit_is_truncated_not_refused() {
    let model = FakeDecisionModel::new()
        .with_profile(ModelProfile { max_state_bytes: 32, ..fake_profile() });
    let answers =
        block_on(model.ask(state(20), questions())).expect("a big plan is still answerable");
    assert_eq!(answers.len(), 2);

    let truncations = model.truncations();
    assert_eq!(truncations.len(), 1, "{truncations:?}");
    assert!(truncations[0].to_bytes <= 32, "{truncations:?}");
    assert_eq!(
        truncations[0].log_line(),
        format!("decision model: state truncated from {} to 32 bytes", truncations[0].from_bytes)
    );
}

/// A model that answers every question off-menu, with no probabilities and a
/// confidence that means nothing — an answer that *looks* like a decision.
struct LyingModel;

impl DecisionModel for LyingModel {
    fn ask<'a>(
        &'a self,
        _state: RedactedState,
        questions: BTreeMap<String, Question>,
    ) -> BoxFuture<'a, Result<BTreeMap<String, Answer>, DecisionError>> {
        let answers = questions
            .keys()
            .map(|id| (id.clone(), Answer::new("not-an-option", BTreeMap::new(), 1.0)))
            .collect();
        Box::pin(std::future::ready(Ok(answers)))
    }

    fn profile(&self) -> ModelProfile {
        ModelProfile {
            model_id: "liar".to_string(),
            version: "0".to_string(),
            calibration_family: "liar".to_string(),
            max_state_bytes: 4096,
        }
    }
}

#[test]
// The specific reason, not just the `conformance:` prefix: if the kit broke for
// an unrelated reason this would still pass on the prefix alone, which is the
// thing this test exists to prevent.
#[should_panic(expected = "does not fit its question")]
fn a_lying_model_fails_the_conformance_kit() {
    block_on(conformance(&LyingModel));
}

#[test]
fn the_fakes_pass_conformance_and_are_dyn_compatible() {
    assert_send_sync::<dyn DecisionModel>();
    block_on(conformance(&FakeDecisionModel::new()));
    block_on(conformance(&NoneDecisionModel));
}
