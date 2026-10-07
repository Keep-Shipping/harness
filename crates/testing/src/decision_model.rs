//! Fakes for the [`DecisionModel`] port: a scriptable one and the
//! escalate-always one. Neither opens a socket, calls a model, or reads the
//! state it is handed beyond truncating it.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Mutex, MutexGuard};

use ks_core::plan_summary::{Kind, Limits, PlanSummary, SummaryAttribute, SummaryEntry, Target};
use ks_core::ports::BoxFuture;
use ks_core::ports::decision_model::{
    Answer, ChoiceOption, DecisionError, DecisionModel, ESCALATE, Fit, ModelProfile, Question,
    RedactedState, Truncation,
};

/// What a fake was asked, without the state itself: text belongs in a state a
/// test asserts on, not in a `Debug` a test prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionCall {
    /// One `ask` call: the state's size and the question keys asked.
    Ask {
        /// The state's length *before* truncation, so a test can prove it really
        /// was over the limit rather than quietly under it.
        state_bytes: usize,
        /// The keys of the questions asked, in the order given.
        question_ids: Vec<String>,
    },
}

/// The profile [`FakeDecisionModel`] reports when a test scripts another. Also
/// useful to an adapter author writing the same kind of test.
pub fn fake_profile() -> ModelProfile {
    ModelProfile {
        model_id: "fake".to_string(),
        version: "0".to_string(),
        calibration_family: "fake".to_string(),
        max_state_bytes: 64 * 1024,
    }
}

#[derive(Default)]
struct State {
    answers: BTreeMap<String, Answer>,
    default: Option<Answer>,
    error: Option<DecisionError>,
    profile: Option<ModelProfile>,
    calls: Vec<DecisionCall>,
    truncations: Vec<Truncation>,
}

/// A [`DecisionModel`] whose answers you script per test.
///
/// Every question gets its scripted answer, else the scripted default, else
/// [`Answer::certain`] on [`ESCALATE`] — so a test scripts the one question it
/// cares about and the rest escalate, rather than guess. Every call is recorded,
/// with the pre-truncation state size and any truncation the bound forced.
///
/// Answers are not validated: a test needs this to hand back a deliberately bad
/// one.
pub struct FakeDecisionModel {
    state: Mutex<State>,
}

impl Default for FakeDecisionModel {
    fn default() -> FakeDecisionModel {
        FakeDecisionModel { state: Mutex::new(State::default()) }
    }
}

impl FakeDecisionModel {
    /// Creates a fake that escalates every question.
    pub fn new() -> Self {
        Self::default()
    }

    /// Answers `id` with `answer`.
    #[must_use]
    pub fn with_answer(self, id: impl Into<String>, answer: Answer) -> Self {
        self.lock().answers.insert(id.into(), answer);
        self
    }

    /// Answers every question without its own script with `answer`.
    #[must_use]
    pub fn with_default(self, answer: Answer) -> Self {
        self.lock().default = Some(answer);
        self
    }

    /// Fails every call with `error`.
    #[must_use]
    pub fn with_error(self, error: DecisionError) -> Self {
        self.lock().error = Some(error);
        self
    }

    /// Fails every call as a model failure — transport, refusal, timeout.
    #[must_use]
    pub fn unavailable(self, message: impl Into<String>) -> Self {
        self.with_error(DecisionError::Model { message: message.into() })
    }

    /// Reports `profile` instead of [`fake_profile`].
    #[must_use]
    pub fn with_profile(self, profile: ModelProfile) -> Self {
        self.lock().profile = Some(profile);
        self
    }

    /// Every call the fake was asked, oldest first.
    pub fn calls(&self) -> Vec<DecisionCall> {
        self.lock().calls.clone()
    }

    /// Every state truncation the fake applied, oldest first. How a test sees
    /// that *this* adapter truncated, which the conformance kit cannot check
    /// from outside.
    pub fn truncations(&self) -> Vec<Truncation> {
        self.lock().truncations.clone()
    }

    /// The scripted profile, or [`fake_profile`].
    fn profile_of(&self) -> ModelProfile {
        self.lock().profile.clone().unwrap_or_else(fake_profile)
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("the fake's state is never held across a panic")
    }
}

impl fmt::Debug for FakeDecisionModel {
    /// Counts only: printing the answers would put a test's decisions into any
    /// log that formats the fake.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.lock();
        f.debug_struct("FakeDecisionModel")
            .field("calls", &state.calls.len())
            .field("answers", &state.answers.len())
            .field("truncations", &state.truncations.len())
            .finish()
    }
}

impl DecisionModel for FakeDecisionModel {
    fn ask<'a>(
        &'a self,
        state: RedactedState,
        questions: BTreeMap<String, Question>,
    ) -> BoxFuture<'a, Result<BTreeMap<String, Answer>, DecisionError>> {
        let profile = self.profile_of();
        let state_bytes = state.len();
        let Fit { truncated, .. } = state.fit(profile.max_state_bytes);
        let question_ids = questions.keys().cloned().collect();

        let result = {
            let mut locked = self.lock();
            locked.calls.push(DecisionCall::Ask { state_bytes, question_ids });
            if let Some(truncation) = truncated {
                locked.truncations.push(truncation);
            }
            if let Some(error) = locked.error.clone() {
                Err(error)
            } else {
                let answers = questions
                    .iter()
                    .map(|(id, question)| {
                        let scripted =
                            locked.answers.get(id).cloned().or_else(|| locked.default.clone());
                        let answer =
                            scripted.unwrap_or_else(|| Answer::certain(question, ESCALATE));
                        (id.clone(), answer)
                    })
                    .collect();
                Ok(answers)
            }
        };
        Box::pin(std::future::ready(result))
    }

    fn profile(&self) -> ModelProfile {
        self.profile_of()
    }
}

/// The adapter for a harness with no decision model: every question gets
/// [`ESCALATE`].
///
/// Not a fallback. "No model configured" fails with
/// [`DecisionError::NotConfigured`] and never reaches here; this adapter
/// existing keeps the two apart in a log — a run reporting "no decision model"
/// failed a step, a run that escalated asked a model that declined.
pub struct NoneDecisionModel;

impl DecisionModel for NoneDecisionModel {
    fn ask<'a>(
        &'a self,
        state: RedactedState,
        questions: BTreeMap<String, Question>,
    ) -> BoxFuture<'a, Result<BTreeMap<String, Answer>, DecisionError>> {
        let answers = questions
            .iter()
            .map(|(id, question)| (id.clone(), Answer::certain(question, ESCALATE)))
            .collect();
        // Its profile's `max_state_bytes` is 0, so this cuts the state to
        // nothing. Dropped rather than sent: this adapter reads no state, so
        // there is nothing to truncate and nothing to log.
        let _fit_to_nothing = state.fit(self.profile().max_state_bytes);
        Box::pin(std::future::ready(Ok(answers)))
    }

    fn profile(&self) -> ModelProfile {
        ModelProfile {
            model_id: "none".to_string(),
            version: "0".to_string(),
            calibration_family: "none".to_string(),
            max_state_bytes: 0,
        }
    }
}

impl fmt::Debug for NoneDecisionModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoneDecisionModel").finish_non_exhaustive()
    }
}

/// A small valid question set. Two questions with different options, so an
/// answer scripted for one cannot stand in for the other.
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

/// The state a model would be shown for a plan of `entries` replacements.
fn state_for(entries: usize) -> RedactedState {
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

/// The `DecisionModel` conformance kit.
///
/// Checks that the profile names the model, its version and its calibration
/// family; that the kit's own questions are askable; that an empty question set
/// is an empty answer set and not an error; that every asked question is
/// answered and nothing else; that every answer passes [`Answer::problem`];
/// and that an oversized state is answered rather than refused.
///
/// That last check catches an adapter that *errors* on a state over its limit.
/// Whether such an adapter actually truncated — and logged the truncation — is
/// not observable from outside it, so this kit does not claim to check it.
/// That is checked where it can be seen: `FakeDecisionModel::truncations()`
/// asserts this fake records the cut, and an adapter's own logs show whether
/// it wrote the [`Truncation::log_line`].
pub async fn conformance(model: &dyn DecisionModel) {
    let profile = model.profile();
    assert!(
        !profile.model_id.trim().is_empty()
            && !profile.version.trim().is_empty()
            && !profile.calibration_family.trim().is_empty(),
        "conformance: the profile must name the model, its version and its calibration \
         family: {profile:?}"
    );

    let questions = questions();
    ks_core::ports::decision_model::check_questions(&questions)
        .expect("conformance: the kit's own questions must be askable");

    let empty = model
        .ask(state_for(0), BTreeMap::new())
        .await
        .expect("conformance: an empty question set is an empty answer set, not an error");
    assert!(
        empty.is_empty(),
        "conformance: nothing asked must be answered with nothing, got {empty:?}"
    );

    let answers = model
        .ask(state_for(1), questions.clone())
        .await
        .expect("conformance: a valid question set must be answered, not refused");
    assert_eq!(
        answers.keys().collect::<Vec<_>>(),
        questions.keys().collect::<Vec<_>>(),
        "conformance: every question asked must be answered, and nothing else"
    );
    for (id, question) in &questions {
        let answer = answers.get(id).expect("conformance: every question must be answered");
        assert_eq!(
            answer.problem(question),
            None,
            "conformance: the answer to {id:?} does not fit its question"
        );
    }

    if let Err(error) = model.ask(state_for(400), questions).await {
        panic!(
            "conformance: a state over the adapter's limit must be answered, not refused: {error}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_on;

    #[test]
    fn the_fake_passes_conformance() {
        block_on(conformance(&FakeDecisionModel::new()));
    }

    #[test]
    fn the_none_adapter_passes_conformance() {
        block_on(conformance(&NoneDecisionModel));
    }

    #[test]
    fn the_fake_records_calls_and_truncations() {
        let model = FakeDecisionModel::new()
            .with_profile(ModelProfile { max_state_bytes: 32, ..fake_profile() });
        let answers = block_on(model.ask(state_for(4), questions())).expect("the scripted answers");
        assert_eq!(answers.len(), 2);

        let calls = model.calls();
        assert_eq!(calls.len(), 1, "{calls:?}");
        let DecisionCall::Ask { state_bytes, question_ids } = &calls[0];
        assert!(*state_bytes > 32, "the recorded size is the pre-truncation one: {state_bytes}");
        assert_eq!(question_ids, &["deploy".to_string(), "storage".to_string()]);

        let truncations = model.truncations();
        assert_eq!(truncations.len(), 1, "{truncations:?}");
        assert!(truncations[0].to_bytes <= 32, "{truncations:?}");
        assert_eq!(truncations[0].from_bytes, *state_bytes);
    }
}
