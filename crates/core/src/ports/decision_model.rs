//! The [`DecisionModel`] port: asking a model a judgement it cannot be handed
//! ([#54](https://github.com/Keep-Shipping/harness/issues/54)).
//!
//! A step that needs a judgement calls this port with one redacted state and a
//! *set* of typed questions, and gets one answer per question: a choice from
//! that question's own options, a probability per option, and a confidence.
//! Questions travel together because the model must see one picture; a
//! per-question call cannot promise the answers are consistent.
//!
//! Three properties make those answers worth trusting:
//!
//! - **The state is redacted by construction.** [`RedactedState`] has no
//!   public constructor; only [`RedactedState::summarise`], which renders an
//!   already secret-stripped [`PlanSummary`], produces one. No value of the
//!   type carries raw plan JSON, so a model cannot be handed one by accident.
//! - **Truncation is deterministic and reported.** [`RedactedState::fit`] cuts
//!   on a character boundary and returns a [`Truncation`] naming what it cut.
//!   The port cannot log on an adapter's behalf, so logging it is the adapter's
//!   job: a state trimmed with no line in the log is the worst failure mode a
//!   decision model has, because the answer reads as reasoned while it was
//!   chosen from half the evidence.
//! - **`NotConfigured` is an error, never a default.** A step that asked for a
//!   judgement and got none fails, rather than continuing with an answer nobody
//!   chose.

use std::collections::BTreeMap;
use std::fmt;

use super::BoxFuture;
use crate::plan_summary::{Limits, PlanSummary, Target};

/// The option every question must offer: the answer "a human decides".
/// Required so an adapter that can decide nothing still has a legal answer.
pub const ESCALATE: &str = "escalate";

/// The most options a choice question may offer. Past this they stop being an
/// enum a person can read in a review comment and become free text.
pub const MAX_OPTIONS: usize = 255;

/// How far the probabilities may miss summing to 1 before an answer is
/// rejected: they are `f64`, and 200 options will not land on exactly 1.0. Far
/// too small to let a sum of 0.99 through.
const PROBABILITY_SLACK: f64 = 1e-6;

/// One way a [`Question`] may be answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChoiceOption {
    /// The stable id an [`Answer`] names to choose this option. Never empty,
    /// unique within its question, stable across runs: it is what lands in a
    /// run log and what a step matches on.
    pub id: String,
    /// Optional prose for whoever reads the decision; never parsed, so a model
    /// may ignore it.
    pub description: Option<String>,
}

impl ChoiceOption {
    /// An option with no description.
    pub fn new(id: impl Into<String>) -> ChoiceOption {
        ChoiceOption { id: id.into(), description: None }
    }

    /// An option with a description for the human reading the decision.
    pub fn described(id: impl Into<String>, description: impl Into<String>) -> ChoiceOption {
        ChoiceOption { id: id.into(), description: Some(description.into()) }
    }
}

/// A single typed question to put to the model.
///
/// Deliberately one variant and not `#[non_exhaustive]`: a step matches on the
/// answers, so a variant added without the step recompiling is the silent
/// break this crate versions against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Question {
    /// Pick exactly one of `options`, in answer to `instructions`.
    Choice {
        /// What is being asked, in the plain terms a reviewer would use. Must
        /// not be blank: an empty instruction leaves the model guessing what is
        /// being judged, and the answer then looks reasoned while resting on
        /// nothing.
        instructions: String,
        /// The answers on offer: between one and [`MAX_OPTIONS`], with unique
        /// non-empty ids, one of which must be [`ESCALATE`].
        options: Vec<ChoiceOption>,
    },
}

impl Question {
    /// A choice question, unvalidated. Prefer building the whole set and
    /// validating it once with [`check_questions`].
    pub fn choice(instructions: impl Into<String>, options: Vec<ChoiceOption>) -> Question {
        Question::Choice { instructions: instructions.into(), options }
    }

    /// The options this question offers.
    fn options(&self) -> &[ChoiceOption] {
        let Question::Choice { options, .. } = self;
        options
    }

    /// Why this question cannot be asked, or `None` when it can.
    ///
    /// Checked in a fixed order, so the same broken question always reports the
    /// same first thing wrong with it.
    #[must_use]
    pub fn problem(&self) -> Option<String> {
        let Question::Choice { instructions, options } = self;
        if instructions.trim().is_empty() {
            return Some("the question has no instructions".to_string());
        }
        if options.is_empty() {
            return Some("a choice question needs at least one option".to_string());
        }
        if options.len() > MAX_OPTIONS {
            return Some(format!("{} options, at most {MAX_OPTIONS}", options.len()));
        }
        if options.iter().any(|option| option.id.is_empty()) {
            return Some("an option has an empty id".to_string());
        }
        let mut seen: Vec<&str> = Vec::with_capacity(options.len());
        for option in options {
            if seen.contains(&option.id.as_str()) {
                return Some(format!("option id `{}` appears twice", option.id));
            }
            seen.push(&option.id);
        }
        if !options.iter().any(|option| option.id == ESCALATE) {
            return Some("every question must offer `escalate`".to_string());
        }
        None
    }
}

/// Checks a set of questions against the contract, keyed by the map key the
/// caller filed them under.
///
/// Returns the first [`DecisionError::InvalidQuestion`] named by that key, so a
/// caller that asked twenty questions learns which one to fix. An empty set is
/// valid.
pub fn check_questions(questions: &BTreeMap<String, Question>) -> Result<(), DecisionError> {
    for (id, question) in questions {
        if let Some(reason) = question.problem() {
            return Err(DecisionError::InvalidQuestion { id: id.clone(), reason });
        }
    }
    Ok(())
}

/// One question's answer: what was chosen, how the options compared, and how
/// much the adapter trusts itself.
#[derive(Debug, Clone, PartialEq)]
pub struct Answer {
    /// The id of the chosen option — always one the question offered.
    pub choice: String,
    /// A probability for every option the question offered, and for no others,
    /// summing to 1 to within [`PROBABILITY_SLACK`] (1e-6) — enough to absorb
    /// `f64` rounding, too little for a sum of 0.99.
    pub probabilities: BTreeMap<String, f64>,
    /// How well calibrated the distribution above is, in `0..=1`.
    ///
    /// *Not* the same number as `probabilities[choice]`: the probabilities rank
    /// the options, the confidence says how often this adapter's
    /// high-probability answers are right. Comparing two adapters' confidence
    /// is meaningless unless their [`ModelProfile::calibration_family`]s
    /// match.
    pub confidence: f64,
}

impl Answer {
    /// An answer built from its three parts, unchecked. Use
    /// [`certain`](Self::certain) when the adapter will not guess; whatever
    /// this builds, [`problem`](Self::problem) decides whether it is
    /// answerable.
    pub fn new(
        choice: impl Into<String>,
        probabilities: BTreeMap<String, f64>,
        confidence: f64,
    ) -> Answer {
        Answer { choice: choice.into(), probabilities, confidence }
    }

    /// Probability 1 for `id`, 0 for every other option, confidence 1 — what an
    /// adapter that will not guess says. The certainty is honest precisely
    /// because nothing was guessed.
    #[must_use]
    pub fn certain(question: &Question, id: &str) -> Answer {
        let probabilities = question
            .options()
            .iter()
            .map(|option| (option.id.clone(), if option.id == id { 1.0 } else { 0.0 }))
            .collect();
        Answer::new(id, probabilities, 1.0)
    }

    /// Why this answer cannot be used against `question`, or `None` when it can.
    /// Checked in a fixed order. Every reason is a way an answer reads as a
    /// decision while being something else: an off-menu choice, a distribution
    /// describing no set of options, a meaningless confidence, or a "choice"
    /// that is not the one the distribution prefers.
    #[must_use]
    pub fn problem(&self, question: &Question) -> Option<String> {
        let options = question.options();
        let offered = options.iter().map(|option| option.id.as_str()).collect::<Vec<_>>();

        if !offered.contains(&self.choice.as_str()) {
            return Some(format!("chose {:?}, which the question did not offer", self.choice));
        }
        if self.probabilities.len() != options.len()
            || !options.iter().all(|option| self.probabilities.contains_key(&option.id))
        {
            return Some(format!(
                "{} probabilities for {} options: every option needs exactly one probability",
                self.probabilities.len(),
                options.len()
            ));
        }
        for (id, probability) in &self.probabilities {
            if !probability.is_finite() || !(0.0..=1.0).contains(probability) {
                return Some(format!("probability for {id:?} is not in 0..=1"));
            }
        }
        let sum: f64 = self.probabilities.values().sum();
        if (sum - 1.0).abs() > PROBABILITY_SLACK {
            return Some(format!("probabilities sum to {sum}, not 1"));
        }
        if !self.confidence.is_finite() || !(0.0..=1.0).contains(&self.confidence) {
            return Some(format!("confidence {} is not in 0..=1", self.confidence));
        }
        let chosen = self.probabilities[&self.choice];
        for (id, probability) in &self.probabilities {
            if *probability > chosen + PROBABILITY_SLACK {
                return Some(format!(
                    "{:?} has probability {chosen}, but {id:?} has {probability}",
                    self.choice
                ));
            }
        }
        None
    }
}

/// The state a model is shown: rendered from an already secret-stripped
/// [`PlanSummary`], and nothing else. No public constructor, private field, so
/// the only way to hold one is [`summarise`](Self::summarise) — and no
/// renderer can leak a value the summary already dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedState {
    text: String,
}

impl RedactedState {
    /// Renders `summary` for `target` within `limits` as the model's state.
    #[must_use]
    pub fn summarise(summary: &PlanSummary, target: Target, limits: &Limits) -> RedactedState {
        RedactedState { text: summary.render(target, limits) }
    }

    /// The rendered text, as the model will see it.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The rendered text's length in bytes, the size [`fit`](Self::fit)
    /// compares against.
    pub fn len(&self) -> usize {
        self.text.len()
    }

    /// Whether the rendered text is empty.
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// Cuts the state to at most `max_bytes`, on a character boundary.
    ///
    /// A state within the bound comes back untouched with no [`Truncation`]. A
    /// longer one is cut at the highest character boundary at or below
    /// `max_bytes` — the same cut every time, so two runs of the same plan see
    /// the same evidence — and reports what was cut. Adapters log that report;
    /// the port cannot log it for them. `max_bytes` of 0 means "this adapter
    /// reads no state".
    #[must_use]
    pub fn fit(self, max_bytes: usize) -> Fit {
        let from_bytes = self.len();
        if from_bytes <= max_bytes {
            return Fit { state: self, truncated: None };
        }
        let mut to_bytes = max_bytes;
        while to_bytes > 0 && !self.text.is_char_boundary(to_bytes) {
            to_bytes -= 1;
        }
        Fit {
            state: RedactedState { text: self.text[..to_bytes].to_string() },
            truncated: Some(Truncation { from_bytes, to_bytes }),
        }
    }
}

/// What the model will see, and what was cut to get there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fit {
    /// The state within the bound — the only text an adapter may send.
    pub state: RedactedState,
    /// How much was cut, or `None` when nothing was. An adapter must log it.
    pub truncated: Option<Truncation>,
}

/// How many bytes of a [`RedactedState`] a bound removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Truncation {
    /// The state's length before the cut.
    pub from_bytes: usize,
    /// The length it was cut to; never more than the adapter's bound.
    pub to_bytes: usize,
}

impl Truncation {
    /// The line to log. A truncation nobody logged is one nobody knows about.
    #[must_use]
    pub fn log_line(&self) -> String {
        format!(
            "decision model: state truncated from {} to {} bytes",
            self.from_bytes, self.to_bytes
        )
    }
}

/// What an adapter says about the model behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelProfile {
    /// The provider's id for the model.
    pub model_id: String,
    /// The pinned version. A model id alone does not identify a model for long
    /// — providers retire and quietly change what sits behind an id — so a
    /// decision logged against "the model" is unreproducible without this.
    pub version: String,
    /// The family [`Answer::confidence`] is measured on; comparable only within
    /// a family.
    pub calibration_family: String,
    /// The bound [`RedactedState::fit`] cuts to. Never a rejection; 0 means the
    /// adapter reads no state at all.
    pub max_state_bytes: usize,
}

/// Why a [`DecisionModel`] call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionError {
    /// A step asked for a decision and the harness has no model wired. An error
    /// on purpose: "approve" that nobody approved is worse than a red step.
    NotConfigured,
    /// A question cannot be asked as written.
    InvalidQuestion {
        /// The key the question was filed under.
        id: String,
        /// What is wrong with it, safe to print.
        reason: String,
    },
    /// An answer cannot be used against the question it claims to answer.
    InvalidAnswer {
        /// The key of the question the answer names.
        id: String,
        /// What is wrong with it, safe to print.
        reason: String,
    },
    /// The adapter's model failed: transport, a provider refusal, a timeout.
    Model {
        /// What the model reported, safe to print.
        message: String,
    },
}

impl fmt::Display for DecisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecisionError::NotConfigured => f.write_str(
                "no decision model is configured: a step asked for one and the harness has none wired",
            ),
            DecisionError::InvalidQuestion { id, reason } => {
                write!(f, "question {id:?} cannot be asked: {reason}")
            }
            DecisionError::InvalidAnswer { id, reason } => {
                write!(f, "answer to {id:?} is not valid: {reason}")
            }
            DecisionError::Model { message } => write!(f, "decision model failed: {message}"),
        }
    }
}

impl std::error::Error for DecisionError {}

/// The `DecisionModel` port: one state, one set of questions, one answer per
/// question.
pub trait DecisionModel: Send + Sync {
    /// Asks every question in `questions` against `state`.
    ///
    /// One call, one state, the whole set, so the answers are consistent with
    /// each other. The returned map has exactly the question set's keys: a
    /// missing answer means the step got no judgement.
    ///
    /// An adapter must truncate with [`RedactedState::fit`] against
    /// [`profile`](DecisionModel::profile)'s `max_state_bytes` and log the
    /// [`Truncation`]; answer only from the options each question offered, with
    /// a probability for each and a confidence in `0..=1`; and fail with a
    /// [`DecisionError`] rather than panicking, so a provider outage is a red
    /// step and not a dead run.
    fn ask<'a>(
        &'a self,
        state: RedactedState,
        questions: BTreeMap<String, Question>,
    ) -> BoxFuture<'a, Result<BTreeMap<String, Answer>, DecisionError>>;

    /// What this adapter says about the model behind it.
    fn profile(&self) -> ModelProfile;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan_summary::{Kind, SummaryAttribute, SummaryEntry};

    fn assert_send_sync<T: ?Sized + Send + Sync>() {}

    #[test]
    fn the_decision_model_trait_is_dyn_compatible() {
        assert_send_sync::<dyn DecisionModel>();
    }

    fn options() -> Vec<ChoiceOption> {
        vec![ChoiceOption::new(ESCALATE), ChoiceOption::described("approve", "ship it")]
    }

    fn opts(a: &str, b: &str) -> Vec<ChoiceOption> {
        vec![ChoiceOption::new(a), ChoiceOption::new(b)]
    }

    fn ids(n: usize) -> Vec<ChoiceOption> {
        (0..n).map(|i| ChoiceOption::new(format!("option-{i}"))).collect()
    }

    /// The reason [`check_questions`] reports for `question` filed under
    /// `"deploy"`, alongside a valid `"storage"` so the failure can only come
    /// from `question` itself.
    fn rejects(question: Question) -> String {
        let questions = BTreeMap::from([
            ("deploy".to_string(), question),
            ("storage".to_string(), Question::choice("right?", options())),
        ]);
        match check_questions(&questions) {
            Ok(()) => panic!("the question set must be rejected"),
            Err(DecisionError::InvalidQuestion { id, reason }) => {
                assert_eq!(id, "deploy", "the failing question's key must be named");
                reason
            }
            Err(other) => panic!("expected InvalidQuestion, got {other:?}"),
        }
    }

    #[test]
    fn questions_are_checked_against_the_contract() {
        assert_eq!(
            check_questions(&BTreeMap::from([(
                "deploy".to_string(),
                Question::choice("Safe to run?", options())
            )])),
            Ok(()),
            "the baseline question set is valid"
        );

        let mut over = ids(MAX_OPTIONS);
        over.push(ChoiceOption::new(ESCALATE));
        let mut at_limit = ids(MAX_OPTIONS - 1);
        at_limit.push(ChoiceOption::new(ESCALATE));

        let q = |instr: &str, opts: Vec<ChoiceOption>, reason: String| {
            (Question::choice(instr, opts), reason)
        };
        for (question, reason) in [
            q("   ", options(), "the question has no instructions".into()),
            q("Safe?", Vec::new(), "a choice question needs at least one option".into()),
            q("Safe?", over, format!("{} options, at most {MAX_OPTIONS}", MAX_OPTIONS + 1)),
            q("Safe?", opts("", "approve"), "an option has an empty id".into()),
            q(
                "Safe?",
                vec![ChoiceOption::new(ESCALATE), ChoiceOption::new(ESCALATE)],
                "option id `escalate` appears twice".into(),
            ),
            q(
                "Safe?",
                vec![ChoiceOption::new("approve")],
                "every question must offer `escalate`".into(),
            ),
        ] {
            assert_eq!(rejects(question), reason);
        }

        // The boundary is inclusive: MAX_OPTIONS is readable, one more is not.
        assert_eq!(Question::choice("Safe?", at_limit).problem(), None);
    }

    #[test]
    fn answers_are_checked_against_their_question() {
        let question = Question::choice("Safe to run?", options());
        let certain = Answer::certain(&question, "approve");
        assert_eq!(certain.problem(&question), None);
        assert_eq!(certain.probabilities["approve"], 1.0);
        assert_eq!(certain.probabilities[ESCALATE], 0.0);

        let both = |choice: &str, approve: f64, escalate: f64| {
            Answer::new(
                choice,
                BTreeMap::from([("approve".into(), approve), (ESCALATE.into(), escalate)]),
                1.0,
            )
        };
        let missing = {
            let mut probabilities = certain.probabilities.clone();
            probabilities.remove("approve");
            Answer::new("approve", probabilities, 1.0)
        };
        let nan = Answer::new(
            "approve",
            BTreeMap::from([("approve".into(), 1.0), (ESCALATE.into(), f64::NAN)]),
            1.0,
        );
        for (answer, reason) in [
            (Answer::certain(&question, "rollback"), "which the question did not offer"),
            (missing, "every option needs exactly one probability"),
            (both("approve", 0.4, 0.0), "not 1"),
            (nan, "is not in 0..=1"),
            (
                Answer::new("approve", certain.probabilities.clone(), 1.5),
                "confidence 1.5 is not in 0..=1",
            ),
            (both("approve", 0.2, 0.8), "but \"escalate\" has 0.8"),
        ] {
            let problem =
                answer.problem(&question).unwrap_or_else(|| panic!("{answer:?} must be refused"));
            assert!(problem.contains(reason), "{answer:?}: {problem} lacks {reason:?}");
        }

        // A tie is not a failure: two options at 0.5 either way is a genuine
        // "I cannot tell", and `escalate` is the honest answer to it.
        assert_eq!(both(ESCALATE, 0.5, 0.5).problem(&question), None);
    }

    fn summary() -> PlanSummary {
        PlanSummary {
            risky: vec![SummaryEntry {
                kind: Kind::Replace,
                address: "aws_instance.web".to_string(),
                attributes: vec![SummaryAttribute {
                    path: "instance_type".to_string(),
                    before: "t3.small".to_string(),
                    after: "m5.large".to_string(),
                    forces_replacement: true,
                }],
                reason: Some("instance type changed".to_string()),
            }],
            add: 1,
            destroy: 1,
            ..PlanSummary::default()
        }
    }

    fn state() -> RedactedState {
        RedactedState::summarise(&summary(), Target::Plain, &Limits::default())
    }

    #[test]
    fn a_state_is_cut_on_a_character_boundary_and_says_so() {
        // A state's whole text is a rendered summary, so it carries the summary's
        // addresses and is exactly as long as that rendering.
        let summary = summary();
        let full = RedactedState::summarise(&summary, Target::Plain, &Limits::default());
        assert!(full.as_str().contains("aws_instance.web"), "{}", full.as_str());
        assert_eq!(full.len(), summary.render(Target::Plain, &Limits::default()).len());
        let length = full.len();
        assert!(length > 64, "the fixture must exceed the bound it is cut to: {length}");

        let fitted = full.clone().fit(64);
        assert!(fitted.state.len() <= 64, "{:?}", fitted.state);
        assert_eq!(fitted.state.as_str(), &full.as_str()[..fitted.state.len()]);
        let truncation = fitted.truncated.clone().expect("a cut state must report the cut");
        assert_eq!((truncation.from_bytes, truncation.to_bytes), (length, fitted.state.len()));
        let line = truncation.log_line();
        assert!(line.contains(&length.to_string()) && line.contains("truncated"), "{line}");

        // Deterministic: the same input and bound cut the same way twice.
        assert_eq!(state().fit(64), fitted);
        assert_eq!(full.clone().fit(length).truncated, None, "a state within its bound is not cut");

        let empty = state().fit(0);
        assert!(empty.state.is_empty());
        assert_eq!(empty.truncated, Some(Truncation { from_bytes: length, to_bytes: 0 }));
    }

    #[test]
    fn decision_errors_display_actionably() {
        let named = |id: &str, reason: &str| DecisionError::InvalidQuestion {
            id: id.to_string(),
            reason: reason.to_string(),
        };
        for (error, carries) in [
            (DecisionError::NotConfigured, "no decision model"),
            (named("deploy", "an option has an empty id"), "empty id"),
            (
                DecisionError::InvalidAnswer {
                    id: "storage".to_string(),
                    reason: "sums to 0.4".to_string(),
                },
                "sums to 0.4",
            ),
            (DecisionError::Model { message: "429".to_string() }, "429"),
        ] {
            let rendered = error.to_string();
            assert!(rendered.contains(carries), "{rendered} must carry {carries:?}");
            assert!(
                rendered.chars().all(|c| !c.is_uppercase()),
                "{rendered} must read as a lowercase sentence"
            );
        }
    }
}
