//! The `decide` step kind: one redacted plan in, one answer out
//! ([#104](https://github.com/Keep-Shipping/harness/issues/104)).
//!
//! A step that needs a judgement asks the
//! [`DecisionModel`](ks_core::ports::decision_model::DecisionModel) port one
//! [`RedactedState`] and one choice question, and gets an answer, a confidence
//! and a distribution. Three properties make that worth acting on: the state is
//! redacted by construction (it is rendered from a [`PlanSummary`], which masks
//! sensitive attributes and strips control characters in [`summarize`]); the
//! answer is pinned to the model that gave it, since `model:` names the model
//! and optionally its version and both are checked against the port's
//! [`ModelProfile`] before anything is asked; and `model: none` escalates
//! rather than answering for nobody.
//!
//! **The `reason` is built by the engine, never by the model.** A model asked
//! to explain itself writes prose that reads as evidence; the engine can write
//! the evidence. So `reason` is a pure function of the answer, the confidence
//! and the plan's own risky entries — `high 0.91 replaces
//! aws_db_instance.main` — and a model that returned a different string for it
//! would be ignored.
//!
//! **A state carrying an instruction-shaped glyph is escalated, not asked
//! about.** Redaction masks secrets; it does not promise the rest is data, so
//! a rendered state that still bears a bidi override or a zero-width space
//! means the renderer let something through (#120). The model is never shown
//! one, because an answer read off it is not an answer about the plan.
//!
//! Only plan changes are summarised into a state so far
//! (#107), and the step is registered behind the `decide` cargo feature until
//! the Jev adapter lands (#8) and its confidence is calibrated (#108).

use std::collections::BTreeMap;

use ks_core::decision_guard;
use ks_core::plan_summary::{Kind, Limits, PlanChange, PlanSummary, Target, summarize};
use ks_core::ports::BoxFuture;
use ks_core::ports::decision_model::{
    ChoiceOption, ESCALATE, ModelProfile, Question, RedactedState,
};
use ks_core::ports::iac::{ChangeAction, ResourceChange};
use ks_core::ports::script_host::{Value, ValueType};
use ks_core::step::{
    ActionClass, ActionKind, Field, Inputs, Outputs, Port, StepCtx, StepError, StepKind,
    StepSchema, TypeRef, Version,
};

/// The `model:` value that means "ask no one": the step escalates instead.
const NO_MODEL: &str = "none";

/// The key the one question is filed under, and the id an answer comes back
/// named: fixed, not derived from the step's name, so a run's log reads the
/// same whatever the file called the step.
const QUESTION_ID: &str = "decide";

/// How many risky resources a `reason` names before it counts the rest: what
/// fits on a line in a review comment.
const MAX_FACTS: usize = 3;

/// Asks a model a judgement about a plan, and returns the answer with a reason
/// the engine wrote itself.
#[derive(Debug, Default)]
pub struct Decide;

impl StepKind for Decide {
    fn name(&self) -> &'static str {
        "decide"
    }

    fn version(&self) -> Version {
        Version::new(1, 0, 0)
    }

    fn schema(&self) -> StepSchema {
        let text = TypeRef::Builtin(ValueType::String);
        StepSchema {
            doc: "Asks a model how risky a plan is, and answers with a reason built from the \
                  plan itself.",
            inputs: vec![
                Field::new("model", text, "the model to ask, as `name[@version]`, or `none`"),
                Field::new("ask", text, "the question in the plain terms a reviewer would use"),
                Field::new("input", TypeRef::Builtin(ValueType::Map), "the plan's `changes`"),
                Field::new("returns", TypeRef::Builtin(ValueType::List), "the answers on offer"),
            ],
            outputs: vec![
                Field::new("answer", text, "one `returns:` declared, or `escalate`"),
                Field::new(
                    "confidence",
                    TypeRef::Builtin(ValueType::Number),
                    "how well calibrated the adapter is; not the probability",
                ),
                Field::new("probabilities", TypeRef::Builtin(ValueType::Map), "one per answer"),
                Field::new("reason", text, "why, written by the engine from the plan"),
            ],
        }
    }

    /// `model: none` reaches for no port, so a composition without a decision
    /// model can still run one — while naming a model with none wired fails.
    fn requires(&self) -> &'static [Port] {
        &[]
    }

    fn optional(&self) -> &'static [Port] {
        &[Port::DecisionModel]
    }

    /// Asking a question changes nothing in the world, so it is not an apply:
    /// what needs an approval is whatever acts on the answer.
    fn action(&self, _inputs: &Inputs) -> ActionClass {
        ActionClass::new(ActionKind::Other)
    }

    fn run(&self, ctx: StepCtx, inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>> {
        Box::pin(async move {
            let model = text(&inputs, "model").trim();
            let wanted = pinned(model)?;
            let summary = plan_summary(&inputs)?;
            let question = question(&inputs)?;

            // `none` is not a model that answers "escalate": it is a file
            // saying no model is configured, and the review has to see that.
            if model == NO_MODEL {
                ctx.log().info("no model configured, escalating", &[("model", NO_MODEL)]);
                return Ok(escalated("no model is configured (model: none)"));
            }
            let Some(decision_model) = ctx.ports().decision_model() else {
                let why =
                    format!("`model: {model}` names a model, but no decision model was provided");
                return Err(port_error(why));
            };
            let profile = decision_model.profile();
            check_pinned(&profile, model, wanted)?;

            let state = RedactedState::summarise(&summary, Target::Plain, &Limits::default());
            // Redaction masks the values the plan marks secret; it does not
            // promise the rest is data. A glyph that survived rendering — a
            // bidi override, a zero-width space — can still reorder or hide
            // what the model reads, so a state carrying one means the renderer
            // let something through. An answer read off that state is not an
            // answer about the plan, so the model is never asked (#120). Checked
            // on the whole state, before `fit`: truncation cutting the glyph
            // away is not a fix, it is a plan where the evidence depends on how
            // long it happened to be.
            // The state quotes every plan string (#107), which escapes some of
            // these glyphs into visible `\u` sequences, so the plan's own text is
            // checked as well: a plan that carries one is not sent, escaped or not.
            let plain = summary.render(Target::Plain, &Limits::default());
            if let Some(defect) = decision_guard::first_defect(state.as_str())
                .or_else(|| decision_guard::first_defect(&plain))
            {
                let what = defect.describe();
                ctx.log().info(
                    "plan text carries a glyph that can hide an instruction, escalating",
                    &[("glyph", &what)],
                );
                return Ok(escalated(&format!(
                    "the plan's text carries {what}, so it was not sent to {model}"
                )));
            }
            let fit = state.fit(profile.max_state_bytes);
            // The port cannot log on an adapter's behalf, and a state trimmed
            // with nothing in the log is the worst failure mode a decision
            // model has: the answer reads as reasoned, chosen from half the
            // evidence.
            if let Some(truncation) = &fit.truncated {
                ctx.log().info(&truncation.log_line(), &[]);
            }

            let questions = BTreeMap::from([(QUESTION_ID.to_string(), question.clone())]);
            let mut answers = decision_model
                .ask(fit.state, questions)
                .await
                .map_err(|error| port_error(error.to_string()))?;
            let answer = answers.remove(QUESTION_ID).ok_or_else(|| {
                port_error(format!("the adapter answered no question `{QUESTION_ID}`"))
            })?;
            // The contract says an adapter answers with a choice from the
            // options it was offered, and checking it is what makes a buggy
            // adapter a red step rather than a review quoting a word nobody
            // offered — and what keeps a NaN out of the `reason` line.
            if let Some(problem) = answer.problem(&question) {
                return Err(port_error(format!("the answer does not fit the question: {problem}")));
            }

            let confidence = &format!("{:.2}", answer.confidence);
            ctx.log().info(&answer.choice, &[("confidence", confidence)]);
            let probabilities =
                answer.probabilities.iter().map(|(id, p)| (id.clone(), Value::Number(*p)));
            let reason = reason(&answer.choice, answer.confidence, &summary);
            Ok(outputs(
                &answer.choice,
                answer.confidence,
                Value::Map(probabilities.collect()),
                reason,
            ))
        })
    }
}

/// A refusal by the decision-model port, in the one shape this step reports.
fn port_error(message: String) -> StepError {
    StepError::Port { port: Port::DecisionModel, message }
}

/// The four outputs of any answer: the answer, how sure the adapter is, its
/// distribution, and the line the engine wrote. An escalation is the same four
/// with `escalate` and 1.0 — nothing there came from a model.
fn outputs(answer: &str, confidence: f64, probabilities: Value, reason: String) -> Outputs {
    let mut out = Outputs::new();
    out.insert("answer".to_string(), Value::from(answer));
    out.insert("confidence".to_string(), Value::Number(confidence));
    out.insert("probabilities".to_string(), probabilities);
    out.insert("reason".to_string(), Value::from(reason));
    out
}

/// The outputs of `model: none`.
fn escalated(why: &str) -> Outputs {
    let certain = Value::Map(BTreeMap::from([(ESCALATE.to_string(), Value::Number(1.0))]));
    outputs(ESCALATE, 1.0, certain, format!("{ESCALATE} 1.00 {why}"))
}

/// The line a reviewer reads: `high 0.91 replaces aws_db_instance.main`. A pure
/// function of the answer, the confidence and the plan's risky entries — the
/// model has no part in it, which is the point.
fn reason(answer: &str, confidence: f64, summary: &PlanSummary) -> String {
    format!("{answer} {confidence:.2} {}", facts(summary))
}

/// What the plan did that the answer is read against: every replacement and
/// every destroy, by address, in plan order. A plan that destroys nothing has
/// no addresses worth naming, so the counts stand alone — the wording `tofu`
/// prints, and the one the review beside this line shows.
fn facts(summary: &PlanSummary) -> String {
    if summary.risky.is_empty() {
        return summary.counts();
    }
    let named = summary
        .risky
        .iter()
        .take(MAX_FACTS)
        .map(|entry| {
            let verb = if entry.kind == Kind::Replace { "replaces" } else { "destroys" };
            format!("{verb} {}", entry.address)
        })
        .collect::<Vec<_>>()
        .join(", ");
    match summary.risky.len().saturating_sub(MAX_FACTS) {
        0 => named,
        hidden => format!("{named}, and {hidden} more"),
    }
}

/// The `input:` as a [`PlanSummary`], so the model sees a masked rendering and
/// the reason sees the counts the review does. Plan changes are the only shape
/// summarised so far: anything else is refused with that said outright, rather
/// than as an empty plan — which would ask the model about nothing and answer
/// as if it had been asked.
fn plan_summary(inputs: &Inputs) -> Result<PlanSummary, StepError> {
    let bad = |why: String| StepError::InvalidInput { field: "input".to_string(), reason: why };
    let unsupported =
        || bad("only a plan's `changes` are summarised so far; this is not one (#107)".to_string());
    let listed = inputs.get("input").and_then(|input| match input {
        Value::Map(plan) => plan.get("resources"),
        _ => None,
    });
    let Some(Value::List(resources)) = listed else {
        return Err(unsupported());
    };
    let mut changes = Vec::with_capacity(resources.len());
    for resource in resources {
        let Value::Map(entry) = resource else { return Err(unsupported()) };
        let (Some(Value::String(address)), Some(Value::String(action))) =
            (entry.get("address"), entry.get("action"))
        else {
            let why =
                "each resource needs a string `address` and `action`, as `tofu.plan` wrote it";
            return Err(bad(why.to_string()));
        };
        // Spelled the way `classify` reads them: a replace is a delete and a
        // create of one resource, and a read is a change to the plan but not
        // to a resource, so the summary drops it.
        let actions = match action.as_str() {
            "create" => vec![ChangeAction::Create],
            "update" => vec![ChangeAction::Update],
            "delete" => vec![ChangeAction::Delete],
            "replace" => vec![ChangeAction::Delete, ChangeAction::Create],
            "read" => vec![ChangeAction::Read],
            _ => {
                let why = format!(
                    "`{action}` is not an action `tofu.plan` reports: `create`, `update`, \
                     `delete`, `replace` or `read`"
                );
                return Err(bad(why));
            }
        };
        changes.push(PlanChange::from(&ResourceChange { address: address.clone(), actions }));
    }
    Ok(summarize(&changes))
}

/// The one question this step asks, with `escalate` added to the answers the
/// file declared. The contract's own rules are asked with
/// [`Question::problem`], so a violation is reported against the input to fix
/// rather than as a rejected question.
fn question(inputs: &Inputs) -> Result<Question, StepError> {
    let bad = |why: String| StepError::InvalidInput { field: "returns".to_string(), reason: why };
    let Some(Value::List(items)) = inputs.get("returns") else {
        return Err(bad("expected `returns:` as a list of words".to_string()));
    };
    let mut options: Vec<ChoiceOption> = Vec::with_capacity(items.len() + 1);
    for item in items {
        match item {
            Value::String(word) if word == ESCALATE => {
                return Err(bad(format!("`{ESCALATE}` is on offer with every question")));
            }
            Value::String(word) => options.push(ChoiceOption::new(word.clone())),
            other => return Err(bad(format!("an answer is a {}, not a word", other.value_type()))),
        }
    }
    // `escalate` is added below, so an empty `returns:` would satisfy the
    // contract on the strength of that one word — a question with nothing to
    // choose between.
    if options.is_empty() {
        return Err(bad("a `decide` must offer at least one answer".to_string()));
    }
    options.push(ChoiceOption::new(ESCALATE));
    let question = Question::choice(text(inputs, "ask"), options);
    // A blank `ask:` and a bad `returns:` are one problem to the contract and
    // two inputs to fix, so the field names which.
    if let Some(problem) = question.problem() {
        let field = if text(inputs, "ask").trim().is_empty() { "ask" } else { "returns" };
        return Err(StepError::InvalidInput { field: field.to_string(), reason: problem });
    }
    Ok(question)
}

/// The `model:` value, split into the id to match and the version to pin. With
/// no lock file, this is the only half of pinning there is: a run either ran
/// against the version the file named, or it failed.
fn pinned(model: &str) -> Result<(&str, Option<&str>), StepError> {
    let bad = |why: String| StepError::InvalidInput { field: "model".to_string(), reason: why };
    if model.is_empty() {
        return Err(bad("expected `name`, `name@version`, or `none`".to_string()));
    }
    Ok(match model.split_once('@') {
        Some((_, "")) => return Err(bad("the version after `@` is empty".to_string())),
        Some((id, version)) => (id, Some(version)),
        None => (model, None),
    })
}

/// Whether `profile` is the model `model:` named: answering from a model the
/// file did not ask for is a decision nobody reviewed, so a mismatch fails.
fn check_pinned(
    profile: &ModelProfile,
    model: &str,
    (id, version): (&str, Option<&str>),
) -> Result<(), StepError> {
    let mismatch =
        |why: String| port_error(format!("`model: {model}` is not the wired model: {why}"));
    if profile.model_id != id {
        return Err(mismatch(format!("it is `{}`, not `{id}`", profile.model_id)));
    }
    match version {
        Some(version) if profile.version != version => {
            Err(mismatch(format!("it is at `{}`, not `{version}`", profile.version)))
        }
        _ => Ok(()),
    }
}

/// The `&str` under `name`; inputs arrive prepared, so a wrong type never
/// reaches a step.
fn text<'a>(inputs: &'a Inputs, name: &str) -> &'a str {
    match inputs.get(name) {
        Some(Value::String(text)) => text,
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ks_core::plan_summary::SummaryEntry;

    fn entry(kind: Kind, address: &str) -> SummaryEntry {
        SummaryEntry { kind, address: address.to_string(), attributes: Vec::new(), reason: None }
    }

    #[test]
    fn the_reason_names_the_plans_own_changes() {
        let mut risky = PlanSummary {
            risky: vec![entry(Kind::Replace, "aws_db_instance.main")],
            ..PlanSummary::default()
        };
        // The line the site's `high` answer has to produce, exactly.
        assert_eq!(reason("high", 0.91, &risky), "high 0.91 replaces aws_db_instance.main");
        risky.risky.push(entry(Kind::Destroy, "aws_s3_bucket.logs"));
        assert_eq!(
            reason("high", 0.91, &risky),
            "high 0.91 replaces aws_db_instance.main, destroys aws_s3_bucket.logs",
        );
        // Over the cap: three named in plan order, the rest counted.
        risky.risky.extend([
            entry(Kind::Destroy, "aws_iam_role.old"),
            entry(Kind::Replace, "aws_ecs_service.api"),
        ]);
        assert_eq!(
            reason("high", 0.5, &risky),
            "high 0.50 replaces aws_db_instance.main, destroys aws_s3_bucket.logs, destroys \
             aws_iam_role.old, and 1 more",
        );
        // Nothing risky: the counts stand alone, as `tofu` prints them.
        let adds = PlanSummary { add: 1, change: 1, ..PlanSummary::default() };
        assert_eq!(reason("low", 0.97, &adds), "low 0.97 1 to add · 1 to change · 0 to destroy");
    }

    #[test]
    fn a_model_is_pinned_to_the_profile_that_answers() {
        let profile = ModelProfile {
            model_id: "typesafe/jev".to_string(),
            version: "2026-10-01".to_string(),
            calibration_family: "jev".to_string(),
            max_state_bytes: 1024,
        };
        for (model, parses, matches) in [
            ("typesafe/jev", true, true),
            ("typesafe/jev@2026-10-01", true, true),
            ("typesafe/jev@2026-10-02", true, false),
            ("typesafe/other", true, false),
            ("typesafe/jev@", false, false),
            ("", false, false),
        ] {
            let wanted = pinned(model);
            assert_eq!(wanted.is_ok(), parses, "`model: {model:?}` must parse");
            if let Ok(wanted) = wanted {
                assert_eq!(
                    check_pinned(&profile, model, wanted).is_ok(),
                    matches,
                    "`model: {model:?}` must {} the wired model",
                    if matches { "match" } else { "refuse" }
                );
            }
        }
    }
}
