//! The site's `auto:` rule over the facts of a run: the three scenarios the
//! rule exists for, and the hard rules that stop an `auto:` the file wrote too
//! broadly.

use std::collections::BTreeMap;

use ks_core::auto_rule::{
    Answered, DecisionSource, Facts, POLICY_AUTO, Resolution, Why, baseline_allows_auto, resolve,
};
use ks_core::ports::policy::{Baseline, Disposition, Provenance, Rule, Subject};
use ks_core::ports::script_host::Value;
use ks_core::step::Outputs;
use ks_lang::{Expr, Parse};

const SITE: &str = "\
name: decide-demo
steps:
  plan: tofu.plan
    dir: ./infra
  risk: decide
    model: typesafe/jev
    ask: \"How risky is this plan?\"
    input: plan.changes
    returns: low | medium | high
  review: approval
    auto: risk is low \u{2265} 0.95 and plan.destroys == 0
    else: ask @platform, show risk.reason
";

/// The `auto:` and `else:` expressions of the `review` step, as written.
fn review_rule(parse: &Parse) -> (Expr<'_>, Expr<'_>) {
    let mut steps = Vec::new();
    for entry in parse.file().entries() {
        steps.extend(entry.children());
    }
    let review =
        steps.into_iter().find(|e| e.key_name() == Some("review")).expect("the review step");
    let child =
        |key: &str| review.children().find(|e| e.key_name() == Some(key)).and_then(|e| e.expr());
    (child("auto").expect("the `auto:` expression"), child("else").expect("the `else:`"))
}

/// The same file with a different `auto:` rule, for the cases where the rule
/// itself is what is under test.
fn site_with(rule: &str) -> String {
    SITE.replace("risk is low \u{2265} 0.95 and plan.destroys == 0", rule)
}

fn answered(answer: &str, confidence: f64, reason: &str, source: DecisionSource) -> Answered {
    Answered { answer: answer.into(), confidence, reason: reason.into(), source }
}

/// A plan that counts what it adds, changes and destroys, e.g. `0 1 0`.
fn plan(counts: [f64; 3]) -> Outputs {
    ["adds", "changes", "destroys"]
        .into_iter()
        .zip(counts)
        .map(|(name, count)| (name.into(), Value::Number(count)))
        .collect()
}

/// A plan that changes nothing that has to be replaced.
fn clean_plan() -> Outputs {
    plan([0.0, 1.0, 0.0])
}

/// The same plan, renaming a module: one resource replaced.
fn replace_plan() -> Outputs {
    plan([1.0, 0.0, 1.0])
}

fn facts<'a>(env: &'a str, answer: Answered, plan: &'a Outputs) -> Facts<'a> {
    Facts {
        answers: BTreeMap::from([("risk", answer)]),
        outputs: BTreeMap::from([("plan", plan)]),
        ..Facts::new(env)
    }
}

fn approved(resolution: Resolution) -> (&'static str, String, Vec<(String, String)>) {
    match resolution {
        Resolution::Approved { by, rule, saw } => (by, rule, saw),
        other => panic!("expected an approval by policy, got {other:?}"),
    }
}

fn asked(resolution: Resolution) -> (Vec<String>, Vec<(String, String)>, Why) {
    match resolution {
        Resolution::Ask { teams, show, why } => (teams, show, why),
        other => panic!("expected a step waiting on someone, got {other:?}"),
    }
}

/// The value the rule read at `name`.
fn read(saw: &[(String, String)], name: &str) -> String {
    saw.iter()
        .find(|(seen, _)| seen == name)
        .unwrap_or_else(|| panic!("the rule did not read `{name}`: {saw:?}"))
        .1
        .clone()
}

/// The site's first scenario: a replica bump, answered `low` and certain
/// enough, changing nothing that has to be replaced.
#[test]
fn a_low_and_confident_change_is_approved_by_policy_and_says_what_it_saw() {
    let parse = ks_lang::parse(SITE);
    let (auto, otherwise) = review_rule(&parse);
    let plan = clean_plan();
    let f = facts("staging", answered("low", 0.97, "a replica bump", DecisionSource::Model), &plan);

    let (by, rule, saw) = approved(resolve(&auto, Some(&otherwise), &f));

    assert_eq!(by, POLICY_AUTO, "policy approved it, not a person");
    assert_eq!(rule, "risk is low \u{2265} 0.95 and plan.destroys == 0");
    assert_eq!(read(&saw, "risk"), "low");
    assert_eq!(read(&saw, "risk.confidence"), "0.97");
    assert_eq!(read(&saw, "plan.destroys"), "0");
}

/// The site's second: renaming the database module replaces it, so the rule
/// does not hold and the step waits on the team the `else:` named, with the
/// reason the model gave.
#[test]
fn a_replace_waits_on_the_team_the_else_named_with_the_reason() {
    let parse = ks_lang::parse(SITE);
    let (auto, otherwise) = review_rule(&parse);
    let plan = replace_plan();
    let reason = "renaming the database module replaces the volume";
    let f = facts("staging", answered("high", 0.91, reason, DecisionSource::Model), &plan);

    let (teams, show, why) = asked(resolve(&auto, Some(&otherwise), &f));

    assert_eq!(teams, ["@platform".to_string()]);
    assert_eq!(show, [("risk.reason".to_string(), reason.to_string())]);
    assert!(matches!(why, Why::RuleDidNotHold { .. }), "{why:?}");
    let said = why.to_string();
    assert!(said.contains("did not hold") && said.contains("high"), "{said}");
    assert!(said.contains("destroys"), "the rule read the count too: {said}");
}

/// A replace is refused whatever the file wrote — here the rule never mentions
/// destroys at all, and the engine's own count is the only thing that stops it.
#[test]
fn a_rule_that_omits_the_destroys_clause_still_refuses_a_replace() {
    let parse = ks_lang::parse(&site_with("risk is low \u{2265} 0.95"));
    let (auto, otherwise) = review_rule(&parse);
    let plan = replace_plan();
    let f = facts("staging", answered("low", 0.99, "a green plan", DecisionSource::Model), &plan);

    let (_, _, why) = asked(resolve(&auto, Some(&otherwise), &f));

    assert_eq!(why, Why::Destroys { count: 1 });
    assert!(why.to_string().contains("destroys or replaces 1 resource"), "{why}");
}

/// A decision nobody can trust is never approved, however the rule is spelled.
/// Every shape below reads `risk`, so every one of them is an approval with no
/// decision behind it.
#[test]
fn a_decision_from_no_model_or_a_failed_call_is_never_approved() {
    let shapes = [
        "risk is low \u{2265} 0.95",
        "(risk is low \u{2265} 0.95) == true",
        "plan.destroys == 0 and (risk is low) == true",
        "risk.confidence >= 0.95",
        "risk.answer == low",
    ];
    for (source, mentioned) in
        [(DecisionSource::NoModel, "model: none"), (DecisionSource::Errored, "errored")]
    {
        for rule in shapes {
            let parse = ks_lang::parse(&site_with(rule));
            let (auto, otherwise) = review_rule(&parse);
            let plan = clean_plan();
            let f = facts("staging", answered("low", 0.99, "a green plan", source), &plan);

            let (teams, _, refused) = asked(resolve(&auto, Some(&otherwise), &f));

            assert_eq!(teams, ["@platform".to_string()]);
            assert!(
                matches!(refused, Why::NoModel { .. } | Why::Errored { .. }),
                "`{rule}` with {source:?} approved on an untrusted decision: {refused:?}"
            );
            assert!(refused.to_string().contains(mentioned), "{refused}");
        }
    }
}

/// **An escalation the engine wrote itself is not a confident answer.** A
/// `decide` step that refused to ask — a state its guard would not send, a
/// question it could not build — answers `escalate` at confidence 1.0, because
/// an escalation is certain. Nothing about those outputs says so: they are the
/// same four the step returns when a model said `escalate`, and a rule reading
/// `risk.confidence` alone reads 1.0 as a certainty worth approving on. So the
/// source is a variant of its own here, and it can only ever ask.
#[test]
fn an_escalation_the_engine_wrote_itself_is_never_approved() {
    let why = "the plan's text carries a line break that is not a newline (U+2028), \
               so it was not sent to typesafe/jev";
    // The shape the step writes: the answer and its confidence, then the why.
    let reason = format!("escalate 1.00 {why}");
    let shapes = [
        "risk.confidence >= 0.95 and plan.destroys == 0",
        "risk is low \u{2265} 0.95",
        "risk.confidence >= 0.95",
        "risk.answer == escalate",
        "risk.confidence >= 0.95 or risk.confidence < 0",
    ];
    for rule in shapes {
        let parse = ks_lang::parse(&site_with(rule));
        let (auto, otherwise) = review_rule(&parse);
        let plan = clean_plan();
        let f =
            facts("staging", answered("escalate", 1.0, &reason, DecisionSource::Escalated), &plan);

        let (teams, show, refused) = asked(resolve(&auto, Some(&otherwise), &f));

        assert_eq!(teams, ["@platform".to_string()]);
        // The reason keeps what the engine said and loses only the answer and
        // confidence `Why::Escalated`'s own sentence has already given.
        assert_eq!(refused, Why::Escalated { step: "risk".into(), why: why.into() }, "`{rule}`");
        // The review is told what stopped the question, which is the only thing
        // the engine knows that no file and no rule can work out.
        assert!(show.iter().any(|(_, said)| said.contains("U+2028")), "`{rule}`: {show:?}");
    }
}

/// **Only the engine's own `escalate <confidence> …` prefix comes off.** The
/// engine writes its reasons that way, and [`Why::Escalated`]'s sentence has
/// already said the step was escalated and never asked — so the prefix would be
/// said twice in one line. Every other reason is the human's only record of what
/// stopped the question, and two words taken off the front of it delete that
/// record: the engine's *other* escalation, `no model is configured (model:
/// none)`, has no prefix to take, and a reason that merely opens with a word and
/// a number — `risk 3 destroys happened` — is not a prefix at all.
#[test]
fn only_the_engines_own_answer_and_confidence_are_stripped_from_the_reason() {
    let decided = |reason: &str| {
        let parse = ks_lang::parse(&site_with("risk.confidence >= 0.95"));
        let (auto, otherwise) = review_rule(&parse);
        let plan = clean_plan();
        let f =
            facts("staging", answered("escalate", 1.0, reason, DecisionSource::Escalated), &plan);
        asked(resolve(&auto, Some(&otherwise), &f))
    };

    // The engine's other escalation, `model: none`: kept whole and unchanged.
    let none = "no model is configured (model: none)";
    let (_, show, refused) = decided(none);
    assert_eq!(refused, Why::Escalated { step: "risk".into(), why: none.into() });
    assert_eq!(show, [("risk.reason".to_string(), none.to_string())]);

    // A word and a number that are not the answer and the confidence: the reason
    // says what happened, and the count is the part a reviewer cannot do without.
    let count = "risk 3 destroys happened";
    let (_, show, refused) = decided(count);
    assert_eq!(refused, Why::Escalated { step: "risk".into(), why: count.into() });
    assert_eq!(show, [("risk.reason".to_string(), count.to_string())]);

    // The shape the step really writes: the prefix, and only the prefix, goes.
    let why = "the plan's text carries a line break that is not a newline (U+2028)";
    let (_, _, refused) = decided(&format!("escalate 1.00 {why}"));
    assert_eq!(refused, Why::Escalated { step: "risk".into(), why: why.into() });
}

/// What the human waiting on the approval is told. It has to name the step, it
/// has to carry the engine's own reason, and it must not borrow another
/// variant's wording: `model: none` is a file's sentence about a missing model,
/// and this run had a model and would not use it.
#[test]
fn an_escalation_says_the_engine_escalated_and_why() {
    // The reason as [`resolve`] hands it over: the engine's own sentence, without
    // the answer and confidence the reason line opened with.
    let why = "the plan's text carries a tag character (U+E0061), \
               so it was not sent to typesafe/jev";

    let said = Why::Escalated { step: "risk".into(), why: why.into() }.to_string();

    assert!(said.contains("risk"), "the step it is about: {said}");
    // On the sentence's own verb, not on the prefix the reason line opens with:
    // `resolve` strips that prefix, so the sentence is what says it.
    assert!(said.contains("the engine escalated `risk`"), "who answered, in our words: {said}");
    assert!(!said.contains("escalate 1.00"), "the reason's own prefix is not said twice: {said}");
    assert!(said.contains("U+E0061"), "the engine's own reason is kept: {said}");
    assert!(!said.contains("model: none"), "no model was missing; one was not asked: {said}");
    assert!(!said.contains('\u{E0061}'), "and no glyph comes back: {said}");
}

/// The org baseline is the one authority a workflow file cannot write, so a
/// rule that holds on a plan that changes nothing still asks in the
/// environment the baseline refuses.
#[test]
fn the_org_baseline_can_switch_auto_off_for_one_environment() {
    let baseline = Baseline {
        rules: vec![Rule {
            subject: Subject::Any,
            verb: "auto".to_string(),
            object: "production".to_string(),
            disposition: Disposition::Never,
            provenance: Provenance::Default,
        }],
        source: None,
        publishers: Vec::new(),
    };
    let plan = clean_plan();
    let decided = |env: &str| {
        let parse = ks_lang::parse(SITE);
        let (auto, otherwise) = review_rule(&parse);
        let mut f = facts(env, answered("low", 0.97, "a bump", DecisionSource::Model), &plan);
        f.auto_allowed = ks_core::baseline_allows_auto(&baseline, env);
        resolve(&auto, Some(&otherwise), &f)
    };

    assert!(baseline_allows_auto(&Baseline::conservative(), "production"), "opt-out, not opt-in");

    let (_, _, why) = asked(decided("production"));
    assert_eq!(why, Why::BaselineDenied { env: "production".to_string() });
    assert!(why.to_string().contains("production"), "{why}");

    approved(decided("staging"));
}

/// Anything the evaluator cannot read asks rather than approves: a reference
/// to a step that ran, no more than a `destroys` count that is not a count.
#[test]
fn a_rule_that_cannot_be_read_asks_rather_than_approves() {
    let decided = |rule: &str, plan: &Outputs| {
        let parse = ks_lang::parse(&site_with(rule));
        let (auto, otherwise) = review_rule(&parse);
        let f = facts("staging", answered("low", 0.97, "a bump", DecisionSource::Model), plan);
        resolve(&auto, Some(&otherwise), &f)
    };

    let unknown = decided("risk is low \u{2265} 0.95 and nope.changes == 0", &clean_plan());
    let (_, _, why) = asked(unknown);
    assert!(matches!(why, Why::Unreadable { .. }) && why.to_string().contains("nope"), "{why}");

    let strange = Outputs::from([("destroys".into(), Value::String("one".into()))]);
    let (_, _, why) = asked(decided("risk is low \u{2265} 0.95", &strange));
    assert!(matches!(why, Why::Unreadable { .. }) && why.to_string().contains("destroys"), "{why}");
}
