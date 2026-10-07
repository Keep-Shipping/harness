//! The site's `policy:` block over a workflow that plans, decides and
//! approves, and the one hard rule on `auto:` — destroys always go to a human
//! (ADR 0012).

use ks_core::auto_rule::{
    Decision, MISSING_GUARD_HINT, MISSING_GUARD_MESSAGE, auto_approves, decide,
};
use ks_core::ports::run_context::ActorKind as Actor;
use ks_core::{Checked, check};
use ks_lang::{Code, Diagnostic, Severity};

const POLICY: &str = include_str!("../../lang/tests/fixtures/site-policy.ks");

const HEAD: &str = "\
name: ship-it
envs:
  staging:
    ci-only: true
  prod:
    ci-only: true
steps:
  plan: tofu.plan
    dir: ./infra
  risk: decide
    model: typesafe/jev
    ask: \"How risky is this plan?\"
    input: plan.changes
    returns: low | medium | high
  review: approval
";

/// The workflow above with the given `auto:` expression, under the site's
/// policy block.
fn file(auto: &str) -> String {
    format!("{HEAD}    auto: {auto}\n    else: ask @platform, show risk.reason\n{POLICY}")
}

fn checked(src: &str) -> Checked {
    check(&ks_lang::parse(src))
}

fn diagnostics(src: &str) -> Vec<Diagnostic> {
    checked(src).diagnostics
}

fn codes(src: &str) -> Vec<Code> {
    diagnostics(src).iter().map(|d| d.code).collect()
}

fn errors(src: &str) -> Vec<String> {
    diagnostics(src)
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .map(ToString::to_string)
        .collect()
}

#[test]
fn the_site_policy_over_an_auto_approval_checks_clean() {
    let src = file("risk is low \u{2265} 0.95 and plan.destroys == 0");
    let checked = checked(&src);
    assert!(checked.diagnostics.is_empty(), "{:#?}", checked.diagnostics);
    // The approval still gates what it shows.
    assert!(
        checked.workflow.edges().contains(&("risk".to_string(), "review".to_string())),
        "{:?}",
        checked.workflow.edges()
    );
}

#[test]
fn an_auto_without_the_destroys_guard_warns_once() {
    let src = file("risk is low \u{2265} 0.95");
    assert!(errors(&src).is_empty(), "{:?}", errors(&src));
    let codes = codes(&src);
    assert_eq!(codes, [Code::AutoDestroys], "one warning, nothing else");

    let warning = &diagnostics(&src)[0];
    assert_eq!(warning.severity, Severity::Warning);
    assert_eq!(warning.message, MISSING_GUARD_MESSAGE);
    assert_eq!(warning.hints, [MISSING_GUARD_HINT]);
    // At the `auto:` value, not at the step or the file.
    let value = src.find("auto: risk").expect("the auto input") + "auto: ".len();
    assert!(
        warning.span.start as usize >= value && warning.span.end as usize <= src.len(),
        "the warning span {:?} should sit on the `auto:` value",
        warning.span
    );
}

#[test]
fn only_a_top_level_conjunct_counts_as_the_guard() {
    // Inside an `or`: the rule still approves when the plan destroys.
    for auto in [
        "risk is low \u{2265} 0.95 or plan.destroys == 0",
        "not (plan.destroys == 0)",
        "true",
        "plan.destroys != 0",
    ] {
        let src = file(auto);
        assert!(errors(&src).is_empty(), "{auto}: {:?}", errors(&src));
        let codes = codes(&src);
        assert_eq!(codes, [Code::AutoDestroys], "{auto}: {codes:?}");
    }
}

#[test]
fn the_guard_may_be_spelled_either_way_round() {
    for auto in
        ["plan.destroys == 0", "0 == plan.destroys", "plan.destroys <= 0", "plan.destroys < 1"]
    {
        let src = file(auto);
        assert!(errors(&src).is_empty(), "{auto}: {:?}", errors(&src));
        assert!(diagnostics(&src).is_empty(), "{auto}: {:#?}", diagnostics(&src));
    }
}

#[test]
fn a_path_that_does_not_read_a_destroys_count_is_not_the_guard() {
    // `risk` is a `decide` step: it produces no `destroys` count, so this is
    // not the guard however it reads.
    for auto in [
        "risk is low \u{2265} 0.95 and risk.destroys == 0",
        "risk.destroys == 0",
        "env.destroys == 0",
    ] {
        let src = file(auto);
        let codes = codes(&src);
        assert!(codes.contains(&Code::AutoDestroys), "{auto}: {codes:?}");
    }
}

#[test]
fn the_guard_is_numeric_and_keyed_on_the_output_not_the_kind_name() {
    use ks_core::step::{Field, StepSchema, TypeRef};
    // `00` is zero: the guard is read as an integer, not as text.
    let src = file("risk is low \u{2265} 0.95 and plan.destroys == 00");
    assert!(diagnostics(&src).is_empty(), "{:#?}", diagnostics(&src));

    // Any step whose kind declares a `destroys` output counts, whatever the
    // kind is called.
    let mut catalog = ks_core::Catalog::builtin();
    catalog
        .add_schema(
            "web.plan",
            &StepSchema {
                doc: "a plan-like step",
                inputs: vec![],
                outputs: vec![Field::new("destroys", TypeRef::Named("int"), "what it removes")],
            },
        )
        .expect("the schema joins");
    let src = "steps:\n  p: web.plan\n  review: approval\n    auto: p.destroys == 0\n";
    let checked = ks_core::check_with(&ks_lang::parse(src), &ks_core::CheckOptions::new(&catalog));
    assert!(checked.diagnostics.is_empty(), "{:#?}", checked.diagnostics);
}

#[test]
fn only_an_approval_steps_auto_is_gated() {
    // Another step kind may declare an input named `auto`; the guard is
    // `approval`'s rule, not every `auto:` input's.
    use ks_core::step::{Field, StepSchema, TypeRef};
    let mut catalog = ks_core::Catalog::builtin();
    catalog
        .add_schema(
            "web.flag",
            &StepSchema {
                doc: "a step with an `auto:` input of its own",
                inputs: vec![Field::new("auto", TypeRef::Named("bool"), "the flag")],
                outputs: vec![],
            },
        )
        .expect("the schema joins");
    let options = ks_core::CheckOptions::new(&catalog);
    let src = "steps:\n  flag: web.flag\n    auto: true\n";
    let checked = ks_core::check_with(&ks_lang::parse(src), &options);
    assert!(checked.diagnostics.is_empty(), "{:#?}", checked.diagnostics);
}

#[test]
fn the_engine_refuses_a_destroys_plan_however_the_rule_reads() {
    assert!(!auto_approves(true, 1), "the guard is conjoined by the engine");
    assert!(auto_approves(true, 0));
    assert!(!auto_approves(false, 0));

    assert_eq!(decide(true, 0), Decision::AutoApprove);
    assert_eq!(decide(true, 1), Decision::AskHuman);
    assert_eq!(decide(false, 0), Decision::AskHuman);
}

const ENV_FILE: &str = "\
name: policy-demo
envs:
  staging:
    ci-only: true
  prod:
    ci-only: true
steps:
  build: oci.image
    from: ./Dockerfile
";

fn policy_file(block: &str) -> String {
    format!("{ENV_FILE}policy:\n{block}")
}

#[test]
fn unknown_verbs_are_refused_under_every_property() {
    for prop in ["never", "can", "before"] {
        let src = policy_file(&format!("  agents:\n    {prop}: deply staging\n"));
        let all = diagnostics(&src);
        assert!(
            errors(&src).iter().any(|m| m.contains("unknown action `deply`")),
            "{prop}: {all:#?}"
        );
        assert!(all.iter().any(|d| d.code == Code::PolicyAction), "{prop}");
        // With a word close enough to suggest the real one.
        assert!(
            all.iter().any(|d| d.hints.iter().any(|h| h.contains("did you mean `deploy`?"))),
            "{prop}"
        );
    }
}

#[test]
fn undeclared_environments_are_refused_under_every_property() {
    for prop in ["never", "can", "before"] {
        let src = policy_file(&format!("  agents:\n    {prop}: deploy qa\n"));
        let all = diagnostics(&src);
        assert!(
            errors(&src).iter().any(|m| m.contains("undeclared environment `qa`")),
            "{prop}: {all:#?}"
        );
        assert!(all.iter().any(|d| d.code == Code::EnvProblem), "{prop}");
    }
    // Declared, so nothing is said about it.
    for prop in ["never", "can", "before"] {
        let src = policy_file(&format!("  agents:\n    {prop}: deploy staging\n"));
        assert!(errors(&src).is_empty(), "{prop}: {:?}", errors(&src));
    }
}

#[test]
fn only_never_rules_are_retained_for_enforcement() {
    // `can:` and `before:` parse and validate but grant nothing: the two
    // blocks differ only in the rules the workflow keeps.
    let can = checked(&policy_file("  agents:\n    can: read secrets\n")).workflow;
    let never = checked(&policy_file("  agents:\n    never: read secrets\n")).workflow;
    assert!(!can.policy().forbids(Actor::Agent, "read", "secrets"));
    assert!(never.policy().forbids(Actor::Agent, "read", "secrets"));
}
