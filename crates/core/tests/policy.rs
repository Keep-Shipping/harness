//! The site's `policy:` block over a workflow that plans, decides and
//! approves, and the one hard rule on `auto:` — destroys always go to a human
//! (ADR 0012).

use ks_core::auto_rule::{
    Decision, MISSING_GUARD_HINT, MISSING_GUARD_MESSAGE, auto_approves, decide as auto_rule_decide,
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
  build: oci.image
    from: ./Dockerfile
  plan: tofu.plan
    dir: ./infra
  apply: tofu.apply
    plan: plan.file
  deploy: k8s.rollout
    image: build.digest
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

    assert_eq!(auto_rule_decide(true, 0), Decision::AutoApprove);
    assert_eq!(auto_rule_decide(true, 1), Decision::AskHuman);
    assert_eq!(auto_rule_decide(false, 0), Decision::AskHuman);
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

// --- effective policy ------------------------------------------------------

use ks_core::policy::{Source, decide as effective};
use ks_core::ports::policy::{
    ANY_OBJECT, Baseline, BaselineSource, Disposition, Provenance, Rule, Subject,
};
use ks_core::step::{ActionClass, ActionKind};

/// The site's policy block over a file with an apply step: `apply` sits under
/// `before:`, so an agent's apply asks `@platform`.
fn site_policy() -> ks_core::Policy {
    checked(&format!("{HEAD}{POLICY}")).workflow.policy().clone()
}

/// An org baseline with one rule, declared the way a real one is.
fn baseline(rules: Vec<Rule>) -> Baseline {
    let source = BaselineSource::Hosted { location: "https://policy.example.com".to_string() };
    Baseline { rules, source: Some(source) }
}

fn rule(subject: Subject, verb: &str, object: &str, disposition: Disposition) -> Rule {
    Rule {
        subject,
        verb: verb.to_string(),
        object: object.to_string(),
        disposition,
        provenance: Provenance::Baseline {
            source: BaselineSource::Hosted { location: "https://policy.example.com".to_string() },
        },
    }
}

fn apply() -> ActionClass {
    ActionClass::new(ActionKind::Apply)
}

fn deploy_in(env: &str) -> ActionClass {
    ActionClass::new(ActionKind::Deploy).in_env(env)
}

fn envless_deploy() -> ActionClass {
    ActionClass::new(ActionKind::Deploy)
}

/// One decision, with the whole of it asserted. `#[track_caller]` so a failing
/// row names the row rather than this helper.
#[track_caller]
fn assert_decision(
    policy: &ks_core::Policy,
    baseline: Option<&Baseline>,
    actor: Actor,
    class: &ActionClass,
    disposition: Disposition,
    source: Source,
) {
    let decision = effective(policy, baseline, actor, class).expect("governed");
    assert_eq!((decision.disposition, decision.source), (disposition, source), "class {class}");
}

#[test]
fn the_whole_policy_block_is_retained_not_only_the_never_rules() {
    let policy = site_policy();
    let rule_for = |verb: &str, object: &str| {
        policy
            .rules()
            .iter()
            .find(|r| r.subject == Actor::Agent && r.verb == verb && r.object == object)
            .map(|r| r.disposition)
    };
    assert_eq!(rule_for("build", ANY_OBJECT), Some(Disposition::Allow), "`can: build`");
    assert_eq!(rule_for("deploy", "prod"), Some(Disposition::Ask), "`before: deploy prod`");
    // The handles are the handle, not the `@`.
    assert_eq!(policy.ask_handles(Actor::Agent).collect::<Vec<_>>(), ["platform"]);
}

#[test]
fn with_no_baseline_the_effective_policy_is_the_files_own() {
    // ADR 0012's fifth acceptance condition, asserted rather than assumed: the
    // unconfigured case is the file's policy and nothing else.
    let policy = checked(&policy_file("  agents:\n    can: apply\n")).workflow;
    let policy = policy.policy();
    assert_decision(policy, None, Actor::Agent, &apply(), Disposition::Allow, Source::File);

    // Naming the built-in default instead would change the answer: it carries
    // no `apply` rule, so it asks where the file allows.
    let against = Baseline::conservative();
    assert_decision(
        policy,
        Some(&against),
        Actor::Agent,
        &apply(),
        Disposition::Ask,
        Source::Default,
    );
}

#[test]
fn the_file_rules_the_actor_it_names() {
    // `can:` allows, `before:` asks the named handles, `never:` refuses, and
    // an action no rule names is the leash: an ask for an agent, an allow for
    // a human.
    let policy = site_policy();
    let asks = effective(&policy, None, Actor::Agent, &apply()).expect("governed");
    assert_eq!(asks.ask, ["platform"]);
    assert!(asks.rule_span.is_some(), "the deciding rule points at the file");
    // `publish` is outside the vocabulary, so no rule governs it at all.
    assert!(effective(&policy, None, Actor::Agent, &ActionClass::new(ActionKind::Other)).is_none());

    let cases: &[(Actor, ActionClass, Disposition, Source)] = &[
        (Actor::Agent, ActionClass::new(ActionKind::Build), Disposition::Allow, Source::File),
        (Actor::Agent, apply(), Disposition::Ask, Source::File),
        (Actor::Agent, ActionClass::new(ActionKind::ReadSecrets), Disposition::Never, Source::File),
        (Actor::Agent, ActionClass::new(ActionKind::Plan), Disposition::Allow, Source::File),
        // Nothing names `plan` for a human: no leash, so an allow by default.
        (Actor::Human, ActionClass::new(ActionKind::Plan), Disposition::Allow, Source::Default),
        (Actor::Human, apply(), Disposition::Allow, Source::Default),
        (Actor::Human, deploy_in("prod"), Disposition::Allow, Source::Default),
    ];
    for (actor, class, disposition, source) in cases {
        assert_decision(&policy, None, *actor, class, *disposition, *source);
    }
}

#[test]
fn humans_follow_the_same_file_minus_the_leash() {
    // The file refuses agents an apply; a human running the same apply reads
    // `humans:`, which the file does not declare, and is not refused.
    let policy = site_policy();
    assert_decision(&policy, None, Actor::Human, &apply(), Disposition::Allow, Source::Default);
    assert_decision(
        &policy,
        None,
        Actor::Human,
        &deploy_in("prod"),
        Disposition::Allow,
        Source::Default,
    );

    // A `humans:` section does bind a human — and only a human.
    let src = policy_file("  humans:\n    never: apply\n  agents:\n    can: apply\n");
    let policy = checked(&src).workflow;
    let policy = policy.policy();
    assert_decision(policy, None, Actor::Human, &apply(), Disposition::Never, Source::File);
    assert_decision(policy, None, Actor::Agent, &apply(), Disposition::Allow, Source::File);

    // CI reads `humans:` too: it is a machine somebody else put in the
    // repository on a reviewed branch, not the agent driving itself.
    assert_decision(policy, None, Actor::Ci, &apply(), Disposition::Never, Source::File);
}

#[test]
fn a_baseline_can_narrow_but_never_widen() {
    let ask_apply =
        baseline(vec![rule(Subject::Actor(Actor::Agent), "apply", ANY_OBJECT, Disposition::Ask)]);
    // The file would allow it; the baseline asks. The file cannot widen.
    let policy = checked(&policy_file("  agents:\n    can: apply\n")).workflow;
    assert_decision(
        policy.policy(),
        Some(&ask_apply),
        Actor::Agent,
        &apply(),
        Disposition::Ask,
        Source::Baseline,
    );
    // A baseline rule that is *not* the strict one says nothing either way.
    let wider =
        baseline(vec![rule(Subject::Actor(Actor::Agent), "apply", ANY_OBJECT, Disposition::Allow)]);
    let decision =
        effective(policy.policy(), Some(&wider), Actor::Agent, &apply()).expect("governed");
    assert_eq!(decision.disposition, Disposition::Allow);
    assert_eq!(decision.source, Source::File, "the file decided, not the baseline");

    // The reverse: the file asks where the baseline allows. The file narrows,
    // and the file is where the answer came from.
    let policy = checked(&policy_file("  agents:\n    before: apply\n")).workflow;
    assert_decision(
        policy.policy(),
        Some(&ask_apply),
        Actor::Agent,
        &apply(),
        Disposition::Ask,
        Source::File,
    );

    // A `never:` rule refuses whatever the baseline says.
    let permissive =
        baseline(vec![rule(Subject::Actor(Actor::Agent), "read", "secrets", Disposition::Allow)]);
    let secrets = ActionClass::new(ActionKind::ReadSecrets);
    assert_decision(
        &site_policy(),
        Some(&permissive),
        Actor::Agent,
        &secrets,
        Disposition::Never,
        Source::File,
    );
}

#[test]
fn a_leash_ask_is_default_not_the_baselines_allow() {
    // No file rule names `build`, so the leash decides it. A baseline allowing
    // build is not the reason, so the source is `Default` — naming the
    // baseline would credit a document with a decision it lost.
    let src = policy_file("  agents:\n    can: apply\n");
    let policy = checked(&src).workflow;
    let allow_build =
        baseline(vec![rule(Subject::Actor(Actor::Agent), "build", ANY_OBJECT, Disposition::Allow)]);
    assert_decision(
        policy.policy(),
        Some(&allow_build),
        Actor::Agent,
        &ActionClass::new(ActionKind::Build),
        Disposition::Ask,
        Source::Default,
    );
}

#[test]
fn an_env_scoped_rule_leaves_an_envless_class_at_least_an_ask() {
    // `can: deploy staging` grants nothing to a deploy whose environment
    // nobody has named. A `never:`/`before:` naming one is different — which
    // deploy this is the one thing the checker could not answer — so the
    // env-less decision is an ask, and the per-environment answers decide.
    let src = policy_file("  agents:\n    can: deploy staging\n    never: deploy prod\n");
    let policy = checked(&src).workflow;
    let policy = policy.policy();

    let cases: &[(ActionClass, Disposition, Source)] = &[
        (deploy_in("staging"), Disposition::Allow, Source::File),
        (deploy_in("prod"), Disposition::Never, Source::File),
        (envless_deploy(), Disposition::Ask, Source::File),
    ];
    for (class, disposition, source) in cases {
        assert_decision(policy, None, Actor::Agent, class, *disposition, *source);
    }
    // A human is still not bound by the `agents:` block.
    assert_decision(
        policy,
        None,
        Actor::Human,
        &envless_deploy(),
        Disposition::Allow,
        Source::Default,
    );

    // `before: deploy prod` is env-scoped too, and names who is asked.
    let src = policy_file("  agents:\n    before: deploy prod\n    ask: @platform\n");
    let decision =
        effective(checked(&src).workflow.policy(), None, Actor::Agent, &envless_deploy())
            .expect("governed");
    assert_eq!(decision.disposition, Disposition::Ask);
    assert_eq!(decision.ask, ["platform"]);

    // `*` is not an environment, so a rule naming it is not env-scoped: it
    // decides an env-less class outright, as it decides any other.
    let src = policy_file("  agents:\n    never: build\n");
    assert_decision(
        checked(&src).workflow.policy(),
        None,
        Actor::Agent,
        &ActionClass::new(ActionKind::Build),
        Disposition::Never,
        Source::File,
    );
}

#[test]
fn destroy_never_reaches_an_agent_as_an_allow() {
    // The file allows destroy outright, and so does the baseline.
    let src = policy_file("  agents:\n    can: destroy prod\n");
    let policy = checked(&src).workflow;
    let destroy = ActionClass::new(ActionKind::Destroy).in_env("prod");
    let permissive = baseline(vec![rule(
        Subject::Actor(Actor::Agent),
        "destroy",
        ANY_OBJECT,
        Disposition::Allow,
    )]);
    assert_decision(
        policy.policy(),
        Some(&permissive),
        Actor::Agent,
        &destroy,
        Disposition::Ask,
        Source::HardRule,
    );
    // A human is not refused, and the baseline's agent rule does not reach
    // them — so it asks, which is its fail-closed default.
    assert_ne!(
        effective(policy.policy(), Some(&permissive), Actor::Human, &destroy)
            .expect("governed")
            .disposition,
        Disposition::Never
    );
}

// --- check-time enforcement ------------------------------------------------

/// The same file checked as `actor`, so policy rules that bind it fire.
fn checked_as(src: &str, actor: Actor) -> Checked {
    ks_core::check_with(
        &ks_lang::parse(src),
        &ks_core::CheckOptions::new(&ks_core::Catalog::builtin()).actor(actor),
    )
}

fn checked_as_agent(src: &str) -> Checked {
    checked_as(src, Actor::Agent)
}

const APPLY_FILE: &str = "\
name: enforced
envs:
  prod:
    ci-only: true
steps:
  plan: tofu.plan
    dir: ./infra
  apply: tofu.apply
    plan: plan.file
";

#[test]
fn a_never_rule_refuses_the_step_it_covers_for_the_actor_it_names() {
    // The `agents:` block does not bind a human, whatever the step is.
    for (actor, section) in [(Actor::Agent, "agents"), (Actor::Human, "humans")] {
        let src = format!("{APPLY_FILE}policy:\n  {section}:\n    never: apply\n");
        let found = checked_as(&src, actor);
        let refusals: Vec<&Diagnostic> =
            found.diagnostics.iter().filter(|d| d.code == Code::PolicyForbidden).collect();
        assert_eq!(refusals.len(), 2, "{section}: the step and the rule: {:#?}", found.diagnostics);
        assert!(
            refusals[0].message.contains("but this run has a `tofu.apply` step"),
            "{section}: {:#?}",
            refusals[0]
        );
        assert!(refusals[0].hints[0].contains("never: apply"), "{section}: {:#?}", refusals[0]);
    }
    // And each actor is untouched by the other's section.
    let src = format!("{APPLY_FILE}policy:\n  agents:\n    never: apply\n");
    assert!(!errors(&src).iter().any(|m| m.contains("policy forbids")));
}

const DEPLOY_STEP: &str = "  deploy: k8s.rollout\n    \
     image: \"sha256:0000000000000000000000000000000000000000000000000000000000000000\"\n";

#[test]
fn an_env_scoped_never_does_not_refuse_an_envless_step() {
    // A step names no environment, so a rule about `prod` alone cannot be
    // shown to cover it: the env-less decision is an ask, not an error.
    let src = format!("{APPLY_FILE}{DEPLOY_STEP}policy:\n  agents:\n    never: deploy prod\n");
    let found = checked_as_agent(&src);
    assert!(
        !found.diagnostics.iter().any(|d| d.code == Code::PolicyForbidden),
        "{:#?}",
        found.diagnostics
    );
    // A rule that names no environment does refuse the same step.
    let src = format!("{APPLY_FILE}{DEPLOY_STEP}policy:\n  agents:\n    never: deploy\n");
    let found = checked_as_agent(&src);
    assert!(
        found.diagnostics.iter().any(|d| d.code == Code::PolicyForbidden),
        "{:#?}",
        found.diagnostics
    );
}

#[test]
fn an_ask_is_not_an_error_at_check_time() {
    // `before: apply` asks; it does not refuse. The approval is the run's job.
    let src = format!(
        "{APPLY_FILE}policy:\n  agents:\n    can: check\n    ask: @platform\n    before: apply\n"
    );
    let found = checked_as_agent(&src);
    assert!(errors(&src).is_empty(), "{:?}", errors(&src));
    assert!(!found.diagnostics.iter().any(|d| d.code == Code::PolicyForbidden));
}

#[test]
fn the_read_secrets_refusal_is_unchanged() {
    let src = "\
name: secrets
policy:
  agents:
    never: read secrets
steps:
  migrate: web.migrate
    url: secrets.db_url
";
    let messages: Vec<String> =
        checked_as_agent(src).diagnostics.iter().map(ToString::to_string).collect();
    assert!(
        messages.iter().any(|m| m.contains(
            "policy forbids agents from reading secrets, but this run needs secrets.db_url"
        )),
        "{messages:?}"
    );
    assert!(
        messages.iter().any(|m| m.contains("the `never: read secrets` rule applies to this run")),
        "{messages:?}"
    );
}

// --- vocabulary ------------------------------------------------------------

#[test]
fn the_new_verbs_parse_and_keep_their_objects() {
    let src = policy_file("  agents:\n    can: run scripts, publish blocks\n");
    assert!(errors(&src).is_empty(), "{:?}", errors(&src));
    let policy = checked(&src).workflow;
    let policy = policy.policy();
    let object = |verb: &str| {
        policy
            .rules()
            .iter()
            .find(|r| r.verb == verb)
            .map(|r| r.object.clone())
            .unwrap_or_else(|| panic!("{verb} was not kept"))
    };
    assert_eq!(object("run"), "scripts");
    assert_eq!(object("publish"), "blocks");
    // The environment form still parses, and still names an environment.
    let src = policy_file("  agents:\n    can: publish staging\n");
    assert!(errors(&src).is_empty(), "{:?}", errors(&src));
    assert_eq!(checked(&src).workflow.policy().rules()[0].object, "staging");
}

#[test]
fn the_object_taking_verbs_refuse_anything_else() {
    for (verb, object) in [("read", "secrets"), ("run", "scripts")] {
        let src = policy_file(&format!("  agents:\n    can: {verb} prod\n"));
        let all = diagnostics(&src);
        assert!(
            errors(&src).iter().any(|m| m.contains(&format!("`{verb}` takes `{object}`"))),
            "{verb}: {all:#?}"
        );
    }
}

// --- the unused-verb warning -----------------------------------------------

/// The KS0404 warnings `block` earns over the apply file.
fn unused_warnings(block: &str) -> Vec<String> {
    let src = format!("{APPLY_FILE}policy:\n{block}");
    checked(&src)
        .diagnostics
        .iter()
        .filter(|d| d.code == Code::PolicyUnused)
        .map(|d| d.message.clone())
        .collect()
}

#[test]
fn ks0404_is_only_about_verbs_a_step_kind_can_produce() {
    // A `can:`/`before:` rule for a verb no step kind produces is vocabulary
    // ahead of the step kinds, not a claim about this file.
    assert!(unused_warnings("  agents:\n    can: check\n").is_empty());
    assert!(unused_warnings("  agents:\n    can: test\n").is_empty());
    assert!(unused_warnings("  agents:\n    can: run scripts\n").is_empty());
    assert!(unused_warnings("  agents:\n    can: publish blocks\n").is_empty());
    // A producing verb with no matching step is a real claim about the file.
    assert_eq!(
        unused_warnings("  agents:\n    can: deploy prod\n"),
        ["no step in this file can `deploy prod`".to_string()]
    );
    // `destroy` counts as produced: an apply whose plan destroys is one.
    assert!(unused_warnings("  agents:\n    before: destroy\n").is_empty());
    // So does a rule whose object a reference produces.
    assert_eq!(
        unused_warnings("  agents:\n    can: read secrets\n"),
        ["no step in this file can `read secrets`".to_string()]
    );
    // `never:` is exempt in the other direction: forbidding what the file does
    // not do is defensible policy.
    assert!(unused_warnings("  agents:\n    never: publish prod\n").is_empty());
}

#[test]
fn ks0404_goes_quiet_when_the_step_it_is_about_arrives() {
    assert!(
        !checked(&format!(
            "{APPLY_FILE}  deploy: k8s.rollout\n    image: \
             \"sha256:0000000000000000000000000000000000000000000000000000000000000000\"\n\
             policy:\n  agents:\n    can: deploy prod\n"
        ))
        .diagnostics
        .iter()
        .any(|d| d.code == Code::PolicyUnused)
    );
    // A secret reference produces `read secrets`, as a reference rather than a
    // step kind.
    let src = format!("{APPLY_FILE}  migrate: web.migrate\n    url: secrets.db_url\n");
    assert!(
        !checked(&format!("{src}policy:\n  agents:\n    can: read secrets\n"))
            .diagnostics
            .iter()
            .any(|d| d.code == Code::PolicyUnused)
    );
}
