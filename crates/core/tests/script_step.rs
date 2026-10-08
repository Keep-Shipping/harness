//! Script steps: a step whose kind is a path to a `.ts` file
//! ([#89](https://github.com/Keep-Shipping/harness/issues/89)). What a script
//! step declares with `action:`, and the production rule that stops an agent
//! running one that declares nothing.

use ks_core::check;
use ks_core::ports::run_context::ActorKind;
use ks_core::script_step::{PRODUCTION_ENVS, is_production, is_script_kind, needing_approval};
use ks_core::step::ActionKind;
use ks_lang::Code;

/// A script step beside a deploy that waits for it: the issue's example.
const ISSUE: &str = "\
name: api
envs:
  prod:
    secrets: prod
steps:
  migrate: ./ship/migrate.ts
    db:    secret(\"db-url\")
  deploy: k8s.rollout
    after: migrate
";

/// The same, with the step saying what kind of run it is.
const DECLARED: &str = "\
name: api
envs:
  prod:
    secrets: prod
steps:
  migrate: ./ship/migrate.ts
    db:     secret(\"db-url\")
    action: apply
";

/// An approval that will not fire in `prod`: the script step is not excused.
const SKIPPED_APPROVAL: &str = "\
name: api
envs:
  prod:
    secrets: prod
steps:
  review:  approval
    when:   env is staging
    from:   @platform
  migrate: ./ship/migrate.ts
    after:  review
    db:     secret(\"db-url\")
";

/// The steps the run would take, by name — every step unless `only` says
/// otherwise, which is what `--only` does.
fn running(src: &str, only: &[&str]) -> Vec<String> {
    let workflow = check(&ks_lang::parse(src)).workflow;
    let order = workflow.topo_order().map(<[String]>::to_vec).unwrap_or_default();
    if only.is_empty() {
        return order;
    }
    order.into_iter().filter(|name| only.contains(&name.as_str())).collect()
}

/// What the run gate would refuse, by name.
fn refused(src: &str, actor: ActorKind, env: Option<&str>, only: &[&str]) -> Vec<String> {
    let workflow = check(&ks_lang::parse(src)).workflow;
    let run = running(src, only);
    needing_approval(&workflow, actor, env, &run.iter().map(String::as_str).collect::<Vec<_>>())
        .iter()
        .map(|s| s.name.clone())
        .collect()
}

#[test]
fn a_relative_ts_path_is_a_script_kind() {
    assert!(is_script_kind("./ship/migrate.ts"));
    assert!(is_script_kind("./migrate.ts"));
    // Absolute paths, other extensions and catalog kinds are not scripts.
    assert!(!is_script_kind("migrate.ts"));
    assert!(!is_script_kind("/abs/ship/migrate.ts"));
    assert!(!is_script_kind("./ship/migrate.js"));
    assert!(!is_script_kind("k8s.rollout"));
}

#[test]
fn action_names_parse_back_to_their_kinds() {
    assert_eq!(ActionKind::parse("apply"), Some(ActionKind::Apply));
    assert_eq!(ActionKind::parse("read-secrets"), Some(ActionKind::ReadSecrets));
    assert_eq!(ActionKind::parse("other"), Some(ActionKind::Other));
    assert_eq!(ActionKind::parse("Apply"), None);
    assert_eq!(ActionKind::parse("migrate"), None);
    assert_eq!(ActionKind::parse(""), None);
}

#[test]
fn production_is_spelled_not_configured() {
    for name in PRODUCTION_ENVS {
        assert!(is_production(Some(name)), "{name}");
    }
    assert!(!is_production(Some("staging")));
    // No environment chosen is no production.
    assert!(!is_production(None));
}

#[test]
fn an_agent_in_production_needs_an_approval_or_an_action() {
    assert_eq!(refused(ISSUE, ActorKind::Agent, Some("prod"), &[]), ["migrate"]);
    assert_eq!(refused(ISSUE, ActorKind::Agent, Some("production"), &[]), ["migrate"]);
    // Declaring the action is what was missing.
    assert!(refused(DECLARED, ActorKind::Agent, Some("prod"), &[]).is_empty());
}

#[test]
fn only_an_approval_that_will_actually_run_excuses_the_step() {
    // One hop: the approval is upstream of the script step.
    let direct = "\
steps:
  review:  approval
    from:   @platform
  migrate: ./ship/migrate.ts
    after:  review
";
    assert!(refused(direct, ActorKind::Agent, Some("prod"), &[]).is_empty());
    // Two hops, through a step of its own.
    let two_hops = "\
steps:
  review:  approval
    from:   @platform
  build:   oci.image
    from:   ./Dockerfile
    after:  review
  migrate: ./ship/migrate.ts
    after:  build
";
    assert!(refused(two_hops, ActorKind::Agent, Some("prod"), &[]).is_empty());
    // An approval downstream of the script step is not before it.
    let after = "\
steps:
  migrate: ./ship/migrate.ts
  review:  approval
    from:   @platform
    after:  migrate
";
    assert_eq!(refused(after, ActorKind::Agent, Some("prod"), &[]), ["migrate"]);
    // Neither is one whose `when:` is false for the environment chosen.
    assert_eq!(refused(SKIPPED_APPROVAL, ActorKind::Agent, Some("prod"), &[]), ["migrate"]);
}

#[test]
fn a_step_the_run_does_not_cover_is_never_gated() {
    // `--only build` runs no script step, so there is nothing to refuse.
    assert!(refused(ISSUE, ActorKind::Agent, Some("prod"), &["build"]).is_empty());
    // Naming the script step itself still counts.
    assert_eq!(refused(ISSUE, ActorKind::Agent, Some("prod"), &["migrate"]), ["migrate"]);
}

#[test]
fn a_human_or_a_non_production_run_is_never_gated() {
    assert!(refused(ISSUE, ActorKind::Human, Some("prod"), &[]).is_empty());
    assert!(refused(ISSUE, ActorKind::Ci, Some("prod"), &[]).is_empty());
    assert!(refused(ISSUE, ActorKind::Agent, Some("staging"), &[]).is_empty());
    assert!(refused(ISSUE, ActorKind::Agent, None, &[]).is_empty());
}

#[test]
fn a_valid_action_checks_clean_and_is_carried_onto_the_step() {
    let checked = check(&ks_lang::parse(DECLARED));
    assert!(checked.diagnostics.is_empty(), "{:#?}", checked.diagnostics);
    let step = checked.workflow.step("migrate").expect("the migrate step");
    assert_eq!(step.kind.as_deref(), Some("./ship/migrate.ts"));
    assert_eq!(step.action, Some(ActionKind::Apply));
}

#[test]
fn an_action_the_language_does_not_know_is_an_error() {
    let src = ISSUE.replace("    db:    secret(\"db-url\")\n", "    action:  frobnicate\n");
    let checked = check(&ks_lang::parse(&src));
    let errors: Vec<_> =
        checked.diagnostics.iter().filter(|d| d.code == Code::UnknownAction).collect();
    assert_eq!(errors.len(), 1, "{:#?}", checked.diagnostics);
    assert_eq!(errors[0].message, "unknown action `frobnicate`");
    assert_eq!(
        errors[0].hints[0],
        "`action:` takes one of apply, build, deploy, destroy, other, plan, read-secrets"
    );
    // A value that is not one word at all is the same error.
    let src = ISSUE.replace("    db:    secret(\"db-url\")\n", "    action:  apply, plan\n");
    let checked = check(&ks_lang::parse(&src));
    assert!(
        checked.diagnostics.iter().any(|d| d.message == "`action` takes one word"),
        "{:#?}",
        checked.diagnostics
    );
}

#[test]
fn a_script_path_may_not_leave_the_ship_ks_directory() {
    for kind in ["./../outside.ts", "./ship/../../outside.ts"] {
        let src = ISSUE.replace("./ship/migrate.ts", kind);
        let checked = check(&ks_lang::parse(&src));
        assert!(
            checked.diagnostics.iter().any(
                |d| d.message == format!("`{kind}` is not a path inside the ship.ks directory")
            ),
            "{kind} should not be readable: {:#?}",
            checked.diagnostics
        );
    }
    // A path that stays inside is fine, however deep.
    let src = ISSUE.replace("./ship/migrate.ts", "./ship/db/migrate.ts");
    assert!(check(&ks_lang::parse(&src)).diagnostics.is_empty());
}

#[test]
fn action_on_a_catalog_kind_is_still_an_input_the_catalog_decides() {
    // `k8s.rollout` declares no `action:`, so the file is wrong the way any
    // unknown input is — the rule is reserved on script steps only.
    let checked = check(&ks_lang::parse("steps:\n  deploy: k8s.rollout\n    action: apply\n"));
    assert!(
        checked.diagnostics.iter().any(|d| d.code == Code::UnknownInput),
        "{:#?}",
        checked.diagnostics
    );
    assert_eq!(checked.workflow.step("deploy").expect("deploy").action, None);
}
