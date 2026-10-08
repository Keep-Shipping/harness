//! The environment guard ([#123](https://github.com/Keep-Shipping/harness/issues/123)):
//! an environment that says `ci-only: true`, or that is named `prod`, stops
//! a local run before an apply or a deploy. A plan is not a change, and a
//! step the run does not cover is not this guard's business.
//!
//! There is deliberately no in-file opt-out: the file is written by the
//! people the rule is there to stop.

use std::collections::BTreeMap;

use ks_core::block::{self, BlockSignature};
use ks_core::env_guard::{ci_only_refusal, is_ci_only};
use ks_core::{Catalog, CheckOptions, check_with};

/// A site whose environments are told apart by name alone, and whose steps
/// cover each of the three things that matter here: a plan, an apply and a
/// deploy.
const SITE: &str = "\
name: api
envs:
  staging:
    secrets: staging
  prod:
    secrets: prod
steps:
  build: oci.image
    from: ./Dockerfile
  plan:  tofu.plan
    dir:  ./infra
  apply: tofu.apply
    plan: plan.file
  ship:  k8s.rollout
    image: build.digest
";

/// The same site with a non-production environment that declares the rule
/// itself, so the property is exercised apart from the name.
const DECLARED: &str = "\
name: api
envs:
  qa:
    ci-only: true
steps:
  plan:  tofu.plan
    dir:  ./infra
  apply: tofu.apply
    plan: plan.file
  ship:  k8s.rollout
    image: apply.out.thing
";

/// A block file declaring `name`, and a site whose only other step is a
/// build, so what is refused is the use and not the site.
fn with_block(label: &str, steps: &str) -> (String, String) {
    let block = format!("block: {label}\nsteps:\n{steps}");
    let site = format!(
        "\
name: api
envs:
  prod:
    secrets: prod
steps:
  build: oci.image
    from: ./Dockerfile
  do: {label}
"
    );
    (block, site)
}

/// The step names `env` refuses over `running`, in file order.
fn refused(src: &str, env: &str, running: &[&str]) -> Vec<String> {
    let checked = check_with(&ks_lang::parse(src), &CheckOptions::new(&Catalog::builtin()));
    assert!(checked.diagnostics.is_empty(), "{src}: {:#?}", checked.diagnostics);
    let target = checked.workflow.envs().iter().find(|e| e.name == env).expect("the environment");
    ci_only_refusal(&checked.workflow, target, running)
        .steps
        .iter()
        .map(|s| s.name.clone())
        .collect()
}

/// The message a user reads, one line per refused step.
fn message(src: &str, env: &str, running: &[&str]) -> String {
    let checked = check_with(&ks_lang::parse(src), &CheckOptions::new(&Catalog::builtin()));
    let target = checked.workflow.envs().iter().find(|e| e.name == env).expect("the environment");
    ci_only_refusal(&checked.workflow, target, running).to_string()
}

/// What a site whose `do` step uses a block made of `steps` refuses, with the
/// block resolved as the CLI resolves it — `blocks/` beside the file.
fn refused_through_block(block_src: &str, site_src: &str, running: &[&str]) -> Vec<String> {
    let signature: BlockSignature =
        block::signature(&ks_lang::parse(block_src), &Catalog::builtin(), &BTreeMap::new())
            .expect("a block file");
    let blocks = BTreeMap::from([("roll".to_string(), signature)]);
    let checked = check_with(
        &ks_lang::parse(site_src),
        &CheckOptions::new(&Catalog::builtin()).blocks(&blocks),
    );
    assert!(checked.diagnostics.is_empty(), "{:#?}", checked.diagnostics);
    let prod = checked.workflow.envs().iter().find(|e| e.name == "prod").expect("prod");
    ci_only_refusal(&checked.workflow, prod, running).steps.iter().map(|s| s.name.clone()).collect()
}

/// The name is the claim a reader already trusts, and the declaration is the
/// same answer — one rule, not a default a file can lower.
#[test]
fn an_environment_is_ci_only_by_name_or_by_declaration() {
    let src = "\
envs:
  staging:
  prod:
  production:
  qa:
    ci-only: true
  live:
steps:
  apply: tofu.apply
    dir: ./infra
";
    let checked = check_with(&ks_lang::parse(src), &CheckOptions::new(&Catalog::builtin()));
    let ci_only = |name: &str| {
        is_ci_only(checked.workflow.envs().iter().find(|e| e.name == name).expect(name))
    };
    assert!(ci_only("prod") && ci_only("production"), "the production names are the claim");
    assert!(ci_only("qa"), "so is a declared one");
    assert!(!ci_only("staging"));
    // Spelling, not reach: `live` is production to whoever runs it and this
    // rule does not read it. A file that wants it says so.
    assert!(!ci_only("live"));
}

/// The deliberate absence of an opt-out.
#[test]
fn an_environment_the_file_lowers_stays_ci_only() {
    let src = SITE.replace("  prod:\n    secrets: prod\n", "  prod:\n    ci-only: false\n");
    assert_eq!(refused(&src, "prod", &["apply"]), ["apply"]);
}

/// Only apply and deploy change an environment, and only the steps this run
/// covers are the run's business — what makes `--skip` and `--until` a way
/// out the guard can offer.
#[test]
fn only_a_step_the_run_takes_and_that_changes_is_refused() {
    assert_eq!(refused(SITE, "prod", &["plan"]), Vec::<String>::new(), "planning changes nothing");
    assert_eq!(refused(SITE, "prod", &["apply"]), ["apply"]);
    assert_eq!(refused(SITE, "prod", &["ship"]), ["ship"]);
    assert_eq!(refused(SITE, "prod", &["build", "plan"]), Vec::<String>::new());
    assert_eq!(refused(SITE, "prod", &[]), Vec::<String>::new());
    assert_eq!(refused(SITE, "staging", &["apply", "ship"]), Vec::<String>::new());
    assert_eq!(message(SITE, "prod", &["plan"]), "");
}

/// A script step says what it does with `action:`; one that says nothing
/// asserts nothing this rule can act on.
#[test]
fn a_script_step_is_read_through_the_action_it_declares() {
    let src = "\
envs:
  prod:
    secrets: prod
steps:
  migrate: ./ship/migrate.ts
    action: apply
  report: ./ship/report.ts
    action: other
  nudge: ./ship/nudge.ts
";
    assert_eq!(refused(src, "prod", &["migrate", "report", "nudge"]), ["migrate"]);
}

/// A block use carries the actions of the steps inside it
/// ([#80](https://github.com/Keep-Shipping/harness/issues/80)), so a block
/// cannot launder a change past an environment that is `ci-only` — whichever
/// kind of step makes it.
#[test]
fn a_block_cannot_hide_a_change_from_the_environment() {
    for (what, steps) in [
        ("a catalog step", "  apply: tofu.apply\n    dir: ./infra\n"),
        (
            "a script step declaring `action: apply`",
            "  migrate: ./ship/migrate.ts\n    action: apply\n",
        ),
        (
            "a script step declaring `action: deploy`",
            "  ship: ./ship/ship.ts\n    action: deploy\n",
        ),
    ] {
        let (block_src, site_src) = with_block("roll", steps);
        assert_eq!(
            refused_through_block(&block_src, &site_src, &["build", "do"]),
            ["do"],
            "{what} inside a block must not launder itself past prod"
        );
    }
}

/// What a user reads: the step, the environment, and why this is not the
/// place for it — every refused step named on its own line.
#[test]
fn the_message_names_every_step_the_environment_and_why() {
    assert_eq!(
        message(SITE, "prod", &["apply", "ship"]),
        "refusing to start: step `apply` applies into `prod`; prod credentials belong in CI, \
         not on a laptop\n\
         refusing to start: step `ship` deploys into `prod`; prod credentials belong in CI, \
         not on a laptop"
    );
    // An environment that is not production says the declaration instead of
    // claiming credentials it may not have.
    assert_eq!(
        message(DECLARED, "qa", &["apply"]),
        "refusing to start: step `apply` applies into `qa`; `qa` is `ci-only: true`"
    );
    assert_eq!(refused(DECLARED, "qa", &["apply", "ship"]), ["apply", "ship"]);
}
