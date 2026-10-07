//! Steps that need more than the context they would run in
//! ([#34](https://github.com/Keep-Shipping/harness/issues/34)): the `ci-only:`
//! annotation under a step, and the `KS0602` warning it earns locally.

use ks_core::{Catalog, CheckContext, CheckOptions, Checked, check, check_with};
use ks_lang::{Code, Diagnostic};

/// The hero-shaped file with one CI-only step at the end: everything before
/// `apply` runs on a laptop.
const SITE: &str = "\
name: api
steps:
  build:   oci.image
    from:   ./Dockerfile
  plan:    tofu.plan
    dir:    ./infra/prod
  review:  approval
    show:   plan.changes
    from:   @platform
  apply:   tofu.apply
    plan:   plan.file
  deploy:  k8s.rollout
    ci-only: true
    image:  build.digest
    to:     apply.out.cluster
";

fn checked(src: &str, context: Option<CheckContext>) -> Checked {
    let catalog = Catalog::builtin();
    let mut options = CheckOptions::new(&catalog);
    if let Some(context) = context {
        options = options.context(context);
    }
    check_with(&ks_lang::parse(src), &options)
}

fn found(checked: &Checked, code: Code) -> Vec<&Diagnostic> {
    checked.diagnostics.iter().filter(|d| d.code == code).collect()
}

#[test]
fn a_ci_only_step_warns_locally_and_is_clean_on_ci() {
    let laptop = checked(SITE, Some(CheckContext::local()));
    let local = found(&laptop, Code::NeedsContext);
    assert_eq!(local.len(), 1, "{:#?}", local);
    assert_eq!(local[0].severity, ks_lang::Severity::Warning);
    assert_eq!(
        local[0].message,
        "step `deploy` needs CI (not available locally): it will be skipped or fail"
    );
    assert_eq!(local[0].subject.as_deref(), Some("deploy"));
    assert_eq!(local[0].hints, ["run with `--skip deploy` or `--until apply`"]);

    let ci = checked(SITE, Some(CheckContext::ci()));
    assert!(ci.diagnostics.is_empty(), "{:#?}", ci.diagnostics);

    // Nothing is said when there is no context to say it against.
    assert!(check(&ks_lang::parse(SITE)).diagnostics.is_empty());
}

#[test]
fn ci_only_is_never_reported_as_an_unknown_input() {
    for kind in ["oci.image", "k8s.rollout"] {
        let src = format!("steps:\n  deploy: {kind}\n    ci-only: true\n");
        for context in [None, Some(CheckContext::local()), Some(CheckContext::ci())] {
            let checked = checked(&src, context);
            assert!(
                found(&checked, Code::UnknownInput).is_empty(),
                "`ci-only` is reserved, not an input of `{kind}`: {:#?}",
                checked.diagnostics
            );
        }
    }
}

#[test]
fn a_ci_only_that_is_not_a_boolean_is_the_type_error_it_looks_like() {
    let checked = checked(&SITE.replace("ci-only: true", "ci-only: maybe"), None);
    let errors = found(&checked, Code::TypeMismatch);
    assert_eq!(errors.len(), 1, "{:#?}", checked.diagnostics);
    assert_eq!(errors[0].message, "`ci-only` takes `true` or `false`");
    assert_eq!(errors[0].subject.as_deref(), Some("deploy.ci-only"));
    assert_eq!(errors[0].hints, ["`ci-only: true`"]);
}

/// The annotation rides on the step, which is what the run gate reads; the
/// environment's own `ci-only:` stays where it was.
#[test]
fn the_annotation_travels_with_the_step() {
    let workflow = check(&ks_lang::parse(SITE)).workflow;
    assert!(workflow.step("deploy").expect("declared").ci_only);
    assert!(!workflow.step("apply").expect("declared").ci_only);

    let false_to =
        checked(&SITE.replace("ci-only: true", "ci-only: false"), Some(CheckContext::local()));
    assert!(false_to.diagnostics.is_empty(), "{:#?}", false_to.diagnostics);
}

/// The reusable answer the checker warns from and the `run` gate reads.
#[test]
fn unmet_steps_names_what_is_missing_and_where_to_stop() {
    let workflow = check(&ks_lang::parse(SITE)).workflow;
    let catalog = Catalog::builtin();
    let unmet = ks_core::unmet_steps(&workflow, &catalog, &CheckContext::local());
    assert_eq!(unmet.len(), 1);
    assert_eq!(unmet[0].name, "deploy");
    assert_eq!(unmet[0].missing, ["CI"]);
    assert_eq!(unmet[0].until.as_deref(), Some("apply"));
    assert_eq!(
        unmet[0].message(&CheckContext::local()),
        "step `deploy` needs CI (not available locally): it will be skipped or fail"
    );
    assert!(ks_core::unmet_steps(&workflow, &catalog, &CheckContext::ci()).is_empty());
}
