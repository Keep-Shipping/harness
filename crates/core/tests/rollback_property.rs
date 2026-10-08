//! `rollback:` as a reserved step property ([#78](https://github.com/Keep-Shipping/harness/issues/78)):
//! `check` accepts the key on every step, checks its value, and carries the
//! policy it parsed onto the workflow's step, so the answer is the executor's
//! to read rather than its own default.

use ks_core::step::RollbackPolicy;
use ks_core::{Checked, check};
use ks_lang::{Code, Diagnostic};

fn checked(src: &str) -> Checked {
    check(&ks_lang::parse(src))
}

fn found(checked: &Checked, code: Code) -> Vec<&Diagnostic> {
    checked.diagnostics.iter().filter(|d| d.code == code).collect()
}

#[test]
fn rollback_is_never_reported_as_an_unknown_input() {
    // Every policy, on a step kind that declares no such input.
    for policy in ["auto", "manual", "none"] {
        let src = format!("steps:\n  deploy: k8s.rollout\n    rollback: {policy}\n");
        let checked = checked(&src);
        assert!(
            found(&checked, Code::UnknownInput).is_empty(),
            "`rollback` is reserved, not an input of `k8s.rollout`: {:#?}",
            checked.diagnostics
        );
    }
}

#[test]
fn every_policy_the_executor_spells_is_accepted() {
    let src = "\
steps:
  build: oci.image
    from: ./Dockerfile
    rollback: auto
  deploy: k8s.rollout
    image: build.digest
    rollback: manual
  tear: k8s.rollout
    image: build.digest
    rollback: none
";
    let checked = checked(src);
    assert!(checked.diagnostics.is_empty(), "{:#?}", checked.diagnostics);
    // The key is reserved on every kind, not only a deploy: `oci.image` has no
    // rollback to do and still checks clean.
    assert_eq!(checked.workflow.steps().len(), 3);
}

#[test]
fn a_rollback_that_is_not_a_policy_is_the_type_error_it_looks_like() {
    let checked = checked("steps:\n  deploy: k8s.rollout\n    rollback: never\n");
    let errors = found(&checked, Code::TypeMismatch);
    assert_eq!(errors.len(), 1, "{:#?}", checked.diagnostics);
    assert_eq!(errors[0].message, "`rollback` takes `auto`, `manual` or `none`");
    assert_eq!(errors[0].subject.as_deref(), Some("deploy.rollback"));
    assert_eq!(errors[0].hints, ["`rollback: auto`"]);
    assert!(found(&checked, Code::UnknownInput).is_empty(), "{:#?}", checked.diagnostics);
}

/// The checker is not the end of the road: the policy it parses travels on
/// the workflow's step, so two files that differ only in `rollback:` produce
/// two steps that are genuinely different. A file that says `manual` gets
/// `manual`; a file that says nothing gets the default, `auto`.
#[test]
fn the_checked_policy_reaches_the_workflows_step() {
    for (written, expected) in [
        ("auto", RollbackPolicy::Auto),
        ("manual", RollbackPolicy::Manual),
        ("none", RollbackPolicy::None),
    ] {
        let src = format!("steps:\n  deploy: k8s.rollout\n    rollback: {written}\n");
        let wf = checked(&src).workflow;
        let step = wf.step("deploy").expect("the deploy step is declared");
        assert_eq!(step.rollback, expected, "from `rollback: {written}`");
    }

    // A step that writes no key is the default, and the default is `auto` —
    // so the key is what changes the answer, not the presence of the step.
    let plain = checked("steps:\n  deploy: k8s.rollout\n");
    let plain_step = plain.workflow.step("deploy").expect("the deploy step is declared");
    assert_eq!(plain_step.rollback, RollbackPolicy::Auto);
    assert_eq!(RollbackPolicy::default(), RollbackPolicy::Auto, "the default is `auto`");
}

/// A value that is present but is not a bare word naming one of the three
/// policies names no policy at all — and guessing `auto` would be the one
/// guess that reverts the deployment. Each of these shapes is the same type
/// error as `rollback: never`, not silence.
#[test]
fn a_rollback_written_as_something_other_than_a_bare_word_is_an_error() {
    for written in ["never", "AUTO", "\"manual\"", "\"bogus\"", "[auto]", "[auto, manual]"] {
        let checked = checked(&format!("steps:\n  deploy: k8s.rollout\n    rollback: {written}\n"));
        let errors = found(&checked, Code::TypeMismatch);
        assert_eq!(
            errors.len(),
            1,
            "`rollback: {written}` should be one type error, got {:#?}",
            checked.diagnostics
        );
        assert_eq!(errors[0].message, "`rollback` takes `auto`, `manual` or `none`");
        assert_eq!(errors[0].subject.as_deref(), Some("deploy.rollback"));
        assert_eq!(errors[0].hints, ["`rollback: auto`"]);
    }
}
