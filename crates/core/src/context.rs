//! What a step needs from its environment, against what a context has
//! ([#34](https://github.com/Keep-Shipping/harness/issues/34)).
//!
//! A step declares its needs — its kind's
//! [`StepCapabilities`](crate::step::StepCapabilities), plus
//! `ci-only: true` in the file — and a [`CheckContext`] says what a run here
//! has. Comparing the two before anything runs is the whole job: the checker's
//! warning and the `run` gate speak from one answer.
//!
//! Pure computation; reading the environment to decide *which* context you are
//! in belongs to the caller.

use std::collections::BTreeSet;

use ks_lang::Span;

use crate::catalog::Catalog;
use crate::ports::run_context::{Capabilities, NetworkScope};
use crate::workflow::{Step, Workflow};

/// Which kind of place a run would happen in, as `--context` spells it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextName {
    /// A laptop: no CI, no OIDC token, and a person to answer prompts.
    Local,
    /// A CI job: CI itself, an OIDC token, and nobody at the keyboard.
    Ci,
}

impl ContextName {
    /// `local` or `ci`; anything else is a usage error.
    #[must_use]
    pub fn parse(text: &str) -> Option<ContextName> {
        match text {
            "local" => Some(ContextName::Local),
            "ci" => Some(ContextName::Ci),
            _ => None,
        }
    }

    /// The context this name stands for.
    #[must_use]
    pub fn context(self) -> CheckContext {
        match self {
            ContextName::Local => CheckContext::local(),
            ContextName::Ci => CheckContext::ci(),
        }
    }
}

/// What a run in a given place can do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckContext {
    name: ContextName,
    capabilities: Capabilities,
}

impl CheckContext {
    /// A laptop: nothing only a CI job has.
    #[must_use]
    pub fn local() -> CheckContext {
        CheckContext {
            name: ContextName::Local,
            capabilities: Capabilities {
                oidc: false,
                interactive: true,
                ci_cache: false,
                network: NetworkScope::Any,
                secret_resolvers: BTreeSet::new(),
            },
        }
    }

    /// A CI job: OIDC tokens and a cache, and nobody at the keyboard.
    #[must_use]
    pub fn ci() -> CheckContext {
        CheckContext {
            name: ContextName::Ci,
            capabilities: Capabilities {
                oidc: true,
                interactive: false,
                ci_cache: true,
                network: NetworkScope::Any,
                secret_resolvers: BTreeSet::new(),
            },
        }
    }

    /// Whether CI is in charge, which is what a `ci-only` step asks for.
    fn is_ci(&self) -> bool {
        self.name == ContextName::Ci
    }

    /// How a message says where the run would happen, to say what is missing
    /// from it.
    fn absence(&self) -> &'static str {
        match self.name {
            ContextName::Local => "locally",
            ContextName::Ci => "on CI",
        }
    }
}

/// One step this context cannot run as it stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnmetStep {
    /// The step's name, as the file spells it.
    pub name: String,
    /// The step header, where a diagnostic about it points.
    pub span: Span,
    /// What the context lacks, in plain words — never `ci.only`, which names
    /// a context reference.
    pub missing: Vec<&'static str>,
    /// The step to stop at instead: the last runnable one before the *first*
    /// step that cannot run, in [`run_order`]. Every unmet step shares it, so
    /// the `--until` a warning suggests stops before all of them.
    pub until: Option<String>,
}

impl UnmetStep {
    /// What the step needs that this context has not got, said once:
    /// "needs CI (not available locally)".
    #[must_use]
    pub fn reason(&self, ctx: &CheckContext) -> String {
        format!("needs {} (not available {})", list(&self.missing), ctx.absence())
    }

    /// The warning the checker raises at the step.
    #[must_use]
    pub fn message(&self, ctx: &CheckContext) -> String {
        format!("step `{}` {}: it will be skipped or fail", self.name, self.reason(ctx))
    }

    /// How to run anyway, without the step.
    #[must_use]
    pub fn hint(&self) -> String {
        match &self.until {
            Some(until) => format!("run with `--skip {}` or `--until {until}`", self.name),
            None => format!("run with `--skip {}`", self.name),
        }
    }
}

/// The steps in the order a run would take them: the topological order when
/// the file has one, and the file's own order when it does not (a cycle is an
/// error; it never runs). The one definition — hints, `--until` and the
/// "N of M" numbers all count in it.
#[must_use]
pub fn run_order(workflow: &Workflow) -> Vec<&str> {
    match workflow.topo_order() {
        Some(order) => order.iter().map(String::as_str).collect(),
        None => workflow.steps().iter().map(|s| s.name.as_str()).collect(),
    }
}

/// Every step of `workflow` whose needs `ctx` cannot meet, in file order.
///
/// A step's needs are its kind's declared
/// [`StepCapabilities`](crate::step::StepCapabilities) plus `ci-only:
/// true` in the file, so a harness whose step kinds declare their needs is
/// checked the same way a hand-annotated file is.
#[must_use]
pub fn unmet_steps(workflow: &Workflow, catalog: &Catalog, ctx: &CheckContext) -> Vec<UnmetStep> {
    let missing = |step: &Step| -> Vec<&'static str> {
        let mut needs = step
            .kind
            .as_deref()
            .and_then(|kind| catalog.step(kind))
            .map(|spec| spec.capabilities.clone())
            .unwrap_or_default();
        if step.ci_only {
            needs.ci_only = true;
        }
        let mut missing = Vec::new();
        if needs.ci_only && !ctx.is_ci() {
            missing.push("CI");
        }
        if needs.oidc && !ctx.capabilities.oidc {
            missing.push("an OIDC token");
        }
        if reach(&needs.network) > reach(&ctx.capabilities.network) {
            missing.push("network access");
        }
        missing
    };
    let per_step: Vec<Vec<&'static str>> = workflow.steps().iter().map(&missing).collect();
    let order = run_order(workflow);
    let unmet_at = |name: &str| {
        workflow
            .steps()
            .iter()
            .position(|s| s.name == name)
            .is_some_and(|i| !per_step[i].is_empty())
    };
    // One stop point for every warning: the last runnable step before the
    // first that cannot run. Everything from there on is out of reach of a
    // `--until` that stays inside what this context can do.
    let until = order
        .iter()
        .position(|name| unmet_at(name))
        .and_then(|first| first.checked_sub(1))
        .map(|at| order[at].to_string());
    let mut unmet = Vec::new();
    for (i, step) in workflow.steps().iter().enumerate() {
        if per_step[i].is_empty() {
            continue;
        }
        unmet.push(UnmetStep {
            name: step.name.clone(),
            span: step.span,
            missing: per_step[i].clone(),
            until: until.clone(),
        });
    }
    unmet
}

/// How far a scope reaches, so the two are comparable: none, the hosts named,
/// or anywhere.
fn reach(scope: &NetworkScope) -> u8 {
    match scope {
        NetworkScope::None => 0,
        NetworkScope::Hosts(_) => 1,
        NetworkScope::Any => 2,
    }
}

/// A list in a sentence: `a`, `a and b`, `a, b and c`.
fn list(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => (*one).to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn until(src: &str) -> Vec<Option<String>> {
        let checked = crate::check(&ks_lang::parse(src));
        let unmet = unmet_steps(&checked.workflow, &Catalog::builtin(), &CheckContext::local());
        unmet.iter().map(|s| s.until.clone()).collect()
    }

    /// Two CI-only steps with a runnable one between them: stopping after the
    /// first runnable step leaves the second out too, so both suggest it.
    #[test]
    fn one_stop_point_serves_every_unmet_step() {
        assert_eq!(
            until(
                "\
steps:
  build: oci.image
    from: ./Dockerfile
  sign: oci.image
    from: ./Dockerfile
    ci-only: true
  plan: tofu.plan
    dir: ./infra
  deploy: oci.image
    from: ./Dockerfile
    ci-only: true
"
            ),
            [Some("build".into()), Some("build".into())]
        );
    }

    /// A run order that is not the file's order: `deploy` is written first,
    /// but reads `build.digest`, so it runs last.
    #[test]
    fn the_stop_point_follows_run_order_not_file_order() {
        let src = "\
steps:
  deploy: k8s.rollout
    image: build.digest
    ci-only: true
  build: oci.image
    from: ./Dockerfile
";
        assert_eq!(until(src), [Some("build".into())]);
        let checked = crate::check(&ks_lang::parse(src));
        assert_eq!(run_order(&checked.workflow), ["build", "deploy"]);
    }

    /// Nothing runs before the first step, so there is nowhere to stop.
    #[test]
    fn a_step_that_cannot_run_first_can_only_be_skipped() {
        let unmet = unmet_steps(
            &crate::check(&ks_lang::parse(
                "steps:\n  deploy: oci.image\n    from: ./Dockerfile\n    ci-only: true\n",
            ))
            .workflow,
            &Catalog::builtin(),
            &CheckContext::local(),
        );
        assert_eq!(unmet[0].until, None);
        assert_eq!(unmet[0].hint(), "run with `--skip deploy`");
    }
}
