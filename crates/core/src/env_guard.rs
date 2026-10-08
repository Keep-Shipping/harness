//! Which environments a local run may not change
//! ([#123](https://github.com/Keep-Shipping/harness/issues/123)).
//!
//! An `envs:` block can say `ci-only: true`, and an environment named `prod`
//! says it without being asked. Applying into production with production
//! credentials from a laptop is the mistake this exists to stop, and it is not
//! one a file gets to permit: there is deliberately no `ci-only: false` that
//! lowers a production environment, because the file is written by the same
//! people the rule is there to stop. The route through is a run in CI, or an
//! approval someone else gives — a local `y` is neither.
//!
//! What counts as *changing* is narrow on purpose: an apply and a deploy
//! ([`ActionKind::Apply`], [`ActionKind::Deploy`]). A `tofu.plan` reads the
//! world and writes a file, and refusing it would only make it harder to see
//! what the apply behind it would do.
//!
//! **The gap this leaves, stated rather than papered over.** A script step
//! that declares no `action:` asserts nothing: it is read as
//! [`ActionKind::Other`], which is neither an apply nor a deploy, so this
//! guard does not see it however it is reached — directly or inside a block.
//! The existing script-step gate
//! ([`script_step::needing_approval`](crate::script_step::needing_approval)) covers
//! exactly that case for an *agent*, which must have an `approval` step before
//! an undeclared script in production; it covers nothing for a human, for whom
//! a script step is ungated by design. So a human on a laptop running a script
//! step that declares no `action:` into `prod` is not stopped here, and this
//! module does not claim otherwise. Declaring the action is what closes it,
//! and `changing` honours the declaration wherever it is written.
//!
//! Pure computation, like the [`context`](crate::context) gate it sits beside.
//! Deciding *which* context a run is in belongs to the caller: this module
//! answers what a local run may not do, and a run in CI does not ask.

use std::fmt;

use crate::script_step::is_production;
use crate::step::ActionKind;
use crate::workflow::{Env, Step, Workflow};

/// Is `env` a place a local run may not change?
///
/// Yes when the file says `ci-only: true`, and yes when the environment is
/// named [`PRODUCTION_ENVS`](crate::script_step::PRODUCTION_ENVS) — the name
/// is the claim a reader already trusts, so it counts whether or not the file
/// bothers to spell it out. The two are one answer, not a default a file can
/// lower.
#[must_use]
pub fn is_ci_only(env: &Env) -> bool {
    env.ci_only || is_production(Some(&env.name))
}

/// The running steps a local run may not take into `env`, and why.
///
/// Empty for an environment that is not `ci-only`, and for a run whose
/// selection covers no apply or deploy — a `--skip apply` run has nothing to
/// refuse, and saying otherwise would make the way out the guard suggests
/// unusable.
#[derive(Clone, Debug)]
pub struct CiOnlyRefusal<'a> {
    /// The environment the run selected, named in every message.
    pub env: &'a Env,
    /// The steps that would change it, in file order.
    pub steps: Vec<&'a Step>,
}

impl CiOnlyRefusal<'_> {
    /// Nothing to refuse: the run may start.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Why this environment and not another, said once for every step: what
    /// the file would put at risk by changing it here.
    #[must_use]
    fn why(&self) -> String {
        if is_production(Some(&self.env.name)) {
            format!("{} credentials belong in CI, not on a laptop", self.env.name)
        } else {
            format!("`{}` is `ci-only: true`", self.env.name)
        }
    }
}

impl fmt::Display for CiOnlyRefusal<'_> {
    /// One line per step, so each names itself: what it would change, and
    /// why this environment is not where that happens.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, step) in self.steps.iter().enumerate() {
            if i > 0 {
                f.write_str("\n")?;
            }
            write!(
                f,
                "refusing to start: step `{}` {} `{}`; {}",
                step.name,
                verb(step),
                self.env.name,
                self.why()
            )?;
        }
        Ok(())
    }
}

/// What a step would do to an environment, said as a verb: `applies into`,
/// `deploys into`.
fn verb(step: &Step) -> &'static str {
    match changing(step) {
        Some(ActionKind::Apply) => "applies into",
        _ => "deploys into",
    }
}

/// The apply or deploy this step is, and the kind of change it makes.
///
/// A step's action classes are the ones the checker settled when it read the
/// file ([`Step::actions`]) — the same answer `policy` reads, so a block use
/// cannot hide an apply behind the steps inside it. A step the catalog cannot
/// name, a script step, makes its one claim with `action:`, which reads as
/// [`ActionKind::Other`] and so asserts nothing when it declares none.
///
/// A class's environment is not consulted: the run's selected environment is
/// what every step in the run acts on, whether or not the step wrote
/// `when: env is <name>`.
fn changing(step: &Step) -> Option<ActionKind> {
    let changes = |kind: &ActionKind| matches!(kind, ActionKind::Apply | ActionKind::Deploy);
    let classes: Vec<ActionKind> = match step.actions.as_slice() {
        [] => step.action.into_iter().collect(),
        classes => classes.iter().map(|class| class.kind).collect(),
    };
    classes.into_iter().find(changes)
}

/// The steps among `running` that apply or deploy into `env`, and which a
/// local run therefore may not take.
#[must_use]
pub fn ci_only_refusal<'a>(
    workflow: &'a Workflow,
    env: &'a Env,
    running: &[&str],
) -> CiOnlyRefusal<'a> {
    let steps = if is_ci_only(env) {
        workflow
            .steps()
            .iter()
            .filter(|step| running.contains(&step.name.as_str()) && changing(step).is_some())
            .collect()
    } else {
        Vec::new()
    };
    CiOnlyRefusal { env, steps }
}
