//! Script steps: the escape hatch a repository ships beside its `ship.ks`
//! ([#89](https://github.com/Keep-Shipping/harness/issues/89)). A step whose
//! kind is a relative path to a `.ts` file is one. Its action class defaults
//! to [`ActionKind::Other`](crate::step::ActionKind::Other) unless it declares
//! one with `action:`, and in a production environment an agent may not run
//! one that declares nothing without an `approval` step before it.
//!
//! The runtime behind these steps is
//! [ADR 0009](../../../../docs/adr/0009-typescript-escape-hatch-runtime.md);
//! what `check` knows of a script today is its kind.

use std::collections::HashSet;
use std::path::{Component, Path};

use crate::ports::run_context::ActorKind;
use crate::workflow::{Step, Workflow};

/// Is `kind` a script step? A relative path to a `.ts` file, written as the
/// file spells it: leading `./`, resolved against the ship.ks directory.
#[must_use]
pub fn is_script_kind(kind: &str) -> bool {
    kind.starts_with("./") && kind.ends_with(".ts")
}

/// The path `kind` names, relative to the ship.ks directory — the run's
/// workspace root, as a `ScriptRef` is resolved. `./ship/migrate.ts` reads
/// `ship/migrate.ts`.
///
/// `None` when `kind` names a script outside that directory: a `..`
/// component, an absolute path, or nothing at all. A run may only reach a
/// script the repository ships beside its `ship.ks`.
#[must_use]
pub fn script_path(kind: &str) -> Option<&str> {
    let path = kind.strip_prefix("./")?;
    let mut parts = Path::new(path).components();
    let inside = parts.clone().count() > 0 && parts.all(|c| matches!(c, Component::Normal(_)));
    inside.then_some(path)
}

/// The environment names that count as production. Spelling, not a setting:
/// a file that calls its live environment `live` says `live`, and this rule
/// does not reach it.
pub const PRODUCTION_ENVS: [&str; 2] = ["prod", "production"];

/// Is `env` one of the [`PRODUCTION_ENVS`]?
#[must_use]
pub fn is_production(env: Option<&str>) -> bool {
    env.is_some_and(|name| PRODUCTION_ENVS.contains(&name))
}

/// The script steps among `running` that `actor` may not run in `env`
/// without an approval first: the ones that declare no `action:`, which
/// reads as [`ActionKind::Other`](crate::step::ActionKind::Other) — an agent
/// changing production without saying how is the case this refuses.
///
/// A step is excused when an `approval` step in `running` runs before it,
/// directly or through other steps ([`Workflow::edges`]). An approval that
/// will not run — because it was left out of the run, or its `when:` is
/// false for `env` — excuses nothing: the person it was waiting for is not
/// there.
///
/// Empty for a human, for a non-production environment, and for a run with no
/// script steps, so the caller needs no guard of its own.
#[must_use]
pub fn needing_approval<'a>(
    workflow: &'a Workflow,
    actor: ActorKind,
    env: Option<&str>,
    running: &[&str],
) -> Vec<&'a Step> {
    if actor != ActorKind::Agent || !is_production(env) {
        return Vec::new();
    }
    let env = env.unwrap_or_default();
    let approvals: Vec<&str> = workflow
        .steps()
        .iter()
        .filter(|s| {
            s.kind.as_deref() == Some("approval")
                && running.contains(&s.name.as_str())
                && will_run(s, env)
        })
        .map(|s| s.name.as_str())
        .collect();
    let excused = run_after(workflow, &approvals);
    workflow
        .steps()
        .iter()
        .filter(|s| {
            s.kind.as_deref().is_some_and(is_script_kind)
                && s.action.is_none()
                && running.contains(&s.name.as_str())
                && !excused.contains(s.name.as_str())
        })
        .collect()
}

/// Every step `approvals` runs before, themselves included: one forward walk
/// over the edges, so one closure answers for every approval at once.
fn run_after<'a>(workflow: &'a Workflow, approvals: &[&'a str]) -> HashSet<&'a str> {
    let mut seen: HashSet<&str> = approvals.iter().copied().collect();
    let mut frontier: Vec<&str> = approvals.to_vec();
    while let Some(name) = frontier.pop() {
        for (from, to) in workflow.edges() {
            if from == name && seen.insert(to.as_str()) {
                frontier.push(to.as_str());
            }
        }
    }
    seen
}

/// Will `step` run in `env`? The same question the engine's planner asks, over
/// the same [`ContextTest::eval`](crate::ContextTest::eval): a condition that
/// reads no step output is settled now, and one that does is settled at run
/// time — where it still runs, so it counts.
#[must_use]
fn will_run(step: &Step, env: &str) -> bool {
    step.when.as_ref().and_then(|w| w.test.as_ref()).is_none_or(|test| test.eval(env))
}
