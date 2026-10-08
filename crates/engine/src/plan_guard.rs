//! The plan guard: an approved plan is applied, or the run stops and asks again
//! ([#67](https://github.com/Keep-Shipping/harness/issues/67)).
//!
//! OpenTofu and Terraform already refuse a saved plan whose *state* moved after it
//! was written ([`IacError::StalePlan`]) — and nothing more. Infrastructure changed by
//! somebody else (a console edit, another pipeline, a human) does not move the state
//! serial, so the saved plan applies cleanly and the review was against a world that no
//! longer exists. This module is what stands in that gap, and it is deliberately narrow:
//!
//! - **Stale state always stops.** On [`IacError::StalePlan`] the guard *records the stop
//!   first* ([`plan.stale`](ks_core::ports::run_log::RunEvent::PlanStale)), then re-plans and
//!   returns [`Guarded::Reapprove`] *even when the re-plan's change set equals the approved
//!   one*. Recording before re-planning is what makes a failed re-plan readable: there is no
//!   fresh plan to name, so the event carries `replanned: None` and the tool's error
//!   propagates — but the run still says why it stopped. An approval is bound to a plan's
//!   sha256 ([`ApprovalRequest`](ks_core::ports::approval::ApprovalRequest)), and the
//!   comparison below cannot see attribute values — so a new plan file contains things
//!   nobody reviewed. Asking again is the only honest answer.
//! - **Drift is caught only with `recheck`.** A fresh plan is taken and its change set
//!   compared with the approved one; if it differs the guard stops and asks again. If it
//!   does not, the **approved** plan is applied and the fresh one is thrown away — a plan
//!   nobody approved never reaches `apply`.
//! - **What "differs" means is narrow**, and [`diff`] is the whole definition: an address
//!   present in one change set and not the other, or the same address with a different
//!   action list. Attribute values are invisible here ([`PlanJson`] does not carry them), so
//!   drift that only moves values of a resource the plan already updates *is not caught*.
//!
//! The limits are the point of `docs/STALE_PLANS.md`; this module's job is to be honest
//! about them rather than to imply a safety it does not have.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use ks_core::Env;
use ks_core::ports::iac::{
    ApplyResult, Backend, ChangeAction, IacError, IacTool, PlanJson, SavedPlan,
};
use ks_core::ports::run_log::RunLogError;

use crate::journal::Journal;

/// What the guard is being asked to apply: the plan `approved` names, the change set
/// that plan was reviewed against, and the directory, vars and backend to plan again with.
#[derive(Debug, Clone, Copy)]
pub struct Workspace<'a> {
    /// The module directory `plan` initialises and plans.
    pub dir: &'a Path,
    /// Variables passed to `plan`, iterated sorted by the port.
    pub vars: &'a BTreeMap<String, String>,
    /// The backend `plan` initialises against.
    pub backend: &'a Backend,
}

/// Why an approved plan could not be applied as approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaleCause {
    /// The tool found the *state* had moved since the plan was written —
    /// [`IacError::StalePlan`]. Caught with or without `recheck`.
    State,
    /// A pre-apply `recheck` found the change set no longer matches the approved one:
    /// the world moved out of band, in a way the tool's own stale check cannot see. Caught
    /// only with `recheck`.
    Drift,
}

impl StaleCause {
    /// The cause's name in the run log and in messages.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            StaleCause::State => "state",
            StaleCause::Drift => "drift",
        }
    }
}

impl fmt::Display for StaleCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StaleCause::State => write!(f, "the state changed since the plan was written"),
            StaleCause::Drift => write!(f, "the world moved since the plan was approved"),
        }
    }
}

/// One address whose planned actions differ between two change sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionChange {
    /// The resource address.
    pub address: String,
    /// The actions the approved plan had, in its order.
    pub before: Vec<ChangeAction>,
    /// The actions the fresh plan has, in its order.
    pub after: Vec<ChangeAction>,
}

/// What changed between the approved change set and a fresh one — the report an approver
/// reads before answering again, and the guard's only definition of "differs".
///
/// Sorted by address, so the diff of two change sets is itself deterministic.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeDiff {
    /// Addresses the fresh plan touches and the approved one did not.
    pub added: Vec<String>,
    /// Addresses the approved plan touched and the fresh one does not.
    pub removed: Vec<String>,
    /// Addresses both touch, with different actions.
    pub changed: Vec<ActionChange>,
}

impl ChangeDiff {
    /// Whether the two change sets are the same for the guard's purposes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

/// The plan to put in front of approvers instead of applying: freshly planned, freshly
/// shown, and never applied by this guard.
#[derive(Debug, Clone)]
pub struct Reapproval {
    /// Why the approved plan was stopped.
    pub cause: StaleCause,
    /// The fresh plan file, which the caller must save and have approved afresh.
    pub plan: SavedPlan,
    /// What the fresh plan would change.
    pub changes: PlanJson,
    /// How that change set differs from the approved one.
    pub diff: ChangeDiff,
}

/// What the guard did with an approved plan.
#[derive(Debug, Clone)]
pub enum Guarded {
    /// The approved plan was applied; this is the tool's own summary.
    Applied(ApplyResult),
    /// Nothing was applied. The caller parks at an approval and hands `plan` to approvers.
    Reapprove(Reapproval),
}

/// Why the guard could not do its job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardError {
    /// The tool failed while planning the fresh plan (a recheck, or a replacement after a
    /// stale plan). Nothing was applied.
    Plan(IacError),
    /// The tool could not parse a saved plan into a [`PlanJson`]. Nothing was applied.
    Show(IacError),
    /// The tool failed applying the approved plan for some reason other than staleness —
    /// a bad configuration, a refused backend. The error is the tool's own, verbatim.
    Apply(IacError),
    /// The run log refused the [`plan.stale`](ks_core::ports::run_log::RunEvent::PlanStale)
    /// entry. The guard fails closed: nothing is applied and no approval is implied.
    Log(RunLogError),
}

impl fmt::Display for GuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GuardError::Plan(error) => write!(f, "could not plan again: {error}"),
            GuardError::Show(error) => write!(f, "could not read the plan's changes: {error}"),
            GuardError::Apply(error) => write!(f, "apply failed: {error}"),
            GuardError::Log(error) => write!(f, "{error}; nothing was applied"),
        }
    }
}

impl std::error::Error for GuardError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            GuardError::Plan(error) | GuardError::Show(error) | GuardError::Apply(error) => {
                Some(error)
            }
            GuardError::Log(error) => Some(error),
        }
    }
}

/// Whether `recheck` should be on for `env` when the workflow did not say: yes in a
/// `ci-only: true` environment, where a stop costs a re-run rather than a human, and no
/// elsewhere. An explicit `recheck:` in the workflow always wins
/// ([`resolve_recheck`]).
#[must_use]
pub fn recheck_default(env: &Env) -> bool {
    env.ci_only
}

/// The `recheck` setting for a run: the explicit value when the workflow gave one,
/// otherwise [`recheck_default`] for `env`.
#[must_use]
pub fn resolve_recheck(explicit: Option<bool>, env: &Env) -> bool {
    explicit.unwrap_or_else(|| recheck_default(env))
}

/// Compares two change sets by address and action, which is the whole of "differs":
///
/// - an entry whose actions are exactly `[NoOp]` is dropped — an untouched resource is not
///   a change, so a fresh plan that merely re-reports it is not a difference;
/// - an address in `fresh` and not in `approved` is [`added`](ChangeDiff::added), one in
///   `approved` and not in `fresh` is [`removed`](ChangeDiff::removed);
/// - an address in both whose action lists are not equal is
///   [`changed`](ChangeDiff::changed). Order is significant: `[Delete, Create]` (replace)
///   and `[Create, Delete]` (create-before-destroy) are different plans, and `Read` is an
///   action like any other;
/// - a duplicate address keeps its first entry — the port says one entry per resource, so
///   this is a defined answer rather than a guess.
///
/// Attribute *values* are not compared: [`PlanJson`] does not carry them.
#[must_use]
pub fn diff(approved: &PlanJson, fresh: &PlanJson) -> ChangeDiff {
    let before = normalise(approved);
    let after = normalise(fresh);
    let mut out = ChangeDiff::default();
    for (address, actions) in &after {
        match before.get(address) {
            None => out.added.push((*address).to_string()),
            Some(old) if old != actions => out.changed.push(ActionChange {
                address: (*address).to_string(),
                before: old.clone(),
                after: actions.clone(),
            }),
            Some(_) => {}
        }
    }
    for address in before.keys() {
        if !after.contains_key(address) {
            out.removed.push((*address).to_string());
        }
    }
    out
}

/// The change set as `address -> actions`, no-ops dropped, first entry per address.
fn normalise(plan: &PlanJson) -> BTreeMap<&str, Vec<ChangeAction>> {
    let mut map = BTreeMap::new();
    for change in &plan.changes {
        if change.actions == [ChangeAction::NoOp] {
            continue;
        }
        map.entry(change.address.as_str()).or_insert_with(|| change.actions.clone());
    }
    map
}

/// Plans and shows again, which is how the port asks for a fresh change set: there is no
/// refresh-only call and none may be added (the trait's contract is pinned).
async fn replan(
    tool: &dyn IacTool,
    workspace: Workspace<'_>,
) -> Result<(SavedPlan, PlanJson), GuardError> {
    let plan = tool
        .plan(workspace.dir, workspace.vars, workspace.backend)
        .await
        .map_err(GuardError::Plan)?;
    let changes = tool.show(&plan).await.map_err(GuardError::Show)?;
    Ok((plan, changes))
}

/// Records the stop and hands back the fresh plan, for a run that got as far as one. The log
/// write failing is a stop, not a warning — a run that cannot say why it stopped is not one to
/// guess at.
async fn stop(
    journal: &Journal,
    step: &str,
    cause: StaleCause,
    approved: &SavedPlan,
    plan: SavedPlan,
    changes: PlanJson,
    diff: ChangeDiff,
) -> Result<Guarded, GuardError> {
    record(journal, step, cause, approved, Some(plan.sha256()), Some(!diff.is_empty())).await?;
    Ok(Guarded::Reapprove(Reapproval { cause, plan, changes, diff }))
}

/// The one place a `plan.stale` is written, so every stop is recorded the same way — including
/// one the guard could not plan past.
async fn record(
    journal: &Journal,
    step: &str,
    cause: StaleCause,
    approved: &SavedPlan,
    replanned: Option<&str>,
    differs: Option<bool>,
) -> Result<(), GuardError> {
    journal
        .plan_stale(step, cause.as_str(), approved.sha256(), replanned, differs)
        .await
        .map_err(GuardError::Log)
}

/// Applies `approved` — or stops and asks again.
///
/// With `recheck`, a fresh plan is taken first and compared with `approved_changes` by
/// [`diff`]; a difference stops before `apply` is ever called. Without it, `approved` goes
/// straight to the tool, which is what catches a moved state on its own. Either way a
/// [`IacError::StalePlan`] from `apply` stops the run: the guard re-plans, records why, and
/// returns the new plan unapplied, because the old approval is bound to the old plan's
/// sha256 and cannot release this one. If that re-plan fails, the stop is still recorded —
/// with `replanned: None`, since there is no new plan to ask about — and the tool's error
/// propagates.
///
/// A successful apply returns [`Guarded::Applied`]; any other tool error propagates as
/// [`GuardError`], having applied nothing further.
pub async fn apply_approved(
    tool: &dyn IacTool,
    journal: &Journal,
    step: &str,
    workspace: Workspace<'_>,
    approved: &SavedPlan,
    approved_changes: &PlanJson,
    recheck: bool,
) -> Result<Guarded, GuardError> {
    if recheck {
        let (fresh, changes) = replan(tool, workspace).await?;
        let diff = diff(approved_changes, &changes);
        if !diff.is_empty() {
            return stop(journal, step, StaleCause::Drift, approved, fresh, changes, diff).await;
        }
        // The change set matches, so the *approved* plan applies — never the fresh one,
        // which nobody has seen. The fresh plan is discarded here on purpose.
    }
    match tool.apply(approved).await {
        Ok(result) => Ok(Guarded::Applied(result)),
        Err(IacError::StalePlan) => {
            stale(tool, journal, step, workspace, approved, approved_changes).await
        }
        Err(error) => Err(GuardError::Apply(error)),
    }
}

/// The tool says the state moved. The stop is recorded *before* the re-plan, not after: if
/// planning again fails there is no new plan to hand the approvers, and a run that stopped
/// without saying why is worse than a run that stopped. The log write failing still wins — the
/// guard fails closed either way.
async fn stale(
    tool: &dyn IacTool,
    journal: &Journal,
    step: &str,
    workspace: Workspace<'_>,
    approved: &SavedPlan,
    approved_changes: &PlanJson,
) -> Result<Guarded, GuardError> {
    match replan(tool, workspace).await {
        Ok((fresh, changes)) => {
            let diff = diff(approved_changes, &changes);
            // Reported, not decisive: an identical change set is still a plan file nobody
            // approved, so it is asked about again all the same.
            stop(journal, step, StaleCause::State, approved, fresh, changes, diff).await
        }
        Err(error) => {
            record(journal, step, StaleCause::State, approved, None, None).await?;
            Err(error)
        }
    }
}
