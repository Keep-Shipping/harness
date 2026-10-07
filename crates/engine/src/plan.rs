//! The plan: what a workflow would do, in what order, for one environment and
//! event ([#40](https://github.com/Keep-Shipping/harness/issues/40)).
//!
//! Pure computation over a checked [`Workflow`] — no clock, no ports, no I/O.
//! The order is a function of the file alone: [`Workflow::topo_order`] breaks
//! ties by position in the file, so the same file always plans the same way.
//! `keepshipping graph` prints exactly this and runs nothing.

use std::collections::HashMap;

use ks_core::{Condition, TriggerKind, Workflow};

/// What a plan is planned for: the environment the run selected, and the
/// event that selected it, when there was one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlanCtx {
    /// The selected environment (`keepshipping --env`, or what the event
    /// chose).
    pub env: String,
    /// The event, for a plan made for one.
    pub event: Option<TriggerKind>,
}

/// Whether a step is in this run, and why not when it is not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gate {
    /// Nothing holds it back: it runs.
    Always,
    /// It is out for this plan, and says why — a `when:` that is false for
    /// this environment, or a step it depends on that is out too.
    Skip { reason: String },
    /// Its `when:` reads step outputs, so only the run can settle it. The
    /// condition travels with the plan so the log can say what was waited
    /// for.
    Runtime { condition: Condition },
}

impl Gate {
    /// Whether the step is out before the run starts.
    #[must_use]
    pub fn is_skipped(&self) -> bool {
        matches!(self, Gate::Skip { .. })
    }
}

/// One planned step. `seq` is its 1-based position in the plan, and it is
/// what the run log sorts by: independent steps may finish in any order, but
/// they are reported in this one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedStep {
    pub seq: usize,
    pub name: String,
    /// The kind named in the header, when the header carried one.
    pub kind: Option<String>,
    /// The sequence numbers of the steps that must finish first, ascending.
    pub deps: Vec<usize>,
    pub gate: Gate,
}

/// A workflow planned for one environment and event.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// The environment this plan is for.
    pub env: String,
    /// The events that would reach this plan: the event it was planned for,
    /// when there was one, and otherwise the file's triggers in declaration
    /// order.
    pub triggers: Vec<TriggerKind>,
    /// The steps, in plan order; `steps[i].seq == i + 1`.
    pub steps: Vec<PlannedStep>,
}

impl Plan {
    /// Plan `workflow` for `ctx`. A workflow whose graph has a cycle has no
    /// order and plans no steps: the checker has already refused the file, and
    /// a plan that guessed an order would be the guess the whole design is
    /// against.
    #[must_use]
    pub fn new(workflow: &Workflow, ctx: &PlanCtx) -> Plan {
        // A plan made for one event is reached by that event, whatever else
        // the file would also reach; a plan made without one is reached by
        // everything the file declares.
        let triggers = match ctx.event {
            Some(kind) => vec![kind],
            None => workflow.triggers().iter().map(|t| t.kind).collect(),
        };
        let Some(order) = workflow.topo_order() else {
            return Plan { env: ctx.env.clone(), triggers, steps: Vec::new() };
        };
        // Edges are names; the plan speaks sequence numbers.
        let seq: HashMap<&str, usize> =
            order.iter().enumerate().map(|(i, name)| (name.as_str(), i + 1)).collect();
        let mut steps: Vec<PlannedStep> = Vec::with_capacity(order.len());
        for (i, name) in order.iter().enumerate() {
            let step = workflow.step(name);
            let mut deps: Vec<usize> = workflow
                .edges()
                .iter()
                .filter(|(_, to)| to == name)
                .filter_map(|(from, _)| seq.get(from.as_str()).copied())
                .collect();
            deps.sort_unstable();
            deps.dedup();
            let gate = gate_for(step.and_then(|s| s.when.as_ref()), &deps, &steps, ctx);
            steps.push(PlannedStep {
                seq: i + 1,
                name: name.clone(),
                kind: step.and_then(|s| s.kind.clone()),
                deps,
                gate,
            });
        }
        Plan { env: ctx.env.clone(), triggers, steps }
    }

    /// The step at `seq`, 1-based.
    #[must_use]
    pub fn step(&self, seq: usize) -> Option<&PlannedStep> {
        seq.checked_sub(1).and_then(|i| self.steps.get(i))
    }

    /// The steps that will run, in plan order: everything not skipped.
    pub fn running(&self) -> impl Iterator<Item = &PlannedStep> {
        self.steps.iter().filter(|s| !s.gate.is_skipped())
    }
}

/// A step's gate, once `deps` (already planned) and its `when:` are known.
/// Every dependency's sequence number is smaller than the step's own, because
/// the plan follows a topological order, so a skip is always seen in time to
/// cascade.
fn gate_for(
    when: Option<&Condition>,
    deps: &[usize],
    planned: &[PlannedStep],
    ctx: &PlanCtx,
) -> Gate {
    if let Some(dep) = deps.iter().map(|d| &planned[d - 1]).find(|d| d.gate.is_skipped()) {
        return Gate::Skip { reason: format!("{dep_name} is skipped", dep_name = dep.name) };
    }
    let Some(when) = when else { return Gate::Always };
    // A condition that reads a step's outputs cannot be settled before the
    // steps run; one that reads only context can, and is.
    if !when.steps.is_empty() {
        return Gate::Runtime { condition: when.clone() };
    }
    match when.test.as_ref().map(|test| test.eval(&ctx.env)) {
        Some(true) => Gate::Always,
        Some(false) => {
            Gate::Skip { reason: format!("`when: {}` is false in {}", when.source, ctx.env) }
        }
        None => Gate::Runtime { condition: when.clone() },
    }
}
