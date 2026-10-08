//! The checked shape of a site file: steps, triggers, environments and the
//! data-dependence graph between steps.

use std::collections::BTreeMap;

use ks_lang::Span;

use crate::ports::policy::{ANY_OBJECT, Disposition};
use crate::ports::run_context::ActorKind;
use crate::step::{ActionClass, RollbackPolicy};

/// One `on:` trigger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trigger {
    pub kind: TriggerKind,
    /// The branch or tag glob (`push main`, `tag v*`).
    pub glob: Option<String>,
    pub span: Span,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TriggerKind {
    Push,
    Pr,
    Tag,
    Manual,
}

impl TriggerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TriggerKind::Push => "push",
            TriggerKind::Pr => "pr",
            TriggerKind::Tag => "tag",
            TriggerKind::Manual => "manual",
        }
    }
}

/// One step: its declared kind and where it sits in the file.
#[derive(Clone, Debug)]
pub struct Step {
    pub name: String,
    /// The kind named in the header, if the header carried a value.
    pub kind: Option<String>,
    pub span: Span,
    pub kind_span: Span,
    /// `ci-only: true`: the step refuses to run off CI
    /// ([#34](https://github.com/Keep-Shipping/harness/issues/34)).
    pub ci_only: bool,
    /// What the step does, for policy. A block use carries the actions of
    /// the steps inside it, so a use cannot hide an apply
    /// ([#80](https://github.com/Keep-Shipping/harness/issues/80)).
    pub actions: Vec<ActionClass>,
    /// A block use's inputs, with the signature's defaults filled in — what
    /// the run will get, whether the file spelled it or the block declared
    /// it. Empty for any other step.
    pub block_inputs: BTreeMap<String, String>,
    /// The `rollback:` policy the step declared, or [`RollbackPolicy::Auto`]
    /// when it declared none ([#78](https://github.com/Keep-Shipping/harness/issues/78)).
    /// The executor reads this: it is the only place the file's answer lives
    /// once the workflow exists.
    pub rollback: RollbackPolicy,
    /// The `when:` condition, when the step declares one. The planner reads
    /// it: a condition that names no step is settled before the run starts,
    /// one that reads step outputs cannot be.
    pub when: Option<Condition>,
}

/// A step's `when:` condition, kept as written plus the two things a planner
/// needs from it: which steps it reads (empty means it depends on context
/// only) and, for the context-only shapes the language has, a form it can
/// evaluate ([`Condition::test`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Condition {
    /// The expression as written, for the run log and `keepshipping graph`.
    pub source: String,
    /// The steps the condition reads; empty when it is context-only.
    pub steps: Vec<String>,
    /// The condition in evaluable form, when it is one. `None` is never a
    /// guess: the condition is settled at run time instead.
    pub test: Option<ContextTest>,
}

/// A context-only `when:` in a form the planner can settle before the run
/// starts ([#40](https://github.com/Keep-Shipping/harness/issues/40)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContextTest {
    /// A boolean literal (`when: false`).
    Bool(bool),
    /// The selected environment is this one (`when: env is prod`; its
    /// negation is spelled `not env is prod`).
    EnvIs { env: String },
    /// The negation of a test (`when: not env is prod`).
    Not(Box<ContextTest>),
}

impl ContextTest {
    /// The test's verdict for the environment `env` selects. Pure: the same
    /// file and event always give the same answer.
    #[must_use]
    pub fn eval(&self, env: &str) -> bool {
        match self {
            ContextTest::Bool(value) => *value,
            ContextTest::EnvIs { env: wanted } => env == wanted,
            ContextTest::Not(inner) => !inner.eval(env),
        }
    }
}

/// An environment: per-target overrides.
#[derive(Clone, Debug)]
pub struct Env {
    pub name: String,
    pub span: Span,
    /// Triggers that select this environment.
    pub triggers: Vec<Trigger>,
    pub ci_only: bool,
    /// The secrets resolver this environment reads from.
    pub secrets: Option<String>,
    pub approvers: Vec<String>,
    /// Names declared under `vars:`; their values are available as
    /// `env.<name>` (type `any`).
    pub vars: Vec<String>,
}

pub(crate) fn implicit_default() -> Env {
    Env {
        name: "default".into(),
        span: Span::default(),
        triggers: Vec::new(),
        ci_only: false,
        secrets: None,
        approvers: Vec::new(),
        vars: Vec::new(),
    }
}

/// One `policy:` rule: what a subject may do, and what happens if they try
/// (`agents: never: read secrets`, `agents: can: deploy staging`).
///
/// The same shape covers all three declarations — `can:` records
/// [`Disposition::Allow`], `before:` [`Disposition::Ask`], `never:`
/// [`Disposition::Never`] — because a decision has to weigh all three
/// together ([#101](https://github.com/Keep-Shipping/harness/issues/101)):
/// a rule that is dropped on the floor because it sat under `can:` is a
/// policy the engine cannot answer questions about.
#[derive(Clone, Debug)]
pub struct PolicyRule {
    /// The subject the rule binds.
    pub subject: ActorKind,
    /// The action verb (`read`, `deploy`, …).
    pub verb: String,
    /// The action object: the environment a verb names, `secrets` / `scripts`
    /// / `blocks` for the object-taking verbs, or [`ANY_OBJECT`] when the
    /// rule names none.
    pub object: String,
    /// What the rule says: `can` allows, `before` asks, `never` refuses.
    pub disposition: Disposition,
    /// Where the rule is declared, for diagnostics that point at it.
    pub span: Span,
}

/// One handle a subject's `ask:` names: `@platform`, and where it is
/// declared.
#[derive(Clone, Debug)]
pub struct AskHandle {
    /// The subject the handles belong to.
    pub subject: ActorKind,
    /// The handle text, without the `@`.
    pub handle: String,
    /// Where the handle is declared.
    pub span: Span,
}

/// The workflow's policy, as the file declares it: every rule under `can:`,
/// `before:` and `never:`, and the handles under `ask:`, per subject
/// ([#101](https://github.com/Keep-Shipping/harness/issues/101)).
///
/// Nothing here is *decided* — a policy answers no question on its own; it is
/// an input to [`decide`](crate::policy::decide), which weighs it against the
/// org baseline and the hard rules. What the checker does with it directly is
/// refuse an agent run a `never:` rule forbids
/// ([#27](https://github.com/Keep-Shipping/harness/issues/27)).
#[derive(Clone, Debug, Default)]
pub struct Policy {
    rules: Vec<PolicyRule>,
    asks: Vec<AskHandle>,
}

impl Policy {
    /// Every rule the file declares, in declaration order.
    #[must_use]
    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }

    /// The handles `subject` asks, in declaration order — empty when the
    /// subject declares no `ask:`, which the decision renders as "ask a
    /// human".
    pub fn ask_handles(&self, subject: ActorKind) -> impl Iterator<Item = &str> {
        self.asks.iter().filter(move |a| a.subject == subject).map(|a| a.handle.as_str())
    }

    /// Whether `subject` is forbidden `verb` on `object`.
    #[must_use]
    pub fn forbids(&self, subject: ActorKind, verb: &str, object: &str) -> bool {
        self.rules.iter().any(|r| {
            r.subject == subject
                && r.verb == verb
                && matches_object(&r.object, object)
                && r.disposition == Disposition::Never
        })
    }

    /// Where a rule binding `subject` to `verb` `object` is declared.
    pub(crate) fn rule_span(&self, subject: ActorKind, verb: &str, object: &str) -> Option<Span> {
        self.rules
            .iter()
            .find(|r| {
                r.subject == subject
                    && r.verb == verb
                    && matches_object(&r.object, object)
                    && r.disposition == Disposition::Never
            })
            .map(|r| r.span)
    }

    /// Records a rule; `check` does this while reading `policy:`.
    pub(crate) fn forbid(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
    }

    /// Records an `ask:` handle; `check` does this while reading `policy:`.
    pub(crate) fn ask(&mut self, handle: AskHandle) {
        self.asks.push(handle);
    }
}

/// Whether a rule's object covers the object an action names: `*` covers
/// every environment, anything else must match exactly.
fn matches_object(rule_object: &str, object: &str) -> bool {
    rule_object == ANY_OBJECT || rule_object == object
}

/// The checked workflow.
#[derive(Clone, Debug, Default)]
pub struct Workflow {
    name: Option<String>,
    triggers: Vec<Trigger>,
    envs: Vec<Env>,
    steps: Vec<Step>,
    edges: Vec<(String, String)>,
    order: Option<Vec<String>>,
    policy: Policy,
}

impl Workflow {
    /// Build a workflow directly; `check` does this from a parsed file.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        name: Option<String>,
        triggers: Vec<Trigger>,
        envs: Vec<Env>,
        steps: Vec<Step>,
        edges: Vec<(String, String)>,
        order: Option<Vec<String>>,
        policy: Policy,
    ) -> Self {
        Self { name, triggers, envs, steps, edges, order, policy }
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn triggers(&self) -> &[Trigger] {
        &self.triggers
    }

    /// The declared environments, or the implicit `default` when the file
    /// has no `envs:`.
    pub fn envs(&self) -> &[Env] {
        &self.envs
    }

    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    pub fn step(&self, name: &str) -> Option<&Step> {
        self.steps.iter().find(|s| s.name == name)
    }

    /// Data-dependence edges `(from, to)`: `from` must run before `to`.
    /// Includes the approval gating edges (an `approval` step runs before
    /// every other consumer of what it shows).
    pub fn edges(&self) -> &[(String, String)] {
        &self.edges
    }

    /// A topological order of the steps, when the graph is acyclic.
    pub fn topo_order(&self) -> Option<&[String]> {
        self.order.as_deref()
    }

    /// The policy the file declares; empty when there is no `policy:` block.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
}
