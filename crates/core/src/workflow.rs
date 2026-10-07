//! The checked shape of a site file: steps, triggers, environments and the
//! data-dependence graph between steps.

use ks_lang::Span;

use crate::ports::run_context::ActorKind;

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

/// One `never:` rule: who may never do what
/// (`agents: never: read secrets`).
#[derive(Clone, Debug)]
pub struct NeverRule {
    /// The subject the rule binds.
    pub subject: ActorKind,
    /// The action verb (`read`).
    pub verb: String,
    /// The action object (`secrets`, or the environment another verb names).
    pub object: String,
    /// Where the rule is declared, for diagnostics that point at it.
    pub span: Span,
}

/// The workflow's policy, as far as static checks enforce it: the `never:`
/// rules a declared subject must respect. The checker enforces the agents'
/// `read secrets` rule against agent runs
/// ([#27](https://github.com/Keep-Shipping/harness/issues/27)); nothing else
/// is refused yet.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    never: Vec<NeverRule>,
}

impl Policy {
    /// Whether `subject` is forbidden `verb` on `object`.
    #[must_use]
    pub fn forbids(&self, subject: ActorKind, verb: &str, object: &str) -> bool {
        self.never.iter().any(|r| r.subject == subject && r.verb == verb && r.object == object)
    }

    /// Where a rule binding `subject` to `verb` `object` is declared.
    pub(crate) fn rule_span(&self, subject: ActorKind, verb: &str, object: &str) -> Option<Span> {
        self.never
            .iter()
            .find(|r| r.subject == subject && r.verb == verb && r.object == object)
            .map(|r| r.span)
    }

    /// Records a `never:` rule; `check` does this while reading `policy:`.
    pub(crate) fn forbid(&mut self, rule: NeverRule) {
        self.never.push(rule);
    }
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
