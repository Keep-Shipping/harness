//! The checked shape of a site file: steps, triggers, environments and the
//! data-dependence graph between steps.

use ks_lang::Span;

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

/// The checked workflow.
#[derive(Clone, Debug, Default)]
pub struct Workflow {
    name: Option<String>,
    triggers: Vec<Trigger>,
    envs: Vec<Env>,
    steps: Vec<Step>,
    edges: Vec<(String, String)>,
    order: Option<Vec<String>>,
}

impl Workflow {
    /// Build a workflow directly; `check` does this from a parsed file.
    pub(crate) fn new(
        name: Option<String>,
        triggers: Vec<Trigger>,
        envs: Vec<Env>,
        steps: Vec<Step>,
        edges: Vec<(String, String)>,
        order: Option<Vec<String>>,
    ) -> Self {
        Self { name, triggers, envs, steps, edges, order }
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
}
