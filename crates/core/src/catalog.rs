//! The built-in step catalog: the inputs each kind checks and the outputs it
//! declares. Custom step families (the `StepKind` trait) plug in later.

use crate::types::Type;

/// Catalog entry for one built-in step kind.
pub(crate) struct StepSpec {
    pub name: &'static str,
    pub inputs: &'static [(&'static str, Ty)],
    pub outputs: &'static [(&'static str, Ty)],
    /// Outputs known only at run time; read as `<step>.out.<name>`.
    pub runtime_outputs: bool,
    /// `decide`: the bare step name types as `Decision(returns)`.
    pub decision: bool,
}

/// A catalog type: a compact mirror of [`Type`] for the static table. The
/// `decide` answer output depends on the step's `returns:`, so it is a
/// marker ([`Ty::Answer`]) resolved per step.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ty {
    String,
    Bool,
    Int,
    Float,
    Path,
    Handle,
    Any,
    Named(&'static str),
    Answer,
}

impl Ty {
    pub(crate) fn to_type(self) -> Type {
        match self {
            Ty::String => Type::String,
            Ty::Bool => Type::Bool,
            Ty::Int => Type::Int,
            Ty::Float => Type::Float,
            Ty::Path => Type::Path,
            Ty::Handle => Type::Handle,
            Ty::Any | Ty::Answer => Type::Any,
            Ty::Named(n) => Type::Named(n),
        }
    }

    fn matches(self, t: &Type) -> bool {
        match self {
            Ty::Answer => matches!(t, Type::Decision(_) | Type::Any),
            other => other.to_type() == *t || t == &Type::Any,
        }
    }
}

/// `when:` is a reserved input on every step: a boolean expression.
const WHEN: &str = "when";

pub(crate) const STEPS: &[StepSpec] = &[
    StepSpec {
        name: "oci.image",
        inputs: &[("from", Ty::Path), ("push", Ty::Named("oci.Tag")), ("sign", Ty::Bool)],
        outputs: &[("digest", Ty::Named("oci.Digest")), ("tag", Ty::String), ("signed", Ty::Bool)],
        runtime_outputs: false,
        decision: false,
    },
    StepSpec {
        name: "tofu.plan",
        inputs: &[("dir", Ty::Path)],
        outputs: &[
            ("file", Ty::Named("tofu.PlanFile")),
            ("changes", Ty::Named("tofu.Changes")),
            ("adds", Ty::Int),
            ("destroys", Ty::Int),
        ],
        runtime_outputs: false,
        decision: false,
    },
    StepSpec {
        name: "approval",
        inputs: &[("show", Ty::Any), ("from", Ty::Handle), ("auto", Ty::Bool), ("else", Ty::Any)],
        outputs: &[("approved", Ty::Bool), ("by", Ty::String)],
        runtime_outputs: false,
        decision: false,
    },
    StepSpec {
        name: "tofu.apply",
        inputs: &[("plan", Ty::Named("tofu.PlanFile"))],
        outputs: &[],
        runtime_outputs: true,
        decision: false,
    },
    StepSpec {
        name: "k8s.rollout",
        inputs: &[("image", Ty::Named("oci.Digest")), ("to", Ty::Any), ("wait", Ty::Any)],
        outputs: &[],
        runtime_outputs: true,
        decision: false,
    },
    StepSpec {
        name: "decide",
        inputs: &[
            ("model", Ty::String),
            ("ask", Ty::String),
            ("input", Ty::Any),
            ("returns", Ty::Any),
        ],
        outputs: &[("answer", Ty::Answer), ("confidence", Ty::Float), ("reason", Ty::String)],
        runtime_outputs: false,
        decision: true,
    },
];

pub(crate) fn find(name: &str) -> Option<&'static StepSpec> {
    STEPS.iter().find(|s| s.name == name)
}

pub(crate) fn input(spec: &StepSpec, name: &str) -> Option<Ty> {
    if name == WHEN {
        return Some(Ty::Bool);
    }
    spec.inputs.iter().find(|(n, _)| *n == name).map(|(_, ty)| *ty)
}

pub(crate) fn output(spec: &StepSpec, name: &str) -> Option<Ty> {
    spec.outputs.iter().find(|(n, _)| *n == name).map(|(_, ty)| *ty)
}

/// Another output of the same kind with the wanted type, for
/// did-you-mean hints on type mismatches.
pub(crate) fn alt_output(spec: &StepSpec, want: &Type) -> Option<&'static str> {
    spec.outputs.iter().find(|(_, ty)| ty.matches(want)).map(|(n, _)| *n)
}

pub(crate) fn input_names(spec: &StepSpec) -> Vec<String> {
    let mut v: Vec<String> = spec.inputs.iter().map(|(n, _)| n.to_string()).collect();
    v.push(WHEN.to_string());
    v
}
