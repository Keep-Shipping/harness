//! The checker's small static type system.

use std::fmt;

/// The type of a step output, context value or step input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Type {
    String,
    Bool,
    Int,
    Float,
    Duration,
    Path,
    Handle,
    /// A value that exists but must never reach a string or a log.
    Secret,
    /// An opaque domain type (`oci.Digest`, `tofu.PlanFile`, ...).
    Named(&'static str),
    /// The answer of a `decide` step, with its declared variants.
    Decision(Vec<String>),
    /// A value that may be absent (`git.tag`, `pr.number`).
    Optional(Box<Type>),
    /// Unknown or unchecked: unknown step kinds, run-time outputs.
    Any,
}

impl Type {
    /// Whether the type is a number: [`Type::Int`] or [`Type::Float`].
    pub fn is_numeric(&self) -> bool {
        matches!(self, Type::Int | Type::Float)
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::String => f.write_str("String"),
            Type::Bool => f.write_str("Bool"),
            Type::Int => f.write_str("Int"),
            Type::Float => f.write_str("Float"),
            Type::Duration => f.write_str("Duration"),
            Type::Path => f.write_str("Path"),
            Type::Handle => f.write_str("Handle"),
            Type::Secret => f.write_str("Secret"),
            Type::Named(n) => f.write_str(n),
            Type::Decision(vs) if vs.is_empty() => f.write_str("decision"),
            Type::Decision(vs) => write!(f, "decision ({})", vs.join(" | ")),
            Type::Optional(t) => write!(f, "{t}?"),
            Type::Any => f.write_str("any"),
        }
    }
}
