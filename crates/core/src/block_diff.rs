//! What changed between two versions of a block's interface, and whether a
//! consumer of the old one is broken by it
//! ([#83](https://github.com/Keep-Shipping/harness/issues/83)).
//!
//! A [`BlockDefinition`] is the block's typed contract: the inputs a step must
//! supply and the outputs it can read. Comparing two of them is what lets
//! `check` say "your workflow is fine against 3.1.0 and will not be against
//! 4.0.0" *before* anyone runs it.
//!
//! # What is breaking, and why
//!
//! Breaking, because a consumer written against the old definition stops
//! working:
//!
//! - an input that is gone — the step still passes it and the new block does
//!   not declare it;
//! - an input that is now required — the step never supplied it;
//! - an input or output whose type changed — the value flowing through it was
//!   checked against the other type;
//! - an output that is gone — the step reads it.
//!
//! Not breaking, because a consumer written against the old definition still
//! works unchanged: a new optional input (nothing has to supply it), a new
//! output (nothing was reading it), and an input that became optional (the step
//! was already supplying it).
//!
//! # Types are compared as types, where they can be
//!
//! A [`BlockField`]'s `type_name` is the *publisher's* spelling and carries no
//! guarantee of being normalised, so two spellings are the same type when
//! [`Type::parse`] reads both and they come out equal — `list[ string ]` and
//! `list[string]` are one type. Only a spelling that differs by whitespace is
//! thereby forgiven: `Type::parse` reads `string` and `string?` as two
//! different types, and so does this module. Where neither side parses, the
//! trimmed strings are compared: this module must be able to talk about a type
//! vocabulary it has never heard of, so an unparseable name is compared as
//! written rather than refused.
//!
//! # Purity
//!
//! No I/O and no dependencies: this module answers about two definitions it is
//! handed, and deciding which two is the caller's.

use std::fmt;

use crate::Type;
use crate::ports::block_source::{BlockDefinition, BlockField};

/// One difference between two versions of a block's interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// The input is not declared by the new definition. A step written against
    /// the old one still supplies it.
    InputRemoved {
        /// The input's name, as the old definition declared it.
        name: String,
    },
    /// The input is new. Breaking only when it is required: a consumer that
    /// never heard of an optional input still type-checks.
    InputAdded {
        /// The input's name, as the new definition declares it.
        name: String,
        /// Whether a step must now supply it.
        required: bool,
    },
    /// The input existed and was optional; it is now required. The same effect
    /// on a consumer as a brand new required input, reported separately
    /// because the name is one it already had.
    InputRequired {
        /// The input's name.
        name: String,
    },
    /// The input existed and was required; it is now optional. A step that
    /// supplied it still supplies it.
    InputOptional {
        /// The input's name.
        name: String,
    },
    /// The input's type changed. Anything the consumer passes or reads was
    /// checked against the old type.
    InputRetyped {
        /// The input's name.
        name: String,
        /// The type as the old definition spelled it.
        from: String,
        /// The type as the new definition spells it.
        to: String,
    },
    /// The output is not declared by the new definition, but a consumer reads
    /// it.
    OutputRemoved {
        /// The output's name, as the old definition declared it.
        name: String,
    },
    /// The output is new. Never breaking: nothing was reading it.
    OutputAdded {
        /// The output's name, as the new definition declares it.
        name: String,
    },
    /// The output's type changed, so a consumer reading it is reading a type
    /// it did not check against.
    OutputRetyped {
        /// The output's name.
        name: String,
        /// The type as the old definition spelled it.
        from: String,
        /// The type as the new definition spells it.
        to: String,
    },
}

impl Change {
    /// Whether a consumer written against the old definition stops working.
    pub fn is_breaking(&self) -> bool {
        match self {
            Change::InputAdded { required, .. } => *required,
            Change::InputRemoved { .. }
            | Change::InputRequired { .. }
            | Change::InputRetyped { .. }
            | Change::OutputRemoved { .. }
            | Change::OutputRetyped { .. } => true,
            Change::InputOptional { .. } | Change::OutputAdded { .. } => false,
        }
    }

    /// Whether this change would break `usage` specifically, as opposed to
    /// some consumer in general.
    ///
    /// The two asymmetries are the whole point. An *added* required input and
    /// an input that *became* required both fail a site that does not mention
    /// the name — it has nothing to put there — but pass a site that already
    /// supplies it, which the old definition happened to allow. Everything else
    /// needs the site to touch the field at all.
    fn hits(&self, usage: &Usage) -> bool {
        match self {
            Change::InputRemoved { name } | Change::InputRetyped { name, .. } => {
                usage.supplies(name)
            }
            Change::InputAdded { name, .. } | Change::InputRequired { name } => {
                !usage.supplies(name)
            }
            Change::OutputRemoved { name } | Change::OutputRetyped { name, .. } => {
                usage.reads(name)
            }
            Change::InputOptional { .. } | Change::OutputAdded { .. } => false,
        }
    }
}

impl fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Change::InputRemoved { name } => write!(f, "input `{name}` was removed"),
            Change::InputAdded { name, required: true } => {
                write!(f, "input `{name}` is new and required")
            }
            Change::InputAdded { name, required: false } => {
                write!(f, "input `{name}` is new and optional")
            }
            Change::InputRequired { name } => write!(f, "input `{name}` is now required"),
            Change::InputOptional { name } => write!(f, "input `{name}` is now optional"),
            Change::InputRetyped { name, from, to } => {
                write!(f, "input `{name}` changed type from {from} to {to}")
            }
            Change::OutputRemoved { name } => write!(f, "output `{name}` was removed"),
            Change::OutputAdded { name } => write!(f, "output `{name}` is new"),
            Change::OutputRetyped { name, from, to } => {
                write!(f, "output `{name}` changed type from {from} to {to}")
            }
        }
    }
}

/// Everything that differs between two versions of a block's interface.
///
/// The changes are ordered deterministically — inputs before outputs, and
/// within each side the removals and retypes in the old definition's order
/// followed by the additions in the new definition's order, a field's requiredness
/// change following its retype — so a diff can be printed, compared or
/// snapshotted without a sort that might reorder equal elements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureDiff {
    changes: Vec<Change>,
}

impl SignatureDiff {
    /// The changes, in the order [`diff`] produced them.
    pub fn changes(&self) -> &[Change] {
        &self.changes
    }

    /// Whether any change breaks a consumer written against the old definition.
    pub fn is_breaking(&self) -> bool {
        self.changes.iter().any(Change::is_breaking)
    }

    /// Whether the two definitions were identical.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// The breaking changes this usage would trip over, in diff order.
    ///
    /// A site that supplies and reads nothing the changed fields are named
    /// after survives every breaking change, so this is the gate that lets
    /// `blocks upgrade` accept an upgrade whose breakages are elsewhere. It is
    /// the *name*-level gate and nothing more: whether a supplied value still
    /// type-checks against a retyped input is `check`'s job once `check`
    /// checks block steps, and a caller that wants to refuse that too should
    /// wait for that verdict rather than infer it here.
    pub fn affecting<'a>(&'a self, usage: &Usage) -> impl Iterator<Item = &'a Change> {
        self.changes.iter().filter(|change| change.is_breaking() && change.hits(usage))
    }
}

/// How one site uses a block: the inputs it supplies and the outputs it reads.
///
/// Names only, and only the ones the site actually mentions — a workflow that
/// reads `deploy.url` depends on the `url` output and on nothing else the
/// block declares. What the site *puts in* an input is not here, which is the
/// limit [`SignatureDiff::affecting`] documents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Usage {
    /// The input names this site supplies.
    pub inputs: Vec<String>,
    /// The output names this site reads.
    pub outputs: Vec<String>,
}

impl Usage {
    /// A usage that supplies `inputs` and reads `outputs`.
    pub fn new(inputs: &[&str], outputs: &[&str]) -> Usage {
        Usage {
            inputs: inputs.iter().map(|name| (*name).to_string()).collect(),
            outputs: outputs.iter().map(|name| (*name).to_string()).collect(),
        }
    }

    /// Whether the site names this input at all — which is what "supplies" and
    /// "does not supply" mean for every rule below.
    fn supplies(&self, name: &str) -> bool {
        self.inputs.iter().any(|supplied| supplied == name)
    }

    /// Whether the site reads this output.
    fn reads(&self, name: &str) -> bool {
        self.outputs.iter().any(|read| read == name)
    }
}

/// Compares two versions of a block's interface.
///
/// Fields are matched by name; a field present on only one side is an addition
/// or a removal, and a field present on both is compared for type and
/// requiredness. Names are assumed unique within `inputs` and within `outputs`
/// — a definition that declares the same name twice is malformed and this says
/// nothing about it — so a field that moved from `inputs` to `outputs` shows up
/// as a removal plus an addition rather than as a rename. The `summary` is
/// documentation and not part of the contract, so it is deliberately not
/// diffed: a release that only rewrote the synopsis breaks nobody.
pub fn diff(old: &BlockDefinition, new: &BlockDefinition) -> SignatureDiff {
    let mut changes = Vec::new();

    // Removals and retypes in the old declaration order...
    for old_field in &old.inputs {
        match new.inputs.iter().find(|f| f.name == old_field.name) {
            None => changes.push(Change::InputRemoved { name: old_field.name.clone() }),
            Some(new_field) => push_input_change(&mut changes, old_field, new_field),
        }
    }
    // ...then additions in the new declaration order.
    for new_field in &new.inputs {
        if !old.inputs.iter().any(|f| f.name == new_field.name) {
            changes.push(Change::InputAdded {
                name: new_field.name.clone(),
                required: new_field.required,
            });
        }
    }

    for old_field in &old.outputs {
        match new.outputs.iter().find(|f| f.name == old_field.name) {
            None => changes.push(Change::OutputRemoved { name: old_field.name.clone() }),
            Some(new_field) => {
                // Requiredness is not part of an output's contract — a step
                // cannot supply anything to an output — so only the type moves.
                if !same_type(&old_field.type_name, &new_field.type_name) {
                    changes.push(Change::OutputRetyped {
                        name: old_field.name.clone(),
                        from: old_field.type_name.clone(),
                        to: new_field.type_name.clone(),
                    });
                }
            }
        }
    }
    for new_field in &new.outputs {
        if !old.outputs.iter().any(|f| f.name == new_field.name) {
            changes.push(Change::OutputAdded { name: new_field.name.clone() });
        }
    }

    SignatureDiff { changes }
}

/// One field's worth of change: type first, then requiredness. Both are
/// reported when both moved — they are two facts about the same field, and a
/// consumer is broken by either.
fn push_input_change(changes: &mut Vec<Change>, old: &BlockField, new: &BlockField) {
    if !same_type(&old.type_name, &new.type_name) {
        changes.push(Change::InputRetyped {
            name: old.name.clone(),
            from: old.type_name.clone(),
            to: new.type_name.clone(),
        });
    }
    match (old.required, new.required) {
        (false, true) => changes.push(Change::InputRequired { name: old.name.clone() }),
        (true, false) => changes.push(Change::InputOptional { name: old.name.clone() }),
        (true, true) | (false, false) => {}
    }
}

/// Whether two spellings of a type name are the same type. An annotation this
/// crate cannot read is still comparable as text, and refusing to compare it
/// would mean a block in a vocabulary newer than this build could not be
/// diffed at all.
fn same_type(a: &str, b: &str) -> bool {
    match (Type::parse(a), Type::parse(b)) {
        (Some(ta), Some(tb)) => ta == tb,
        _ => a.trim() == b.trim(),
    }
}
