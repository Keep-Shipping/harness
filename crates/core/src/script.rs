//! The `script` step's type bridge: what a TypeScript step's declared
//! outputs mean in ks
//! ([#88](https://github.com/Keep-Shipping/harness/issues/88)).
//!
//! A script step's *kind* is the module it runs — `migrate: ./ship/migrate.ts`
//! — so there is no kind to register. A script-host adapter loads the module
//! without calling `run` and reports the `step()` descriptor's constructors as
//! tags ([`Tag`]); this module is the pure half, mapping those tags to
//! [`Type`]s. Everything here is a function of a tag, so the crate stays
//! I/O-free.

use std::collections::BTreeMap;

use crate::types::Type;

/// Whether a step kind names a TypeScript module: a relative path ending in
/// `.ts`. An absolute path is not a site's own code, so it is not a script
/// step — a site says `migrate: ./ship/migrate.ts`.
#[must_use]
pub fn is_script_kind(kind: &str) -> bool {
    (kind.starts_with("./") || kind.starts_with("../")) && kind.ends_with(".ts")
}

/// The constructors the bridge maps, as a person would write them. Named once
/// so the error for a tag that does not map offers exactly these.
pub const SUPPORTED: &str = "`int()`, `float()`, `string()`, `bool()`, `secret()`, `path()`, `url()`, `duration()`, \
     `list(…)`, `optional(…)`";

/// One runtime type tag, as the extractor reports it: the constructor a step
/// declared, with what a `list()`/`optional()` holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tag {
    Int,
    Float,
    Str,
    Bool,
    Secret,
    Path,
    Url,
    Duration,
    /// A TypeScript `number`, which ks cannot resolve: `int` and `float` are
    /// different types and only the module knows which it meant.
    Number,
    /// A TypeScript `Boolean`. Unlike `number` it is unambiguous.
    Boolean,
    List(Box<Tag>),
    Optional(Box<Tag>),
    /// Anything the extractor saw that is not a constructor.
    Unknown(String),
    /// A `list()`/`optional()` written without what it holds.
    Missing,
}

impl Tag {
    /// The tag for the constructor named `kind`, with `of` what a
    /// `list()`/`optional()` holds. An unrecognised name is kept as
    /// [`Tag::Unknown`] rather than dropped, so the message can name it.
    #[must_use]
    pub fn new(kind: &str, of: Option<Tag>) -> Tag {
        match kind {
            "int" => Tag::Int,
            "float" => Tag::Float,
            "string" => Tag::Str,
            "bool" => Tag::Bool,
            "secret" => Tag::Secret,
            "path" => Tag::Path,
            "url" => Tag::Url,
            "duration" => Tag::Duration,
            "number" => Tag::Number,
            "boolean" => Tag::Boolean,
            "list" => of.map_or(Tag::Missing, |of| Tag::List(Box::new(of))),
            "optional" => of.map_or(Tag::Missing, |of| Tag::Optional(Box::new(of))),
            other => Tag::Unknown(other.to_string()),
        }
    }

    /// The ks type this tag declares, or the message to write where it is
    /// read. Every arm is a decision about what a TypeScript constructor
    /// means in a language with no implicit conversions.
    pub fn to_type(&self) -> Result<Type, String> {
        Ok(match self {
            Tag::Int => Type::Int,
            Tag::Float => Type::Float,
            Tag::Str => Type::String,
            Tag::Bool | Tag::Boolean => Type::Bool,
            Tag::Secret => Type::Secret,
            Tag::Path => Type::Path,
            Tag::Url => Type::Url,
            Tag::Duration => Type::Duration,
            Tag::List(of) => Type::List(Box::new(of.to_type()?)),
            Tag::Optional(of) => Type::Optional(Box::new(of.to_type()?)),
            Tag::Number => {
                return Err(
                    "a TS `number` is ambiguous in ks: declare it `int()` or `float()`".to_string()
                );
            }
            Tag::Missing => {
                return Err(format!(
                    "the constructor needs the type it holds, as in `list(int)`; the bridge maps \
                     {SUPPORTED}"
                ));
            }
            Tag::Unknown(kind) => {
                return Err(format!(
                    "`{kind}` is not a TypeScript constructor the bridge maps to a ks type; \
                     declare it as one of {SUPPORTED}"
                ));
            }
        })
    }
}

/// What one script step's module declares: each output's type, or the
/// message to write where that output is read. One bad output does not hide
/// the others — each carries its own verdict.
#[derive(Clone, Debug, Default)]
pub struct ScriptOutputs {
    outputs: BTreeMap<String, Result<Type, String>>,
}

impl ScriptOutputs {
    /// Nothing declared: the step's outputs stay unchecked, as they were
    /// before anything read the module.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.outputs.is_empty()
    }

    /// What the tag for output `name` declares: its type, or why it has
    /// none. `None` when the module declares no such output.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Result<Type, String>> {
        self.outputs.get(name)
    }

    /// Every declared output name, in name order, so a diagnostic can list
    /// what the module really does declare.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.outputs.keys().cloned().collect()
    }
}

/// Maps what a module declares to what the checker checks against. Each
/// output is mapped on its own, so one that cannot be mapped leaves the rest
/// typed.
#[must_use]
pub fn outputs(tags: &BTreeMap<String, Tag>) -> ScriptOutputs {
    ScriptOutputs { outputs: tags.iter().map(|(n, t)| (n.clone(), t.to_type())).collect() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag(kind: &str) -> Tag {
        Tag::new(kind, None)
    }

    #[test]
    fn every_constructor_maps_to_its_ks_type() {
        for (kind, want) in [
            ("int", Type::Int),
            ("float", Type::Float),
            ("string", Type::String),
            ("bool", Type::Bool),
            ("secret", Type::Secret),
            ("path", Type::Path),
            ("url", Type::Url),
            ("duration", Type::Duration),
            // A plain JavaScript constructor maps where it is unambiguous.
            ("boolean", Type::Bool),
        ] {
            assert_eq!(tag(kind).to_type(), Ok(want.clone()), "{kind}");
        }
    }

    #[test]
    fn a_container_maps_to_its_own_type() {
        let list = Tag::new("list", Some(tag("int")));
        assert_eq!(list.to_type(), Ok(Type::List(Box::new(Type::Int))));
        let opt = Tag::new("optional", Some(tag("secret")));
        assert_eq!(opt.to_type(), Ok(Type::Optional(Box::new(Type::Secret))));
        let nested = Tag::new("list", Some(Tag::new("list", Some(tag("url")))));
        assert_eq!(nested.to_type(), Ok(Type::List(Box::new(Type::List(Box::new(Type::Url))))));
        // The inner failure is the whole failure.
        assert_eq!(Tag::new("list", Some(tag("number"))).to_type(), tag("number").to_type());
    }

    #[test]
    fn a_tag_that_does_not_map_says_what_to_write_instead() {
        let number = tag("number").to_type().expect_err("a number has no one ks type");
        assert!(number.contains("ambiguous in ks"), "{number}");
        assert!(number.contains("`int()`") && number.contains("`float()`"), "{number}");
        let bare = Tag::new("list", None).to_type().expect_err("list() alone");
        assert!(bare.contains("needs the type it holds") && bare.contains("list(int)"), "{bare}");
        let other = tag("Date").to_type().expect_err("a Date is not a ks type");
        assert!(other.contains("`Date`") && other.contains("`optional(…)`"), "{other}");
    }

    #[test]
    fn one_output_that_cannot_map_leaves_the_others_typed() {
        let tags = BTreeMap::from([
            ("applied".to_string(), tag("int")),
            ("count".to_string(), tag("number")),
        ]);
        let declared = outputs(&tags);
        assert_eq!(declared.get("applied"), Some(&Ok(Type::Int)));
        assert!(declared.get("count").expect("count").is_err());
        assert_eq!(declared.names(), ["applied", "count"]);
    }

    #[test]
    fn a_script_step_is_a_kind_that_names_a_module() {
        assert!(is_script_kind("./ship/migrate.ts"));
        assert!(is_script_kind("../shared/hook.ts"));
        // Not a module: another kind, a path that is not TypeScript, or a
        // module outside the site.
        for kind in ["oci.image", "./migrate.js", "./migrate", "/abs/migrate.ts", "ship/migrate.ts"]
        {
            assert!(!is_script_kind(kind), "{kind}");
        }
    }

    #[test]
    fn a_module_that_declares_nothing_declares_nothing() {
        assert!(outputs(&BTreeMap::new()).is_empty());
        assert_eq!(outputs(&BTreeMap::new()).get("applied"), None);
    }
}
