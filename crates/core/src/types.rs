//! The checker's small static type system: primitives, nominal domain
//! types, and the deliberately tiny coercion relation between them
//! ([#24](https://github.com/Keep-Shipping/harness/issues/24)).

use std::fmt;

use ks_lang::{Scalar, classify_scalar};

/// The type of a step output, context value or step input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Type {
    String,
    Bool,
    Int,
    Float,
    Duration,
    Path,
    /// An `http(s)://…` address.
    Url,
    /// A team handle (`@platform`), as spelled in the language.
    Handle,
    /// A value that exists but must never reach a string or a log.
    Secret,
    /// An opaque domain type (`oci.Digest`, `tofu.PlanFile`, ...). Nominal:
    /// nothing coerces into or out of one except itself and `any`.
    Named(String),
    /// The answer of a `decide` step, with its declared variants.
    Decision(Vec<String>),
    /// The variants a schema declares for a value: `low | medium | high`.
    Enum(Vec<String>),
    /// A list of `T`.
    List(Box<Type>),
    /// A map with string keys and values of `T`.
    Map(Box<Type>),
    /// A record with named fields, in declaration order.
    Record(Vec<(String, Type)>),
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

    /// Whether this is the named type `name` (`oci.Digest`, ...).
    pub fn is_named(&self, name: &str) -> bool {
        matches!(self, Type::Named(n) if n == name)
    }

    /// Parses a type annotation as the language spells it: a primitive
    /// (`int`), an optional suffix (`string?`), a container (`list[string]`,
    /// `map[url]`), a record (`{healthy: bool, grace: duration}`), an enum
    /// union (`low | medium | high`), or a nominal name (`oci.Digest`).
    /// `None` when the annotation is not well-formed; an unknown name is
    /// well-formed and becomes [`Type::Named`].
    pub fn parse(annotation: &str) -> Option<Type> {
        let a = annotation.trim();
        if let Some(inner) = a.strip_suffix('?') {
            return Type::parse(inner).map(|t| Type::Optional(Box::new(t)));
        }
        if let Some(inner) = a.strip_prefix("list[").and_then(|s| s.strip_suffix(']')) {
            return Type::parse(inner).map(|t| Type::List(Box::new(t)));
        }
        if let Some(inner) = a.strip_prefix("map[").and_then(|s| s.strip_suffix(']')) {
            return Type::parse(inner).map(|t| Type::Map(Box::new(t)));
        }
        if let Some(inner) = a.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            return parse_record(inner);
        }
        if a.contains('|') {
            let alts: Vec<String> =
                a.split('|').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect();
            let idents =
                !alts.is_empty() && alts.iter().all(|v| classify_scalar(v) == Scalar::Ident);
            return idents.then_some(Type::Enum(alts));
        }
        Some(match a {
            "string" => Type::String,
            "bool" => Type::Bool,
            "int" => Type::Int,
            "float" => Type::Float,
            "duration" => Type::Duration,
            "path" => Type::Path,
            "url" => Type::Url,
            "any" => Type::Any,
            "Secret" => Type::Secret,
            "Team" | "Handle" => Type::Handle,
            other => {
                let spelled = matches!(classify_scalar(other), Scalar::Ident | Scalar::DottedName);
                spelled.then(|| Type::Named(other.to_string()))?
            }
        })
    }
}

/// `{name: type, ...}`, split on commas that name no nested container.
fn parse_record(inner: &str) -> Option<Type> {
    let mut fields = Vec::new();
    for part in split_top(inner, ',') {
        let (name, ty) = part.split_once(':')?;
        let name = name.trim();
        if classify_scalar(name) != Scalar::Ident {
            return None;
        }
        fields.push((name.to_string(), Type::parse(ty.trim())?));
    }
    Some(Type::Record(fields))
}

/// Splits `text` on `sep` at brace/bracket depth zero.
fn split_top(text: &str, sep: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (i, c) in text.char_indices() {
        match c {
            '[' | '{' => depth += 1,
            ']' | '}' => depth = depth.saturating_sub(1),
            _ if c == sep && depth == 0 => {
                parts.push(&text[start..i]);
                start = i + sep.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(&text[start..]);
    parts
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::String => f.write_str("string"),
            Type::Bool => f.write_str("bool"),
            Type::Int => f.write_str("int"),
            Type::Float => f.write_str("float"),
            Type::Duration => f.write_str("duration"),
            Type::Path => f.write_str("path"),
            Type::Url => f.write_str("url"),
            Type::Handle => f.write_str("Team"),
            Type::Secret => f.write_str("Secret"),
            Type::Named(n) => f.write_str(n),
            Type::List(t) => write!(f, "list[{t}]"),
            Type::Map(t) => write!(f, "map[{t}]"),
            Type::Record(fields) => {
                f.write_str("{")?;
                for (i, (name, ty)) in fields.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{name}: {ty}")?;
                }
                f.write_str("}")
            }
            Type::Enum(vs) if vs.is_empty() => f.write_str("<never>"),
            Type::Enum(vs) => f.write_str(&vs.join(" | ")),
            Type::Decision(vs) if vs.is_empty() => f.write_str("decision"),
            Type::Decision(vs) => write!(f, "decision ({})", vs.join(" | ")),
            Type::Optional(t) => write!(f, "{t}?"),
            Type::Any => f.write_str("any"),
        }
    }
}

/// Whether a value of type `got` may flow where `want` is declared. The
/// whole coercion relation, and deliberately a small one: identical types,
/// `any` either way, `int` into `float`, optional unwrapping, and
/// element-wise containers. Nominal types coerce only to themselves; a
/// [`Type::Secret`] never coerces to or from a string.
pub fn coerce(want: &Type, got: &Type) -> bool {
    if want == got {
        return true;
    }
    match (want, got) {
        (Type::Any, _) | (_, Type::Any) => true,
        (Type::Float, Type::Int) => true,
        // `T?` unwraps to `T` and accepts it: a may-be-absent value is
        // checked against the bare type, and a bare one fills an optional
        // slot.
        (Type::Optional(w), g) => coerce(w, g),
        (w, Type::Optional(g)) => coerce(w, g),
        (Type::List(w), Type::List(g)) | (Type::Map(w), Type::Map(g)) => coerce(w, g),
        (Type::Record(ws), Type::Record(gs)) => {
            ws.len() == gs.len()
                && ws.iter().zip(gs).all(|((wn, wt), (gn, gt))| wn == gn && coerce(wt, gt))
        }
        _ => false,
    }
}

/// How a literal value fits the type an input declares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LiteralFit {
    /// A literal of the type.
    Ok,
    /// Allowed, but worth a warning: the message says why, the hint what to
    /// do instead.
    Warn { message: String, hint: String },
    /// Not a literal of the type.
    Err,
}

/// Classifies the literal `text` against `want`. Literals are spelled into
/// the type the input declares — `true` is a bool, `5m` a duration,
/// `./x` a path, an enum member names its variant, any text is a string or
/// an `oci.Tag`. `digest_alt` names a same-workflow output of the wanted
/// nominal type, so a pasted digest can be answered with the reference to
/// use instead.
pub fn literal(want: &Type, text: &str, digest_alt: Option<&str>) -> LiteralFit {
    // An interpolated value is a reference, not a literal.
    if text.contains('{') || text.contains('}') {
        return LiteralFit::Err;
    }
    let scalar = classify_scalar(text);
    match want {
        Type::Any | Type::String => LiteralFit::Ok,
        Type::Bool if scalar == Scalar::Bool => LiteralFit::Ok,
        Type::Int if scalar == Scalar::Number && !text.contains('.') => LiteralFit::Ok,
        Type::Float if scalar == Scalar::Number => LiteralFit::Ok,
        Type::Duration if scalar == Scalar::Duration => LiteralFit::Ok,
        Type::Path if scalar == Scalar::Path => LiteralFit::Ok,
        Type::Handle if scalar == Scalar::Handle => LiteralFit::Ok,
        Type::Url if is_url(text) => LiteralFit::Ok,
        Type::Enum(vs) if scalar == Scalar::Ident && vs.iter().any(|v| v == text) => LiteralFit::Ok,
        Type::Optional(inner) => literal(inner, text, digest_alt),
        Type::Named(name) => nominal_literal(name, text, digest_alt),
        _ => LiteralFit::Err,
    }
}

/// Nominal types take no literals, with two exceptions the domain spells
/// for a living: tags and refs are strings (`ghcr.io/acme/api:v1`), and a
/// digest may be pasted — well-formed, but exactly what the type is here to
/// prevent, so it warns.
fn nominal_literal(name: &str, text: &str, digest_alt: Option<&str>) -> LiteralFit {
    match name {
        "oci.Tag" | "oci.Ref" => LiteralFit::Ok,
        "oci.Digest" if is_sha256_digest(text) => LiteralFit::Warn {
            message: "digest literal pinned by value".into(),
            hint: match digest_alt {
                Some(alt) => format!("pin by reference, not by pasted digest: use {alt}"),
                None => "pin by reference, not by pasted digest".into(),
            },
        },
        _ => LiteralFit::Err,
    }
}

/// `sha256:` followed by exactly 64 lowercase hex digits.
pub fn is_sha256_digest(text: &str) -> bool {
    let Some(hex) = text.strip_prefix("sha256:") else { return false };
    hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_url(text: &str) -> bool {
    text.starts_with("http://") || text.starts_with("https://")
}

/// The type a literal spells when no declared type claims it — what a
/// mismatch message says (`got string`, never `got any` for a literal).
pub fn literal_type(text: &str) -> Type {
    match classify_scalar(text) {
        Scalar::Bool => Type::Bool,
        Scalar::Number if text.contains('.') => Type::Float,
        Scalar::Number => Type::Int,
        Scalar::Duration => Type::Duration,
        Scalar::Handle => Type::Handle,
        Scalar::Path => Type::Path,
        Scalar::DottedName | Scalar::Ident | Scalar::Str | Scalar::Text => Type::String,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(n: &str) -> Type {
        Type::Named(n.to_string())
    }

    #[test]
    fn identical_types_are_accepted() {
        let types = [
            Type::String,
            Type::Bool,
            Type::Int,
            Type::Float,
            Type::Duration,
            Type::Path,
            Type::Url,
            Type::Handle,
            Type::Secret,
            named("oci.Digest"),
            Type::Decision(vec!["low".into()]),
            Type::Enum(vec!["low".into()]),
            Type::List(Box::new(Type::Int)),
            Type::Map(Box::new(Type::String)),
            Type::Record(vec![("a".into(), Type::Int)]),
            Type::Optional(Box::new(Type::String)),
            Type::Any,
        ];
        for t in &types {
            assert!(coerce(t, t), "{t} does not accept itself");
        }
    }

    #[test]
    fn any_is_accepted_by_and_accepts_everything() {
        for t in [Type::Secret, named("oci.Digest"), Type::List(Box::new(Type::Int))] {
            assert!(coerce(&Type::Any, &t), "any accepts {t}");
            assert!(coerce(&t, &Type::Any), "{t} is accepted by any");
        }
    }

    #[test]
    fn int_promotes_to_float_but_never_back() {
        assert!(coerce(&Type::Float, &Type::Int));
        assert!(!coerce(&Type::Int, &Type::Float));
    }

    #[test]
    fn optional_and_bare_types_coerce_either_way() {
        let tag = Type::Optional(Box::new(Type::String));
        // `string?` unwraps into `string` — the one direction the #160
        // checker already accepted, kept here.
        assert!(coerce(&Type::String, &tag), "string? flows into string");
        // A bare value fills an optional slot: the sound addition.
        assert!(coerce(&tag, &Type::String), "string flows into string?");
        // Element-wise: only coercible inners unwrap.
        assert!(coerce(
            &Type::Optional(Box::new(Type::Float)),
            &Type::Optional(Box::new(Type::Int))
        ));
        assert!(!coerce(&Type::Int, &tag));
    }

    #[test]
    fn lists_and_maps_coerce_element_wise_only() {
        assert!(coerce(&Type::List(Box::new(Type::Float)), &Type::List(Box::new(Type::Int))));
        assert!(coerce(&Type::Map(Box::new(Type::Any)), &Type::Map(Box::new(Type::Bool))));
        assert!(!coerce(&Type::List(Box::new(Type::Int)), &Type::List(Box::new(Type::String))));
        assert!(!coerce(&Type::List(Box::new(Type::Int)), &Type::Int));
    }

    #[test]
    fn records_coerce_field_wise() {
        let want =
            Type::Record(vec![("healthy".into(), Type::Bool), ("grace".into(), Type::Duration)]);
        let ok =
            Type::Record(vec![("healthy".into(), Type::Bool), ("grace".into(), Type::Duration)]);
        assert!(coerce(&want, &ok));
        let renamed =
            Type::Record(vec![("hale".into(), Type::Bool), ("grace".into(), Type::Duration)]);
        assert!(!coerce(&want, &renamed), "field names must match");
        let shorter = Type::Record(vec![("healthy".into(), Type::Bool)]);
        assert!(!coerce(&want, &shorter), "arity must match");
    }

    #[test]
    fn secrets_never_coerce_with_strings() {
        assert!(!coerce(&Type::String, &Type::Secret));
        assert!(!coerce(&Type::Secret, &Type::String));
        assert!(coerce(&Type::Secret, &Type::Secret));
        // ... not even wrapped: the leak must not slip through a container.
        assert!(!coerce(&Type::List(Box::new(Type::String)), &Type::List(Box::new(Type::Secret))));
    }

    #[test]
    fn nominal_types_coerce_only_to_themselves() {
        assert!(!coerce(&named("oci.Digest"), &named("oci.Tag")));
        assert!(!coerce(&named("oci.Digest"), &Type::String));
        assert!(!coerce(&Type::String, &named("oci.Digest")));
        assert!(!coerce(&named("tofu.PlanFile"), &named("tofu.Changes")));
    }

    // --- Type::parse -------------------------------------------------------

    #[test]
    fn parse_reads_primitives_and_secret_and_team() {
        let cases = [
            ("string", Type::String),
            ("int", Type::Int),
            ("float", Type::Float),
            ("bool", Type::Bool),
            ("duration", Type::Duration),
            ("path", Type::Path),
            ("url", Type::Url),
            ("Secret", Type::Secret),
            ("Team", Type::Handle),
        ];
        for (annotation, want) in cases {
            assert_eq!(Type::parse(annotation), Some(want), "{annotation}");
        }
    }

    #[test]
    fn parse_reads_optionals_containers_records_and_enums() {
        assert_eq!(Type::parse("string?"), Some(Type::Optional(Box::new(Type::String))));
        assert_eq!(Type::parse("list[string]"), Some(Type::List(Box::new(Type::String))));
        assert_eq!(
            Type::parse("list[list[int]]"),
            Some(Type::List(Box::new(Type::List(Box::new(Type::Int)))))
        );
        assert_eq!(Type::parse("map[url]"), Some(Type::Map(Box::new(Type::Url))));
        assert_eq!(
            Type::parse("{healthy: bool, grace: duration}"),
            Some(Type::Record(vec![
                ("healthy".into(), Type::Bool),
                ("grace".into(), Type::Duration)
            ]))
        );
        assert_eq!(
            Type::parse("low | medium | high"),
            Some(Type::Enum(vec!["low".into(), "medium".into(), "high".into()]))
        );
    }

    #[test]
    fn parse_reads_nominal_names_and_rejects_garbage() {
        assert_eq!(Type::parse("oci.Digest"), Some(named("oci.Digest")));
        assert_eq!(Type::parse("web.Cluster"), Some(named("web.Cluster")));
        assert_eq!(Type::parse(""), None);
        assert_eq!(Type::parse("list["), None);
        assert_eq!(Type::parse("{a: }"), None);
        assert_eq!(Type::parse("a | 5"), None, "enum variants are idents");
        assert_eq!(Type::parse("ghcr.io/x"), None, "// and : do not spell a name");
    }

    // --- literal -----------------------------------------------------------

    #[test]
    fn bool_and_number_literals_fit_their_primitives() {
        assert_eq!(literal(&Type::Bool, "true", None), LiteralFit::Ok);
        assert_eq!(literal(&Type::Bool, "false", None), LiteralFit::Ok);
        assert_eq!(literal(&Type::Int, "2", None), LiteralFit::Ok);
        assert_eq!(literal(&Type::Int, "2.0", None), LiteralFit::Err);
        assert_eq!(literal(&Type::Float, "2", None), LiteralFit::Ok);
        assert_eq!(literal(&Type::Float, "0.95", None), LiteralFit::Ok);
        assert_eq!(literal(&Type::Bool, "yes", None), LiteralFit::Err);
    }

    #[test]
    fn duration_path_and_handle_literals_are_spelled_not_coerced() {
        assert_eq!(literal(&Type::Duration, "5m", None), LiteralFit::Ok);
        assert_eq!(literal(&Type::Duration, "250ms", None), LiteralFit::Ok);
        assert_eq!(literal(&Type::Path, "./infra/prod", None), LiteralFit::Ok);
        assert_eq!(literal(&Type::Path, "/etc/hosts", None), LiteralFit::Ok);
        assert_eq!(literal(&Type::Handle, "@platform", None), LiteralFit::Ok);
        assert_eq!(literal(&Type::Duration, "5", None), LiteralFit::Err);
        assert_eq!(literal(&Type::Handle, "platform", None), LiteralFit::Err);
    }

    #[test]
    fn a_url_literal_must_say_its_scheme() {
        assert_eq!(literal(&Type::Url, "https://api.acme.dev", None), LiteralFit::Ok);
        assert_eq!(literal(&Type::Url, "http://localhost:8080", None), LiteralFit::Ok);
        assert_eq!(literal(&Type::Url, "api.acme.dev", None), LiteralFit::Err);
    }

    #[test]
    fn enum_literals_must_name_a_declared_variant() {
        let size = Type::Enum(vec!["s".into(), "m".into(), "l".into()]);
        assert_eq!(literal(&size, "m", None), LiteralFit::Ok);
        assert_eq!(literal(&size, "xl", None), LiteralFit::Err);
    }

    #[test]
    fn any_text_is_a_string_and_a_tag() {
        assert_eq!(literal(&Type::String, "api.acme.dev", None), LiteralFit::Ok);
        assert_eq!(literal(&named("oci.Tag"), "ghcr.io/acme/api:v1", None), LiteralFit::Ok);
        assert_eq!(literal(&named("oci.Ref"), "main", None), LiteralFit::Ok);
    }

    #[test]
    fn a_well_formed_digest_literal_warns_and_names_what_to_use_instead() {
        let digest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let fit = literal(&named("oci.Digest"), digest, Some("build.digest"));
        assert_eq!(
            fit,
            LiteralFit::Warn {
                message: "digest literal pinned by value".into(),
                hint: "pin by reference, not by pasted digest: use build.digest".into(),
            }
        );
        // Without a known producer the hint stays generic.
        assert!(matches!(literal(&named("oci.Digest"), digest, None), LiteralFit::Warn { .. }));
    }

    #[test]
    fn a_digest_literal_must_be_a_full_lowercase_sha256() {
        assert_eq!(literal(&named("oci.Digest"), "sha256:abc", None), LiteralFit::Err);
        assert_eq!(
            literal(
                &named("oci.Digest"),
                "sha256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
                None
            ),
            LiteralFit::Err,
            "uppercase hex is not a spelled digest"
        );
        assert_eq!(literal(&named("oci.Digest"), "md5:e3b0", None), LiteralFit::Err);
    }

    #[test]
    fn other_nominal_types_take_no_literal_at_all() {
        assert_eq!(literal(&named("tofu.PlanFile"), "./plan.tfplan", None), LiteralFit::Err);
        assert_eq!(literal(&named("web.Cluster"), "prod", None), LiteralFit::Err);
    }

    #[test]
    fn secret_takes_no_literal_and_optionals_unwrap() {
        assert_eq!(literal(&Type::Secret, "hunter2", None), LiteralFit::Err);
        assert_eq!(literal(&Type::Optional(Box::new(Type::Duration)), "5m", None), LiteralFit::Ok);
    }

    #[test]
    fn interpolated_text_is_a_reference_not_a_literal() {
        assert_eq!(literal(&Type::String, "{git.sha}", None), LiteralFit::Err);
        assert_eq!(literal(&named("oci.Tag"), "ghcr.io/x:{git.sha}", None), LiteralFit::Err);
    }

    #[test]
    fn literals_type_as_themselves_for_mismatch_messages() {
        assert_eq!(literal_type("true"), Type::Bool);
        assert_eq!(literal_type("2"), Type::Int);
        assert_eq!(literal_type("0.95"), Type::Float);
        assert_eq!(literal_type("5m"), Type::Duration);
        assert_eq!(literal_type("@platform"), Type::Handle);
        assert_eq!(literal_type("./infra"), Type::Path);
        assert_eq!(literal_type("banana"), Type::String);
    }

    // --- Display -----------------------------------------------------------

    #[test]
    fn display_spells_types_as_the_language_does() {
        let shown = [
            (Type::String.to_string(), "string"),
            (Type::Bool.to_string(), "bool"),
            (Type::Int.to_string(), "int"),
            (Type::Float.to_string(), "float"),
            (Type::Duration.to_string(), "duration"),
            (Type::Path.to_string(), "path"),
            (Type::Url.to_string(), "url"),
            (Type::Handle.to_string(), "Team"),
            (Type::Secret.to_string(), "Secret"),
            (named("oci.Digest").to_string(), "oci.Digest"),
            (Type::List(Box::new(Type::String)).to_string(), "list[string]"),
            (Type::Map(Box::new(Type::Url)).to_string(), "map[url]"),
            (
                Type::Record(vec![("a".into(), Type::Int), ("b".into(), Type::String)]).to_string(),
                "{a: int, b: string}",
            ),
            (Type::Enum(vec!["low".into(), "high".into()]).to_string(), "low | high"),
            (
                Type::Decision(vec!["low".into(), "high".into()]).to_string(),
                "decision (low | high)",
            ),
            (Type::Optional(Box::new(Type::String)).to_string(), "string?"),
            (Type::Any.to_string(), "any"),
        ];
        for (actual, expected) in shown {
            assert_eq!(actual, expected);
        }
    }
}
