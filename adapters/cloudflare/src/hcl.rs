//! A small HCL2 emitter: enough of the native syntax to write provider blocks,
//! attributes and objects, and not much more.
//!
//! What it refuses to do is format for humans — there is no `tofu fmt` here and
//! no alignment pass, so the same model always renders byte for byte the same.
//! Its whole job is that property, plus escaping that cannot be talked out of:
//! every string this module emits is quoted and escaped such that a `$` or `%`
//! in account data cannot open an interpolation, and keys that are not bare
//! identifiers are quoted rather than trusted.

use std::fmt::Write as _;

use serde_json::Value;

use crate::Attr;

/// How many spaces one level of nesting is.
const INDENT: usize = 2;

/// Renders one attribute value. `level` is the nesting level of the lines the
/// value itself spans, so a block's contents sit one level deeper than its key.
pub fn attr(attr: &Attr, level: usize) -> String {
    match attr {
        Attr::Lit(value) => value_of(value, level),
        // Emitted verbatim: the only producers of `Expr` are the ones in this
        // crate, which build `var.<name>` references out of slugs.
        Attr::Expr(text) => text.clone(),
        Attr::Obj(fields) => object(fields.iter().map(|(key, value)| (key.as_str(), value)), level),
        Attr::List(items) => list(items, level),
    }
}

/// Renders a `key = value` body as an HCL object: `{` on the caller's line,
/// one attribute per line, closing brace on its own line at `level - 1`.
pub fn object<'a>(fields: impl Iterator<Item = (&'a str, &'a Attr)>, level: usize) -> String {
    let pad = " ".repeat(level * INDENT);
    let mut out = String::from("{\n");
    for (key, value) in fields {
        if matches!(value, Attr::Lit(Value::Null)) {
            continue;
        }
        let _ = writeln!(out, "{pad}{} = {}", key_of(key), attr(value, level + 1));
    }
    let _ = write!(out, "{}}}", " ".repeat((level - 1) * INDENT));
    out
}

/// Renders a list: scalars inline (`["a", "b"]`), anything containing an object
/// or a list one entry per line. Like [`object`], the closing bracket sits at
/// `level - 1`, level with the line that opened the list.
fn list(items: &[Attr], level: usize) -> String {
    let scalars = items.iter().all(|item| {
        !matches!(
            item,
            Attr::List(_) | Attr::Obj(_) | Attr::Lit(Value::Array(_) | Value::Object(_))
        )
    });
    if items.is_empty() {
        return "[]".to_string();
    }
    if scalars {
        let rendered: Vec<String> = items.iter().map(|item| attr(item, level)).collect();
        return format!("[{}]", rendered.join(", "));
    }
    let pad = " ".repeat(level * INDENT);
    let mut out = String::from("[\n");
    for (index, item) in items.iter().enumerate() {
        let comma = if index + 1 == items.len() { "" } else { "," };
        let _ = writeln!(out, "{pad}{}{comma}", attr(item, level + 1));
    }
    let _ = write!(out, "{}]", " ".repeat((level - 1) * INDENT));
    out
}

/// Renders a JSON value this crate read off the API.
fn value_of(value: &Value, level: usize) -> String {
    match value {
        // A null inside a list stays a null — dropping it would move every
        // item after it. (`object` drops null attributes before this runs.)
        Value::Null => "null".to_string(),
        // Anything with structure goes the long way round: `from_json` sorts the
        // keys and `attr` lays the block out.
        Value::Array(_) | Value::Object(_) => attr(&Attr::from_json(value), level),
        _ => scalar(value),
    }
}

/// A JSON scalar as HCL: strings quoted and escaped, numbers and booleans bare.
fn scalar(value: &Value) -> String {
    match value {
        Value::String(text) => quoted(text),
        Value::Bool(flag) => flag.to_string(),
        number => number.to_string(),
    }
}

/// Quotes and escapes `text` so no byte of it can end the string or open an
/// interpolation: `${` and `%{` are doubled, control characters escaped.
pub fn quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '$' if chars.clone().next() == Some('{') => {
                chars.next();
                out.push_str("$${");
            }
            '%' if chars.clone().next() == Some('{') => {
                chars.next();
                out.push_str("%%{");
            }
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ if ch.is_control() => {
                let _ = write!(out, "\\u{:04x}", ch as u32);
            }
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

/// A key bare when it is an identifier, quoted otherwise.
fn key_of(key: &str) -> String {
    let bare = !key.is_empty()
        && !key.starts_with(|ch: char| ch.is_ascii_digit())
        && key.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-');
    if bare { key.to_string() } else { quoted(key) }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::*;

    #[test]
    fn strings_escape_what_could_open_an_interpolation() {
        assert_eq!(quoted("plain"), "\"plain\"");
        assert_eq!(quoted("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(quoted("${var.x}"), "\"$${var.x}\"");
        assert_eq!(quoted("%{if true}"), "\"%%{if true}\"");
        assert_eq!(quoted("100$ and %"), "\"100$ and %\"");
        assert_eq!(quoted("a\nb"), "\"a\\nb\"");
    }

    #[test]
    fn objects_indent_and_quote_non_identifier_keys() {
        let mut fields = BTreeMap::new();
        fields.insert("zone_id".to_string(), Attr::from_json(&Value::String("z".to_string())));
        fields.insert("2nd".to_string(), Attr::from_json(&Value::Bool(true)));
        let object = Attr::Obj(fields.into_iter().collect());
        assert_eq!(attr(&object, 1), "{\n  \"2nd\" = true\n  zone_id = \"z\"\n}");
    }

    #[test]
    fn scalar_lists_stay_inline_and_nested_lists_do_not() {
        let scalars = Attr::List(vec![Attr::from_json(&Value::String("a".into()))]);
        assert_eq!(attr(&scalars, 1), "[\"a\"]");
        let objects = Attr::List(vec![Attr::Obj(vec![(
            "type".to_string(),
            Attr::from_json(&Value::String("all".into())),
        )])]);
        assert_eq!(attr(&objects, 1), "[\n  {\n    type = \"all\"\n  }\n]");
    }

    #[test]
    fn null_fields_are_dropped_from_objects() {
        let fields = [("comment", Attr::Lit(Value::Null)), ("name", Attr::from_json(&json!("a")))];
        assert_eq!(object(fields.iter().map(|(k, v)| (*k, v)), 1), "{\n  name = \"a\"\n}");
    }

    #[test]
    fn nulls_inside_lists_stay_nulls() {
        let list = Attr::List(vec![
            Attr::from_json(&json!("a")),
            Attr::from_json(&Value::Null),
            Attr::from_json(&json!(1)),
        ]);
        assert_eq!(attr(&list, 1), "[\"a\", null, 1]");
    }
}
