//! What Terraform declares, read without running Terraform: the name and
//! type of every `output` block in a `.tf` file. The checker needs no more
//! than that — a site file reads `apply.out.cluster`, and this is what says
//! whether `cluster` is there and what it holds ([#70](https://github.com/Keep-Shipping/harness/issues/70)).
//!
//! Pure computation: text in, [`Output`]s out, so `ks-core` stays I/O-free
//! and the CLI decides which files to read. Parsing is deliberately shallow —
//! a hand-rolled scan for `output "<name>" { … }`, robust to comments,
//! quoted strings with `${…}` and heredocs, not a Terraform parser.
//!
//! A type comes from the first of these that applies:
//!
//! - a `# keepshipping:type <Type>` comment (also spelled `//`) on the
//!   comment lines above the block or on a line directly inside it;
//! - the shape of an object literal `value = { … }`: the keys
//!   `endpoint`, `ca` and `auth` make it a [`Type::Named`] `k8s.Cluster` —
//!   an API server, its CA and an exec-based auth method (`eks`, `gke`,
//!   `aks`), never a credential — and any other object types as a record of
//!   its keys;
//! - nothing, in which case the output is [`Type::Any`].
//!
//! An annotation that does not parse is treated as if it were not there, so
//! a typo in a comment widens a type to what the value's shape says rather
//! than failing a check over a comment.

use crate::types::Type;

/// The marker comment that names an output's type.
const ANNOTATION: &str = "keepshipping:type";

/// One `output` block, as far as the checker cares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    /// The block's name, as `output "cluster"` spells it.
    pub name: String,
    /// What the output holds, from its annotation, else from its shape.
    pub ty: Type,
}

/// Every top-level `output` block in `src`, in source order.
#[must_use]
pub fn scan(src: &str) -> Vec<Output> {
    Scanner::new(src).outputs()
}

/// The type an object literal's keys describe. The one shape the catalog
/// knows is a cluster; anything else is a record whose fields are unchecked.
fn shape(keys: &[String]) -> Type {
    let has = |k: &str| keys.iter().any(|x| x == k);
    if has("endpoint") && has("ca") && has("auth") {
        return Type::Named("k8s.Cluster".to_string());
    }
    Type::Record(keys.iter().map(|k| (k.clone(), Type::Any)).collect())
}

/// A cursor over Terraform source, positioned at the next token.
struct Scanner<'a> {
    src: &'a str,
    bytes: &'a [u8],
    at: usize,
    /// The type named by the `# keepshipping:type …` comment most recently
    /// read, kept until a real token says it was for something else.
    annotation: Option<String>,
}

/// One token of Terraform source: an identifier, a quoted string with its
/// quotes and escapes resolved, or a single symbol.
enum Tok {
    Ident(String),
    Str(String),
    Sym(u8),
}

impl<'a> Scanner<'a> {
    fn new(src: &'a str) -> Scanner<'a> {
        Scanner { src, bytes: src.as_bytes(), at: 0, annotation: None }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    /// Skips everything that is not a token: whitespace, comments and
    /// heredoc bodies. A comment naming a type is remembered for the block
    /// that follows it.
    fn junk(&mut self) {
        loop {
            match self.peek() {
                Some(c) if c.is_ascii_whitespace() => self.at += 1,
                Some(b'#') => self.line_comment(),
                Some(b'/') if self.bytes.get(self.at + 1) == Some(&b'/') => self.line_comment(),
                Some(b'/') if self.bytes.get(self.at + 1) == Some(&b'*') => self.block_comment(),
                Some(b'<') if self.opens_heredoc() => self.heredoc(),
                _ => return,
            }
        }
    }

    fn line_comment(&mut self) {
        let start = self.at;
        while self.peek().is_some_and(|c| c != b'\n') {
            self.at += 1;
        }
        // Only a comment that opens its own line names a type: one trailing
        // a value (`a = 1 # keepshipping:type string`) is prose about that
        // value, not an annotation for whatever comes next.
        if !self.starts_its_line(start) {
            return;
        }
        let text = self.src[start + 1..self.at].trim_start_matches('/').trim();
        if let Some(rest) = text.strip_prefix(ANNOTATION) {
            self.annotation = Some(rest.trim().to_string());
        }
    }

    /// Whether only whitespace precedes `at` since the last newline.
    fn starts_its_line(&self, at: usize) -> bool {
        let line = self.src[..at].rfind('\n').map_or(0, |n| n + 1);
        self.src[line..at].chars().all(char::is_whitespace)
    }

    fn block_comment(&mut self) {
        while self.at < self.bytes.len() {
            if self.bytes[self.at..].starts_with(b"*/") {
                self.at += 2;
                return;
            }
            self.at += 1;
        }
    }

    /// The width of the character at `at`, always at least one byte, so a
    /// cursor moves forward over a `char` and a slice never splits one.
    fn width(&self, at: usize) -> usize {
        self.src.get(at..).and_then(|s| s.chars().next()).map_or(1, char::len_utf8)
    }

    /// Whether the `<<` at the cursor opens a heredoc, as HCL spells it: an
    /// identifier, then nothing but spaces to the end of the line. Anything
    /// else is an operator — `x <<y` is an expression, and swallowing the
    /// rest of the file as a body would lose every output after it.
    fn opens_heredoc(&self) -> bool {
        let mut at = self.at + 2;
        if self.bytes.get(at) == Some(&b'-') {
            at += 1;
        }
        let start = at;
        while self.bytes.get(at).is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_') {
            at += 1;
        }
        at > start && self.bytes[at..].iter().all(|c| matches!(c, b' ' | b'\t' | b'\r' | b'\n'))
    }

    /// A `<<EOF` / `<<-EOF` body: skipped to the line that closes it, so a
    /// brace or a quote in the data is not read as structure.
    fn heredoc(&mut self) {
        self.at += 2;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        let start = self.at;
        while self.peek().is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_') {
            self.at += 1;
        }
        let tag = &self.src[start..self.at];
        if tag.is_empty() {
            return; // `<<` that opens nothing: leave it to the caller
        }
        while self.peek().is_some_and(|c| c != b'\n') {
            self.at += 1;
        }
        loop {
            match self.peek() {
                None => {
                    // No closing tag: the body ran to the end of the file.
                    self.at = self.src.len();
                    return;
                }
                Some(b'\n') => self.at += 1,
                Some(_) => {
                    // The end of this line, or of the file if it has none:
                    // either way the cursor moves, so this terminates.
                    let end =
                        self.src[self.at..].find('\n').map_or(self.src.len(), |n| self.at + n);
                    if self.src[self.at..end].trim() == tag {
                        self.at = end;
                        return;
                    }
                    self.at = end;
                }
            }
        }
    }

    fn next_token(&mut self) -> Option<Tok> {
        let c = self.peek()?;
        if c.is_ascii_alphanumeric() || c == b'_' || c == b'-' {
            let start = self.at;
            while self.peek().is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-') {
                self.at += 1;
            }
            return Some(Tok::Ident(self.src[start..self.at].to_string()));
        }
        if c == b'"' {
            return self.string().map(Tok::Str);
        }
        self.at += 1;
        Some(Tok::Sym(c))
    }

    /// A quoted string, without its quotes: `\n` is the character it names,
    /// and `${…}` is read to its closing brace, interpolations and all.
    fn string(&mut self) -> Option<String> {
        self.at += 1;
        let mut out = String::new();
        let mut interp = 0usize;
        loop {
            match self.peek()? {
                b'"' if interp == 0 => {
                    self.at += 1;
                    return Some(out);
                }
                b'\\' => {
                    // An escape names the whole character after it, which
                    // need not be one byte wide.
                    self.at += 1;
                    let start = self.at;
                    self.at += self.width(self.at);
                    if start < self.src.len() {
                        out.push_str(&self.src[start..self.at]);
                    }
                }
                b'$' if self.bytes.get(self.at + 1) == Some(&b'{') => {
                    interp += 1;
                    out.push_str("${");
                    self.at += 2;
                }
                b'}' if interp > 0 => {
                    interp -= 1;
                    out.push('}');
                    self.at += 1;
                }
                b'"' => {
                    // A quote inside an interpolation opens a nested string.
                    let nested = self.string().unwrap_or_default();
                    out.push('"');
                    out.push_str(&nested);
                    out.push('"');
                }
                _ => {
                    let start = self.at;
                    self.at += self.width(self.at);
                    out.push_str(&self.src[start..self.at]);
                }
            }
        }
    }

    /// Every top-level `output` block, with its body.
    fn outputs(mut self) -> Vec<Output> {
        let mut out = Vec::new();
        let mut depth = 0usize;
        loop {
            self.junk();
            let tok = self.next_token();
            match &tok {
                Some(Tok::Ident(id)) if depth == 0 && id == "output" => {
                    if let Some(o) = self.block() {
                        out.push(o);
                    }
                }
                Some(Tok::Sym(b'{')) => depth += 1,
                Some(Tok::Sym(b'}')) => depth = depth.saturating_sub(1),
                // Any token at all closes the run of comment lines above
                // the block: an annotation belongs to what follows it, and
                // a brace ends the block whose lines those were.
                Some(_) => {}
                None => return out,
            }
            self.annotation = None;
        }
    }

    /// The `output "<name>" { … }` block at the cursor: its name and the
    /// text between its braces.
    fn block(&mut self) -> Option<Output> {
        // The comment above the block is taken before the body is walked:
        // reading the body would otherwise mistake one of its own comments
        // for an annotation from above.
        let above = self.annotation.take();
        self.junk();
        let Tok::Str(name) = self.next_token()? else { return None };
        self.junk();
        if !matches!(self.next_token(), Some(Tok::Sym(b'{'))) {
            return None;
        }
        let start = self.at;
        let mut depth = 0usize;
        let end = loop {
            self.junk();
            let at = self.at;
            match self.next_token() {
                Some(Tok::Sym(b'{')) => depth += 1,
                Some(Tok::Sym(b'}')) if depth == 0 => break at,
                Some(Tok::Sym(b'}')) => depth -= 1,
                Some(_) => {}
                None => return None,
            }
        };
        let body = &self.src[start..end];
        let ty = annotation_of(body)
            .or(above)
            .and_then(|t| Type::parse(&t))
            .or_else(|| object_keys(body).map(|k| shape(&k)))
            .unwrap_or(Type::Any);
        Some(Output { name, ty })
    }
}

/// The `# keepshipping:type <T>` comment on a line of `body` itself, when
/// the block carries one inside rather than above. Only the block's own
/// attributes count: a comment inside a nested block is about that block.
fn annotation_of(body: &str) -> Option<String> {
    let mut s = Scanner::new(body);
    let mut depth = 0usize;
    let mut found = None;
    loop {
        s.junk();
        if depth == 0 && s.annotation.is_some() {
            found = s.annotation.clone();
        } else {
            s.annotation = None;
        }
        match s.next_token() {
            Some(Tok::Sym(b'{')) | Some(Tok::Sym(b'[')) => depth += 1,
            Some(Tok::Sym(b'}')) | Some(Tok::Sym(b']')) => depth = depth.saturating_sub(1),
            Some(_) => {}
            None => return found,
        }
        s.annotation = None;
    }
}

/// The top-level keys of the block's own `value = { … }`, when its value is
/// an object literal. A `value` inside a nested block — a `dynamic` or
/// `lifecycle` argument — is not this output's value, and a value that is a
/// reference or a call names no keys this scanner can read.
fn object_keys(body: &str) -> Option<Vec<String>> {
    let mut s = Scanner::new(body);
    let mut depth = 0usize;
    loop {
        s.junk();
        match s.next_token() {
            Some(Tok::Ident(id)) if id == "value" && depth == 0 => {
                s.junk();
                if !matches!(s.next_token(), Some(Tok::Sym(b'='))) {
                    return None;
                }
                s.junk();
                return match s.next_token() {
                    Some(Tok::Sym(b'{')) => Some(s.keys()),
                    _ => None,
                };
            }
            Some(Tok::Sym(b'{')) | Some(Tok::Sym(b'[')) => depth += 1,
            Some(Tok::Sym(b'}')) | Some(Tok::Sym(b']')) => depth = depth.saturating_sub(1),
            Some(_) => {}
            None => return None,
        }
    }
}

impl Scanner<'_> {
    /// The keys of the object literal whose `{` was just read, at its own
    /// depth only — a nested object's keys are values, not this shape.
    fn keys(&mut self) -> Vec<String> {
        let mut keys = Vec::new();
        let mut depth = 0usize;
        // A name is only a key when the token after it is `=`; until then
        // it may just as well be the value of the key before it.
        let mut pending: Option<String> = None;
        loop {
            self.junk();
            let tok = self.next_token();
            if let Some(name) = pending.take()
                && matches!(tok, Some(Tok::Sym(b'=')) | Some(Tok::Sym(b':')))
            {
                keys.push(name);
                continue;
            }
            match tok {
                Some(Tok::Sym(b'{')) | Some(Tok::Sym(b'[')) => {
                    depth += 1;
                    pending = None;
                }
                Some(Tok::Sym(b'}')) | Some(Tok::Sym(b']')) if depth == 0 => return keys,
                Some(Tok::Sym(b'}')) | Some(Tok::Sym(b']')) => depth -= 1,
                Some(Tok::Ident(i)) | Some(Tok::Str(i)) if depth == 0 => pending = Some(i),
                Some(_) => {}
                None => return keys,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ty_of(src: &str) -> Type {
        let outputs = scan(src);
        assert_eq!(outputs.len(), 1, "{outputs:?}");
        outputs.into_iter().next().unwrap().ty
    }

    #[test]
    fn a_cluster_is_known_from_its_shape() {
        let src = "\
resource \"aws_eks_cluster\" \"api\" {}

output \"cluster\" {
  value = {
    endpoint = aws_eks_cluster.api.endpoint
    ca       = aws_eks_cluster.api.certificate_authority[0].data
    auth     = \"eks\"
  }
}
";
        assert_eq!(ty_of(src), Type::Named("k8s.Cluster".to_string()));
    }

    #[test]
    fn an_annotation_names_the_type_above_or_inside_the_block() {
        let above = "# keepshipping:type k8s.Cluster\noutput \"cluster\" { value = 1 }\n";
        assert_eq!(ty_of(above), Type::Named("k8s.Cluster".to_string()));
        let inner = "output \"cluster\" {\n  // keepshipping:type k8s.Namespace\n  value = 1\n}\n";
        assert_eq!(ty_of(inner), Type::Named("k8s.Namespace".to_string()));
    }

    #[test]
    fn an_annotation_beats_the_shape_and_an_unreadable_one_is_ignored() {
        let src = "\
# keepshipping:type map[string]
output \"cluster\" {
  value = { endpoint = \"e\", ca = \"c\", auth = \"eks\" }
}
";
        assert_eq!(ty_of(src), Type::Map(Box::new(Type::String)));
        let typo = "\
# keepshipping:type k8s Cluster
output \"cluster\" {
  value = { endpoint = \"e\", ca = \"c\", auth = \"eks\" }
}
";
        // A comment that does not parse widens to the shape, never fails.
        assert_eq!(ty_of(typo), Type::Named("k8s.Cluster".to_string()));
    }

    #[test]
    fn any_other_object_is_a_record_of_its_own_keys() {
        let src = "output \"db\" {\n  value = {\n    host = \"db\"\n    port = 5432\n  }\n}\n";
        assert_eq!(
            ty_of(src),
            Type::Record(vec![("host".to_string(), Type::Any), ("port".to_string(), Type::Any)])
        );
    }

    #[test]
    fn braces_in_strings_comments_and_heredocs_are_not_structure() {
        let src = r##"
# a } brace and a "quote
/* } too */
variable "policy" {
  default = <<-EOT
    resource "output" "nope" { }
  EOT
}

output "region" {
  value = "${var.prefix}{output \"cluster\" {}"
}
"##;
        assert_eq!(scan(src), vec![Output { name: "region".to_string(), ty: Type::Any }]);
    }

    #[test]
    fn nested_objects_contribute_no_keys_and_blocks_do_not_nest() {
        let src = "\
output \"outer\" {
  value = { top = { inner = 1 }, other = 2 }
}

output \"inner\" {
  value = 3
}
";
        let outputs = scan(src);
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].name, "outer");
        assert_eq!(
            outputs[0].ty,
            Type::Record(vec![("top".to_string(), Type::Any), ("other".to_string(), Type::Any)])
        );
        assert_eq!(outputs[1].ty, Type::Any);
    }

    #[test]
    fn a_shift_operator_is_not_a_heredoc() {
        // `<<` opens a heredoc only when an identifier ends the line; here
        // it is an operator, so the outputs after it are still found.
        let src = "\
output \"left\" {
  value = a <<b
}

output \"right\" {
  value = 1
}
";
        assert_eq!(
            scan(src).iter().map(|o| o.name.as_str()).collect::<Vec<_>>(),
            ["left", "right"]
        );
    }

    #[test]
    fn an_unterminated_heredoc_ends_the_scan() {
        // No closing tag, and no newline at the end of the file: the body
        // runs to the end rather than the cursor standing still.
        assert_eq!(scan("output \"a\" {\n  value = <<EOF\nnever closed"), vec![]);
        // A tag that does close the file, with no trailing newline.
        let src = "output \"a\" {\n  value = <<EOF\n{ e = 1 }\nEOF\n}";
        assert_eq!(scan(src), vec![Output { name: "a".to_string(), ty: Type::Any }]);
    }

    #[test]
    fn an_escape_names_the_whole_character() {
        // A non-ASCII character after a backslash must not be split.
        let src = "output \"a\" {\n  value = { x = \"a\\\u{e4}b\" }\n}\n";
        assert_eq!(scan(src)[0].ty, Type::Record(vec![("x".to_string(), Type::Any)]));
    }

    #[test]
    fn an_annotation_belongs_to_the_block_that_follows_it() {
        // A trailing comment is prose about its own line, and a comment
        // inside another block is not this output's.
        let src = "\
resource \"a\" \"b\" {
  x = 1 # keepshipping:type k8s.Namespace
}

output \"one\" {
  value = 1
}

output \"two\" {
  nested {
    # keepshipping:type map[string]
    x = 1
  }
  value = { host = \"h\" }
}
";
        assert_eq!(scan(src)[0].ty, Type::Any, "one: the trailing comment is not above it");
        assert_eq!(
            scan(src)[1].ty,
            Type::Record(vec![("host".to_string(), Type::Any)]),
            "two: the nested comment does not override the shape"
        );
    }

    #[test]
    fn a_nested_blocks_value_is_not_the_outputs_value() {
        let src = "\
output \"cluster\" {
  dynamic \"endpoint\" {
    for_each = var.x
    content {
      value = { ca = \"c\", auth = \"eks\" }
    }
  }
  value = 3
}
";
        assert_eq!(scan(src)[0].ty, Type::Any);
    }
}
