//! Typed view over the CST: files of entries whose values are expressions.
//!
//! Everything borrows the parse result (tree and source); nothing is copied
//! except the `String`s produced by explicit convenience methods
//! (`Str::value`, `BlockString::text`).

use crate::diagnostic::Span;
use crate::lexer::is_dotted_name;
use crate::syntax::{SyntaxElement, SyntaxKind, SyntaxNode, SyntaxToken};

/// The kinds that make up an expression tree.
const EXPR_KINDS: [SyntaxKind; 10] = [
    SyntaxKind::Default,
    SyntaxKind::Tuple,
    SyntaxKind::OrExpr,
    SyntaxKind::AndExpr,
    SyntaxKind::NotExpr,
    SyntaxKind::Compare,
    SyntaxKind::IsTest,
    SyntaxKind::Union,
    SyntaxKind::Phrase,
    SyntaxKind::Paren,
];

/// A parsed source file: the root of the entry tree.
#[derive(Clone, Copy, Debug)]
pub struct File<'a> {
    src: &'a str,
    node: &'a SyntaxNode,
}

impl<'a> File<'a> {
    pub(crate) fn new(src: &'a str, node: &'a SyntaxNode) -> Self {
        Self { src, node }
    }

    pub fn node(&self) -> &'a SyntaxNode {
        self.node
    }

    /// Top-level entries.
    pub fn entries(&self) -> impl Iterator<Item = Entry<'a>> + 'a {
        self.node.child_nodes_of_kind(SyntaxKind::Entry).map(|n| Entry { src: self.src, node: n })
    }
}

/// One `key: value` line with, possibly, a value expression, a block string
/// and child entries. A step header (`build: oci.image` with indented inputs)
/// is just an entry whose children are the inputs.
#[derive(Clone, Copy, Debug)]
pub struct Entry<'a> {
    src: &'a str,
    node: &'a SyntaxNode,
}

impl<'a> Entry<'a> {
    pub fn node(&self) -> &'a SyntaxNode {
        self.node
    }

    /// The `KEY` token of the entry header.
    pub fn key_token(&self) -> Option<&'a SyntaxToken> {
        self.node.first_token_of_kind(SyntaxKind::Key)
    }

    pub fn key_name(&self) -> Option<&'a str> {
        Some(self.key_token()?.span().slice(self.src))
    }

    pub fn key_span(&self) -> Span {
        self.key_token().map_or_else(Span::default, SyntaxToken::span)
    }

    /// The value node, if the header line (or its continuation lines)
    /// carried a value.
    pub fn value(&self) -> Option<Value<'a>> {
        self.node
            .first_child_node_of_kind(SyntaxKind::Value)
            .map(|n| Value { src: self.src, node: n })
    }

    /// The value as a structured expression, unless it is a block string.
    pub fn expr(&self) -> Option<Expr<'a>> {
        self.value().and_then(|v| v.expr())
    }

    /// The value as a `|` block string.
    pub fn block_string(&self) -> Option<BlockString<'a>> {
        self.value().and_then(|v| v.block_string())
    }

    /// Entries indented below this one.
    pub fn children(&self) -> impl Iterator<Item = Entry<'a>> + 'a {
        self.node.child_nodes_of_kind(SyntaxKind::Entry).map(|n| Entry { src: self.src, node: n })
    }
}

/// The value of an entry: either an expression or a block string.
#[derive(Clone, Copy, Debug)]
pub struct Value<'a> {
    src: &'a str,
    node: &'a SyntaxNode,
}

impl<'a> Value<'a> {
    pub fn node(&self) -> &'a SyntaxNode {
        self.node
    }

    pub fn expr(&self) -> Option<Expr<'a>> {
        let inner = self.node.child_nodes().next()?;
        if inner.kind() == SyntaxKind::BlockString { None } else { expr_of(self.src, inner) }
    }

    pub fn block_string(&self) -> Option<BlockString<'a>> {
        self.node.first_child_node_of_kind(SyntaxKind::BlockString).map(|n| BlockString { node: n })
    }
}

/// A value expression. `replicas: int = 2` is an [`Expr::Default`];
/// `wait: healthy, 5m` a [`Expr::Tuple`]; `auto: risk is low ≥ 0.95 and …`
/// an [`Expr::And`] of an [`Expr::IsTest`] and a [`Expr::Compare`].
#[derive(Clone, Debug)]
pub enum Expr<'a> {
    Default {
        src: &'a str,
        node: &'a SyntaxNode,
        lhs: Box<Expr<'a>>,
        eq: &'a SyntaxToken,
        rhs: Box<Expr<'a>>,
    },
    Tuple {
        src: &'a str,
        node: &'a SyntaxNode,
        items: Vec<Expr<'a>>,
    },
    Or {
        src: &'a str,
        node: &'a SyntaxNode,
        args: Vec<Expr<'a>>,
    },
    And {
        src: &'a str,
        node: &'a SyntaxNode,
        args: Vec<Expr<'a>>,
    },
    Not {
        src: &'a str,
        node: &'a SyntaxNode,
        arg: Box<Expr<'a>>,
    },
    Compare {
        src: &'a str,
        node: &'a SyntaxNode,
        lhs: Box<Expr<'a>>,
        op: CmpOp,
        op_token: &'a SyntaxToken,
        rhs: Option<Box<Expr<'a>>>,
    },
    IsTest {
        src: &'a str,
        node: &'a SyntaxNode,
        subject: Box<Expr<'a>>,
        answer: Box<Expr<'a>>,
        threshold: Option<(CmpOp, &'a SyntaxToken, Box<Expr<'a>>)>,
    },
    Union {
        src: &'a str,
        node: &'a SyntaxNode,
        alts: Vec<Expr<'a>>,
    },
    Phrase {
        src: &'a str,
        node: &'a SyntaxNode,
        atoms: Vec<Atom<'a>>,
    },
    Atom {
        src: &'a str,
        node: &'a SyntaxNode,
        atom: Atom<'a>,
    },
}

impl<'a> Expr<'a> {
    pub fn node(&self) -> &'a SyntaxNode {
        match self {
            Expr::Default { node, .. }
            | Expr::Tuple { node, .. }
            | Expr::Or { node, .. }
            | Expr::And { node, .. }
            | Expr::Not { node, .. }
            | Expr::Compare { node, .. }
            | Expr::IsTest { node, .. }
            | Expr::Union { node, .. }
            | Expr::Phrase { node, .. }
            | Expr::Atom { node, .. } => node,
        }
    }

    pub fn span(&self) -> Span {
        self.node().span()
    }

    /// Every dotted name and interpolation referenced by this expression, in
    /// source order, with spans.
    pub fn refs(&self) -> Vec<NameRef<'a>> {
        let mut out = Vec::new();
        self.collect_refs(&mut out);
        out
    }

    /// The juxtaposed items of a phrase-shaped expression: a [`Expr::Phrase`]'s
    /// atoms, or the one atom of an [`Expr::Atom`] (normalization collapses a
    /// one-atom phrase). Empty for any other shape.
    pub fn atoms(&self) -> &[Atom<'a>] {
        match self {
            Expr::Phrase { atoms, .. } => atoms,
            Expr::Atom { atom, .. } => std::slice::from_ref(atom),
            _ => &[],
        }
    }

    fn collect_refs(&self, out: &mut Vec<NameRef<'a>>) {
        match self {
            Expr::Default { lhs, rhs, .. } => {
                lhs.collect_refs(out);
                rhs.collect_refs(out);
            }
            Expr::Tuple { items, .. } | Expr::Union { alts: items, .. } => {
                for item in items {
                    item.collect_refs(out);
                }
            }
            Expr::Or { args, .. } | Expr::And { args, .. } => {
                for arg in args {
                    arg.collect_refs(out);
                }
            }
            Expr::Not { arg, .. } => arg.collect_refs(out),
            Expr::Compare { lhs, rhs, .. } => {
                lhs.collect_refs(out);
                if let Some(rhs) = rhs {
                    rhs.collect_refs(out);
                }
            }
            Expr::IsTest { subject, answer, threshold, .. } => {
                subject.collect_refs(out);
                answer.collect_refs(out);
                if let Some((_, _, t)) = threshold {
                    t.collect_refs(out);
                }
            }
            Expr::Phrase { atoms, .. } => {
                for atom in atoms {
                    atom.collect_refs(out);
                }
            }
            Expr::Atom { atom, .. } => atom.collect_refs(out),
        }
    }
}

/// A comparison operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Ge,
    Le,
    GeUnicode,
    LeUnicode,
    Lt,
    Gt,
}

impl CmpOp {
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "==" => CmpOp::Eq,
            "!=" => CmpOp::Ne,
            ">=" => CmpOp::Ge,
            "<=" => CmpOp::Le,
            "\u{2265}" => CmpOp::GeUnicode,
            "\u{2264}" => CmpOp::LeUnicode,
            "<" => CmpOp::Lt,
            ">" => CmpOp::Gt,
            _ => return None,
        })
    }

    pub fn symbol(self) -> &'static str {
        match self {
            CmpOp::Eq => "==",
            CmpOp::Ne => "!=",
            CmpOp::Ge => ">=",
            CmpOp::Le => "<=",
            CmpOp::GeUnicode => "\u{2265}",
            CmpOp::LeUnicode => "\u{2264}",
            CmpOp::Lt => "<",
            CmpOp::Gt => ">",
        }
    }
}

/// One juxtaposed item of an [`Expr::Phrase`].
#[derive(Clone, Debug)]
pub enum Atom<'a> {
    Word(Word<'a>),
    Str(Str<'a>),
    /// A `( … )` group. `inner` is absent for `()` (or a group the parser
    /// recovered from); the node always spans `(`..`)`.
    Paren {
        node: &'a SyntaxNode,
        inner: Option<Box<Expr<'a>>>,
    },
}

impl<'a> Atom<'a> {
    pub fn span(&self) -> Span {
        match self {
            Atom::Word(w) => w.node.span(),
            Atom::Str(s) => s.node.span(),
            Atom::Paren { node, .. } => node.span(),
        }
    }

    fn collect_refs(&self, out: &mut Vec<NameRef<'a>>) {
        match self {
            Atom::Word(w) => {
                if w.scalar() == Scalar::DottedName {
                    out.push(NameRef {
                        text: w.text(),
                        span: w.node.span(),
                        kind: NameKind::Dotted,
                    });
                }
                for part in w.parts() {
                    if let WordPart::Interp(i) = part
                        && let Some(name) = i.name()
                    {
                        out.push(NameRef {
                            text: name,
                            span: i.node.span(),
                            kind: NameKind::Interp,
                        });
                    }
                }
            }
            Atom::Str(s) => {
                for part in s.parts() {
                    if let StrPart::Interp(i) = part
                        && let Some(name) = i.name()
                    {
                        out.push(NameRef {
                            text: name,
                            span: i.node.span(),
                            kind: NameKind::Interp,
                        });
                    }
                }
            }
            Atom::Paren { inner: Some(e), .. } => e.collect_refs(out),
            Atom::Paren { inner: None, .. } => {}
        }
    }
}

/// A bare scalar: a word, possibly containing interpolations.
#[derive(Clone, Copy, Debug)]
pub struct Word<'a> {
    pub src: &'a str,
    pub node: &'a SyntaxNode,
}

impl<'a> Word<'a> {
    /// The word's text, interpolations included verbatim as `{name}`.
    pub fn text(&self) -> &'a str {
        self.node.span().slice(self.src)
    }

    pub fn parts(&self) -> Vec<WordPart<'a>> {
        self.node
            .children()
            .iter()
            .filter_map(|c| match c {
                SyntaxElement::Token(t) if t.kind() == SyntaxKind::WordText => {
                    Some(WordPart::Text { text: t.text(), span: t.span() })
                }
                SyntaxElement::Node(n) if n.kind() == SyntaxKind::Interp => {
                    Some(WordPart::Interp(Interp { src: self.src, node: n }))
                }
                _ => None,
            })
            .collect()
    }

    /// Syntactic scalar classification of the word's text.
    pub fn scalar(&self) -> Scalar {
        classify_scalar(self.text())
    }

    /// The dot-separated segments with their spans, if the word is a dotted
    /// name (`build.digest`, `apply.out.cluster`, `api.acme.dev`).
    pub fn segments(&self) -> Option<Vec<(&'a str, Span)>> {
        if self.scalar() != Scalar::DottedName {
            return None;
        }
        let text = self.text();
        let base = self.node.span().start as usize;
        let mut segs = Vec::new();
        let mut off = 0usize;
        for seg in text.split('.') {
            segs.push((seg, Span::new((base + off) as u32, (base + off + seg.len()) as u32)));
            off += seg.len() + 1;
        }
        Some(segs)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum WordPart<'a> {
    Text { text: &'a str, span: Span },
    Interp(Interp<'a>),
}

/// A quoted string, possibly containing interpolations.
#[derive(Clone, Copy, Debug)]
pub struct Str<'a> {
    pub src: &'a str,
    pub node: &'a SyntaxNode,
}

impl<'a> Str<'a> {
    /// The raw text between the quotes, escapes unprocessed.
    pub fn raw(&self) -> &'a str {
        let quotes: Vec<&SyntaxToken> =
            self.node.tokens().filter(|t| t.kind() == SyntaxKind::Quote).collect();
        match (quotes.first(), quotes.last()) {
            (Some(open), Some(close)) if quotes.len() >= 2 => {
                let start = open.span().end as usize;
                let end = close.span().start as usize;
                Span::new(start as u32, end as u32).slice(self.src)
            }
            _ => "",
        }
    }

    /// The string's value: `\"` and `\\` unescaped, interpolations kept as
    /// literal `{name}` text.
    pub fn value(&self) -> String {
        let mut out = String::new();
        for part in self.parts() {
            match part {
                StrPart::Text { text, .. } => {
                    let mut chars = text.chars();
                    while let Some(c) = chars.next() {
                        if c == '\\' {
                            match chars.next() {
                                Some('"') => out.push('"'),
                                Some('\\') => out.push('\\'),
                                Some(other) => {
                                    out.push('\\');
                                    out.push(other);
                                }
                                None => out.push('\\'),
                            }
                        } else {
                            out.push(c);
                        }
                    }
                }
                StrPart::Interp(i) => {
                    out.push('{');
                    if let Some(name) = i.name() {
                        out.push_str(name);
                    }
                    out.push('}');
                }
            }
        }
        out
    }

    pub fn parts(&self) -> Vec<StrPart<'a>> {
        self.node
            .children()
            .iter()
            .filter_map(|c| match c {
                SyntaxElement::Token(t) if t.kind() == SyntaxKind::StringText => {
                    Some(StrPart::Text { text: t.text(), span: t.span() })
                }
                SyntaxElement::Node(n) if n.kind() == SyntaxKind::Interp => {
                    Some(StrPart::Interp(Interp { src: self.src, node: n }))
                }
                _ => None,
            })
            .collect()
    }
}

#[derive(Clone, Copy, Debug)]
pub enum StrPart<'a> {
    Text { text: &'a str, span: Span },
    Interp(Interp<'a>),
}

/// A `{name}` interpolation inside a word or string.
#[derive(Clone, Copy, Debug)]
pub struct Interp<'a> {
    pub src: &'a str,
    pub node: &'a SyntaxNode,
}

impl<'a> Interp<'a> {
    /// The interpolated name without braces, if one is present.
    pub fn name(&self) -> Option<&'a str> {
        let open = self.node.first_token_of_kind(SyntaxKind::LBrace)?;
        let start = open.span().end as usize;
        match self.node.first_token_of_kind(SyntaxKind::RBrace) {
            Some(close) => Some(Span::new(open.span().end, close.span().start).slice(self.src)),
            None => {
                // Unclosed: the raw text token carries the name.
                let t = self
                    .node
                    .tokens()
                    .find(|t| matches!(t.kind(), SyntaxKind::WordText | SyntaxKind::StringText))?;
                let end = t.span().end as usize;
                Some(&self.src[start.min(end)..end])
            }
        }
    }

    /// Span of the name inside the braces (excludes the braces).
    pub fn name_span(&self) -> Option<Span> {
        let open = self.node.first_token_of_kind(SyntaxKind::LBrace)?;
        let end = match self.node.first_token_of_kind(SyntaxKind::RBrace) {
            Some(close) => close.span().start,
            None => self.node.span().end,
        };
        Some(Span::new(open.span().end, end))
    }
}

/// A `|` block string: raw lines kept verbatim, dedented on request.
#[derive(Clone, Copy, Debug)]
pub struct BlockString<'a> {
    pub node: &'a SyntaxNode,
}

impl<'a> BlockString<'a> {
    /// The raw lines, exactly as written (each token includes its
    /// indentation and newline).
    pub fn raw(&self) -> String {
        self.node
            .tokens()
            .filter(|t| t.kind() == SyntaxKind::BlockLine)
            .map(SyntaxToken::text)
            .collect()
    }

    /// The dedented text: the indentation of the first non-blank line is
    /// stripped from every line; blank lines become empty.
    pub fn text(&self) -> String {
        let raw = self.raw();
        let indent = raw
            .lines()
            .find(|l| !l.trim().is_empty())
            .map_or(0, |l| l.len() - l.trim_start_matches(' ').len());
        raw.lines()
            .map(|l| {
                if l.trim().is_empty() {
                    String::new()
                } else {
                    let lead = l.len() - l.trim_start_matches(' ').len();
                    l[indent.min(lead)..].to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Syntactic classification of a bare scalar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scalar {
    Bool,
    Number,
    Duration,
    Handle,
    Path,
    DottedName,
    Ident,
    Str,
    Text,
}

/// Syntactic scalar classification only — whether a [`Scalar::DottedName`]
/// refers to another step is the checker's call, not the parser's.
pub fn classify_scalar(text: &str) -> Scalar {
    if text == "true" || text == "false" {
        return Scalar::Bool;
    }
    if is_number(text) {
        return Scalar::Number;
    }
    if is_duration(text) {
        return Scalar::Duration;
    }
    if let Some(rest) = text.strip_prefix('@') {
        if !rest.is_empty()
            && rest.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_'))
        {
            return Scalar::Handle;
        }
        return Scalar::Text;
    }
    if text == "."
        || text == ".."
        || text.starts_with("./")
        || text.starts_with("../")
        || text.starts_with('/')
        || text.starts_with("~/")
    {
        return Scalar::Path;
    }
    if text.contains('.') && is_dotted_name(text) {
        return Scalar::DottedName;
    }
    if crate::lexer::is_ident(text) {
        return Scalar::Ident;
    }
    Scalar::Text
}

fn is_number(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    match digits.split_once('.') {
        Some((int, frac)) => {
            !int.is_empty() && !frac.is_empty() && is_digits(int) && is_digits(frac)
        }
        None => !digits.is_empty() && is_digits(digits),
    }
}

fn is_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

fn is_duration(text: &str) -> bool {
    if let Some(n) = text.strip_suffix("ms") {
        return is_digits(n);
    }
    match text.char_indices().last() {
        Some((i, 's' | 'm' | 'h' | 'd')) => is_digits(&text[..i]),
        _ => false,
    }
}

/// A name a value refers to: a dotted name written directly, or an
/// interpolation.
#[derive(Clone, Copy, Debug)]
pub struct NameRef<'a> {
    pub text: &'a str,
    pub span: Span,
    pub kind: NameKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameKind {
    /// Written directly (`build.digest`).
    Dotted,
    /// Inside braces (`{git.sha}`).
    Interp,
}

/// Collapse trivial wrappers so the checker sees the real shape, at every
/// level: a one-item tuple is its item, and a one-atom phrase is the atom
/// itself (`show: a, b` has two atoms, `on: pr` is one). Children are
/// already normalized — every expression is built by [`expr_of`], which
/// normalizes what it builds — so one level of collapsing is enough here.
fn normalize(e: Expr<'_>) -> Expr<'_> {
    match e {
        Expr::Tuple { mut items, .. } if items.len() == 1 => items.remove(0),
        Expr::Phrase { src, node, mut atoms } if atoms.len() == 1 => {
            Expr::Atom { src, node, atom: atoms.remove(0) }
        }
        other => other,
    }
}

/// Build the expression view of an expression-shaped node.
fn expr_of<'a>(src: &'a str, node: &'a SyntaxNode) -> Option<Expr<'a>> {
    let expr_children = || {
        node.child_nodes()
            .filter(|n| EXPR_KINDS.contains(&n.kind()))
            .filter_map(|n| expr_of(src, n))
    };
    let e = match node.kind() {
        SyntaxKind::Default => {
            let mut kids = expr_children();
            let lhs = Box::new(kids.next()?);
            let rhs = Box::new(kids.next()?);
            let eq = node.first_token_of_kind(SyntaxKind::Op)?;
            Expr::Default { src, node, lhs, eq, rhs }
        }
        SyntaxKind::Tuple => Expr::Tuple { src, node, items: expr_children().collect() },
        SyntaxKind::OrExpr => Expr::Or { src, node, args: expr_children().collect() },
        SyntaxKind::AndExpr => Expr::And { src, node, args: expr_children().collect() },
        SyntaxKind::NotExpr => {
            let arg = Box::new(expr_children().next()?);
            Expr::Not { src, node, arg }
        }
        SyntaxKind::Compare => {
            let mut kids = expr_children();
            let lhs = Box::new(kids.next()?);
            let op_token = node.first_token_of_kind(SyntaxKind::Op)?;
            let op = CmpOp::parse(op_token.text())?;
            let rhs = kids.next().map(Box::new);
            Expr::Compare { src, node, lhs, op, op_token, rhs }
        }
        SyntaxKind::IsTest => {
            let mut kids = expr_children();
            let subject = Box::new(kids.next()?);
            let answer = Box::new(kids.next()?);
            let threshold = match (kids.next(), node.tokens().find(|t| t.kind() == SyntaxKind::Op))
            {
                (Some(t), Some(op_token)) => {
                    Some((CmpOp::parse(op_token.text())?, op_token, Box::new(t)))
                }
                _ => None,
            };
            Expr::IsTest { src, node, subject, answer, threshold }
        }
        SyntaxKind::Union => Expr::Union { src, node, alts: expr_children().collect() },
        SyntaxKind::Phrase => Expr::Phrase {
            src,
            node,
            atoms: node
                .child_nodes()
                .filter(|n| {
                    matches!(n.kind(), SyntaxKind::Word | SyntaxKind::String | SyntaxKind::Paren)
                })
                .map(|n| atom_of(src, n))
                .collect(),
        },
        SyntaxKind::Paren => {
            let inner = node
                .child_nodes()
                .find(|n| EXPR_KINDS.contains(&n.kind()))
                .and_then(|n| expr_of(src, n))
                .map(Box::new);
            Expr::Atom { src, node, atom: Atom::Paren { node, inner } }
        }
        SyntaxKind::Word => Expr::Atom { src, node, atom: Atom::Word(Word { src, node }) },
        SyntaxKind::String => Expr::Atom { src, node, atom: Atom::Str(Str { src, node }) },
        _ => return None,
    };
    Some(normalize(e))
}

fn atom_of<'a>(src: &'a str, node: &'a SyntaxNode) -> Atom<'a> {
    match node.kind() {
        SyntaxKind::String => Atom::Str(Str { src, node }),
        SyntaxKind::Paren => Atom::Paren {
            node,
            inner: node
                .child_nodes()
                .find(|n| EXPR_KINDS.contains(&n.kind()))
                .and_then(|n| expr_of(src, n))
                .map(Box::new),
        },
        _ => Atom::Word(Word { src, node }),
    }
}
