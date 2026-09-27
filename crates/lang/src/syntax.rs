//! Syntax kinds and the lossless concrete syntax tree (CST).
//!
//! Every byte of the input lives in exactly one token — whitespace,
//! indentation, newlines, comments and error tokens included — so printing a
//! tree always reproduces its source exactly.

use std::fmt;
use std::fmt::Write as _;

use crate::diagnostic::Span;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SyntaxKind {
    // Trivia.
    Whitespace,
    Indent,
    Newline,
    Comment,
    // Punctuation and words.
    Key,
    Colon,
    Comma,
    Pipe,
    Op,
    Keyword,
    Quote,
    StringText,
    WordText,
    LBrace,
    RBrace,
    LParen,
    RParen,
    BlockLine,
    // Nodes.
    File,
    Entry,
    Value,
    BlockString,
    Word,
    String,
    Interp,
    Default,
    Tuple,
    OrExpr,
    AndExpr,
    NotExpr,
    Compare,
    IsTest,
    Union,
    Phrase,
    Paren,
}

impl SyntaxKind {
    pub fn name(self) -> &'static str {
        match self {
            SyntaxKind::Whitespace => "WHITESPACE",
            SyntaxKind::Indent => "INDENT",
            SyntaxKind::Newline => "NEWLINE",
            SyntaxKind::Comment => "COMMENT",
            SyntaxKind::Key => "KEY",
            SyntaxKind::Colon => "COLON",
            SyntaxKind::Comma => "COMMA",
            SyntaxKind::Pipe => "PIPE",
            SyntaxKind::Op => "OP",
            SyntaxKind::Keyword => "KEYWORD",
            SyntaxKind::Quote => "QUOTE",
            SyntaxKind::StringText => "STRING_TEXT",
            SyntaxKind::WordText => "WORD_TEXT",
            SyntaxKind::LBrace => "LBRACE",
            SyntaxKind::RBrace => "RBRACE",
            SyntaxKind::LParen => "LPAREN",
            SyntaxKind::RParen => "RPAREN",
            SyntaxKind::BlockLine => "BLOCK_LINE",
            SyntaxKind::File => "FILE",
            SyntaxKind::Entry => "ENTRY",
            SyntaxKind::Value => "VALUE",
            SyntaxKind::BlockString => "BLOCK_STRING",
            SyntaxKind::Word => "WORD",
            SyntaxKind::String => "STRING",
            SyntaxKind::Interp => "INTERP",
            SyntaxKind::Default => "DEFAULT",
            SyntaxKind::Tuple => "TUPLE",
            SyntaxKind::OrExpr => "OR_EXPR",
            SyntaxKind::AndExpr => "AND_EXPR",
            SyntaxKind::NotExpr => "NOT_EXPR",
            SyntaxKind::Compare => "COMPARE",
            SyntaxKind::IsTest => "IS_TEST",
            SyntaxKind::Union => "UNION",
            SyntaxKind::Phrase => "PHRASE",
            SyntaxKind::Paren => "PAREN",
        }
    }

    pub fn is_trivia(self) -> bool {
        matches!(
            self,
            SyntaxKind::Whitespace | SyntaxKind::Indent | SyntaxKind::Newline | SyntaxKind::Comment
        )
    }
}

impl fmt::Display for SyntaxKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A leaf of the tree: one contiguous byte range of the source, carrying its
/// own text.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SyntaxToken {
    kind: SyntaxKind,
    span: Span,
    text: Box<str>,
}

impl SyntaxToken {
    pub(crate) fn new(kind: SyntaxKind, span: Span, text: Box<str>) -> Self {
        Self { kind, span, text }
    }

    pub fn kind(&self) -> SyntaxKind {
        self.kind
    }

    pub fn span(&self) -> Span {
        self.span
    }

    pub fn text(&self) -> &str {
        &self.text
    }
}

/// An interior node: a kind plus its children in source order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntaxNode {
    kind: SyntaxKind,
    span: Span,
    children: Vec<SyntaxElement>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyntaxElement {
    Node(SyntaxNode),
    Token(SyntaxToken),
}

impl SyntaxNode {
    pub(crate) fn new(kind: SyntaxKind, children: Vec<SyntaxElement>) -> Self {
        let span = match (children.first(), children.last()) {
            (Some(first), Some(last)) => Span::new(first.span().start, last.span().end),
            _ => Span::default(),
        };
        Self { kind, span, children }
    }

    /// The node's kind.
    pub fn kind(&self) -> SyntaxKind {
        self.kind
    }

    pub fn span(&self) -> Span {
        self.span
    }

    pub fn children(&self) -> &[SyntaxElement] {
        &self.children
    }

    pub fn child_nodes(&self) -> impl Iterator<Item = &SyntaxNode> + '_ {
        self.children.iter().filter_map(SyntaxElement::as_node)
    }

    pub fn tokens(&self) -> impl Iterator<Item = &SyntaxToken> + '_ {
        self.children.iter().filter_map(SyntaxElement::as_token)
    }

    /// All nodes of exactly this kind among the direct children.
    pub fn child_nodes_of_kind(&self, kind: SyntaxKind) -> impl Iterator<Item = &SyntaxNode> + '_ {
        self.children.iter().filter_map(SyntaxElement::as_node).filter(move |n| n.kind == kind)
    }

    /// The first direct child node whose kind is in `kinds`.
    pub fn first_child_node_of_kind(&self, kind: SyntaxKind) -> Option<&SyntaxNode> {
        self.children.iter().find(|c| c.kind() == kind).and_then(SyntaxElement::as_node)
    }

    /// The first token with the given kind among the direct children.
    pub fn first_token_of_kind(&self, kind: SyntaxKind) -> Option<&SyntaxToken> {
        self.children.iter().find(|c| c.kind() == kind).and_then(SyntaxElement::as_token)
    }

    /// Concatenated text of all descendant tokens in order.
    pub fn text(&self) -> String {
        let mut out = String::with_capacity(self.span.len() as usize);
        self.write_text(&mut out);
        out
    }

    fn write_text(&self, out: &mut String) {
        for child in &self.children {
            match child {
                SyntaxElement::Token(t) => out.push_str(&t.text),
                SyntaxElement::Node(n) => n.write_text(out),
            }
        }
    }

    /// A rust-analyzer-style dump: `KIND@start..end` per node, tokens with
    /// their quoted text, two spaces of nesting per level.
    pub fn dump(&self) -> String {
        let mut out = String::new();
        self.write_dump(&mut out, 0);
        out
    }

    fn write_dump(&self, out: &mut String, depth: usize) {
        for _ in 0..depth {
            out.push_str("  ");
        }
        let _ = writeln!(out, "{}@{}", self.kind.name(), self.span);
        for child in &self.children {
            match child {
                SyntaxElement::Node(n) => n.write_dump(out, depth + 1),
                SyntaxElement::Token(t) => {
                    for _ in 0..depth + 1 {
                        out.push_str("  ");
                    }
                    let _ = writeln!(out, "{}@{} {:?}", t.kind.name(), t.span, t.text);
                }
            }
        }
    }
}

impl SyntaxElement {
    pub fn kind(&self) -> SyntaxKind {
        match self {
            SyntaxElement::Node(n) => n.kind,
            SyntaxElement::Token(t) => t.kind,
        }
    }

    pub fn span(&self) -> Span {
        match self {
            SyntaxElement::Node(n) => n.span,
            SyntaxElement::Token(t) => t.span,
        }
    }

    pub fn as_node(&self) -> Option<&SyntaxNode> {
        match self {
            SyntaxElement::Node(n) => Some(n),
            SyntaxElement::Token(_) => None,
        }
    }

    pub fn as_token(&self) -> Option<&SyntaxToken> {
        match self {
            SyntaxElement::Node(_) => None,
            SyntaxElement::Token(t) => Some(t),
        }
    }
}

impl fmt::Display for SyntaxToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl fmt::Display for SyntaxElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyntaxElement::Node(n) => fmt::Display::fmt(n, f),
            SyntaxElement::Token(t) => fmt::Display::fmt(t, f),
        }
    }
}

impl fmt::Display for SyntaxNode {
    /// Printing the tree reproduces the source byte for byte.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for child in &self.children {
            fmt::Display::fmt(child, f)?;
        }
        Ok(())
    }
}
