//! The Keep Shipping language: lexer, parser, lossless CST with spans, and a
//! typed AST view.
//!
//! Pure computation: no I/O of any kind, so the crate compiles unchanged for
//! `wasm32-unknown-unknown`.
//!
//! # Example
//!
//! ```
//! let parse = ks_lang::parse("steps:\n  build: oci.image\n    from: ./Dockerfile\n");
//! assert!(parse.diagnostics().is_empty());
//!
//! // The tree is lossless: printing it reproduces the input byte for byte.
//! assert_eq!(parse.syntax().to_string(), "steps:\n  build: oci.image\n    from: ./Dockerfile\n");
//!
//! // The typed view: `build` is an entry whose value names a step kind and
//! // whose children are its inputs.
//! let steps = parse.file().entries().next().expect("entry");
//! let build = steps.children().next().expect("step");
//! assert_eq!(build.key_name(), Some("build"));
//! // `oci.image` is a dotted-name reference the checker can resolve.
//! let kind = build.value().and_then(|v| v.expr()).expect("value");
//! assert_eq!(kind.refs()[0].text, "oci.image");
//! // `./Dockerfile` is a path scalar, not a reference.
//! let from = build.children().next().expect("input");
//! let refs = from.expr().map(|e| e.refs()).unwrap_or_default();
//! assert!(refs.is_empty());
//! ```
//!
//! The grammar is specified in [docs/LANGUAGE.md](../docs/LANGUAGE.md);
//! meaning (which keys exist, what a dotted name refers to) is the checker's
//! job in `ks-core`.

#![forbid(unsafe_code)]

mod ast;
mod diagnostic;
mod lexer;
mod parser;
mod syntax;

pub use ast::{
    Atom, BlockString, CmpOp, Entry, Expr, File, Interp, NameKind, NameRef, Scalar, Str, StrPart,
    Value, Word, WordPart, classify_scalar,
};
pub use diagnostic::{Diagnostic, Severity, Span};
pub use syntax::{SyntaxElement, SyntaxKind, SyntaxNode, SyntaxToken};

/// The result of parsing: a lossless tree, the source it came from, and the
/// diagnostics produced along the way.
///
/// The parser never fails: every input yields a tree that prints back the
/// input exactly, plus diagnostics for whatever it had to recover from.
pub struct Parse {
    src: Box<str>,
    root: SyntaxNode,
    diags: Vec<Diagnostic>,
}

impl Parse {
    /// The source this parse came from.
    pub fn src(&self) -> &str {
        &self.src
    }

    /// The lossless tree. Printing it reproduces the source byte for byte.
    pub fn syntax(&self) -> &SyntaxNode {
        &self.root
    }

    /// The typed view of the tree.
    pub fn file(&self) -> File<'_> {
        File::new(&self.src, &self.root)
    }

    /// Recoveries the parser had to make, in source order.
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diags
    }

    /// A rust-analyzer-style dump of the tree followed by the diagnostics —
    /// the format of the golden snapshots in `tests/fixtures/*.cst`.
    pub fn dump(&self) -> String {
        let mut out = self.root.dump();
        if !self.diags.is_empty() {
            out.push_str("diagnostics:\n");
            for d in &self.diags {
                out.push_str(&d.to_string());
                out.push('\n');
            }
        }
        out
    }
}

/// Parse `src` into a [`Parse`]: lossless tree, typed view and diagnostics.
pub fn parse(src: &str) -> Parse {
    let parser::Parsed { root, mut diags } = parser::parse(src);
    // Recovery can emit out of order (lexer errors surface before parser
    // errors further back in the file); report in source order.
    diags.sort_by_key(|d| (d.span.start, d.span.end));
    Parse { src: src.into(), root, diags }
}
