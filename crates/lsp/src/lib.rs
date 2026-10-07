//! The Keep Shipping language server: what `keepshipping lsp` speaks, and
//! the checker behind every answer.
//!
//! The transport ([`server`]) is the only part that does I/O, over stdio
//! with hand-rolled JSON-RPC framing ([`rpc`]). Everything else — the
//! features ([`analysis`]), the byte-offset/LSP-position arithmetic and the
//! prose on hover — is a pure function of a document, so it can be tested
//! without a client.

#![forbid(unsafe_code)]

pub mod analysis;
mod docs;
pub mod rpc;
pub mod server;
mod text;

pub use analysis::{Doc, SOURCE};
pub use server::{serve, serve_stream};
pub use text::{Encoding, LineIndex, Position, Range};

use ks_lang::Span;

/// A hover answer: the span it covers and the text to show.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hover {
    pub span: Span,
    pub contents: String,
}

/// The hover for the expression at byte `offset`, or `None` when the
/// checker typed nothing there: `build.digest: oci.Digest`.
pub fn hover(src: &str, offset: u32) -> Option<Hover> {
    if !src.is_char_boundary((offset as usize).min(src.len())) {
        return None;
    }
    let checked = ks_core::check(&ks_lang::parse(src));
    let (span, ty) = checked.type_at(offset)?;
    Some(Hover { span, contents: format!("{}: {ty}", span.slice(src)) })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEPLOY: &str = "\
steps:
  build: oci.image
    from: ./Dockerfile
    sign: true
  deploy: k8s.rollout
    image: build.digest
";

    #[test]
    fn hovering_a_reference_names_its_nominal_type() {
        let at = DEPLOY.find("build.digest").expect("the reference") + 3;
        let hover = hover(DEPLOY, at as u32).expect("a hover");
        assert_eq!(hover.contents, "build.digest: oci.Digest");
        assert_eq!(hover.span.slice(DEPLOY), "build.digest");
    }

    #[test]
    fn hovering_a_literal_names_its_primitive_type() {
        let path = DEPLOY.find("./Dockerfile").expect("the path") as u32 + 1;
        assert_eq!(hover(DEPLOY, path).expect("a hover").contents, "./Dockerfile: path");

        let flag = DEPLOY.find("true").expect("the flag") as u32;
        assert_eq!(hover(DEPLOY, flag).expect("a hover").contents, "true: bool");
    }

    #[test]
    fn hovering_where_nothing_is_typed_answers_nothing() {
        assert!(hover(DEPLOY, 0).is_none(), "`steps:` names no type");
        assert!(hover(DEPLOY, DEPLOY.len() as u32 + 10).is_none(), "past the end");
    }

    #[test]
    fn the_document_hover_adds_what_the_plain_hover_leaves_out() {
        let at = (DEPLOY.find("build.digest").expect("the reference") + 3) as u32;
        let doc = Doc::new(DEPLOY.to_string(), Encoding::Utf16);
        let hover = analysis::hover(&doc, at).expect("a hover");
        let text = hover["contents"]["value"].as_str().expect("markdown");
        assert!(text.contains("build.digest: oci.Digest"), "{text}");
        assert!(text.contains("container image"), "{text}");
    }
}
