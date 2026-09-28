//! The Keep Shipping language server: exposes `ks-lang` and the `ks-core`
//! checker to editors. Pure functions only — the LSP transport is a host
//! concern.

#![forbid(unsafe_code)]

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
}
