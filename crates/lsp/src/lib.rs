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
pub use server::{ScriptProvider, serve, serve_stream, serve_stream_with, serve_with};
pub use text::{Encoding, LineIndex, Position, Range};

use ks_lang::Span;

/// A hover answer: the span it covers and the text to show.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hover {
    pub span: Span,
    pub contents: String,
}

/// A replacement of the byte range `start..end` with `new_text` — the shape
/// an LSP `TextEdit` carries. Offsets are byte offsets into the source the
/// same way [`Hover::span`] and the checker use them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TextEdit {
    pub start: u32,
    pub end: u32,
    pub new_text: String,
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

/// Format the whole document: one edit replacing every byte.
///
/// `None` when the file does not parse — an editor must not be handed a
/// rewrite that changes meaning — and when the source is already canonical,
/// so a format-on-save leaves an untouched buffer alone.
pub fn formatting(src: &str) -> Option<TextEdit> {
    let formatted = ks_lang::format(src).ok()?;
    if formatted == src {
        return None;
    }
    Some(TextEdit { start: 0, end: src.len() as u32, new_text: formatted })
}

/// Format the top-level entries between `start` and `end`, both byte offsets.
///
/// The range selects whole entries: an edit covers every top-level entry the
/// selection touches, and never spills into the ones it does not. `None` on a
/// parse error, when the selection touches no entry, and when those entries
/// are already canonical.
pub fn range_formatting(src: &str, start: u32, end: u32) -> Option<TextEdit> {
    let start = (start as usize).min(src.len());
    let end = (end as usize).min(src.len());
    if !src.is_char_boundary(start) || !src.is_char_boundary(end) || start > end {
        return None;
    }
    let (range, new_text) = ks_lang::format_range(src, start..end).ok()??;
    if src.get(range.clone())? == new_text {
        return None;
    }
    Some(TextEdit { start: range.start as u32, end: range.end as u32, new_text })
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

    /// Three top-level entries, formatted the way nobody writes them.
    const MESSY: &str = concat!(
        "name:  api\n",
        "steps:\n",
        "  build:   oci.image\n",
        "    from: ./Dockerfile\n",
        "  deploy:  k8s.rollout\n",
        "    image: build.tag\n",
        "\n",
        "policy:\n",
        "  agents: [read]\n",
    );

    /// What [`MESSY`] formats to: one value column across the whole file's
    /// top-level entries, and one inside `steps`.
    const CANONICAL: &str = concat!(
        "name:   api\n",
        "steps:\n",
        "  build:   oci.image\n",
        "    from:  ./Dockerfile\n",
        "  deploy:  k8s.rollout\n",
        "    image: build.tag\n",
        "\n",
        "policy:\n",
        "  agents:  [read]\n",
    );

    #[test]
    fn formatting_a_messy_file_replaces_all_of_it() {
        let edit = formatting(MESSY).expect("a formatting edit");
        assert_eq!((edit.start, edit.end), (0, MESSY.len() as u32));
        assert_eq!(edit.new_text, CANONICAL);
    }

    #[test]
    fn formatting_a_canonical_file_or_a_broken_one_answers_nothing() {
        assert!(formatting(CANONICAL).is_none(), "already canonical");
        // An unclosed string: `fmt` refuses rather than reformatting around
        // a value it cannot understand.
        assert!(formatting("name: \"never closed\nsteps:\n  build: oci.image\n").is_none());
    }

    /// The range a user selects to cover the whole `steps:` entry of
    /// [`MESSY`], and the edit it produces. Every range test starts here.
    fn over_steps() -> (usize, TextEdit) {
        let from = MESSY.find("steps:").expect("the steps entry");
        let to = MESSY.find("policy:").expect("the policy entry");
        let edit = range_formatting(MESSY, from as u32, to as u32).expect("an edit");
        (from, edit)
    }

    #[test]
    fn range_formatting_covers_exactly_the_entries_it_touches() {
        let (from, edit) = over_steps();
        // The entry and nothing else: `name:` before it is untouched, and the
        // edit ends where `policy:` begins.
        assert_eq!(edit.start as usize, from);
        assert_eq!(
            MESSY[edit.start as usize..edit.end as usize].trim_end(),
            "steps:\n  build:   oci.image\n    from: ./Dockerfile\n  deploy:  k8s.rollout\n    image: build.tag"
        );
        assert_eq!(
            edit.new_text,
            "steps:\n  build:   oci.image\n    from:  ./Dockerfile\n  deploy:  k8s.rollout\n    image: build.tag\n\n"
        );
    }

    #[test]
    fn range_formatting_leaves_the_rest_of_the_file_alone() {
        let (_, edit) = over_steps();
        // Applying the edit to the untouched source does not make the whole
        // file canonical — `name:` still wants the root column it only gets
        // once every step has been measured. The edit itself is a fixed point;
        // what matters here is that the bytes it does not replace are left
        // exactly as they were.
        assert!(MESSY[..edit.start as usize].starts_with("name:  api\n"), "the head moved");
        assert!(MESSY[edit.end as usize..].starts_with("policy:"), "the tail moved");
    }

    #[test]
    fn range_formatting_answers_nothing_when_there_is_nothing_to_do() {
        // A file that is already canonical has nothing to edit, whatever
        // the range selects.
        let name = CANONICAL.find("name:").expect("the name entry");
        assert!(
            range_formatting(CANONICAL, name as u32, name as u32 + 4).is_none(),
            "already canonical"
        );

        // A parse error answers nothing, whatever the range.
        assert!(range_formatting("name: \"unclosed\nsteps:\n  a: b\n", 0, 5).is_none());

        // Offsets past the end are clamped to the end of the source rather
        // than panicking; the empty range that leaves touches no entry, so the
        // answer is nothing rather than a guess at the last one.
        let long = MESSY.len() as u32 + 100;
        assert!(range_formatting(MESSY, long, long).is_none(), "clamped to an empty range at EOF");

        // An offset that is not a character boundary is refused outright, not
        // rounded into a range that would split a multi-byte value.
        let wide = "name: \"π\"\nsteps:\n  a:   b\n";
        assert!(range_formatting(wide, 7, 8).is_none(), "inside the two-byte value");
    }
}
