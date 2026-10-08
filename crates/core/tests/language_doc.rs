//! The examples in `docs/LANGUAGE.md` are extracted and checked against the
//! real parser, so the grammar the reference documents and the grammar
//! `ks-lang` accepts cannot drift apart.
//!
//! Only fenced blocks tagged `ks` are examples of the language. The `ebnf`
//! fences are the grammar written as a grammar, and an untagged fence is not
//! claimed to parse, so neither is read as source.
//!
//! Checking stops at the parser. The checker is not run on these examples: a
//! fence is a fragment more often than it is a whole site file, and one names
//! a block kind (`acme/web-service@v3`) the builtin catalog does not carry,
//! so `check` would rightly complain about a doc that is not wrong. Nor is
//! `fmt` round-trip asserted: the fence at `docs/LANGUAGE.md:430` aligns its
//! step values to a narrower column than `fmt` would pick, so the examples are
//! not all `fmt` fixed points and saying so would be a claim about the
//! formatter, not about the grammar.

/// The language reference, read at compile time. It is the specification this
/// file holds the parser to, so a change to either is caught here.
const DOC: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/LANGUAGE.md"));

/// A fenced example: the line in `docs/LANGUAGE.md` its fence opens on, and
/// the text between the fences.
struct Fence {
    line: usize,
    src: String,
}

/// Every ` ```ks ` block in `docs/LANGUAGE.md`, in the order it appears.
///
/// A fence is anchored to column 0 on both ends. `docs/LANGUAGE.md:155`
/// carries an inline code span holding a literal triple backtick, and a scan
/// that looked for ``` anywhere would open a fence there and swallow the rest
/// of the document. The opening line number comes along so a failure can say
/// which example went stale.
fn ks_fences() -> Vec<Fence> {
    let mut out = Vec::new();
    let mut open: Option<(usize, bool)> = None;
    let mut body = String::new();
    for (n, line) in DOC.lines().enumerate() {
        match open {
            Some((at, ks)) => {
                if line.starts_with("```") {
                    if ks {
                        out.push(Fence { line: at + 1, src: std::mem::take(&mut body) });
                    }
                    body.clear();
                    open = None;
                } else {
                    body.push_str(line);
                    body.push('\n');
                }
            }
            None => {
                if let Some(info) = line.strip_prefix("```") {
                    open = Some((n, info.split_whitespace().next() == Some("ks")));
                }
            }
        }
    }
    assert!(open.is_none(), "docs/LANGUAGE.md has a fence it never closes");
    out
}

#[test]
fn every_documented_example_parses_without_a_diagnostic() {
    for fence in ks_fences() {
        let parse = ks_lang::parse(&fence.src);
        assert!(
            parse.diagnostics().is_empty(),
            "docs/LANGUAGE.md:{} does not parse: {:#?}",
            fence.line,
            parse.diagnostics()
        );
    }
}

#[test]
fn the_reference_still_has_the_examples_this_file_checks() {
    // Six `ks` fences at the time of writing. Deleting them all would leave
    // the test above asserting nothing at all, so the count is checked too:
    // a removed example must be a deliberate edit here, not a silent one.
    assert!(
        ks_fences().len() >= 6,
        "docs/LANGUAGE.md has fewer than 6 `ks` examples; if an example was \
         removed on purpose, lower this count in crates/core/tests/language_doc.rs"
    );
}
