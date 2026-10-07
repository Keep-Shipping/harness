//! The formatter: that its output is canonical, and that getting there never
//! changes what the file means.
//!
//! Three promises carry most of the weight here. The site examples format to
//! themselves, so the syntax the docs display is the syntax `fmt` produces.
//! Formatting is idempotent, so running it twice is the same as running it
//! once. And the token stream survives it — same tokens in the same order,
//! with every comment still in the step it was written in.

use std::ops::Range;

use ks_lang::{Severity, SyntaxElement, SyntaxKind, SyntaxNode};

/// The examples the site shows, including the CLI's copy of the hero file.
/// ADR 0003 makes these golden: `fmt` must reproduce them byte for byte.
///
/// `site-decide` is not here: it is the one example written with a Unicode
/// operator, so it is asserted on its own in
/// `site_decide_is_a_fixed_point_modulo_operator_aliases`.
const SITE: &[(&str, &str)] = &[
    ("site-hero", include_str!("fixtures/site-hero.ks")),
    ("site-block", include_str!("fixtures/site-block.ks")),
    ("site-policy", include_str!("fixtures/site-policy.ks")),
    ("site/ship", include_str!("../../cli/tests/fixtures/site/ship.ks")),
];

/// Every `.ks` file in the parser's fixture corpus, read at test time so a new
/// fixture is covered the day it lands.
#[expect(
    clippy::disallowed_methods,
    reason = "reading the corpus is test-only; the library itself stays I/O-free"
)]
fn fixtures() -> Vec<(String, String)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut out: Vec<(String, String)> = std::fs::read_dir(dir)
        .expect("fixture directory")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "ks"))
        .map(|p| {
            let name = p.display().to_string();
            (name, std::fs::read_to_string(&p).expect("readable fixture"))
        })
        .collect();
    out.sort();
    out
}

/// Assert `src` formats to exactly `want`.
fn is(src: &str, want: &str) {
    assert_eq!(ks_lang::format(src).as_deref(), Ok(want), "formatting {src:?}");
}

/// Legal but ugly: the whole point of running `fmt`. Every one of these parses
/// without an error and formats; the ones `fmt` turns down have their own test.
const MESSY: &[&str] = &[
    "",
    "\n",
    "\n\n\n",
    "a: 1\n\n\n\n",
    "# only a comment\n",
    "a:   1\n",
    "a: 1   \n",
    "a:\n  b:\n    c:\n      d: 1\n",
    "a: 1\nb: 2\nc: 3\n",
    "name: api\non: push main\nsteps:\n  build: oci.image\n    from: ./Dockerfile\n",
    "    deep: 1\n        deeper: 2\n",
    "\ta: 1\n",
    "a:\tb\n",
    "a: risk is low ≥ 0.95 and plan.destroys == 0\n",
    "a: x ≤ y\n",
    "a: \"… ≥ ≤ 😀\"\n",
    "a: 1 # trailing\n",
    "a: 1# glued\n",
    "a: 1\n\n# between\n\nb: 2\n",
    "steps:\n  build:\n    from: a\n\n  plan:\n    dir: b\n",
    "steps:\n  build: a\n\n\n\n  plan: b\n",
    "a: |\n  text\nb: 1\n",
    "a: |\n\n  first\n\n    indented\n\n  last\nb: 1\n",
    "a: | # trailing\n   keep   this\nb: 1\n",
    "a: |\n",
    "a: |\n  x",
    "replicas: int = 2\n",
    "a: 1\r\nb: 2\r\n",
    "  risk: decide\n    model: typesafe/jev\n",
    // A ragged run of trailing comments, and the three things that end one.
    "a: 1 # x\nb: 2        # y\nc: 3  # z\n",
    "a: 1 # x\nb: 2        # y\n\nc: 3  # z\n",
    "a: 1 # x\nb: 2        # y\n# full line\nc: 3  # z\n",
    "a: 1 # x\nb: 2\nc: 3  # z\n",
    // Found by the fuzz target: a `#` with nothing after the colon is the word
    // `#`, and it stops being one the moment a space is put in front of it.
    "a:#",
    "a:#c",
    "a:\n  b:#\n",
    // A comment on a line of its own, indented inside the block above it.
    "a: 1\n  # c\n",
    "a: 1\n    # deep\nb: 2\n",
    // Found by the fuzz target: a bare `\r` is folded into the comment token,
    // while `\r\n` is a newline of its own.
    "#\r",
    "#\r\r",
    "a: 1 #c\r",
];

/// Inputs the formatter turns down. Two of these parse without any diagnostic
/// at all — the parser leaves a stray `KEY`/`WORD_TEXT` loose at file level when
/// a dedent lands after an indented entry — so `fmt` has to notice the
/// unplaceable token itself rather than trusting the diagnostic list alone.
const REFUSED: &[&str] = &[
    "a:1\n",
    "a: 1\n   b: 2\n c: 3\n",
    " a: 1\nb: 2\n",
    "  a: 1\nb: 2\n",
    "\t\ta: 1\n\tb: 2\n",
    "# before\n a: 1\n# between\nb: 2\n",
];

/// The significant tokens of a parse: trivia dropped and aliases canonicalised,
/// so two spellings of the same file compare equal.
///
/// Comments are trivia but not nothing, so they are compared too — a comment
/// that changed text or order has moved. A comment's trailing `\r` is a line
/// ending the lexer folded into the token, so it is not part of the text.
///
/// A block line's text carries its indentation and its newline, and the
/// indentation is the formatter's to re-base, so only the rest is compared,
/// trailing spaces included: the block's text is the author's.
fn significant(src: &str) -> Vec<(SyntaxKind, String)> {
    fn walk(node: &SyntaxNode, out: &mut Vec<(SyntaxKind, String)>) {
        for el in node.children() {
            match el {
                SyntaxElement::Node(n) => walk(n, out),
                SyntaxElement::Token(t) => {
                    let kind = t.kind();
                    let text = match kind {
                        SyntaxKind::Comment => t.text().trim_end_matches('\r').to_string(),
                        SyntaxKind::BlockLine => t
                            .text()
                            .trim_start_matches([' ', '\t'])
                            .trim_end_matches(['\n', '\r'])
                            .to_string(),
                        _ if kind.is_trivia() => continue,
                        _ => match t.text() {
                            "\u{2265}" => ">=".to_string(),
                            "\u{2264}" => "<=".to_string(),
                            other => other.to_string(),
                        },
                    };
                    out.push((kind, text));
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(ks_lang::parse(src).syntax(), &mut out);
    out
}

/// Every comment in the file, paired with the top-level entry containing it.
/// A comment before the first entry belongs to no step (`usize::MAX`).
fn comment_steps(src: &str) -> Vec<(usize, String)> {
    fn walk(node: &SyntaxNode, steps: &[&SyntaxNode], out: &mut Vec<(usize, String)>) {
        for el in node.children() {
            match el {
                SyntaxElement::Node(n) => walk(n, steps, out),
                SyntaxElement::Token(t) if t.kind() == SyntaxKind::Comment => {
                    let owner = steps
                        .iter()
                        .position(|s| s.span().contains(t.span().start))
                        .unwrap_or(usize::MAX);
                    // A trailing `\r` is a line ending the lexer folded into
                    // the token, not part of what the author wrote.
                    out.push((owner, t.text().trim_end_matches('\r').to_string()));
                }
                SyntaxElement::Token(_) => {}
            }
        }
    }
    let parse = ks_lang::parse(src);
    let file = parse.syntax();
    let steps: Vec<&SyntaxNode> = file.child_nodes_of_kind(SyntaxKind::Entry).collect();
    let mut out = Vec::new();
    walk(file, &steps, &mut out);
    out
}

/// The invariant every input in this file has to satisfy: formatting stays
/// inside the grammar, keeps every token, and keeps every comment in its step.
fn assert_meaning_preserved(src: &str) {
    let out = ks_lang::format(src).expect("formats");
    let reparsed = ks_lang::parse(&out);
    assert!(
        reparsed.diagnostics().iter().all(|d| d.severity != Severity::Error),
        "formatting {src:?} produced a file that does not parse: {:?}\n{out}",
        reparsed.diagnostics()
    );
    assert_eq!(
        significant(src),
        significant(&out),
        "tokens changed while formatting {src:?}\ngot:\n{out}"
    );
    assert_eq!(
        comment_steps(src),
        comment_steps(&out),
        "a comment changed step while formatting {src:?}\ngot:\n{out}"
    );
}

/// Assert `fmt(fmt(x)) == fmt(x)`.
fn assert_idempotent(src: &str) {
    let once = ks_lang::format(src).unwrap_or_else(|e| panic!("{src:?} refused: {e}"));
    let twice =
        ks_lang::format(&once).unwrap_or_else(|e| panic!("{src:?} refused on reformat: {e}"));
    assert_eq!(once, twice, "fmt(fmt(x)) != fmt(x) for {src:?}");
}

/// Assert `fmt(fmt(x)) == fmt(x)` and the meaning invariants, for everything a
/// test has to hand.
fn check(src: &str) {
    assert_idempotent(src);
    assert_meaning_preserved(src);
}

/// Every byte-boundary prefix of a fixture that formats. A prefix can stop
/// mid-token and be unformattable; those are the parser's to complain about,
/// and they are covered by `a_file_with_parse_errors_is_refused`.
fn prefixes(src: &str) -> impl Iterator<Item = &str> {
    (0..=src.len()).filter(move |&cut| src.is_char_boundary(cut)).map(move |cut| &src[..cut])
}

/// Every prefix of every fixture that formats, checked the same way.
fn check_prefixes() {
    for (_, src) in fixtures() {
        for prefix in prefixes(&src) {
            if ks_lang::format(prefix).is_ok() {
                check(prefix);
            }
        }
    }
}

#[test]
fn site_examples_are_fixed_points() {
    for (name, src) in SITE {
        assert_eq!(
            ks_lang::format(src).as_deref(),
            Ok(*src),
            "the site example {name} is not a fixed point of fmt"
        );
    }
}

/// The `decide` step is the one example the site shows with a Unicode
/// operator, so its canonical form is stated rather than assumed: `≥` becomes
/// its canonical `>=`, and the top-level column is set by `review:`, the widest
/// key in that block. It is a fragment indented for a surrounding block, which
/// is why it keeps its base indent.
#[test]
fn site_decide_is_a_fixed_point_modulo_operator_aliases() {
    let src = include_str!("fixtures/site-decide.ks");
    is(
        src,
        "  risk:   decide\n    model:   typesafe/jev\n    ask:     \"How risky is this plan?\"
    input:   plan.changes\n    returns: low | medium | high\n\n  review: approval\n    auto:    risk is low >= 0.95\n             and plan.destroys == 0\n    else:    ask @platform, show risk.reason\n",
    );
    check(src);
}

/// The property the rest of the file leans on, run over the whole corpus.
#[test]
fn formatting_is_stable_over_the_whole_corpus() {
    for (_, src) in fixtures() {
        assert_idempotent(&src);
        assert_meaning_preserved(&src);
    }
}

#[test]
fn formatting_is_stable_over_messy_input() {
    for src in MESSY {
        check(src);
    }
}

/// Every byte-boundary prefix of every fixture, which covers files cut off
/// mid-entry, mid block string and mid comment.
#[test]
fn formatting_is_stable_over_every_prefix_of_a_fixture() {
    check_prefixes();
}

#[test]
fn values_line_up_in_one_column() {
    // The column is set by the widest key in the block, not by the line it
    // happens to sit on.
    is("name: api\non: push main\n", "name: api\non:   push main\n");
    is("steps:\n  build: a\n    longer_key: b\n", "steps:\n  build:        a\n    longer_key: b\n");
    // A key with no value still sets the column for the entries around it.
    is("block: x\ninputs:\n  image: y\n", "block:  x\ninputs:\n  image: y\n");
    // Every level below the top shares one column, so a nested key wider than
    // its step moves the whole block across.
    is("steps:\n  build: a\n    from: b\n", "steps:\n  build:  a\n    from: b\n");
}

#[test]
fn indentation_is_two_spaces_per_level() {
    is("a:\n    b:\n        c: 1\n", "a:\n  b:\n    c: 1\n");
    is("a:\n  b:\n    c: 1\n", "a:\n  b:\n    c: 1\n");
    // A fragment indented for a surrounding block keeps its base indent.
    is("  a: 1\n    b: 2\n", "  a: 1\n    b: 2\n");
}

#[test]
fn blank_lines_collapse_to_one_and_never_lead_or_trail() {
    is("\n\n\na: 1\n\n\n\nb: 2\n\n\n", "a: 1\n\nb: 2\n");
    is("a: 1\n\n\n\nb: 2\n", "a: 1\n\nb: 2\n");
    is("", "");
    is("a: 1", "a: 1\n");
}

#[test]
fn full_line_comments_keep_their_place() {
    is("# one\n\na: 1\n\n# two\n\nb: 2\n", "# one\n\na: 1\n\n# two\n\nb: 2\n");
    is("a: 1\n# tail\n", "a: 1\n# tail\n");
    is("# lead\na: 1\n", "# lead\na: 1\n");
    // An indented one stays indented: dedenting it out of its block is a
    // different file, and one the parser rejects.
    is("a: 1\n  # c\n", "a: 1\n  # c\n");
    is("a: 1\n    # deep\nb: 2\n", "a: 1\n    # deep\nb: 2\n");
}

/// `fmt` may only ever put back the whitespace the author wrote, because the
/// space it would add is not always the same token. Found by the fuzz target.
#[test]
fn a_value_glued_to_its_colon_stays_glued() {
    // `#` here is a word, and `a: #` would be a comment on a key with no
    // value — a file the parser rejects.
    is("a:#", "a:#\n");
    is("a:#c", "a:#c\n");
    is("a:\n  b:#\n", "a:\n  b:#\n");
    // Everything else is still aligned as usual.
    is("a: 1 #c\n", "a: 1 #c\n");
    is("name: api\non:   push main\n", "name: api\non:   push main\n");
}

/// A comment on a line of its own is never aligned with anything: there is no
/// run for it to belong to.
#[test]
fn a_lone_trailing_comment_keeps_its_gap() {
    is("a: 1 #c\n", "a: 1 #c\n");
    is("a: 1    #c\n", "a: 1    #c\n");
    // `#` with no space before it is word text, so there is no comment to move.
    is("a: 1#c\n", "a: 1#c\n");
    // A comment on the `|` line of a block string keeps its single space.
    is("a: | # why\n  x\n", "a: | # why\n  x\n");
}

/// gofmt's rule, applied per run: no comment moves left, and a run of ragged
/// comments comes out in one column.
#[test]
fn trailing_comments_in_a_run_line_up_in_one_column() {
    // The second comment sets the column and the first moves right to meet it.
    is("a: 1 # one\nb: 2      # two\n", "a: 1      # one\nb: 2      # two\n");
    // A run spans every line between its ends, top level or not.
    is(
        "steps:\n  a: 1 # one\n  b: 2        # two\n",
        "steps:\n  a: 1        # one\n  b: 2        # two\n",
    );
    // A blank line, a full-line comment, or a line of code with no comment
    // each end the run, so the two comments are left alone.
    is("a: 1 # one\n\nb: 2      # two\n", "a: 1 # one\n\nb: 2      # two\n");
    is("a: 1 # one\n# full\nb: 2      # two\n", "a: 1 # one\n# full\nb: 2      # two\n");
    is("a: 1 # one\nb: 2\nc: 3   # three\n", "a: 1 # one\nb: 2\nc: 3   # three\n");
    // A wide first line sets the column, and a later comment never moves left.
    is("a: 1      # one\nb: 2 # two\n", "a: 1      # one\nb: 2      # two\n");
}

/// A comment trailing a key with no value stays on that key's line. On a line
/// of its own it reads as a comment about the step above it, and the pairing
/// `format_range` relies on no longer matches. Found by the fuzz target.
#[test]
fn a_comment_on_a_key_with_no_value_stays_on_its_line() {
    is("review:  # why\n  else:    ask\n", "review:  # why\n  else: ask\n");
    is("review:  # why\n  else: ask\n", "review:  # why\n  else: ask\n");
    // Nested in a block, the comment still belongs to its own key's line.
    is(
        "steps:\n  build: 1\n  review:  # x\n    else: ask\n",
        "steps:\n  build:  1\n  review:  # x\n    else: ask\n",
    );
}

/// A full-line comment keeps its indentation whether the parser hung it off
/// the step above it or let the step's own value swallow it — the two spellings
/// of the same file have to format to the same thing. Found by the fuzz target.
#[test]
fn an_indented_full_line_comment_keeps_its_indent_at_the_end_of_a_file() {
    is("k: m\n\n #\n", "k: m\n\n #\n");
    is("k: m\n\n #", "k: m\n\n #\n");
    // The trailing newline the formatter writes puts the comment inside the
    // value node rather than after it, which must not change the output.
    is("a: 1\n  # c\n\n  # d\n", "a: 1\n  # c\n\n  # d\n");
}

/// A comment runs to the end of its line but does not end the value it sits
/// in: whatever follows it is a continuation line, and dropping it would lose
/// tokens. `fmt` refuses rather than return a file it changed the meaning of.
#[test]
fn a_comment_inside_a_value_keeps_the_rest_of_the_value() {
    is("a: 1 # c\n  2\n", "a: 1 # c\n   2\n");
    // A comment on a line of its own, and more than one of them.
    is("a: 1\n  # c\n  2\n", "a: 1\n  # c\n   2\n");
    is("a: 1 # c\n\n  # d\n  2\n", "a: 1 # c\n\n  # d\n   2\n");
    // Mid-expression, where the comment sits between the comma and the rest.
    is("a: (1,\n  # c\n  2)\n", "a: (1,\n  # c\n   2)\n");
    check("a: 1 # c\n  2\n");
}

/// A `\r` only ends a line where a `\n` follows it. On its own the lexer reads
/// it as whitespace, where no rule in `fmt` covers it — it is not an indent, a
/// gap or a line ending — so a file carrying one is refused rather than
/// guessed at. Found by the fuzz target.
#[test]
fn a_bare_carriage_return_is_refused() {
    for src in ["y:\n \rn: t", "k:\n\t\re", "s: r\n\n \r\r\no: a"] {
        let err = ks_lang::format(src).unwrap_err();
        assert!(err.to_string().contains("carriage return"), "{src:?}: {err}");
        assert!(ks_lang::format_range(src, 0..src.len()).is_err(), "{src:?}");
    }
    // `\r\n` is a line ending of its own and reads as one, so the line below
    // it is indented like any other nested entry.
    is("y:\n \r\n  n: t\n", "y:\n\n  n: t\n");
    is("a: 1\r\nb: 2\r\n", "a: 1\nb: 2\n");
    // A `\r` the lexer folds into a comment, or one the author wrote inside a
    // string, is not a line ending at all and stays where it is.
    is("#\r", "#\n");
    is("a: \"x\ry\"\n", "a: \"x\ry\"\n");
}

/// A comment after a key that has no value of its own, sitting where a
/// continuation follows it, is still a comment on the key's line. Treating it
/// as a full-line comment gave the gap a second reading on the next pass, so
/// the file never settled. Found by the fuzz target.
#[test]
fn a_comment_on_a_key_line_keeps_one_gap() {
    is("s:\n L: #\n  e\n", "s:\n  L: #\n     e\n");
    is("s:\n  L: #\n     e\n", "s:\n  L: #\n     e\n");
    // With a value on its line the gap is the author's, as everywhere else.
    is("s:\n L: 1 # c\n  e\n", "s:\n  L: 1 # c\n     e\n");
    check("s:\n L: #\n  e\n");
}

/// Applying a range edit leaves a file `fmt` accepts and recognises as its own
/// canonical spelling, whatever the edit was.
fn check_range(src: &str, range: Range<usize>) {
    let whole = ks_lang::format(src).unwrap_or_else(|e| panic!("{src:?} refused: {e}"));
    if let Some((edit, replacement)) = ks_lang::format_range(src, range.clone()).unwrap() {
        let edited = format!("{}{replacement}{}", &src[..edit.start], &src[edit.end..]);
        assert_eq!(
            ks_lang::format(&edited).as_deref(),
            Ok(whole.as_str()),
            "range {range:?} edited {src:?} into {edited:?}"
        );
    }
}

/// The base indentation belongs to the first line that starts a top-level
/// entry. Taking the first `INDENT` token in the tree instead picked up a
/// nested entry's or a comment's, and reading it off the front of the file
/// instead made a leading blank or comment line the base, so the file did not
/// settle. Found by the fuzz target.
#[test]
fn the_base_indent_comes_from_the_first_line() {
    is("\ta: 1\n  b: 2\n  #c\n", "a: 1\n  b: 2\n  #c\n");
    is("  a: 1\n    b: 2\n", "  a: 1\n    b: 2\n");
    // A file whose first entry holds the whole file still reads its base from
    // that entry's own line, not from the comment under it.
    is("  a: 1\n  b: 2\n  #c\n", "  a: 1\n  b: 2\n  #c\n");
    check("\ta: 1\n  b: 2\n  #c\n");
    // Nor is it the first line, which may be blank or a comment: the base is
    // read from the first line that starts an entry, so a comment in front of
    // one is not mistaken for an indent.
    is("\n #\nt: b", " #\nt: b\n");
    is("# lead\n  a: 1\n", "# lead\n  a: 1\n");
    is("\n\n  a: 1\n", "  a: 1\n");
    check("\n #\nt: b");
    check("# lead\n  a: 1\n");
    check("\n\n  a: 1\n");
}

/// A block string's lines are the author's text: only their indentation is
/// re-based. `BlockString::raw` promises the bytes back, trailing spaces
/// included. Found by the fuzz target.
#[test]
fn block_string_lines_keep_their_trailing_spaces() {
    is("a: |\n  hello   \n  world\n", "a: |\n  hello   \n  world\n");
    is("a: |\n      hello   \n        world\n", "a: |\n  hello   \n    world\n");
    // A line of nothing but spaces is still blank.
    is("a: |\n  x\n   \n  y\n", "a: |\n  x\n\n  y\n");
    check("a: |\n  hello   \n  world\n");
}

/// A block string's text is the author's and comes back byte for byte, so a
/// tab in it cannot be turned into a space without rewriting it. The lexer
/// reads the body as ordinary content and calls the tab misplaced, and that
/// diagnostic rode straight through into the output — a `fmt` that emits a
/// file the parser rejects. Refused instead. Found by the fuzz target.
#[test]
fn a_tab_in_a_block_strings_text_is_refused() {
    for src in ["k: |\n |\t", "k: |\n  a\tb\n", "k: |\n a\n b\t\n"] {
        let err = ks_lang::format(src).unwrap_err();
        assert!(err.to_string().contains("tab inside a block string"), "{src:?}: {err}");
        assert!(ks_lang::format_range(src, 0..src.len()).is_err(), "{src:?}");
    }
    // Indentation is re-based anyway, tab and all, so that is still fixed.
    is("k: |\n\ta\n\tb\n", "k: |\n  a\n  b\n");
    is("k: |\n a\n\tb\n", "k: |\n  a\n  b\n");
    check("k: |\n\ta\n\tb\n");
}

#[test]
fn unicode_operators_normalise_to_ascii() {
    is("a: x ≥ y\n", "a: x >= y\n");
    is("a: x ≤ y\n", "a: x <= y\n");
    is("a: x >= y\n", "a: x >= y\n");
    // Inside a string the bytes are the author's, whatever they are.
    is("a: \"x ≥ y\"\n", "a: \"x ≥ y\"\n");
}

#[test]
fn block_strings_keep_their_text_and_shift_under_their_key() {
    is("a: |\n      x\n        y\nb: 1\n", "a: |\n  x\n    y\nb: 1\n");
    // Blank lines inside a block string are content, and survive.
    is("a: |\n  x\n\n  y\nb: 1\n", "a: |\n  x\n\n  y\nb: 1\n");
    is("a: |\n  x", "a: |\n  x\n");
}

#[test]
fn tabs_become_spaces() {
    // The one error `fmt` is allowed to see past: replacing tabs is its job.
    is("\ta: 1\n", "a: 1\n");
    is("a:\n\tb: 1\n", "a:\n  b: 1\n");
}

#[test]
fn a_file_with_parse_errors_is_refused() {
    for src in REFUSED {
        let err = ks_lang::format(src).unwrap_err();
        assert!(!err.diagnostics().is_empty(), "{src:?}");
        assert!(err.diagnostics().iter().all(|d| d.severity == Severity::Error), "{src:?}");
        // The refusal is total: range formatting refuses too, rather than
        // rewriting the parts it did understand.
        assert!(ks_lang::format_range(src, 0..src.len()).is_err(), "{src:?}");
    }
    let err = ks_lang::format("a: \"unclosed\n").unwrap_err();
    assert!(err.to_string().contains("unclosed"), "{err}");
}

#[test]
fn a_range_formatting_request_covers_the_steps_it_touches() {
    let src = "name: api\nsteps:\n  build: a\n\n  plan: b\n";
    let whole = ks_lang::format(src).unwrap();
    assert_eq!(whole, "name:  api\nsteps:\n  build: a\n\n  plan:  b\n");

    // A range over the whole file is one edit that reproduces the whole format.
    let (edit, replacement) = ks_lang::format_range(src, 0..src.len()).unwrap().unwrap();
    assert_eq!(edit, 0..src.len());
    assert_eq!(replacement, whole);

    // A range inside the second top-level entry rewrites that entry alone,
    // starting where the entry starts and running to the end of the file.
    let steps = src.find("steps:").unwrap();
    let build = src.find("build").unwrap();
    let (edit, replacement) = ks_lang::format_range(src, build..build + 2).unwrap().unwrap();
    assert_eq!(edit, steps..src.len());
    assert_eq!(replacement, "steps:\n  build: a\n\n  plan:  b\n");

    // A range inside the first entry leaves the second one alone.
    let name = src.find("name").unwrap();
    let (edit, replacement) = ks_lang::format_range(src, name..name + 2).unwrap().unwrap();
    assert_eq!(edit, 0..steps);
    assert_eq!(replacement, "name:  api\n");

    // A range that touches no entry produces no edit at all.
    assert_eq!(ks_lang::format_range(src, 0..0).unwrap(), None);
    assert_eq!(ks_lang::format_range("", 0..0).unwrap(), None);

    // A comment above the first entry belongs to no step, so a range inside it
    // edits nothing — and an edit over the whole file leaves it in place
    // rather than folding it into the step below.
    let src = "# banner\nname:  api\n";
    let whole = ks_lang::format(src).unwrap();
    assert_eq!(ks_lang::format_range(src, 0..3).unwrap(), None);
    assert_eq!(
        ks_lang::format_range(src, 0..src.len()).unwrap(),
        Some((9..src.len(), whole[9..].to_string()))
    );
}

/// A comment written after a key that has no value of its own belongs to that
/// key, not to the step above it: writing it on a line of its own moved it,
/// which broke the source-to-output pairing `format_range` edits by.
/// Found by the fuzz target.
#[test]
fn a_range_edit_never_moves_a_comment_off_its_key() {
    let src = "risk:  decide\n  ask: ok\n\nreview:  #plow 0\n  else: ask\n";
    let whole = ks_lang::format(src).unwrap();
    assert!(whole.contains("review:  #plow 0\n"), "the comment left its key in\n{whole}");

    for cut in 0..=src.len() {
        if !src.is_char_boundary(cut) {
            continue;
        }
        let Some((edit, replacement)) = ks_lang::format_range(src, cut..cut + 1).unwrap() else {
            continue;
        };
        let applied = format!("{}{}{}", &src[..edit.start], replacement, &src[edit.end..]);
        assert_eq!(ks_lang::format(&applied).as_deref(), Ok(whole.as_str()), "offset {cut}");
        assert_eq!(
            ks_lang::format_range(&applied, edit.start..edit.start + replacement.len())
                .unwrap()
                .map(|(_, r)| r),
            None,
            "the edit for offset {cut} was not a fixed point on\n{applied}"
        );
    }
}

#[test]
fn a_range_edit_leaves_the_whole_file_canonical() {
    let src = "steps:\n  build:    a\n\n  plan:  b\n";
    let whole = ks_lang::format(src).unwrap();
    for cut in 0..=src.len() {
        if !src.is_char_boundary(cut) {
            continue;
        }
        let Some((edit, replacement)) = ks_lang::format_range(src, cut..cut + 1).unwrap() else {
            continue;
        };
        let edited = format!("{}{}{}", &src[..edit.start], replacement, &src[edit.end..]);
        assert_eq!(
            ks_lang::format(&edited).as_deref(),
            Ok(whole.as_str()),
            "applying the edit for offset {cut} did not yield the canonical file"
        );
    }
}

/// A tab in the indentation is the one thing `fmt` fixes, and it cannot fix it
/// one step at a time: replacing a tab changes how wide an entry sits, so an
/// entry can cross a neighbour's indentation and become a different entry. A
/// range request over such a file therefore rewrites the whole file.
#[test]
fn a_range_edit_over_a_tabbed_file_rewrites_all_of_it() {
    let src = "\te: 5\n\te: 5\n";
    let whole = ks_lang::format(src).unwrap();
    assert_eq!(whole, "e: 5\ne: 5\n");
    for cut in 0..src.len() {
        let (edit, replacement) = ks_lang::format_range(src, cut..cut + 1).unwrap().unwrap();
        assert_eq!((edit.clone(), &replacement), (0..src.len(), &whole), "offset {cut}");
        let edited = format!("{}{}{}", &src[..edit.start], replacement, &src[edit.end..]);
        check_range(src, cut..cut + 1);
        // The whole file is canonical after the edit, so asking again finds
        // nothing left to do.
        assert_eq!(ks_lang::format_range(&edited, 0..edited.len()).unwrap(), None, "{edited:?}");
    }
    // A file already in its canonical spelling has no edit, tabs or not.
    assert_eq!(ks_lang::format_range(&whole, 0..whole.len()).unwrap(), None);
}

/// A narrow edit is only handed back if the file it produces is one `fmt`
/// still accepts: the bytes outside the range stay as they were, and that can
/// move a step across a neighbour it never touched. Here it split `build:`
/// from its value. So the edit widens instead. Found by the fuzz target.
#[test]
fn a_range_edit_that_would_break_the_file_widens() {
    let src = "#e:   oathla \u{2192}\n  build:   oathleciy, 5m\n  build:   oeciy";
    let whole = ks_lang::format(src).unwrap();
    assert_eq!(whole, "#e:   oathla \u{2192}\n  build: oathleciy, 5m\n  build: oeciy\n");
    // The last byte sits in the second `build` step, and an edit covering only
    // it used to leave `build:   oeciy` with its value torn off.
    for cut in 0..src.len() {
        check_range(src, cut..cut + 1);
    }
}

/// One range per top-level entry, which is how an editor asks: "the cursor is
/// here, format what I can see".
fn step_ranges(src: &str) -> Vec<Range<usize>> {
    let parse = ks_lang::parse(src);
    parse
        .syntax()
        .child_nodes_of_kind(SyntaxKind::Entry)
        .map(|e| {
            let span = e.span();
            span.start as usize..span.end as usize
        })
        .collect()
}

/// Applying a range edit and asking again is the same as having asked once.
/// Columns come from the whole file on every call, so a range never needs a
/// second pass — and a canonical region is reported as "nothing to do".
#[test]
fn a_range_edit_is_idempotent_and_settles_after_one_pass() {
    let fixtures = fixtures();
    let corpus: Vec<&str> = fixtures.iter().map(|(_, s)| s.as_str()).collect();
    for src in corpus.into_iter().chain(MESSY.iter().copied()) {
        let whole = ks_lang::format(src).unwrap_or_else(|e| panic!("{src:?} refused: {e}"));
        for range in step_ranges(src) {
            let Some((edit, replacement)) = ks_lang::format_range(src, range.clone()).unwrap()
            else {
                // No edit means the range was already canonical. Say so again.
                assert_eq!(
                    ks_lang::format_range(src, range.clone()).unwrap().map(|(_, r)| r),
                    None,
                    "an empty range edit was not repeatable for {src:?} at {range:?}"
                );
                continue;
            };
            let applied = format!("{}{}{}", &src[..edit.start], replacement, &src[edit.end..]);
            // (b) the file is no further from canonical than it was.
            assert_eq!(
                ks_lang::format(&applied).as_deref(),
                Ok(whole.as_str()),
                "a range edit over {range:?} moved {src:?} away from canonical"
            );
            // (a) asking again about the lines the edit just wrote finds nothing
            // left to do. Formatting can make a step shorter or longer, so the
            // same lines in the new file are where the edit landed, measured
            // by what it wrote.
            let again = edit.start..edit.start + replacement.len();
            assert_eq!(
                ks_lang::format_range(&applied, again).unwrap().map(|(_, r)| r),
                None,
                "a range edit over {range:?} was not idempotent on\n{applied}"
            );
        }
    }
}
