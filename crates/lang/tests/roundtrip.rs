//! Losslessness: for any input, printing the tree reproduces the input, and
//! the parser neither panics nor hangs.

const NASTY: &[&str] = &[
    "",
    " ",
    "\n",
    "\r\n",
    " \t \n",
    "# only a comment\n",
    "# comment\n# another\n",
    "key: value",
    "key: value\r\n",
    "key:",
    "key",
    ":",
    ":::",
    ": : :",
    "a:\nb:\nc:\n",
    "a: ==\n",
    "a: and\n",
    "a: and and\n",
    "a: == ==\n",
    "a: ,\n",
    "a: |\n",
    "a: |\nb: 1\n",
    "a: |\n  text\nb: 1\n",
    "a: | # trailing\n   keep   this\n\n\n  b: 1\n",
    "a: \"unclosed\nb: 1\n",
    "a: \"esc \\\" \\\\ done\"\n",
    "a: \"line1\\\nstill\"\n",
    "a: {unclosed\n",
    "a: {}\n",
    "a: {a b}\n",
    "a: {.bad..name}\n",
    "a: ghcr.io/x:{git.sha}\n",
    "a: \"pre {git.sha} post\"\n",
    "\ta: 1\n",
    "a:\t1\n",
    "a: 1\t\n",
    "    deep: 1\n        deeper: 2\n",
    "a:\n  b:\n    c:\n      d: 1\n",
    "a:\n    b: 1\n  c: 2\nd: 3\n",
    "a: 1\n   b: 2\n c: 3\n",
    "héllo: wörld ✓\n",
    "a: {ünïcode}\n",
    "a: \"… ≥ ≤ 😀\"\n",
    "a: risk is low ≥ 0.95 and plan.destroys == 0\n",
    "a: not not not x\n",
    "a: (((1)))\n",
    "a: (unclosed\n",
    "a: )(\n",
    "a: b | c | d\n",
    "a: x = y = z\n",
    "\u{0}: \u{1}\n",
    "a: \"\" \n",
    "a: \"\"\n",
    "  \n  a: 1\n  \n",
    "a: 1 # c1 # c2\n",
    "a#b#c: d#e\n",
    "a: <>\n",
    "a: >= <= =\n",
    "replicas: int = 2\n",
    // Found by fuzzing (issue #23): a non-`key:` line after a partial dedent
    // used to drop its INDENT token from the tree.
    "a:\n  b: c\n %d: e\n",
    " %x: y\n",
    // A bare scalar at the edge of a value region used to swallow the next
    // line's token past the region end.
    "{\ng",
    // An unclosed `{` used to glue the following word into the interpolation,
    // leaving the trivia between them printed after it.
    "{\ra",
    // A string's closing quote used to be paired across skipped trivia.
    "\" \n \"",
];

#[test]
fn round_trips_exactly() {
    for src in NASTY {
        let parse = ks_lang::parse(src);
        assert_eq!(parse.syntax().to_string(), *src, "round-trip failed for {src:?}");
    }
}

#[test]
fn round_trips_deeply_nested_input() {
    // Thousands of nested parens and `not`s used to recurse until the stack
    // overflowed; the parser now caps nesting with a diagnostic, and every
    // one of these must still round-trip byte for byte.
    let cases = [
        format!("a: {}{}\n", "(".repeat(100_000), ")".repeat(100_000)),
        format!("a: {}\n", "(".repeat(100_000)),
        format!("a: {}x\n", "not ".repeat(100_000)),
        // Well past the block-nesting cap: each deeper line is recovered.
        (1..2_000).map(|i| format!("{}a:\n", " ".repeat(i))).collect::<String>(),
    ];
    for src in &cases {
        let parse = ks_lang::parse(src);
        assert_eq!(parse.syntax().to_string(), *src, "round-trip failed");
        // Recovery diagnostics still point inside the source.
        for d in parse.diagnostics() {
            assert!(d.span.start <= d.span.end && (d.span.end as usize) <= src.len());
        }
    }
}

#[test]
fn round_trips_all_fixtures() {
    for src in [
        include_str!("fixtures/site-hero.ks"),
        include_str!("fixtures/site-block.ks"),
        include_str!("fixtures/site-policy.ks"),
        include_str!("fixtures/site-decide.ks"),
    ] {
        let parse = ks_lang::parse(src);
        assert_eq!(parse.syntax().to_string(), src);
    }
}

#[test]
fn never_panics_on_repetition_and_truncation() {
    let base = include_str!("fixtures/site-hero.ks");
    for n in [1usize, 2, 3, 7] {
        let joined = base.repeat(n);
        let parse = ks_lang::parse(&joined);
        assert_eq!(parse.syntax().to_string(), joined);
        // Every char-boundary prefix must also survive.
        for cut in [0, 1, 5, 13, 40, joined.len() / 2, joined.len().saturating_sub(1)] {
            let cut = cut.min(joined.len());
            if !joined.is_char_boundary(cut) {
                continue;
            }
            let prefix = &joined[..cut];
            let p = ks_lang::parse(prefix);
            assert_eq!(p.syntax().to_string(), prefix, "prefix {cut} of repeat {n}");
        }
    }
}
