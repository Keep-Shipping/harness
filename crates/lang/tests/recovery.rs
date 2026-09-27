//! Error recovery: several diagnostics from one file, parsing continues,
//! and the tree still round-trips.

fn diags(src: &str) -> Vec<String> {
    ks_lang::parse(src).diagnostics().iter().map(std::string::ToString::to_string).collect()
}

fn messages(src: &str) -> String {
    diags(src).join("\n")
}

#[test]
fn many_diagnostics_from_one_file() {
    let src = "\
name:  api
broken line here
steps:
  build:
  plan: ==
  review: \"unclosed
  apply:
    from {git.sha}
    dir: ./infra
";
    let parse = ks_lang::parse(src);
    assert_eq!(parse.syntax().to_string(), src, "must still round-trip");

    let all = messages(src);
    // stray line without `key:`
    assert!(all.contains("expected `key:`"), "{all}");
    // `build:` with neither value nor children
    assert!(all.contains("missing value for `build`"), "{all}");
    // `==` with no right-hand side
    assert!(all.contains("missing value after `==`"), "{all}");
    // unclosed quote
    assert!(all.contains("unclosed string"), "{all}");
    // `from {git.sha}` under `apply:` — deeper, no `key:`
    assert!(all.contains("expected `key:`"), "{all}");

    // Parsing continued: entries after the damage are still in the tree.
    let steps = parse.file().entries().find(|e| e.key_name() == Some("steps")).expect("steps");
    let names: Vec<_> = steps.children().filter_map(|e| e.key_name()).collect();
    assert_eq!(names, vec!["build", "plan", "review", "apply"]);
    let apply = steps.children().find(|e| e.key_name() == Some("apply")).expect("apply");
    let names: Vec<_> = apply.children().filter_map(|e| e.key_name()).collect();
    assert_eq!(names, vec!["dir"]);
}

#[test]
fn indentation_recovery() {
    // Dedent to a column matching no open level.
    let src = "a:\n    b: 1\n  c: 2\nd: 3\n";
    let all = messages(src);
    assert!(all.contains("indentation doesn't match any outer level"), "{all}");
    let parse = ks_lang::parse(src);
    let names: Vec<_> = parse.file().entries().filter_map(|e| e.key_name()).collect();
    assert_eq!(names, vec!["a", "c", "d"], "recovered entries stay in the tree");

    // Deeper line with nothing to attach to.
    let src = "a: 1\n";
    assert!(!diags(src).iter().any(|d| d.contains("unexpected indentation")));

    // A deeper `key:` line always attaches as a child, no error.
    let src = "build: oci.image\n  from: ./Dockerfile\n";
    assert!(diags(src).is_empty(), "{:?}", diags(src));
}

#[test]
fn tab_in_indentation_reports_but_continues() {
    let src = "a: 1\n\tb: 2\nc: 3\n";
    let all = messages(src);
    assert!(all.contains("tab in indentation"), "{all}");
    assert!(all.contains("hint"), "{all}");
    let parse = ks_lang::parse(src);
    let names: Vec<_> = parse.file().entries().filter_map(|e| e.key_name()).collect();
    assert_eq!(names, vec!["a", "c"], "parsing continued past the tab");
    // The tab-indented line still parsed as an entry, one level under `a`.
    let a = parse.file().entries().next().expect("a");
    let names: Vec<_> = a.children().filter_map(|e| e.key_name()).collect();
    assert_eq!(names, vec!["b"]);
}

#[test]
fn unclosed_interpolation_reports_but_keeps_the_word() {
    let parse = ks_lang::parse("a: ghcr.io/x:{git.sha\n");
    let all = messages("a: ghcr.io/x:{git.sha\n");
    assert!(all.contains("unclosed `{`"), "{all}");
    let a = parse.file().entries().next().expect("entry");
    let expr = a.expr().expect("expr");
    let interps: Vec<_> = expr
        .refs()
        .iter()
        .filter(|r| r.kind == ks_lang::NameKind::Interp)
        .map(|r| r.text)
        .collect();
    assert_eq!(interps, vec!["git.sha"]);
}

#[test]
fn empty_or_unclosed_parens_are_diagnosed() {
    // `()` closed: one diagnostic, and the atom spans the parens.
    let src = "a: ()\n";
    let parse = ks_lang::parse(src);
    assert_eq!(parse.syntax().to_string(), src, "must still round-trip");
    assert!(messages(src).contains("empty `()`"), "{:?}", messages(src));
    let expr = parse.file().entries().next().expect("entry").expr().expect("expr");
    let ks_lang::Expr::Atom { atom: ks_lang::Atom::Paren { node, inner }, .. } = &expr else {
        panic!("expected a paren atom, got {expr:?}");
    };
    assert!(inner.is_none());
    assert_eq!(node.span(), ks_lang::Span::new(3, 5), "the span covers `(`..`)`");

    // Unclosed and empty: still diagnosed (once).
    assert!(messages("a: (\n").contains("empty `()`"));
    // Unclosed with a value keeps its `missing )`.
    assert!(messages("a: (b\n").contains("missing `)`"));
    // A filled group is not diagnosed.
    assert!(messages("a: (b or c)\n").is_empty());
}

#[test]
fn a_leading_bom_is_trivia_and_the_first_key_parses() {
    let src = "\u{FEFF}name: api\nsteps:\n  build: oci.image\n";
    let parse = ks_lang::parse(src);
    assert_eq!(parse.syntax().to_string(), src, "must still round-trip");
    assert!(parse.diagnostics().is_empty(), "{:?}", parse.diagnostics());
    let names: Vec<_> = parse.file().entries().filter_map(|e| e.key_name()).collect();
    assert_eq!(names, vec!["name", "steps"], "the first key must parse");
}

#[test]
fn diagnostics_are_reported_in_source_order() {
    // The unclosed string is a lexer error on line 2, the missing value a
    // parser error on line 1; the report must still be in source order.
    let parse = ks_lang::parse("first:\nsecond: \"unclosed\n");
    let msgs: Vec<_> = parse.diagnostics().iter().map(|d| d.message.clone()).collect();
    assert!(msgs[0].contains("missing value for `first`"), "{msgs:?}");
    assert!(msgs[1].contains("unclosed string"), "{msgs:?}");
    let starts: Vec<_> = parse.diagnostics().iter().map(|d| d.span.start).collect();
    assert!(starts.windows(2).all(|w| w[0] <= w[1]), "{msgs:?}");
}
