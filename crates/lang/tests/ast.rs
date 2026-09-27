//! The typed AST view: the API the ks-core checker builds on.

use ks_lang::{CmpOp, NameKind, Scalar, SyntaxKind};

#[test]
fn entries_children_and_values() {
    let parse = ks_lang::parse(include_str!("fixtures/site-hero.ks"));
    let entries: Vec<_> = parse.file().entries().collect();
    let names: Vec<_> = entries.iter().filter_map(|e| e.key_name()).collect();
    assert_eq!(names, vec!["name", "on", "steps"]);

    let steps = entries.iter().find(|e| e.key_name() == Some("steps")).expect("steps");
    let step_names: Vec<_> = steps.children().filter_map(|e| e.key_name()).collect();
    assert_eq!(step_names, vec!["build", "plan", "review", "apply", "deploy"]);
    let build = steps.children().find(|e| e.key_name() == Some("build")).expect("build");
    // `build: oci.image` — the value names a step kind, a dotted name.
    let refs = build.value().and_then(|v| v.expr()).map(|e| e.refs());
    assert_eq!(refs.as_ref().map(|r| r.len()), Some(1));
    assert_eq!(refs.as_ref().and_then(|r| r.first()).map(|r| r.text), Some("oci.image"));

    // `push: ghcr.io/acme/api:{git.sha}` — a word with an interpolation.
    let push = build.children().find(|e| e.key_name() == Some("push")).expect("push");
    let refs = push.expr().expect("expr").refs();
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].kind, NameKind::Interp);
    assert_eq!(refs[0].text, "git.sha");

    // `deploy: k8s.rollout` with `image: build.digest` — a dotted name.
    let deploy = steps.children().find(|e| e.key_name() == Some("deploy")).expect("deploy");
    let image = deploy.children().find(|e| e.key_name() == Some("image")).expect("image");
    let expr = image.expr().expect("expr");
    let refs = expr.refs();
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].kind, NameKind::Dotted);
    assert_eq!(refs[0].text, "build.digest");

    // `wait: healthy, 5m` — a tuple.
    let wait = deploy.children().find(|e| e.key_name() == Some("wait")).expect("wait");
    match wait.expr() {
        Some(ks_lang::Expr::Tuple { items, .. }) => assert_eq!(items.len(), 2),
        other => panic!("expected a tuple, got {other:?}"),
    }
}

#[test]
fn decide_auto_is_an_and_of_is_test_and_compare() {
    let parse = ks_lang::parse(include_str!("fixtures/site-decide.ks"));
    let review = parse.file().entries().find(|e| e.key_name() == Some("review")).expect("review");
    let auto = review.children().find(|e| e.key_name() == Some("auto")).expect("auto");
    let ks_lang::Expr::And { args, .. } = auto.expr().expect("expr") else {
        panic!("expected And, got {:#?}", auto.expr());
    };
    assert_eq!(args.len(), 2);
    let ks_lang::Expr::IsTest { subject, answer, threshold, .. } = &args[0] else {
        panic!("expected IsTest, got {:#?}", args[0]);
    };
    assert_eq!(subject.node().text(), "risk");
    assert_eq!(answer.node().text(), "low");
    let (op, _, bound) = threshold.as_ref().expect("threshold");
    assert_eq!(*op, CmpOp::GeUnicode);
    assert_eq!(op.symbol(), "\u{2265}");
    assert_eq!(bound.node().text(), "0.95");
    let ks_lang::Expr::Compare { lhs, op, rhs, .. } = &args[1] else {
        panic!("expected Compare, got {:#?}", args[1]);
    };
    assert_eq!(lhs.node().text(), "plan.destroys");
    assert_eq!(*op, CmpOp::Eq);
    assert_eq!(rhs.as_ref().expect("rhs").node().text(), "0");

    // `returns: low | medium | high` — a union of three phrases.
    let risk = parse.file().entries().find(|e| e.key_name() == Some("risk")).expect("risk");
    let returns = risk.children().find(|e| e.key_name() == Some("returns")).expect("returns");
    match returns.expr() {
        Some(ks_lang::Expr::Union { alts, .. }) => assert_eq!(alts.len(), 3),
        other => panic!("expected a union, got {other:?}"),
    }
}

#[test]
fn default_and_block_string() {
    let parse = ks_lang::parse(include_str!("fixtures/site-block.ks"));
    let replicas = parse
        .file()
        .entries()
        .find(|e| e.key_name() == Some("inputs"))
        .expect("inputs")
        .children()
        .find(|e| e.key_name() == Some("replicas"))
        .expect("replicas");
    let ks_lang::Expr::Default { lhs, eq, rhs, .. } = replicas.expr().expect("expr") else {
        panic!("expected a default");
    };
    assert_eq!(lhs.node().text(), "int");
    assert_eq!(eq.kind(), SyntaxKind::Op);
    assert_eq!(eq.text(), "=");
    assert_eq!(rhs.node().text(), "2");
    assert_eq!(rhs.node().span().slice(parse.src()), "2");

    let parse = ks_lang::parse("notes: |\n  first line\n\n  second line\nnext: 1\n");
    let notes = parse.file().entries().find(|e| e.key_name() == Some("notes")).expect("notes");
    let block = notes.block_string().expect("block string");
    assert!(notes.expr().is_none(), "a block string is not an expression");
    assert_eq!(block.raw(), "  first line\n\n  second line\n");
    assert_eq!(block.text(), "first line\n\nsecond line");
}

#[test]
fn scalar_classification_and_segments() {
    use ks_lang::classify_scalar;
    assert_eq!(classify_scalar("true"), Scalar::Bool);
    assert_eq!(classify_scalar("false"), Scalar::Bool);
    assert_eq!(classify_scalar("0"), Scalar::Number);
    assert_eq!(classify_scalar("-12.5"), Scalar::Number);
    assert_eq!(classify_scalar("5m"), Scalar::Duration);
    assert_eq!(classify_scalar("500ms"), Scalar::Duration);
    assert_eq!(classify_scalar("0.95"), Scalar::Number);
    assert_eq!(classify_scalar("@platform"), Scalar::Handle);
    assert_eq!(classify_scalar("@acme/on-call"), Scalar::Handle);
    assert_eq!(classify_scalar("./Dockerfile"), Scalar::Path);
    assert_eq!(classify_scalar("~/bin"), Scalar::Path);
    assert_eq!(classify_scalar("/abs"), Scalar::Path);
    assert_eq!(classify_scalar("../up"), Scalar::Path);
    assert_eq!(classify_scalar("build.digest"), Scalar::DottedName);
    assert_eq!(classify_scalar("apply.out.cluster"), Scalar::DottedName);
    assert_eq!(classify_scalar("api.acme.dev"), Scalar::DottedName);
    assert_eq!(classify_scalar("staging"), Scalar::Ident);
    assert_eq!(classify_scalar("oci.image"), Scalar::DottedName);
    assert_eq!(classify_scalar("ghcr.io/acme/api"), Scalar::Text);

    let parse = ks_lang::parse("to: apply.out.cluster\n");
    let to = parse.file().entries().next().expect("entry");
    let ks_lang::Expr::Atom { atom: ks_lang::Atom::Word(word), .. } = to.expr().expect("expr")
    else {
        panic!("expected a word");
    };
    let segs = word.segments().expect("dotted");
    assert_eq!(segs.len(), 3);
    assert_eq!(segs[0], ("apply", ks_lang::Span::new(4, 9)));
    assert_eq!(segs[2], ("cluster", ks_lang::Span::new(14, 21)));
}

#[test]
fn strings_expose_parts_and_interpolations() {
    let parse = ks_lang::parse("ask: \"plan {plan.id} for {git.sha}?\"\n");
    let ask = parse.file().entries().next().expect("entry");
    let ks_lang::Expr::Atom { atom: ks_lang::Atom::Str(s), .. } = ask.expr().expect("expr") else {
        panic!("expected a string");
    };
    let refs = ask.expr().expect("expr").refs();
    assert_eq!(refs.len(), 2);
    assert!(refs.iter().all(|r| r.kind == NameKind::Interp));
    assert_eq!(refs[0].text, "plan.id");
    assert_eq!(refs[1].text, "git.sha");
    assert_eq!(s.value(), "plan {plan.id} for {git.sha}?");
    assert_eq!(s.parts().len(), 5, "text, interp, text, interp, text");

    let parse = ks_lang::parse("q: \"a \\\"b\\\" c\"\n");
    let q = parse.file().entries().next().expect("entry");
    let ks_lang::Expr::Atom { atom: ks_lang::Atom::Str(s), .. } = q.expr().expect("expr") else {
        panic!("expected a string");
    };
    assert_eq!(s.value(), "a \"b\" c");
}
