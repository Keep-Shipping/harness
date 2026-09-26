//! Fuzz `ks_lang::parse` and `ks_core::check`: arbitrary bytes must never
//! panic, the tree must round-trip byte for byte, every span must land inside
//! the source, and checking must always yield a sane workflow.

#![no_main]
#![forbid(unsafe_code)]

use ks_lang::{Entry, Span};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(src) = std::str::from_utf8(data) {
        parse_and_check(src);
    }
});

/// Parse `src`, check it, and assert every invariant.
fn parse_and_check(src: &str) {
    let parse = ks_lang::parse(src);

    // Losslessness: printing the tree reproduces the input byte for byte.
    assert_eq!(parse.syntax().to_string(), src, "round-trip failed");

    // Diagnostics point into the source, on character boundaries.
    for d in parse.diagnostics() {
        check_span(d.span, src, "diagnostic");
    }

    // The typed view: every entry, recursively, expressions and block strings.
    walk(parse.file().entries(), src);

    // And the rust-analyzer-style dump the golden snapshots are made of.
    let _ = parse.dump();

    // The checker: its diagnostics are in bounds too, the graph only names
    // declared steps, the topological order is a permutation of the steps,
    // and picking an environment never fails.
    let checked = ks_core::check(&parse);
    for d in &checked.diagnostics {
        check_span(d.span, src, "checker diagnostic");
    }
    let wf = &checked.workflow;
    for (from, to) in wf.edges() {
        assert!(
            wf.step(from).is_some() && wf.step(to).is_some(),
            "edge `{from} -> {to}` names an undeclared step",
        );
    }
    if let Some(order) = wf.topo_order() {
        assert_eq!(order.len(), wf.steps().len(), "topo order is not a permutation of the steps");
    }
    let _ = ks_core::select_env(wf, None, None);
}

fn walk<'a>(entries: impl Iterator<Item = Entry<'a>>, src: &str) {
    for entry in entries {
        let _ = entry.key_name();
        if let Some(expr) = entry.expr() {
            for r in expr.refs() {
                check_span(r.span, src, "name reference");
            }
        }
        if let Some(block) = entry.block_string() {
            let _ = block.text();
        }
        walk(entry.children(), src);
    }
}

fn check_span(span: Span, src: &str, what: &str) {
    assert!(
        span.start <= span.end && (span.end as usize) <= src.len(),
        "{what} span {span} out of bounds for a {}-byte source",
        src.len(),
    );
    assert!(
        src.is_char_boundary(span.start as usize) && src.is_char_boundary(span.end as usize),
        "{what} span {span} splits a UTF-8 character",
    );
}
