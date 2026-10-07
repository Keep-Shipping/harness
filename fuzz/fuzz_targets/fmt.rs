//! Fuzz `ks_lang::format`: whatever it accepts must be a fixed point and must
//! still parse. Formatting twice must be the same as formatting once, and the
//! output must carry no error diagnostics — `fmt` never emits source its own
//! parser refuses.

#![no_main]
#![forbid(unsafe_code)]

use ks_lang::Severity;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(src) = std::str::from_utf8(data) {
        format_is_a_fixed_point(src);
    }
});

fn format_is_a_fixed_point(src: &str) {
    // A file `fmt` refuses is outside this target's contract: the formatter
    // never saw it as something it could rewrite.
    let Ok(formatted) = ks_lang::format(src) else {
        return;
    };

    // The output parses, and cleanly: no error diagnostic survives the trip.
    for d in ks_lang::parse(&formatted).diagnostics() {
        assert!(
            d.severity != Severity::Error,
            "fmt produced source that does not parse: {d} in\n{formatted}",
        );
    }

    // Idempotence: formatting the output is the identity. Formatting is
    // allowed to be lossy once — the point is that it converges after one
    // pass and stays there.
    match ks_lang::format(&formatted) {
        Ok(again) => assert_eq!(again, formatted, "fmt is not idempotent on\n{formatted}"),
        Err(e) => panic!("fmt refused its own output {formatted}: {e}"),
    }

    tokens_survive(src, &formatted);
    range_edit_is_a_fixed_point(src, &formatted);
}

/// Every token the input carried is still in the output, in the same order.
/// Whitespace is the formatter's to move and the operators have an ASCII
/// spelling, but nothing else about a file may change: a formatter that drops
/// a token loses the author's work silently, which is worse than one that
/// declines to answer.
///
/// Comments are trivia but not nothing, so they are compared too — a comment
/// that changed text or order has moved to a different step. A comment's
/// trailing `\r` is a line ending the lexer folded into the token, so it is
/// not part of the text the author wrote.
fn tokens_survive(src: &str, formatted: &str) {
    fn walk(node: &ks_lang::SyntaxNode, out: &mut Vec<(ks_lang::SyntaxKind, String)>) {
        for el in node.children() {
            match el {
                ks_lang::SyntaxElement::Node(n) => walk(n, out),
                ks_lang::SyntaxElement::Token(t) => {
                    let kind = t.kind();
                    let text = match kind {
                        ks_lang::SyntaxKind::Comment => t.text().trim_end_matches('\r').to_string(),
                        // A block line carries its own indentation, which is
                        // the formatter's to re-base. The rest is the author's,
                        // trailing spaces included.
                        ks_lang::SyntaxKind::BlockLine => t
                            .text()
                            .trim_start_matches([' ', '\t'])
                            .trim_end_matches(['\n', '\r'])
                            .to_string(),
                        _ if kind.is_trivia() => continue,
                        ks_lang::SyntaxKind::Op => match t.text() {
                            "\u{2265}" => ">=".to_string(),
                            "\u{2264}" => "<=".to_string(),
                            other => other.to_string(),
                        },
                        _ => t.text().to_string(),
                    };
                    out.push((kind, text));
                }
            }
        }
    }
    let text_of = |src: &str| {
        let mut out = Vec::new();
        walk(ks_lang::parse(src).syntax(), &mut out);
        out
    };
    assert_eq!(
        text_of(src),
        text_of(formatted),
        "fmt lost or changed tokens:\n{src}\nbecame\n{formatted}"
    );
}

/// A range edit has to land the file on the same canonical text a whole-file
/// format would, and asking about the lines it just wrote has to come back
/// "nothing to do". `src` supplies the bytes the range is cut from, so the
/// fuzzed input reaches every part of a file the same way.
fn range_edit_is_a_fixed_point(src: &str, formatted: &str) {
    // Long inputs cost a lot per exec and add nothing here.
    if src.len() > 4096 {
        return;
    }
    // Two bytes of the input pick the range, so the search follows the fuzzer.
    let Some(head) = src.as_bytes().get(0..2) else {
        return;
    };
    let picked = u16::from_le_bytes([head[0], head[1]]) as usize;
    let len = src.len();
    let start = picked % (len + 1);
    let end = start + (picked / 256) % (len + 1 - start);

    let first = ks_lang::format_range(src, start..end)
        .unwrap_or_else(|e| panic!("fmt refused a range of {src:?}: {e}"));
    let Some((edit, replacement)) = first else {
        // No edit means the range was already canonical, or touched no entry.
        assert!(
            ks_lang::format_range(src, start..end).unwrap().is_none(),
            "an empty range edit was not repeatable for {src:?}",
        );
        return;
    };

    let applied = format!("{}{}{}", &src[..edit.start], replacement, &src[edit.end..]);
    assert_eq!(
        ks_lang::format(&applied).as_deref(),
        Ok(formatted),
        "a range edit over {start}..{end} moved\n{src}\naway from canonical",
    );
    assert_eq!(
        ks_lang::format_range(&applied, edit.start..edit.start + replacement.len())
            .unwrap()
            .map(|(_, r)| r),
        None,
        "a range edit over {start}..{end} was not idempotent on\n{applied}",
    );
}
