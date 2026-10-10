//! Drift guard for the pricing decision,
//! [ADR 0203](../../../docs/adr/0203-pricing-not-set.md) and
//! [issue #15](https://github.com/Keep-Shipping/harness/issues/15).
//!
//! Until #15 closes, the FZ-012 record says "Pricing is not set" and no
//! user-facing surface may state a price. Docs may still *talk about*
//! pricing — [INTERVIEWS](../../../docs/INTERVIEWS.md) question 16 and the
//! ADR's option table name candidate units — so the tripwire is a stated
//! currency amount (`$50`, `USD 20000`), the shape any published price
//! takes. `docs/research/` is excluded wholesale: the competitor landscape
//! is where prices are the data. When the pricing decision lands, this
//! guard is relaxed deliberately, together with the superseding ADR, the
//! FZ-012 record and the landing site. std-only.

use std::fs;
use std::path::{Path, PathBuf};

/// Currency codes that, followed by a number, read as a written price.
const CURRENCIES: [&str; 3] = ["USD", "EUR", "GBP"];

fn docs_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs")
}

/// True when a `$` is followed, after at most one space, by a digit:
/// `$50`, `$0.10`, `$ 9`. Shell prompts (`$ echo $?`), `${{ }}` template
/// expressions and `$XDG_CACHE_HOME` never match.
fn dollar_amount(line: &[u8]) -> bool {
    for (i, &b) in line.iter().enumerate() {
        if b != b'$' {
            continue;
        }
        let rest = &line[i + 1..];
        if rest.first().is_some_and(u8::is_ascii_digit)
            || (rest.first() == Some(&b' ') && rest.get(1).is_some_and(u8::is_ascii_digit))
        {
            return true;
        }
    }
    false
}

/// True when `code` appears on a word boundary followed, after at most one
/// space, by a digit: `USD 20000`, `eur0.10`. A letter or underscore before
/// the code (`used`, `gbp_`) is not a currency.
fn currency_amount(line: &[u8], code: &[u8]) -> bool {
    line.windows(code.len()).enumerate().any(|(i, window)| {
        if !window.eq_ignore_ascii_case(code) {
            return false;
        }
        let before = i == 0 || !(line[i - 1].is_ascii_alphanumeric() || line[i - 1] == b'_');
        let after = line.get(i + code.len()).copied();
        let digit = |b: Option<u8>| b.is_some_and(|b: u8| b.is_ascii_digit());
        before
            && (digit(after)
                || (after == Some(b' ') && digit(line.get(i + code.len() + 1).copied())))
    })
}

/// The one rule of the guard: does this line state a currency amount?
fn states_a_price(line: &str) -> bool {
    let bytes = line.as_bytes();
    dollar_amount(bytes) || CURRENCIES.iter().any(|c| currency_amount(bytes, c.as_bytes()))
}

/// Every `.md` file under `root`, sorted, skipping `research/` directories.
fn collect_markdown(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some("research") {
                continue;
            }
            collect_markdown(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("md") {
            out.push(path);
        }
    }
}

#[test]
fn no_doc_states_a_price() {
    let root = docs_root();
    let mut files = Vec::new();
    collect_markdown(&root, &mut files);

    let mut hits: Vec<String> = Vec::new();
    for path in files {
        let body =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let rel = path.strip_prefix(&root).unwrap_or(&path).to_string_lossy().into_owned();
        for (n, line) in body.lines().enumerate() {
            if states_a_price(line) {
                hits.push(format!("  docs/{rel}:{}: {line}", n + 1));
            }
        }
    }

    assert!(
        hits.is_empty(),
        "a price appears in the docs before [#15] has closed:\n{}\n\n\
         The FZ-012 record says \"Pricing is not set\" and ADR 0203 holds that\n\
         in place. A competitor's price belongs in docs/research/landscape.md;\n\
         anything else, reword — a `$` in a shell prompt or a template\n\
         expression never trips this. When #15 closes, relax this guard together with the\n\
         superseding ADR, the FZ-012 record and the landing site.",
        hits.join("\n")
    );
}

#[test]
fn shell_prompts_and_templates_are_not_prices() {
    for line in [
        "$ cargo install keepshipping",
        "$ echo $?",
        "run: keepshipping resume \"${{ needs.plan.outputs.run-id }}\" ship.ks",
        "per-user cache (`$XDG_CACHE_HOME/keepshipping/deno/<version>/`)",
        "What would you pay for one decision? Per person, per month, or per call",
        "**Pricing.** <N> of <N> gave a number. Range: <low>–<high> <unit per>.",
    ] {
        assert!(!states_a_price(line), "false positive on: {line}");
    }
    for line in [
        "Team $50/month after a two-week trial",
        "Essentials from $0.10 per resource per month",
        "Business: USD 20000 billed annually",
        "eur0.10 per resource",
        "costs $ 9 per call",
    ] {
        assert!(states_a_price(line), "missed a price in: {line}");
    }
}
