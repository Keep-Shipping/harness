//! Golden CST snapshots: tree plus diagnostics, byte-compared.
//!
//! Regenerate with `UPDATE_GOLDEN=1 cargo test -p ks-lang` after reviewing
//! the diff — the goldens are the spec for recovery behaviour.

use std::fs;
use std::path::{Path, PathBuf};

const SOURCES: &[(&str, &str)] = &[
    ("site-hero", include_str!("fixtures/site-hero.ks")),
    ("site-block", include_str!("fixtures/site-block.ks")),
    ("site-policy", include_str!("fixtures/site-policy.ks")),
    ("site-decide", include_str!("fixtures/site-decide.ks")),
];

fn golden_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(format!("{name}.cst"))
}

#[expect(
    clippy::disallowed_methods,
    reason = "the golden update path is test-only; the library itself stays I/O-free"
)]
fn read_or_update(path: &Path, actual: &str, update: bool) -> String {
    if update {
        fs::write(path, actual).expect("write golden");
        return actual.to_string();
    }
    fs::read_to_string(path).unwrap_or_default()
}

#[test]
fn golden_trees_match() {
    let update = std::env::var_os("UPDATE_GOLDEN").is_some();
    for (name, src) in SOURCES {
        let parse = ks_lang::parse(src);
        assert_eq!(
            parse.syntax().to_string(),
            *src,
            "{name}: the tree must round-trip the source exactly"
        );
        let dump = parse.dump();
        let expected = read_or_update(&golden_path(name), &dump, update);
        assert_eq!(dump, expected, "{name}: golden mismatch; re-run with UPDATE_GOLDEN=1");
    }
}

#[test]
fn site_fixtures_parse_cleanly() {
    for (name, src) in SOURCES {
        let parse = ks_lang::parse(src);
        assert!(
            parse.diagnostics().is_empty(),
            "{name} should have no diagnostics, got: {:#?}",
            parse.diagnostics()
        );
    }
}
