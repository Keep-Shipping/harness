//! Golden checker snapshot: the site-hero deploy, pinned to the tag mistake.
//!
//! `image: build.digest` is the one right spelling; pointing the deploy at
//! `build.tag` instead must produce exactly one error and its hint. Re-run
//! with `UPDATE_GOLDEN=1 cargo test -p ks-core` after reviewing the diff.

use std::fs;
use std::path::{Path, PathBuf};

const HERO: &str = include_str!("../../lang/tests/fixtures/site-hero.ks");

/// The hero file with the deploy pinned to a tag: the canonical mismatch.
fn tagged() -> String {
    HERO.replace("image: build.digest", "image: build.tag")
}

fn golden_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/site-hero-tag.snap")
}

/// Render like the CLI does, minus the file prefix: `line:col: severity:
/// message`, with each hint indented underneath.
fn render(src: &str, checked: &ks_core::Checked) -> String {
    let starts: Vec<u32> = std::iter::once(0)
        .chain(src.bytes().enumerate().filter(|(_, b)| *b == b'\n').map(|(i, _)| i as u32 + 1))
        .collect();
    let mut out = String::new();
    for d in &checked.diagnostics {
        let line = starts.partition_point(|&s| s <= d.span.start) - 1;
        let col = src[starts[line] as usize..d.span.start as usize].chars().count() + 1;
        out.push_str(&format!("{}:{}: {}: {}", line + 1, col, d.severity.as_str(), d.message));
        out.push('\n');
        for hint in &d.hints {
            out.push_str(&format!("  hint: {hint}\n"));
        }
    }
    out
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
fn the_tagged_hero_snapshot_is_exactly_the_mismatch_and_its_hint() {
    let tagged = tagged();
    let dump = render(&tagged, &ks_core::check(&ks_lang::parse(tagged.as_str())));
    let expected =
        read_or_update(&golden_path(), &dump, std::env::var_os("UPDATE_GOLDEN").is_some());
    assert_eq!(dump, expected, "golden mismatch; re-run with UPDATE_GOLDEN=1");
    assert_eq!(
        expected,
        "22:12: error: expected oci.Digest, got oci.Tag\n  \
         hint: use build.digest so prod runs exactly the image you built\n",
        "the committed snapshot must be exactly the digest mismatch"
    );
    // The canonical mistake is KS0101, about `deploy.image`, and nothing
    // else: no other diagnostic, no secondary span.
    let checked = ks_core::check(&ks_lang::parse(&tagged));
    assert_eq!(checked.diagnostics.len(), 1, "{:#?}", checked.diagnostics);
    let d = &checked.diagnostics[0];
    assert_eq!(d.code, ks_lang::Code::TypeMismatch);
    assert_eq!(d.code.as_str(), "KS0101");
    assert_eq!(d.subject.as_deref(), Some("deploy.image"));
    assert!(d.labels.is_empty(), "the mismatch carries no secondary span");
}

#[test]
fn the_hero_file_checks_clean() {
    let checked = ks_core::check(&ks_lang::parse(HERO));
    assert!(checked.diagnostics.is_empty(), "{:#?}", checked.diagnostics);
}
