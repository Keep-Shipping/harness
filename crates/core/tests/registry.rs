//! The diagnostics registry: every code documented, every example real, and
//! `docs/ERRORS.md` in sync with what the registry renders.

use std::fs;
use std::path::Path;

use ks_core::registry::{errors_md, explain};
use ks_core::{Catalog, CheckOptions, Checked, check, check_with};
use ks_lang::{Code, Severity};

fn check_src(src: &str) -> Checked {
    check(&ks_lang::parse(src))
}

/// A format table one version ahead of the built-in one, so the code that
/// only fires on a file written for the *previous* format has one to fire on:
/// the built-in table is format 1 with nothing behind it.
const PREVIOUS: ks_core::format::Formats<'static> = ks_core::format::Formats {
    current: 2,
    migrations: &[ks_core::format::Migration {
        from: 1,
        summary: "test-only: nothing is rewritten",
        rewrite: |_| ks_core::format::Rewrites::default(),
    }],
};

/// The codes that only fire under options the default check does not use: one
/// bound to an actor (`agents: never: read secrets`), one only under CI, and
/// one only against a format table with a format behind the current one.
fn check_explained(src: &str, code: Code) -> Checked {
    let catalog = Catalog::builtin();
    let options = match code {
        Code::PolicyForbidden => {
            CheckOptions::new(&catalog).actor(ks_core::ports::run_context::ActorKind::Agent)
        }
        Code::FormatUndeclared => {
            CheckOptions::new(&catalog).actor(ks_core::ports::run_context::ActorKind::Ci)
        }
        Code::FormatDeprecated => CheckOptions::new(&catalog).formats(&PREVIOUS),
        _ => return check_src(src),
    };
    check_with(&ks_lang::parse(src), &options)
}

#[test]
fn all_lists_the_codes_in_ascending_order() {
    let nums: Vec<u32> =
        Code::ALL.iter().map(|c| c.as_str()[2..].parse().expect("KS number")).collect();
    assert!(nums.windows(2).all(|w| w[0] < w[1]), "Code::ALL must be in numeric order");
}

#[test]
fn every_documented_bad_example_emits_its_code_and_good_example_does_not() {
    for code in Code::ALL {
        let e = explain(*code);
        assert_eq!(e.code, *code, "the explanation must carry the code it explains");

        let bad = check_explained(e.bad, *code);
        assert!(
            bad.diagnostics.iter().any(|d| d.code == *code),
            "{}: the bad example must emit the code, got {:#?}",
            e.code,
            bad.diagnostics
        );
        let hit = bad.diagnostics.iter().find(|d| d.code == *code).expect("checked above");
        assert_eq!(hit.severity, e.severity, "{}: severity must match the docs", e.code);

        let good = check_explained(e.good, *code);
        assert!(
            good.diagnostics.iter().all(|d| d.code != *code),
            "{}: the good example must not emit the code, got {:#?}",
            e.code,
            good.diagnostics
        );
        assert!(
            good.diagnostics.iter().all(|d| d.severity != Severity::Error),
            "{}: the good example must not error at all, got {:#?}",
            e.code,
            good.diagnostics
        );
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "the golden update path is test-only; the library itself stays I/O-free"
)]
fn read_or_update(path: &Path, actual: &str) -> String {
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        fs::write(path, actual).expect("write docs/ERRORS.md");
    }
    fs::read_to_string(path).unwrap_or_default()
}

#[test]
fn errors_md_matches_the_committed_docs() {
    let md = errors_md();
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/ERRORS.md");
    let committed = read_or_update(&path, &md);
    assert_eq!(md, committed, "docs/ERRORS.md drifted; re-run with UPDATE_GOLDEN=1");
}
