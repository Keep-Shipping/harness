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

/// The one code that only fires when the run's actor is known: checked as an
/// agent, so the `agents: never: read secrets` rule binds.
fn check_explained(src: &str, code: Code) -> Checked {
    if code == Code::PolicyForbidden {
        let catalog = Catalog::builtin();
        let options =
            CheckOptions::new(&catalog).actor(ks_core::ports::run_context::ActorKind::Agent);
        check_with(&ks_lang::parse(src), &options)
    } else if code == Code::NeedsContext {
        // Checked as a laptop, where a `ci-only` step cannot run.
        let catalog = Catalog::builtin();
        let options = CheckOptions::new(&catalog).context(ks_core::CheckContext::local());
        check_with(&ks_lang::parse(src), &options)
    } else {
        check_src(src)
    }
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
