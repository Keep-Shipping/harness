//! The diagnostics registry: every code documented, every example real, and
//! `docs/ERRORS.md` in sync with what the registry renders.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use ks_core::block::{self, BlockProblem, BlockSignature};
use ks_core::registry::{errors_md, explain};
use ks_core::repro::scan_dockerfile;
use ks_core::{Catalog, CheckOptions, Checked, check, check_with};
use ks_lang::{Code, Diagnostic, Severity};

/// The block the `web-service` examples below use, as it is declared.
const BLOCK: &str = "\
block: web-service
inputs:
  image: oci.Digest
  domain: string
  replicas: int = 2
";

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
/// bound to an actor (`agents: never: read secrets`), one only under CI, one
/// only against a format table with a format behind the current one, and one
/// checked against a block's signature.
fn check_explained(src: &str, code: Code) -> Checked {
    let catalog = Catalog::builtin();
    let blocks = web_service();
    let options = match code {
        Code::PolicyForbidden => {
            CheckOptions::new(&catalog).actor(ks_core::ports::run_context::ActorKind::Agent)
        }
        // Checked as a laptop, where a `ci-only` step cannot run.
        Code::NeedsContext => CheckOptions::new(&catalog).context(ks_core::CheckContext::local()),
        Code::FormatUndeclared => {
            CheckOptions::new(&catalog).actor(ks_core::ports::run_context::ActorKind::Ci)
        }
        Code::FormatDeprecated => CheckOptions::new(&catalog).formats(&PREVIOUS),
        // A block use is checked against the signature the caller resolved.
        Code::MissingInput => CheckOptions::new(&catalog).blocks(&blocks),
        _ => return check_src(src),
    };
    check_with(&ks_lang::parse(src), &options)
}

/// The signature a use of `acme/web-service@v3` is checked against: the
/// block of the name, keyed by the kind as the file spells it.
fn web_service() -> BTreeMap<String, BlockSignature> {
    let catalog = Catalog::builtin();
    let parse = ks_lang::parse(BLOCK);
    let sig = block::signature(&parse, &catalog, &BTreeMap::new()).expect("a block file");
    BTreeMap::from([("acme/web-service@v3".to_string(), sig)])
}

/// KS0801 is the one code the checker never emits: `keepshipping check
/// --repro` scans the Dockerfiles an `oci.image` step names, so its examples
/// are Dockerfiles and its findings come from the scanner. KS0306 is the one
/// no single file can produce: it is found resolving a nest of block files,
/// so its examples spell several, separated by `---`.
fn explained_diagnostics(src: &str, code: Code) -> Vec<Diagnostic> {
    if code == Code::NonReproducible {
        scan_dockerfile(src)
    } else if code == Code::BlockDepth {
        let parses: Vec<ks_lang::Parse> = src.split("\n---\n").map(ks_lang::parse).collect();
        let files: BTreeMap<String, &ks_lang::Parse> =
            parses.iter().enumerate().map(|(i, p)| (format!("block{i}.ks"), p)).collect();
        block::block_signatures(&files, &Catalog::builtin())
            .1
            .iter()
            .map(BlockProblem::diagnostic)
            .collect()
    } else {
        check_explained(src, code).diagnostics
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

        let bad = explained_diagnostics(e.bad, *code);
        assert!(
            bad.iter().any(|d| d.code == *code),
            "{}: the bad example must emit the code, got {:#?}",
            e.code,
            bad
        );
        let hit = bad.iter().find(|d| d.code == *code).expect("checked above");
        assert_eq!(hit.severity, e.severity, "{}: severity must match the docs", e.code);

        let good = explained_diagnostics(e.good, *code);
        assert!(
            good.iter().all(|d| d.code != *code),
            "{}: the good example must not emit the code, got {:#?}",
            e.code,
            good
        );
        assert!(
            good.iter().all(|d| d.severity != Severity::Error),
            "{}: the good example must not error at all, got {:#?}",
            e.code,
            good
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
