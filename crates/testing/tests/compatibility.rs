//! The compatibility gate: the port contract digest pinned against the `STEP_API`
//! it belongs to, the `Port` enum against the `define_ports!` list, the port
//! changelog against the current `STEP_API`, and `docs/COMPATIBILITY.md` against
//! what the version constants render.
//!
//! The point is that changing a port trait cannot land as a silent breaking
//! change: it has to arrive with a `STEP_API` bump and a changelog entry. Run
//! with `KS_BLESS=1` to regenerate `docs/COMPATIBILITY.md`.

use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use ks_core::version::render_compatibility_markdown;

const REGENERATE: &str = "run KS_BLESS=1 cargo test -p ks-testing --test compatibility to regenerate docs/COMPATIBILITY.md";

/// The port contract and the `STEP_API` it was last changed under. Changing a
/// port trait means changing `STEP_API` in `crates/core/src/version.rs` AND
/// this digest — that pair is the review signal.
const PINNED_PORT_CONTRACT: (u32, &str) = (2, "04c92166654e03d2");

/// What to do when the port contract and the `STEP_API` disagree, spelled out
/// once so both asserts below can carry it.
const CONTRACT_MISMATCH: &str = "\
the port contract changed without STEP_API changing with it.

To land a port trait change:
  1. bump STEP_API in crates/core/src/version.rs,
  2. add a changelog entry under `## Changelog` in docs/PORTS.md, under a
     `## STEP_API <new>` heading,
  3. update PINNED_PORT_CONTRACT in this file to (the new STEP_API, the digest
     this test now reports).";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn core_ports_dir() -> PathBuf {
    repo_path("../core/src/ports")
}

/// Collapses one trait block to its signatures: comment lines go, every run of
/// whitespace becomes a single space. Deliberately lossy — a comment edit or a
/// reflow must not require a `STEP_API` bump, a signature edit must.
fn normalise(block: &str) -> String {
    block
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_string()
}

/// Every `pub trait Name ... { ... }` block in `source`, from the line starting
/// `pub trait ` to the first `}` in column zero, normalised.
fn trait_blocks(source: &str) -> Vec<String> {
    let lines: Vec<&str> = source.lines().collect();
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if !lines[i].starts_with("pub trait ") {
            i += 1;
            continue;
        }
        let start = i;
        let end = lines[start..]
            .iter()
            .position(|line| *line == "}")
            .map_or(lines.len() - 1, |o| start + o);
        blocks.push(normalise(&lines[start..=end].join("\n")));
        i = end + 1;
    }
    blocks
}

/// Concatenates extracted trait blocks into the string the digest is taken over.
///
/// Pure, and rejects the empty case: hashing `""` would yield the stable,
/// plausible-looking `e3b0c44298fc1c14`, which would then have to be pinned and
/// would pass forever no matter what the port traits said. Zero extracted
/// blocks means the extractor broke — a renamed or re-indented `pub trait`, a
/// moved `ports/` directory — and that must fail loudly rather than pin a
/// constant.
fn contract_material(blocks: &[String]) -> Result<String, String> {
    if blocks.is_empty() {
        return Err(
            "no `pub trait` blocks were extracted from crates/core/src/ports/. The extractor \
             looks for a line starting exactly with `pub trait ` closed by a `}` in column zero; \
             if the traits moved or their layout changed, fix `trait_blocks` before pinning any \
             digest."
                .to_string(),
        );
    }
    let mut material = String::new();
    for block in blocks {
        material.push_str(block);
        material.push('\n');
    }
    Ok(material)
}

/// The fingerprint of the port contract: every trait block in
/// `crates/core/src/ports/`, files sorted by name, hashed with SHA-256 and cut
/// to 16 hex chars.
fn port_contract_digest() -> String {
    let mut files: Vec<PathBuf> = fs::read_dir(core_ports_dir())
        .expect("crates/core/src/ports/ must be readable")
        .map(|entry| entry.expect("a readable directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .collect();
    files.sort();

    let mut blocks = Vec::new();
    for file in files {
        let source = fs::read_to_string(&file)
            .unwrap_or_else(|e| panic!("{} must be readable: {e}", file.display()));
        blocks.extend(trait_blocks(&source));
    }

    let material = contract_material(&blocks).unwrap_or_else(|e| panic!("{e}"));

    let hash = Sha256::digest(material.as_bytes());
    let hex: String = hash.iter().map(|byte| format!("{byte:02x}")).collect();
    hex[..16].to_string()
}

#[test]
fn changing_a_port_trait_without_bumping_step_api_fails_ci() {
    let digest = port_contract_digest();
    assert_eq!(
        digest, PINNED_PORT_CONTRACT.1,
        "the port contract digest is {digest}, but PINNED_PORT_CONTRACT pins {}: {CONTRACT_MISMATCH}",
        PINNED_PORT_CONTRACT.1
    );
    assert_eq!(
        ks_core::STEP_API,
        PINNED_PORT_CONTRACT.0,
        "STEP_API is {} but PINNED_PORT_CONTRACT pins {}: {CONTRACT_MISMATCH}",
        ks_core::STEP_API,
        PINNED_PORT_CONTRACT.0
    );
}

/// The `Port` variants in `step.rs`, in declaration order.
fn port_enum_variants(source: &str) -> Vec<String> {
    let body = source
        .split_once("pub enum Port {")
        .and_then(|(_, rest)| rest.split_once('}'))
        .map_or_else(|| panic!("step.rs must declare `pub enum Port`"), |(body, _)| body);
    body.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//"))
        .map(|line| line.trim_end_matches(',').to_string())
        .collect()
}

/// The trait names in the `define_ports!` invocation, in order — the second
/// element of each `($module, $trait, $field, $with)` tuple.
fn define_ports_traits(source: &str) -> Vec<String> {
    let start = source
        .find("define_ports! {")
        .unwrap_or_else(|| panic!("step.rs must invoke `define_ports!`"));
    let body =
        source[start..].split_once('{').and_then(|(_, rest)| rest.split_once('}')).map_or_else(
            || panic!("the `define_ports!` invocation must have a body"),
            |(body, _)| body,
        );
    body.lines()
        .map(str::trim)
        .filter(|line| line.starts_with('(') && line.ends_with(','))
        .filter_map(|line| line.trim_matches(['(', ')']).trim_end_matches(',').split(',').nth(1))
        .map(|name| name.trim().to_string())
        .collect()
}

#[test]
fn the_port_enum_and_define_ports_agree_in_order() {
    let step_rs = fs::read_to_string(repo_path("../core/src/step.rs"))
        .expect("crates/core/src/step.rs is readable");
    let variants = port_enum_variants(&step_rs);
    let traits = define_ports_traits(&step_rs);
    assert_eq!(
        variants, traits,
        "`pub enum Port` and the `define_ports!` list in crates/core/src/step.rs disagree \
         (the macro doc comment says the list must match the variants above, in order): \
         enum = {variants:?}, define_ports! = {traits:?}"
    );
}

#[test]
fn the_port_changelog_has_an_entry_for_the_current_step_api() {
    let heading = format!("## STEP_API {}", ks_core::STEP_API);
    let ports_md =
        fs::read_to_string(repo_path("../../docs/PORTS.md")).expect("docs/PORTS.md is readable");
    assert!(
        ports_md.lines().any(|line| line.trim() == heading),
        "docs/PORTS.md has no `{heading}` section, so the current STEP_API ({}) is unchangelogged. \
         Add one under `## Changelog` recording what changed in the port contract; \
         CONTRIBUTING.md and the pull request template both ask for it.",
        ks_core::STEP_API
    );
}

#[test]
fn docs_compatibility_md_is_in_sync() {
    let rendered = render_compatibility_markdown(&port_contract_digest());
    let path = repo_path("../../docs/COMPATIBILITY.md");
    if std::env::var("KS_BLESS").as_deref() == Ok("1") {
        fs::write(&path, rendered).expect("docs/COMPATIBILITY.md should be writable");
        return;
    }
    let current = fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("docs/COMPATIBILITY.md is missing; {REGENERATE}"));
    assert!(rendered == current, "docs/COMPATIBILITY.md is stale; {REGENERATE}");
}

/// An empty extraction is what a broken extractor looks like, so the digest
/// helper has to reject it rather than return the hash of `""`.
#[test]
fn contract_material_rejects_an_empty_extraction() {
    let err = contract_material(&[]).expect_err("no blocks must be an error, not a hash");
    assert!(
        err.contains("no `pub trait` blocks were extracted"),
        "the error must name the failure: {err}"
    );
    assert!(!contract_material(&[]).is_ok(), "the empty case must never produce material");
}

#[test]
fn contract_material_joins_blocks_one_per_line() {
    let blocks = vec!["pub trait A {}".to_string(), "pub trait B {}".to_string()];
    assert_eq!(
        contract_material(&blocks).expect("two blocks are not empty"),
        "pub trait A {}\npub trait B {}\n"
    );
}

/// The guard is reachable from the real extractor: a source with no
/// `pub trait ` line at all yields no blocks, which is what would happen if the
/// traits were re-indented or renamed.
#[test]
fn a_source_without_a_pub_trait_line_extracts_nothing_and_is_rejected() {
    assert!(trait_blocks("struct NotATrait;\n").is_empty());
    assert!(contract_material(&trait_blocks("struct NotATrait;\n")).is_err());
}
