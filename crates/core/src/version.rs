//! The three public contracts a third party binds to, and their versions.
//!
//! A step author writing an adapter, a script author writing TypeScript and a
//! user with a `ship.ks` in their repository all depend on something the
//! harness controls. Each of those dependencies has exactly one number here:
//!
//! - [`FORMAT_VERSION`] — the `ship.ks` file format, parsed by `ks-lang`;
//! - [`STEP_API`] — the [`StepKind`](crate::step::StepKind) contract, the shape
//!   of the code a step implements;
//! - [`SCRIPT_PROTOCOL`] — the JSON-stdio protocol between the harness and a
//!   TypeScript script.
//!
//! All three start at `1` and are bumped only for a breaking change.
//! `FORMAT_VERSION` and `STEP_API` are enforced today: a file declaring a
//! format this build cannot read is refused by
//! [`check`](crate::check), and a step built against a different `STEP_API`
//! than the harness is composing is a compile error in intent and a
//! composition error in fact —
//! [`HarnessBuilder::build`](crate::harness::HarnessBuilder::build) refuses
//! it. `SCRIPT_PROTOCOL` is declared and versioned; nothing reads it at
//! runtime yet.
//!
//! The rendered table lives in `docs/COMPATIBILITY.md`, and the port contract
//! digest that guards `STEP_API` is pinned in
//! `crates/testing/tests/compatibility.rs`.

/// The version of the `ship.ks` workflow file format.
///
/// Bumped when a file that parsed under the old version no longer means the
/// same thing: a renamed builtin type, a changed default, a removed key. A
/// mismatch means the workflow must be rewritten for the newer harness.
///
/// Enforced by [`check`](crate::check), which reads the file's optional
/// `keepshipping: 0.N` header: a file declaring the current format, or the
/// one before it, is read (the previous one with a deprecation warning), and
/// anything else is an error. A file with no header is read as the current
/// format. [`upgrade`](crate::format::upgrade) brings an older file forward,
/// and every bump appends a migration to
/// [`MIGRATIONS`](crate::format::MIGRATIONS) — a format with no path out of
/// it is a format nothing can upgrade.
pub const FORMAT_VERSION: u32 = 1;

/// The version of the [`StepKind`](crate::step::StepKind) contract a step was built against;
/// `build` refuses a step whose `step_api` differs.
///
/// Bumped when the trait itself changes shape — a required method added or removed, a
/// signature a step must implement. A mismatch means the step has to be recompiled against
/// the new `ks-core`: its `step_api()` and the harness's `STEP_API` are compared at
/// composition time, so a stale step is a composition error rather than a silent one.
pub const STEP_API: u32 = 5;

/// The version of the JSON-stdio protocol between the harness and a TypeScript
/// script running through the `ScriptHost` port.
///
/// Bumped when the messages on the wire change: a new request kind, a renamed
/// field, a different handshake. A mismatch should mean a script written for
/// the old protocol is rejected by the host as a protocol error.
///
/// Declared and versioned; `script_host.rs` does not read it yet, so a
/// mismatch is not currently a protocol error. The gate lands with the script
/// host.
pub const SCRIPT_PROTOCOL: u32 = 1;

/// What each constant versions, and whether anything enforces it yet.
///
/// Kept as data beside the constants rather than as prose inside the template,
/// so the table and the doc comments cannot drift apart. `enforced` is `None`
/// for a contract that is declared and versioned but not yet read at runtime:
/// claiming a gate that does not exist is worse than admitting the absence.
const CONTRACTS: [(&str, u32, &str, Option<&str>); 3] = [
    (
        "FORMAT_VERSION",
        FORMAT_VERSION,
        "the `ship.ks` file format",
        Some("`ks_core::check`, which reads the file's `keepshipping:` header"),
    ),
    (
        "STEP_API",
        STEP_API,
        "the `StepKind` trait a step implements",
        Some("`HarnessBuilder::build`, which refuses a step built against another version"),
    ),
    (
        "SCRIPT_PROTOCOL",
        SCRIPT_PROTOCOL,
        "the JSON-stdio protocol between the harness and a TypeScript script",
        None,
    ),
];

/// The `Enforced by` cell for a contract: the gate if there is one, otherwise
/// the honest "declared and versioned, not yet enforced" wording and where the
/// gate is expected to land.
fn enforced_by(enforced: Option<&'static str>) -> &'static str {
    enforced.unwrap_or("declared and versioned, not yet enforced — nothing reads it at runtime yet")
}

/// Renders `docs/COMPATIBILITY.md` from the three constants and a port-contract digest.
///
/// The digest is a parameter rather than a constant because `ks-core` cannot read
/// files: the test that computes it from `crates/core/src/ports/` passes it in.
#[must_use]
pub fn render_compatibility_markdown(port_digest: &str) -> String {
    let rows: String = CONTRACTS
        .iter()
        .map(|(name, version, what, enforced)| {
            format!("| `{name}` | {version} | {what} | {} |\n", enforced_by(*enforced))
        })
        .collect();

    format!(
        "<!--\n\
         Generated from the version constants; do not edit by hand.\n\
         Regenerate with: KS_BLESS=1 cargo test -p ks-testing --test compatibility\n\
         -->\n\
         \n\
         # Compatibility\n\
         \n\
         The three contracts outside this repository depend on, and the number\n\
         each is at. Each is bumped only for a breaking change.\n\
         \n\
         | Contract | Version | What it versions | Enforced by |\n\
         | --- | --- | --- | --- |\n\
         {rows}\
         \n\
         `FORMAT_VERSION` and `STEP_API` have a runtime gate today.\n\
         `SCRIPT_PROTOCOL` is read by nothing yet — that lands with the script\n\
         host — so a step author bumping it is making a promise this\n\
         repository has not yet made the tooling keep.\n\
         \n\
         ## Port contract digest: `{port_digest}`\n\
         \n\
         A digest of the port traits in `crates/core/src/ports/` — the method\n\
         signatures only, with comments and formatting normalised away. It is\n\
         pinned in `crates/testing/tests/compatibility.rs` next to the\n\
         `STEP_API` it belongs to, so a port trait changed without `STEP_API`\n\
         bumped fails CI. Change a trait and you must change both, and add a\n\
         `## STEP_API` entry under `## Changelog` in `docs/PORTS.md`.\n\
         \n\
         ## Regenerating this file\n\
         \n\
         This file is generated. To regenerate it after bumping a constant:\n\
         \n\
         ```sh\n\
         KS_BLESS=1 cargo test -p ks-testing --test compatibility\n\
         ```\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_render_is_deterministic() {
        let first = render_compatibility_markdown("0123456789abcdef");
        let second = render_compatibility_markdown("0123456789abcdef");
        assert_eq!(first, second);
    }

    #[test]
    fn the_render_carries_the_three_versions_and_the_digest() {
        let md = render_compatibility_markdown("0123456789abcdef");
        assert!(md.starts_with("<!--\n"), "an H1 needs its generation banner first: {md}");
        assert!(md.contains("\n# Compatibility\n"), "no H1: {md}");
        for row in [
            format!("| `FORMAT_VERSION` | {FORMAT_VERSION} |"),
            format!("| `STEP_API` | {STEP_API} |"),
            format!("| `SCRIPT_PROTOCOL` | {SCRIPT_PROTOCOL} |"),
        ] {
            assert!(md.contains(&row), "missing table row {row}: {md}");
        }
        assert!(md.contains("0123456789abcdef"), "the digest must be rendered: {md}");
    }

    #[test]
    fn the_table_does_not_claim_a_gate_that_does_not_exist() {
        let md = render_compatibility_markdown("0123456789abcdef");
        assert!(
            md.contains(&format!(
                "| `STEP_API` | {STEP_API} | the `StepKind` trait a step implements \
                 | `HarnessBuilder::build`, which refuses a step built against another version |"
            )),
            "STEP_API's gate must name HarnessBuilder::build: {md}"
        );
        assert!(
            md.contains(&format!(
                "| `FORMAT_VERSION` | {FORMAT_VERSION} | the `ship.ks` file format \
                 | `ks_core::check`, which reads the file's `keepshipping:` header |"
            )),
            "FORMAT_VERSION's gate must name the checker that reads the header: {md}"
        );
        let row = "| `SCRIPT_PROTOCOL` | ";
        let line = md
            .lines()
            .find(|line| line.starts_with(row))
            .unwrap_or_else(|| panic!("no row for SCRIPT_PROTOCOL: {md}"));
        assert!(
            line.ends_with(
                "declared and versioned, not yet enforced — nothing reads it at runtime yet |"
            ),
            "SCRIPT_PROTOCOL is not enforced at runtime, so its row must say so: {line}"
        );
        assert!(
            !line.contains("ScriptHost"),
            "SCRIPT_PROTOCOL has no runtime gate; naming one is a false claim: {line}"
        );
    }

    #[test]
    fn the_render_names_the_command_that_regenerates_it() {
        let md = render_compatibility_markdown("0123456789abcdef");
        assert!(
            md.contains("KS_BLESS=1 cargo test -p ks-testing --test compatibility"),
            "the regeneration command must appear in the generated file: {md}"
        );
    }
}
