<!--
Generated from the version constants; do not edit by hand.
Regenerate with: KS_BLESS=1 cargo test -p ks-testing --test compatibility
-->

# Compatibility

The three contracts outside this repository depend on, and the number
each is at. Each is bumped only for a breaking change.

| Contract | Version | What it versions | Enforced by |
| --- | --- | --- | --- |
| `FORMAT_VERSION` | 1 | the `ship.ks` file format | `ks_core::check`, which reads the file's `keepshipping:` header |
| `STEP_API` | 6 | the `StepKind` trait a step implements | `HarnessBuilder::build`, which refuses a step built against another version |
| `SCRIPT_PROTOCOL` | 1 | the JSON-stdio protocol between the harness and a TypeScript script | declared and versioned, not yet enforced — nothing reads it at runtime yet |

`FORMAT_VERSION` and `STEP_API` have a runtime gate today.
`SCRIPT_PROTOCOL` is read by nothing yet — that lands with the script
host — so a step author bumping it is making a promise this
repository has not yet made the tooling keep.

## Port contract digest: `43c412a2ee3a824f`

A digest of the port traits in `crates/core/src/ports/` — the method
signatures only, with comments and formatting normalised away. It is
pinned in `crates/testing/tests/compatibility.rs` next to the
`STEP_API` it belongs to, so a port trait changed without `STEP_API`
bumped fails CI. Change a trait and you must change both, and add a
`## STEP_API` entry under `## Changelog` in `docs/PORTS.md`.

## Regenerating this file

This file is generated. To regenerate it after bumping a constant:

```sh
KS_BLESS=1 cargo test -p ks-testing --test compatibility
```
