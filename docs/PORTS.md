# Ports

A port is a trait a step asks for and never implements
([ADR 0002](adr/0002-ports-and-adapters.md)): `ks-core` declares the traits in
[`crates/core/src/ports/`](https://github.com/Keep-Shipping/harness/tree/main/crates/core/src/ports),
an adapter crate outside this workspace is the only code that knows how to
answer one for a particular vendor, and
[`HarnessBuilder::build`](https://docs.rs/ks-core) hands each step only the
ports it declared. The module's own documentation carries the inventory of
which ports exist today — this page does not repeat it.

What this page records is the **contract version**. `ks_core::STEP_API`
versions the port traits alongside the `StepKind` trait
([ADR 0014](adr/0014-release-and-contract-versioning.md)), and the harness
refuses to compose a step built against a different one. A fingerprint of the
port trait signatures is pinned against `STEP_API` in
`crates/testing/tests/compatibility.rs`, so changing a trait without bumping
the version fails CI rather than landing as a silent break. The generated
compatibility table is [COMPATIBILITY.md](COMPATIBILITY.md).

Adding a port, adding a method to one, or changing a signature is a contract
change: bump `STEP_API` in `crates/core/src/version.rs`, add a `## STEP_API`
entry below, update the pinned digest in the compatibility test, and
regenerate `COMPATIBILITY.md` with
`KS_BLESS=1 cargo test -p ks-testing --test compatibility`. Reformatting and
comment edits do not need any of that — the fingerprint normalises them away.

## Changelog

Newest first, one heading per contract version, dated.

## STEP_API 2

- **2026-10-07** — Added the `RunLog` and `StateStore` ports
  ([#55](https://github.com/Keep-Shipping/harness/issues/55)). `RunLog` is the
  append-only, hash-chained audit record of what a run did — a step appends
  events, reads them back by run, and verifies the chain; `StateStore` is
  working data a run leaves behind under a run-scoped key, with `put`, `get`,
  `list` and `delete_run`. They are two ports rather than one
  `RunStorage` because the two have opposite lifetimes and opposite audiences:
  the log is small, team-visible and kept long — it is what an audit, a
  debugging session or a post-mortem reads — while state is bulk working data
  that can be large and can carry sensitive values, and is kept only as long as
  the run needs it. Folding them together would force one retention policy on
  both, so either the audit trail is deleted with the scratch data or the
  scratch data is retained for years. A step asking for `RunLog` is asking for
  something that outlives the run; a step asking for `StateStore` is asking for
  something that should not. No existing trait changed shape at this version.

## STEP_API 1

- **2026-10-07** — The initial port contract
  ([ADR 0014](adr/0014-release-and-contract-versioning.md)). The port traits
  as declared in `crates/core/src/ports/` at this version are `RunContext`,
  `Secrets`, `ImageBuilder`, `Registry`, `Signer`, `IacTool`, `HttpClient`,
  `Clock`, `IdGen`, `ScriptHost` and `BlocksIndex`. `STEP_API` moved from
  `crates/core/src/step.rs` to `crates/core/src/version.rs`, which is now the
  single home for the three public contract versions; `ks_core::step::STEP_API`
  still resolves. Any later change to a port trait adds a `## STEP_API 2`
  heading above this one and bumps the constant.