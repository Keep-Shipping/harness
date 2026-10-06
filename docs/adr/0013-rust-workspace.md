# ADR 0013: Rust workspace

Status: accepted, 2026-10-06

## Context
The checker has to answer in under a second: that is the M0 exit criterion
in [README.md](../../README.md), the budget is pinned in
`crates/cli/benches/check.rs` (cold 1 s, warm p95 100 ms) and the CI `bench`
job fails the build when one is blown. The same binary has to run on a
laptop — macOS and Linux now, Windows later — and on CI runners with no
runtime to install. The language core has to run in an editor (`ks-lsp`) and,
later, in a browser: a playground and the hosted web review page
([ADR 0200](0200-hosted-venture-on-the-cratefield-harness.md)). Keep Shipping
is built as a harness in the style of the `cratefield` harness
([ADR 0000](0000-record-architecture-decisions.md)), so the language should be
one whose toolchain and conventions the rest of Factory Zero's projects
already share.

[ADR 0000](0000-record-architecture-decisions.md) planned this decision as
ADR-0001, from issue [#2](https://github.com/Keep-Shipping/harness/issues/2).
It is numbered 0013 because 0001 went to typed values and secret references,
and 0002–0012 stay with issues
[#3](https://github.com/Keep-Shipping/harness/issues/3) to
[#13](https://github.com/Keep-Shipping/harness/issues/13), as ADR 0000
planned.

## Decision
- Rust, in one Cargo workspace: `resolver = "3"`, `edition = "2024"`,
  `rust-version = "1.98"` in the root `Cargo.toml`, toolchain pinned to
  `1.98.1` in `rust-toolchain.toml` with the `wasm32-unknown-unknown` target
  among its targets.
- The crates are `ks-lang`, `ks-core`, `ks-engine`, `ks-cli` (the
  `keepshipping` binary), `ks-lsp` and `ks-testing`, plus `steps/*` and
  `adapters/*` as those epics land. The full map, with each crate's role, is
  the Crates table in [README.md](../../README.md) and
  [docs/ARCHITECTURE.md](../../docs/ARCHITECTURE.md); it is not repeated here.
- `ks-lang` and `ks-core` stay wasm-safe: `crates/lang/clippy.toml` and
  `crates/core/clippy.toml` disallow `std::fs` and `std::net`, and CI builds
  both for `wasm32-unknown-unknown`. That is one of the merge gates listed in
  [CONTRIBUTING.md](../../CONTRIBUTING.md), along with fmt, clippy, tests,
  docs and `cargo deny`.
- Where the Go ecosystem is the only mature implementation — the BuildKit
  client, some cloud SDKs — the adapter drives the upstream binary or API
  over a port instead of linking Go
  ([#11](https://github.com/Keep-Shipping/harness/issues/11)).
- The options, briefly:
  - Rust. For: one static binary; fast startup, which is what a sub-second
    `check` is made of; `ks-lang` and `ks-core` compile to wasm for a
    playground; the same conventions as `cratefield`, so ports and adapters
    and the merge gates are ones we already run; good crates for OCI
    (`oci-client`), Kubernetes (`kube`), SSH and sigstore. Against: slower
    iteration than Go or TypeScript, fewer contributors, and the TypeScript
    escape hatch needs its own runtime anyway
    ([#10](https://github.com/Keep-Shipping/harness/issues/10)).
  - Go. For: the language of the ecosystem this harness talks to (Terraform,
    Kubernetes, BuildKit, cosign), with libraries linkable directly — the
    BuildKit client, `go-containerregistry`. Against: a stack none of the
    other Factory Zero ventures share, no clean wasm story for the checker,
    and no shared conventions with `cratefield`.
  - TypeScript, compiled with Bun or Deno. For: the same language as the
    escape hatch, and the fastest to prototype. Against: startup time and
    distribution size; a weaker fit for a checker that must be wasm-safe and
    must answer in under a second; and the TypeScript v1 precedent — Factory
    Zero's own projects are Rust, and the `cratefield` harness threw its v1
    away for that reason.

## Consequences
- `keepshipping` ships as one static binary with no runtime to install,
  which is what makes the same check honest on a laptop and in CI.
- Contributors need the pinned Rust toolchain; `rustup` fetches it from
  `rust-toolchain.toml`, including the wasm target.
- TypeScript escape-hatch steps run in a separate runtime behind the
  `ScriptHost` port (`crates/core/src/ports/script_host.rs`,
  [#10](https://github.com/Keep-Shipping/harness/issues/10)), not in-process.
- Go-only tools are driven over ports, not linked, so adapters pay process or
  network latency where a library would not
  ([#11](https://github.com/Keep-Shipping/harness/issues/11)).
- Keeping `ks-lang` and `ks-core` wasm-safe is a gate, not a convention: a
  stray `std::fs` in either crate fails CI.
- Slower iteration is accepted as the price of startup time, one binary and
  one toolchain.