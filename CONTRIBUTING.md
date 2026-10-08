# Contributing

Read first: [README.md](README.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/REPRODUCIBILITY.md](docs/REPRODUCIBILITY.md) and the [ADR index](docs/adr/README.md). The plan lives in the issues, starting with the master plan, [#1](https://github.com/Keep-Shipping/harness/issues/1).

## Rules

- **Steps only see ports.** A step never touches a Docker socket, a cloud SDK, a CI environment variable or a model API directly. **Adapters are the only vendor-aware code.**
- **`ks-lang` and `ks-core` stay I/O-free**: no tokio, no `std::fs`, no `std::net`. They must build for `wasm32-unknown-unknown` — CI checks.
- **No ambient global state.** Everything is composed at compile time through the `Harness` builder.
- **`#![forbid(unsafe_code)]`** in every crate.
- **`license.workspace = true`** in every crate, including examples.
- **Never commit real secrets.** Not in tests, not in fixtures.

## Local setup

[rust-toolchain.toml](rust-toolchain.toml) pins the toolchain; rustup picks it up on the first `cargo` command. You also need [cargo-deny](https://github.com/EmbarkStudios/cargo-deny): `cargo install --locked cargo-deny`.

## Merge gates

Every PR runs these on Linux and macOS. Run them before you push:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo deny check
cargo build -p ks-lang -p ks-core --target wasm32-unknown-unknown
```

CI also checks with `cargo tree` that `ks-lang` and `ks-core` pull in no tokio or native-only dependencies.

Nightly CI additionally fuzzes the parser for 10 minutes ([`fuzz/`](fuzz)) and runs the `ks-lang` parse benchmark. Try the fuzzer yourself: `cargo +nightly fuzz run parse --target x86_64-unknown-linux-gnu` (the target is explicit because cargo-fuzz 0.13's static-musl default cannot link the sanitizer), and time the parser with `cargo bench -p ks-lang`.

## Commits

One commit per issue, conventional-commit format with the issue number last:

```
feat(engine): plan steps as a DAG (#42)
```

## Error codes

Every diagnostic carries a stable `KSxxxx` code, documented in [docs/ERRORS.md](docs/ERRORS.md) (generated — do not edit). To add a code: extend `ks_lang::Code`, document it in the exhaustive `explain` match in `crates/core/src/registry.rs` with a bad and a good example, then regenerate the docs with `UPDATE_GOLDEN=1 cargo test -p ks-core --test registry`. How diagnostics are printed — formats, exit codes, colour — is pinned in [docs/DIAGNOSTICS.md](docs/DIAGNOSTICS.md).

## Releasing and compatibility

Three contracts are public surface, each a constant in `crates/core/src/version.rs`: `FORMAT_VERSION` (the `ship.ks` format), `STEP_API` (the `StepKind` and port contract) and `SCRIPT_PROTOCOL` (the TypeScript script-host protocol). [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) is the table a step author reads; [docs/PORTS.md](docs/PORTS.md) is the hand-written port changelog.

**Changing a port trait means bumping `STEP_API`** — `HarnessBuilder::build` refuses a step whose `step_api()` differs, so a silent signature change is a breaking release anyway. Four edits, in this order — the first three are hand edits, and CI fails if you skip one:

1. Bump `STEP_API` in `crates/core/src/version.rs` (minor for additive, major for breaking).
2. Add a `## STEP_API <n>` entry under `## Changelog` in `docs/PORTS.md` saying what changed.
3. Hand-edit `PINNED_PORT_CONTRACT` in `crates/testing/tests/compatibility.rs` to the new `STEP_API` and the new digest. It is a plain `const` and **nothing writes it for you** — not `KS_BLESS`, not `UPDATE_GOLDEN`. Get the digest by running the test below and reading the digest it reports in the failure message.
4. Only then regenerate the compatibility table:

```sh
KS_BLESS=1 cargo test -p ks-testing --test compatibility
```

Order matters. Steps 1–3 are what the gate actually checks; step 4 only rewrites `docs/COMPATIBILITY.md`. Bless first and step 4 makes `docs_compatibility_md_is_in_sync` pass while the pin and changelog checks still fail, so you read green on one test and ship two broken ones.

`docs/COMPATIBILITY.md` is generated — **do not edit it by hand**; `KS_BLESS=1` is the command that rewrites it. That test is the gate: it compares the port-contract fingerprint against `PINNED_PORT_CONTRACT`, checks `Port` and `define_ports!` agree in order, and checks `docs/PORTS.md` has a heading for the current `STEP_API`.

A tag matching `v*` runs [`.github/workflows/release.yml`](.github/workflows/release.yml): `keepshipping` for macOS arm64/x86_64 and Linux x86_64/arm64, a cosign-keyless-signed `SHA256SUMS`, a CycloneDX SBOM per target and SLSA build provenance over the `SHA256SUMS` subjects (`gh attestation verify <file> --repo Keep-Shipping/harness`), and a GitHub Release whose notes come from GitHub's own release-notes generator over the conventional commits. [`install.sh`](install.sh) installs a release after verifying it and never skips that; [docs/INSTALL.md](docs/INSTALL.md) is the hand-written version, with the exact `cosign verify-blob` identity. Crates are **not** published to crates.io — `publish = false` is set workspace-wide and stays set while the repository is private, which [ADR 0006](docs/adr/0006-licence-and-open-source-model.md) holds until M1 exits — so a release is binaries only.

## ADRs

Architecture changes go through a new ADR — never by editing an accepted one.

- Take the next free number in the right block: `0000`–`0099` the harness, `0100`–`0199` steps and adapters, `0200`–`0299` the hosted venture.
- Name the file `NNNN-kebab-title.md` — the number, then the title in lowercase kebab-case — with heading `# ADR NNNN: <Title>` matching it, and `Status`, `Context`, `Decision` and `Consequences` sections.
- Add it to the [ADR index](docs/adr/README.md) exactly once.
- Accepted ADRs are never edited: a change of mind is a new ADR that supersedes the old one.

The ADR guard test enforces this: `cargo test -p ks-testing --test adr_guard`.

## Pull requests

- [ ] The merge gates pass.
- [ ] New behaviour has tests; bug fixes come with a failing-first test.
- [ ] New steps and adapters pass the conformance kit (`ks-testing`); the guide is [docs/STEP-AUTHORING.md](docs/STEP-AUTHORING.md).
- [ ] Port contract changes have a changelog entry.

## Licence

Apache-2.0 — see [LICENSE](LICENSE) and [ADR 0006](docs/adr/0006-licence-and-open-source-model.md). Contributions are accepted under the same terms (Apache-2.0 section 5: inbound is outbound); there is no CLA and no DCO. Copyright is Factory Zero Pte. Ltd.
