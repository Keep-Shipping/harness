# Contributing

Read first: [README.md](README.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and the [ADR index](docs/adr/README.md). The plan lives in the issues, starting with the master plan, [#1](https://github.com/Keep-Shipping/harness/issues/1).

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
- [ ] New steps and adapters pass the conformance kit (`ks-testing`).
- [ ] Port contract changes have a changelog entry.

## Licence

All rights reserved pending the licensing decision (ADR-0006). See [LICENSE](LICENSE).
