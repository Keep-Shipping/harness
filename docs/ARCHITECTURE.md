# Architecture

Keep Shipping is a harness in the style of Factory Zero's [Cratefield harness](https://github.com/Cratefield/harness): a small Rust core, **ports** (traits), and **adapters** (the only vendor-aware code), composed at compile time.

```
ship.ks ──► ks-lang (parse, format) ──► ks-core (types, check, diagnostics)
                                              │
keepshipping (ks-cli): check · run · fmt · graph · approve · log verify · blocks · import
ks-lsp: the same ks-core, for editors
                                              ▼
                  ks-engine (DAG, run state, policy gates, approvals, run log)
                                              │ only sees ports
ports: RunContext · Secrets · ImageBuilder · Registry · Signer · IacTool · Cluster
       RemoteShell · FunctionHost · ScriptHost · ApprovalChannel · Directory
       DecisionModel · RunLog · StateStore · BlockSource · BlocksIndex · PolicyStore
       HttpClient · Clock · IdGen
                                              │
adapters/*: buildkit, oci-distribution, sigstore, tofu-cli, kube, ssh, deno script host,
            tty / GitHub approvals, jev, local run log, github-actions, …
```

The rules that follow from the picture:

- The dependency direction is `ks-lang` → `ks-core` → `ks-engine`. The CLI and the LSP sit on top and depend down, never up.
- Steps implement one `StepKind` trait and only see ports — never a Docker socket, a cloud SDK, a CI environment variable or a model API directly. Adapters answer, and adapters are the only vendor-aware code. That's what lets the same engine run the same file on a laptop and in CI: only the `RunContext` and the adapters change.
- `ks-lang` and `ks-core` do no I/O — no tokio, no `std::fs`, no `std::net` — and must build for `wasm32-unknown-unknown`. CI enforces both.
- No ambient global state; `#![forbid(unsafe_code)]` in every crate.
- `Harness::build()` refuses a composition where a step needs a port nobody provides, where two steps claim the same name, or where a step was built against a different contract version.

## Crates

| Path | Crate | Role |
|---|---|---|
| `crates/lang` | `ks-lang` | Lexer, parser, lossless syntax tree with spans, formatter. No I/O, wasm-safe |
| `crates/core` | `ks-core` | Type system, checker, diagnostics registry, the `StepKind` trait, port traits, the `Harness` builder |
| `crates/engine` | `ks-engine` | DAG planner and executor, run state (park and resume), policy enforcement, run log |
| `crates/cli` | `ks-cli` | The `keepshipping` binary |
| `crates/lsp` | `ks-lsp` | Language server (`keepshipping lsp`) |
| `crates/testing` | `ks-testing` | Fakes for every port, plus the conformance kits steps and adapters must pass, and the ADR guard test |
| `steps/*` | — | Built-in step families (later epic) |
| `adapters/*` | — | One crate per vendor integration (later epic) |
| `sdk/ts` | `@keepshipping/sdk` | `@keepshipping/sdk` for TypeScript escape-hatch steps, and `@keepshipping/sdk/testing` to unit-test one in your own test runner |
| `ventures/keepshipping` | — | The optional hosted parts (waitlist, web approvals, run-log viewer, blocks index) as a Cratefield venture (later epic) |

Changes to this layout go through a new ADR — see the [ADR index](adr/README.md).
