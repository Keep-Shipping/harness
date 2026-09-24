# Keep Shipping harness

**Deploys you can read.** One typed workflow file per repo (`ship.ks`). It builds your images, plans and applies your infrastructure, waits for a human and deploys. It's checked before anything runs, and it runs the same on your laptop as in CI.

This repository will hold the engine, the checker, the `keepshipping` CLI, the language server and the built-in steps. **Nothing here runs yet.** It holds this README, a placeholder licence and the first architecture decision record. The plan is in the issues, starting with the master plan, [#1](https://github.com/Keep-Shipping/harness/issues/1). The site, [keepshipping.run](https://keepshipping.run), shows the planned design: its workflow files, CLI output and timings aren't measurements.

## How it will be built

Keep Shipping is a **harness** in the style of Factory Zero's [Cratefield harness](https://github.com/Cratefield/harness): a small Rust core, **ports** (traits), and **adapters** (the only vendor-aware code), composed at compile time.

> **Steps only see ports.**
> A step never talks to a Docker socket, a cloud SDK, a CI environment variable or a model API directly. It asks for an `ImageBuilder`, a `Registry`, an `IacTool`, an `ApprovalChannel`. Adapters answer. That's what lets the same engine run the same file on a laptop and in CI: only the `RunContext` and the adapters change.

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
       DecisionModel · RunLog · StateStore · BlockSource · PolicyStore
       HttpClient · Clock · IdGen
                                              │
adapters/*: buildkit, oci-distribution, sigstore, tofu-cli, kube, ssh, deno script host,
            tty / GitHub approvals, jev, local run log, github-actions, …
```

Step families (`oci.*`, `tofu.*` / `terraform.*`, `k8s.*`, `vm.*`, `fn.*`, `approval`, `decide`, TypeScript scripts) implement one `StepKind` trait, the way Cratefield modules implement `Module`. `Harness::build()` refuses a composition where a step needs a port nobody provides, where two steps claim the same name, or where a step was built against a different contract version.

### Planned crates

| Crate | Role |
|---|---|
| `ks-lang` | Lexer, parser, lossless syntax tree with spans, formatter. No I/O, wasm-safe |
| `ks-core` | Type system, checker, diagnostics registry, the `StepKind` trait, port traits, the `Harness` builder |
| `ks-engine` | DAG planner and executor, run state (park and resume), policy enforcement, run log |
| `ks-cli` | The `keepshipping` binary |
| `ks-lsp` | Language server (`keepshipping lsp`) |
| `ks-testing` | Fakes for every port, plus the conformance kits steps and adapters must pass |
| `steps/*` | Built-in step families |
| `adapters/*` | One crate per vendor integration |
| `sdk/ts` | `@keepshipping/sdk` for TypeScript escape-hatch steps |
| `ventures/keepshipping` | The optional hosted parts (waitlist, web approvals, run-log viewer, blocks index) as a Cratefield venture |

The language and the layout are proposals until their ADRs are accepted: [#2](https://github.com/Keep-Shipping/harness/issues/2) (Rust), [#3](https://github.com/Keep-Shipping/harness/issues/3) (ports and adapters) and [#4](https://github.com/Keep-Shipping/harness/issues/4) (syntax).

## Milestones

| Milestone | Exit criteria |
|---|---|
| **M0 Foundation** | `keepshipping check` accepts the site's example file and rejects its `build.tag` mistake with the site's error and hint, in under a second. CI gates are green |
| **M1 Local runs** | The site's example runs end to end on a laptop against a local registry, cluster and OpenTofu config, and stops for approval. `keepshipping log verify` passes |
| **M2 Early-access alpha** | The same file runs locally and on GitHub Actions. An agent run waits for a human. The first invite batch can follow the docs alone |
| **M3 Public beta** | Every step and claim on the site is implemented or removed from the site |

## Contributing

Conventions follow the Cratefield harness:
- architecture changes go through a new ADR in [`docs/adr`](docs/adr), never by editing an accepted one;
- conventional commits with the issue number last;
- merge gates `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test` and `cargo doc` with `-D warnings`, plus `cargo deny`.

`CONTRIBUTING.md` lands with the workspace scaffold.

## Licence

All rights reserved for now. See [LICENSE](LICENSE) and the licensing decision, [#7](https://github.com/Keep-Shipping/harness/issues/7).

---

Keep Shipping is a venture of [Factory Zero](https://factory0.ventures/) (Factory Zero Pte. Ltd.).
