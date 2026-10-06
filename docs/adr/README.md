# Architecture decision records

Every architectural decision is an ADR in this directory: one file per decision, with `Status`, `Context`, `Decision` and `Consequences` sections. An ADR starts as a GitHub issue labelled `adr`; the accepted text is committed here. An accepted ADR is never edited — a change of mind is a new ADR that supersedes it, and the old one's status line says which superseded it.

## Numbers

Blocks keep parallel work from colliding: `0000`–`0099` the harness (core, language, engine, CLI), `0100`–`0199` steps and adapters, `0200`–`0299` the hosted venture. The next ADR takes the next free number in its block.

## Conventions

A file named `NNNN-kebab-title.md` — the number, then the title in lowercase kebab-case — with a heading that matches it, e.g. `0000-record-architecture-decisions.md` begins `# ADR 0000: Record architecture decisions`.

A guard test (`cargo test -p ks-testing --test adr_guard`) checks every ADR below: the file exists, the heading matches the filename, and it is linked in the index exactly once.

## Index

| ADR | Title | Status |
| --- | --- | --- |
| [0000](0000-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0001](0001-typed-values-and-secret-references.md) | Typed values and secret references | Accepted |
| [0002](0002-ports-and-adapters.md) | Ports and adapters | Accepted |
| [0005](0005-local-first-core-with-optional-hosted-services.md) | Local-first core with optional hosted services | Accepted |
| [0013](0013-rust-workspace.md) | Rust workspace | Accepted |
| [0100](0100-step-contract-and-composition-checks.md) | Step contract and composition checks | Accepted |
| [0200](0200-hosted-venture-on-the-cratefield-harness.md) | Hosted venture on the Cratefield harness | Accepted |
