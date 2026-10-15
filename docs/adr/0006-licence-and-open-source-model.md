# ADR 0006: Licence and open-source model

Status: superseded by [ADR 0016](0016-mit-licence.md) (MIT instead of Apache-2.0), 2026-10-15; accepted 2026-10-06

## Context
Keep Shipping's harness runs inside other people's CI and holds their deploy
credentials. Reading the code is how a security team decides whether to let
it near a registry token, a cluster kubeconfig or an SSH key, so the licence
is part of the trust argument rather than a formality at the end of it. The
site says "Follow on GitHub" rather than "Star on GitHub" only because
nothing is public yet.

The other Factory Zero projects do not settle it either way. Cratefield's
harness is MIT, with the managed service as the product; PromptDecode keeps
its engines private and paid; Groove Guru plans an open-source harness with
a paid Pro tier. The options for this repository:

| Option | For | Against |
| --- | --- | --- |
| A. Open core, permissive licence on the harness | Trust and adoption; community step and adapter contributions; matches the Cratefield harness | Harder to charge for the core; fork risk |
| B. Source-available (BSL / FSL, converting after N years) | Blocks a competing hosted offering | Some companies ban non-OSI licences outright; community friction |
| C. Closed, free CLI | Maximum control | A hard sell for a tool that holds credentials; no community steps |

## Decision
- **Apache-2.0 for everything in this repository**: the engine, the checker,
  the CLI, the language server, the built-in steps and adapters, the
  conformance kit and `ventures/keepshipping`. The repository carries one
  licence; there is no per-crate split.
- Apache-2.0 rather than MIT for the explicit patent grant and the
  patent-retaliation clause. For a tool enterprises run in CI with their
  credentials, the licence should settle patent exposure for both sides, and
  a licence war between a contributor and a corporate user is the one thing
  that could poison adoption. It is still OSI-approved and permissive, and it
  stays compatible with the MIT-licensed crates in the dependency tree.
- Options B and C are rejected. A source-available licence is a real
  constraint on adoption for a security-audited CI tool, and a closed free
  CLI is not sellable against the trust problem.
- The paid parts — the hosted control plane, team-only features — live in
  private repositories, not here, so nothing in this repository needs a
  second licence.
- `ventures/keepshipping` stays under Apache-2.0. It is composition and
  wiring ([ADR 0200](0200-hosted-venture-on-the-cratefield-harness.md)):
  the name and domain, the origins writes may come from, the mail theme and
  one origin guard, around published `cratefield` crates that are already
  open. There is nothing in it worth keeping private, and a hosted part that
  ever did need to stay closed would move to a private repository rather
  than open this one to a second licence.
- Contributions come in under Apache-2.0 section 5: inbound is outbound.
  There is no CLA and no DCO.
- **The repository stays private until M1 exits**, so the first public
  commit shows a working `check` and `run` rather than a workspace
  skeleton.
- Decided alongside
  [#15](https://github.com/Keep-Shipping/harness/issues/15), which covers
  the same model from the venture side.

### Infrastructure-as-code tools
The `tofu.*` and `terraform.*` steps drive the user's **own** binary: the
`tofu-cli` adapter is handed a path to it and shells out, and the harness
never downloads, bundles or redistributes either tool. That matters most for
Terraform, which is BUSL-1.1 and not ours to ship; OpenTofu is MPL-2.0, and a
future downloader may fetch it on the user's behalf. Everything this
repository adds around them — the port, the adapter, the conformance kit — is
Apache-2.0.

## Consequences
- [LICENSE](../../LICENSE) is the canonical Apache-2.0 text and
  `[workspace.package]` in [Cargo.toml](../../Cargo.toml) carries
  `license = "Apache-2.0"`, inherited by every member crate and mirrored in
  [fuzz/Cargo.toml](../../fuzz/Cargo.toml).
- `cargo deny check licenses` now checks our own crates, not only
  dependencies: [deny.toml](../../deny.toml) no longer ignores unpublished
  workspace crates, and a licence outside the allowlist fails CI.
- [README.md](../../README.md) and
  [CONTRIBUTING.md](../../CONTRIBUTING.md) say Apache-2.0 and link this ADR.
- The site's GitHub link copy changes when the repository goes public
  ([Keep-Shipping/website#6](https://github.com/Keep-Shipping/website/issues/6)).
- Fork risk is accepted. The moat is the hosted service and the adapters,
  as it is for the Cratefield harness; a fork of the harness is a
  distribution problem, not a business one.