# ADR 0005: Local-first core with optional hosted services

Status: accepted, 2026-10-06

## Context
Several features need somewhere shared, and none of them is shared by a
single machine. Approvals can come from chat, from the CLI or from the web,
and an approver named `@platform` has to be notified with enough of the plan
to judge it. An agent should be free to stop while a run sits parked at
`review`. A signed run log has to say who proposed a plan, who approved it
and which digest shipped. Blocks are used from repositories that never run
this binary, and a plan has to survive between the plan job and the apply
job.

None of that may cost the local-first pitch
([README.md](../../README.md),
[docs/ARCHITECTURE.md](../../docs/ARCHITECTURE.md)). Cratefield's limits then
shape the answer — they are Cratefield's, not this repository's: `/v1` request
bodies are capped at 64 KiB, responses are buffered up to 1 MiB, there is no
SSE, and `Blob::signed_url` is GET-only. The first two are pinned in this
repository as `HOSTED_BODY_LIMIT` (`crates/core/src/plan_summary.rs`) and the
`HttpPolicy` default response cap (`crates/core/src/ports/http.rs`).

This ADR decides the shape of ports that do not exist yet: `ApprovalChannel`,
`RunLog`, `StateStore` and `BlockSource` appear in the architecture picture,
and `crates/core/src/ports/mod.rs` says the remaining ports land with their
issues. Nothing here describes code that is written; it fixes the boundary
before the adapters are. The features are tracked as
[#93](https://github.com/Keep-Shipping/harness/issues/93),
[#144](https://github.com/Keep-Shipping/harness/issues/144) and
[#42](https://github.com/Keep-Shipping/harness/issues/42);
[#151](https://github.com/Keep-Shipping/harness/issues/151) consumes the
egress list below. Like [ADR 0013](0013-rust-workspace.md), the number comes
from the block ADR 0000 planned — 0002–0012 stay with issues
[#3](https://github.com/Keep-Shipping/harness/issues/3) to
[#13](https://github.com/Keep-Shipping/harness/issues/13) — and this is issue
[#6](https://github.com/Keep-Shipping/harness/issues/6)'s number in it.

The options, briefly:
- Fully local, CI-native. For: nothing to operate, nothing to trust; GitHub
  environments and PR reviews already are an approval channel. Against:
  cross-repo blocks and chat approval need somewhere that is not one
  repository, and a parked run needs storage the run does not keep.
- Hosted control plane required. For: one place for every team's approvals,
  logs and views. Against: unusable without an account, and our outage becomes
  the customer's failed deploy.
- Local-first core, optional hosted services. For: every flow has a local
  path, and the hosted part fits Cratefield's caps. Against: two adapters per
  port to keep honest, and features that only exist on the hosted side.

## Decision
Option 3.

- The engine, the checker, the local runner and the GitHub Actions runner
  never require the hosted service: no account, no network call to us. The
  hosted service is opt-in by configuring an endpoint. If it is down or
  unconfigured, every flow above still has a local path.
- Four ports, local adapter first, hosted adapter later and maybe:
  - `ApprovalChannel` — local: a `keepshipping approve` command to land, and
    CI-native gates (GitHub environments, PR reviews). Hosted: approval from
    the web and chat, and notification of `@handle` approvers. An approval is
    bound to the plan digest; apply refuses if the saved plan's digest
    differs.
  - `RunLog` — local: append-only, hash-chained, signed entries (through the
    one `Signer` port, as `SignPayload::Bytes`) kept in CI artifacts, as OCI
    referrers of the shipped digest, or in a bucket the customer owns, so a
    `keepshipping log verify` to land can work offline. Hosted: a viewer
    storing copies of the same entries — entries are small, and summaries,
    not step logs.
  - `StateStore` — saved plans and parked-run state live only in storage the
    customer owns, addressed by digest. There is no hosted adapter for plan
    bytes, ever; the hosted side knows the digest and nothing more.
    Cratefield reinforces this: a 64 KiB body cap and GET-only signed URLs
    mean the venture cannot hand out upload URLs.
  - `BlockSource` — block content comes from the org's OCI registry by
    digest. The port is not written; the metadata contract beside it is, as
    `BlocksIndex` (`crates/core/src/ports/blocks.rs`) documents, and that is
    the hosted part ([#149](https://github.com/Keep-Shipping/harness/issues/149)),
    the model for the rest.
- Waiting needs no SSE. A run parked at `review` writes its plan and its state
  to the `StateStore` and exits, leaving the agent or runner free. Resuming is
  a new job that fetches the approval (CLI or CI locally; hosted: plain GET
  polling or a CI re-trigger), checks the digest binding, and applies.
- Sizes fit the caps by construction. Everything we send fits one 64 KiB
  request: summaries are rendered with `Limits::max_bytes =
  HOSTED_BODY_LIMIT`, and `full_plan_url` points at customer-owned storage
  which the hosted side never dereferences. Hosted list responses are
  paginated to stay under 1 MiB.
- The hosted services run as the Cratefield venture in
  [`ventures/keepshipping`](../../ventures/keepshipping) under
  [ADR 0200](0200-hosted-venture-on-the-cratefield-harness.md), which this
  ADR does not supersede: it sets the boundary, and implementation decisions
  go in the 0200 block.
- Egress is a closed allowlist — the lists below are exhaustive, and adding a
  field means amending this ADR. Identity travels as a CI OIDC token minted
  with the hosted service as audience, which the venture verifies: the GitHub
  Actions adapter says in so many words that it does not verify the token and
  that verification belongs to the server consuming the identity
  (`crates/cli/src/github_actions_run_context.rs`). That token is a credential
  for our service only, never a customer secret.

### What leaves the runner

Every request: the run id, a ULID minted by the runner's `IdGen`
(`crates/core/src/ports/id_gen.rs`); the repository `owner/name`, workflow
name and step name — none of which `RunContext` carries today
(`crates/core/src/ports/run_context.rs` has the actor, event, capabilities and
workspace), so the runner reads them from its own environment and workflow
file; `Actor.kind`, `Actor.display_name` and the `Establishment` variant, with
`issuer` and `subject` when it is `CiOidc` and a `marker` when it is
`Detected` — a variable name, never its value; the audience-bound OIDC token
when the runner has one (`RunContext::oidc_token`, a `SecretValue`); and the
event — `GitInfo.sha`, `GitInfo.git_ref`, and the `Trigger` variant with its
PR `number` or tag `name`.

An approval request: the plan digest; the gated step's `ActionClass` — its
`kind` and, when it has one, `env` (`crates/core/src/step.rs`); approver
handles such as `@platform`; and the masked `PlanSummary` — the `add`,
`change` and `destroy` counts, and the `risky` and `others` entries, each
with `kind`, `address`, `reason` and attributes `path`, `before`, `after`,
`forces_replacement`, masked once by `summarize` — bounded by
`HOSTED_BODY_LIMIT`; optionally `full_plan_url`. A per-environment setting
drops the detail to counts and addresses, without attribute values or
reasons, for projects that want the tighter shape; the wire format is
[#151](https://github.com/Keep-Shipping/harness/issues/151)'s.

An approval decision travels the other way — hosted to runner — and is
recorded as a run-log entry on arrival. What the hosted service holds for it:
`approved`, `by` (a handle) with the approver's verified identity, a
timestamp, the plan digest it binds, and its signature.

A run-log entry: sequence number; previous entry hash; run id; event kind —
proposed, approved, rejected, applied or shipped; plan digest; shipped
artifact digest; actor; timestamp; `Signature { bytes, identity }`
(`crates/core/src/ports/supply_chain.rs`).

A blocks search: the query's `text` and `limit` (`BlockQuery`,
`crates/core/src/ports/blocks.rs`). The answer is metadata, exactly the
fields of the existing contract — `GET {base}/v1/blocks/search` with
`results`, each entry `name`, `publisher` (`kind`, plus `issuer`/`subject`
for keyless or `key_id` for a named key), `readme` (optional), and `versions`
of `version`, `digest` and `signature` (`signed` or `unsigned`)
(`crates/cli/src/blocks_index.rs`).

### What never leaves the runner

- plan files and saved plan bytes — `PlanJson` and `ResourceChange`
  (`crates/core/src/ports/iac.rs`), unmasked; state files;
- customer secret values and the `SecretValue`s holding them, and secret
  resolver names (`crates/core/src/ports/secrets.rs`,
  [ADR 0001](0001-typed-values-and-secret-references.md)); the audience-bound
  OIDC token above is the one credential that does leave, and it is ours, not
  the customer's;
- environment variable values; a name may leave as an `Establishment`
  marker, its value may not;
- `Workspace` paths, `Capabilities`;
- step logs — `LogRecord` messages and fields (`crates/core/src/step.rs`) —
  and tool output;
- source and workflow file contents; block *content*. A block's `readme` in
  the index is publisher-supplied metadata already served by the index, not
  block content.

## Consequences
- Two paths to test. Each port gets a fake in `ks-testing`, and both adapters
  run the same contract tests; a local adapter passing them is not evidence
  the hosted one does.
- A hosted outage never blocks a ship, which is the property the local-first
  pitch is made of.
- Web and chat approvals, and views across repositories, exist only for teams
  that turn the hosted service on.
- The masked summary still reveals resource addresses and non-secret values to
  us. That is a real disclosure, bounded by the counts-and-addresses setting,
  not an oversight.
- Polling costs latency: a waiting run finds out on its next poll, not at the
  moment of the click.
- [#151](https://github.com/Keep-Shipping/harness/issues/151) turns the
  allowlist into a wire contract with golden tests, so a field added without
  amending this ADR fails there.
- Port contract changes need a changelog entry, per
  [CONTRIBUTING.md](../../CONTRIBUTING.md), when these traits land.