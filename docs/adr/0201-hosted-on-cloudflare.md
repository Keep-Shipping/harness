# ADR 0201: Hosted on Cloudflare

Status: proposed, 2026-10-08

## Context
The console — the approver's inbox ([#95](https://github.com/Keep-Shipping/harness/issues/95)),
run history, the hosted approval and notification side
([ADR 0005](0005-local-first-core-with-optional-hosted-services.md)) — needs
a home that is always on, and the criterion it must meet is the lock one:
**two applies on one module never run at once**, even across Worker
restarts and resumed workflows. Issue
[#175](https://github.com/Keep-Shipping/harness/issues/175) picks the
platform. Whatever it is must also run OpenTofu, keep every apply behind a
recorded approval, and never let a secret reach a log or a state file.

## Decision
Cloudflare, one account, mapped piece by piece onto the ports the harness
already declares:

| Cloudflare piece | Role | Harness port |
| --- | --- | --- |
| Worker + static assets, behind Cloudflare Access | the console's HTTP surface; Access fronts the human side | — (the venture's own entry point, [ADR 0200](0200-hosted-venture-on-the-cratefield-harness.md)) |
| D1 | fleet, runs, approvals, audit: the queryable half | `RunLog`/journal entries land here — the exportable audit |
| R2, S3-compatible, versioned, lockfile on | state backend: parked-run state and saved plans, addressed by digest | `StateStore` |
| Containers, started on demand by a Durable Object, one pinned image | `tofu`, `git`, `build-dist`, `wrangler` | `IacTool` (tofu), the build and script steps |
| Workflows | plan → `waitForEvent`(approval) → apply; the wait *is* the approval gate | park/resume durability (`StateStore`); `ApprovalChannel` and the `Verdict`'s who+when |
| Durable Object per (account, module) | the lock: one object serialises every run that would change that module | `RunLock` (new, `crates/core/src/ports/run_lock.rs`) — leases with expiry and fencing tokens |
| Workers secrets / Secrets Store | credentials injected per run, never logged, never written to state | `Secrets` + the run's `Redactor` |
| Cron-triggered Workflow, nightly | drift: plan, compare, report — never apply unattended | the same plan/approval shape, approval required before any apply |
| Owlpost | approver notifications | the hosted `ApprovalChannel` side of [ADR 0005](0005-local-first-core-with-optional-hosted-services.md) |

The lock deserves its own sentence: a Durable Object per (account, module)
is single-threaded, so its check-and-grant is atomic by construction; the
lease expires so a crashed run cannot wedge a module, and its fencing token
climbs so a workflow that resumed after a takeover cannot apply anyway. The
port carries that contract; this ADR only says which platform answers it.

- **Bootstrap** is the harness's own flow: the first apply of the console
  runs from a laptop via `keepshipping` — the local-first path of
  [ADR 0005](0005-local-first-core-with-optional-hosted-services.md) — and
  from then on the console manages itself through its own workflows. A
  break-glass runbook (Access bypass by two maintainers, logged) covers the
  case where the console cannot approve its own rescue.
- **Security**: one least-privilege Cloudflare token per account, minted per
  run and expired with it; every apply runs in a fresh container that sees
  only that run's credentials; every apply carries a recorded approval bound
  to the plan digest; the audit log (D1 + `RunLog` entries) is exportable
  and says who proposed, who approved and which digest shipped.

## Consequences
- The lock criterion is met by composition, not by a database advisory lock:
  the guarantee lives in one Durable Object whose only job is the lease.
- State stays in storage its owner controls
  ([ADR 0005](0005-local-first-core-with-optional-hosted-services.md)): the
  console manages the keepshipping fleet, whose R2 bucket sits in the same
  account; a fleet that wants its own backend keeps a local `StateStore`
  adapter and the console never holds its plan bytes.
- Workers, Workflows and Containers are all billed on demand — the console
  idles at near zero, which fits the early-access scale.
- Vendor concentration is real and accepted: the ports keep the engine
  portable, and a second hosted platform would be new adapters, not a
  rewrite.

**What this ADR does not yet deliver** (follow-ups to
[#175](https://github.com/Keep-Shipping/harness/issues/175)): the Durable
Object `RunLock` adapter, the plan → approval → apply Workflow, the
bootstrap tooling and break-glass runbook as written procedures, and the
test that proves a secret cannot reach a log. What exists today is the port
contract the adapter must satisfy, its in-memory fake and the conformance
kit in `ks-testing`.
