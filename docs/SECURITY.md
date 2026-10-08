# Security model

What Keep Shipping defends, who it defends it from, which control covers which
threat, and what is still open.

This document describes the design as it is today. Where a control is designed
but not yet wired, it says so and links the issue; a control that does not exist
yet is never written as though it does. It feeds
[#117](https://github.com/Keep-Shipping/harness/issues/117).

## What is worth defending

| Asset | Why it is worth something |
|---|---|
| Cloud and cluster credentials | A run that can assume a role can write to an account; a step handed the apply role can apply |
| Registry push rights | A push under a trusted image name is a supply-chain event |
| Secrets | The values themselves, and the fact that a step could hand one back |
| The integrity of what ships | The digest that reaches production came from this pipeline |
| The approval record | "A person looked at this" is a claim the engine makes in its own name |

The last two have no clean owner outside the engine. A credential belongs to a
cloud provider and a secret to whoever set it; what ships and who said yes to it
are this tool's own claims.

## Who we defend against

- **A malicious or confused coding agent.** It writes the `ship.ks`, reads the
  task, and may be wrong or steered. It is not treated as hostile code, but it
  is not treated as a person either.
- **A compromised dependency.** A block, a TypeScript step's dependency, an
  adapter crate. It runs inside the process or inside the step's sandbox.
- **A malicious pull request from a fork.** Code the organisation did not
  write, proposed by somebody it does not know.
- **An insider approving their own change.** A person with the rights to approve
  and a reason to.
- **A compromised hosted service.** The venture, a control plane, a forge.

## Trust boundaries

| Boundary | What crosses it | The rule |
|---|---|---|
| Laptop → CI | A run context: actor, workspace, OIDC | A local run can never be CI; a CI identity comes only from a minted OIDC token, and the binary builds no run context at all ([`run_context.rs`](../crates/core/src/ports/run_context.rs), see residual risks) |
| Runner → hosted service | An approval verdict, a baseline | The service may say *who decided*, never *who may* ([`hosted-approvals`](../adapters/hosted-approvals/src/lib.rs)) |
| Engine → step adapter | Ports | A step holds only the ports it declared ([`step.rs`](../crates/core/src/step.rs)) |
| Engine → TypeScript script | A subprocess | A Deno process with an explicit argv and no other permission flags ([`deno-script-host`](../adapters/deno-script-host/src/lib.rs)) |
| Repo file → org baseline | `policy:`, `auto:`, block publishers | The file may narrow, never widen ([`policy.rs`](../crates/core/src/policy.rs)) |

## A malicious or confused coding agent

| Threat | Control | Where |
|---|---|---|
| The agent writes itself an `auto:` that waves everything through | `auto_approves` conjoins the destroys guard whatever the file wrote, `guards_destroys` accepts only a top-level `and`, and an unreadable destroy count is an ask, not a zero. The checker reaches the rule as a `KS0701` warning on an `approval` step; no run path evaluates it yet | [`auto_rule.rs`](../crates/core/src/auto_rule.rs), [`check.rs`](../crates/core/src/check.rs), [#106](https://github.com/Keep-Shipping/harness/issues/106) |
| The agent hides a decision inside a comparison and approves on it | `resolve` checks provenance for every step the rule *actually read*, not the steps it mentions — as written, and unwired like the rule above | [`auto_rule.rs`](../crates/core/src/auto_rule.rs) |
| A decide step had no model, or the model call failed | `ks-jev` returns `Err` on every failure rather than an `escalate`, and `resolve` maps a missing or errored model to an ask. But no run populates `DecisionSource` today, and the engine's `decide` step turns `model: none` into an `escalate` at confidence 1.0 as ordinary outputs, and a model failure into a failed step | [`jev`](../adapters/jev/src/lib.rs), [`decide.rs`](../crates/engine/src/decide.rs), [#104](https://github.com/Keep-Shipping/harness/issues/104) |
| The agent reads secrets it was not issued | `ActorGatedSecrets` refuses a non-allowlisted reference to an agent run with `ForbiddenForActor`, but it is constructed only by its own tests. The gate a run does get is `PolicySecrets`, which refuses every reference when the baseline says `never: read secrets` — on `resume` (see residual risks) | [`secrets.rs`](../crates/core/src/ports/secrets.rs), [`policy_gate.rs`](../crates/engine/src/policy_gate.rs), [#103](https://github.com/Keep-Shipping/harness/issues/103) |
| A step returns a secret in its outputs | `reject_secret_outputs` runs before the schema check, over strings, numbers in `Display` form, list items, map keys and values, and the output names. A secret in a *value* is reported against its field name; an output *named* after a secret is reported as `<output name>` | [`step.rs`](../crates/core/src/step.rs), [#91](https://github.com/Keep-Shipping/harness/issues/91) |
| A secret reaches the log | `StepLog` redacts every message and every field name and value, and `RunEvent::redacted` scrubs every variant before `Journal::emit` appends; a failed append fails the step. Two gaps: `keepshipping approve` appends its approval events straight to the JSONL log with no redactor, and the CLI's script-step logger holds an empty one | [`journal.rs`](../crates/engine/src/journal.rs), [`step.rs`](../crates/core/src/step.rs), [`approve.rs`](../crates/cli/src/approve.rs), [#46](https://github.com/Keep-Shipping/harness/issues/46) |
| A script step in production without an `action:` | An agent's run refuses to start over such a step in `prod` or `production`, unless an `approval` step that will actually run reaches it through the graph. `keepshipping run` enforces this; `keepshipping resume` does not check it | [`main.rs`](../crates/cli/src/main.rs), [`script_step.rs`](../crates/core/src/script_step.rs), [#89](https://github.com/Keep-Shipping/harness/issues/89) |
| The agent claims to be a human | `--as agent` names an agent and `ActorBaseline` carries the org's agent list and its `require_human` rule, but every call site passes `ActorBaseline::default()`, so the list is empty in the binary today. `Establishment::CiOidc` is the only strong identity, and no binary path builds the run context that would mint one; `detect_local_actor` never answers `Ci`, though `--as ci` sets the actor directly (see residual risks) | [`actor.rs`](../crates/cli/src/actor.rs), [`run_context.rs`](../crates/core/src/ports/run_context.rs), [#119](https://github.com/Keep-Shipping/harness/issues/119) |

## A compromised dependency

| Threat | Control | Where |
|---|---|---|
| A block from an unknown publisher | Only identities in the org baseline's publisher list are trusted, compared exactly; unverifiable is refused, with no third "probably fine" case. `verify` is written and has no call site yet (see residual risks) | [`block_trust.rs`](../crates/core/src/block_trust.rs), [#84](https://github.com/Keep-Shipping/harness/issues/84) |
| A block that declares its own policy | Refused by the checker (`KS0405`) | [`check.rs`](../crates/core/src/check.rs) |
| A TypeScript step reaching past the workspace | Pinned Deno by version *and* archive sha256; `--allow-read` limited to the workspace, the embedded bootstrap and the secrets FIFO; `--allow-env`, `--allow-write`, `--allow-run`, `--allow-ffi`, `--allow-sys` are all absent; network only to the hosts the step's own source declares | [`deno-script-host`](../adapters/deno-script-host/src/lib.rs), [ADR 0009](adr/0009-typescript-escape-hatch-runtime.md) |
| A symlink inside the workspace pointing out of it | The walk hands every escaping link to `--deny-read`; unresolvable links are denied, not trusted; a link whose path contains a comma cannot be spelled as a deny grant, and refuses the run instead | [`deno-script-host`](../adapters/deno-script-host/src/lib.rs) |
| A step with a manifest but no lockfile | Refused; `--frozen-lockfile` otherwise | [`deno-script-host`](../adapters/deno-script-host/src/lib.rs) |
| A Rust dependency with a known advisory | `cargo deny` in CI; unknown registries and unknown git sources denied | [`deny.toml`](../deny.toml) |
| The adapter crate itself | Nothing — adapters are statically linked and run in-process | see residual risks |

`ks-jev` is the shape a decision adapter is expected to take: a pinned model,
three attempts by default (`with_retry` can raise the count and the wait cap),
a bounded wait that a hostile `Retry-After` cannot extend, an answer checked
against the question that asked it, and an API key read inside `with_bytes` and
named in no message
([`jev`](../adapters/jev/src/lib.rs),
[#105](https://github.com/Keep-Shipping/harness/issues/105)).

## A malicious pull request from a fork

The answer the classifier gives is short: **a fork run reads no secret, applies
nothing, and checks only.** Nothing in the binary enforces it yet — see residual
risks. GitHub already withholds secrets from `pull_request` runs of forks, hands
them a read-only `GITHUB_TOKEN`, and mints no OIDC token; the harness answers
the same question itself, so that what a run may do does not rest on which
trigger a workflow file happened to pick:

```rust
let origin = ks_github::Origin::of(event_name, &payload);
origin.may_read_secrets();  // false for a Fork
origin.may_apply();         // false for a Fork
origin.check_only();        // true  for a Fork
```

The GitLab adapter and generic `--ci` mode answer the same question from their own
variables, and both fail closed — see [GITLAB_CI.md](GITLAB_CI.md) and
[CI.md](CI.md). The rules below are GitHub's, read from the event payload:

[`fork.rs`](../adapters/github/src/fork.rs) classifies:

- The four PR-family events — `pull_request`, `pull_request_target`,
  `pull_request_review`, `pull_request_review_comment` — each carry the pull
  request, and each compares `pull_request.head.repo` with
  `pull_request.base.repo` **by id**, falling back to a case-insensitive
  `full_name` only when an id is missing on either side. A
  deleted-and-recreated repository under one name is two repositories.
- Within those events, anything that will not compare — no `pull_request`
  object, a null `head.repo` (a deleted fork), no usable id or name — reads as
  `Fork`.
- Every other event (`push`, `workflow_dispatch`, `schedule`, `merge_group`,
  `issue_comment`, …) is `Repository` whatever its payload says, because the run
  executes a ref of this repository. The four above are all the PR-family
  events GitHub has, so the list is closed today; a new one would have to be
  added before it was judged by the head.
- `head.repo.fork` is deliberately never read — it is true for a same-repo pull
  request whose *base* is itself a fork.
- `pull_request_target` is judged like `pull_request`: it runs the base's
  workflow with the base's secrets, but builds the head's code.

Rules and examples are in [`tests/fork.rs`](../adapters/github/tests/fork.rs). Two
things follow, and neither is the classification's job:

- Do not write a `pull_request_target` or `issue_comment` workflow that checks
  out the PR head. That run has the base's secrets and the attacker's code. The
  classification reads the event payload, never the checkout.
- `Origin` is **not yet wired**, and nothing in the binary reaches it: the
  Actions run context is `#[allow(dead_code)]` and the CLI builds no run
  context at all ([`github_actions_run_context.rs`](../crates/cli/src/github_actions_run_context.rs)
  does not depend on this crate). This section is a latent concern that applies
  once that context exists. See residual risks.

## An insider approving their own change

| Threat | Control | Where |
|---|---|---|
| Approving your own run | `ApprovalRequest::accepts` refuses `approver == proposed_by`, refuses a non-human approver, and refuses a verdict bound to different artifacts — in the core port, and no adapter implements around it. The engine calls it from `denial::decide`, which has no call site of its own yet (see residual risks) | [`approval.rs`](../crates/core/src/ports/approval.rs) |
| Approving a plan that changed under you | The approval binds the exact digests; a resume re-hashes `ship.ks`, re-checks every approval's expiry, and re-checks that each still covers the digests the run holds | [`state.rs`](../crates/engine/src/state.rs), [#42](https://github.com/Keep-Shipping/harness/issues/42), [#121](https://github.com/Keep-Shipping/harness/issues/121) |
| An approval from a comment the attacker wrote | The adapter ignores a proposer, a bot, or a non-member; a failed membership lookup counts as *not a member* and the run stays parked | [`github`](../adapters/github/src/lib.rs), [#96](https://github.com/Keep-Shipping/harness/issues/96) |
| An agent approving with `--as ada` | `keepshipping approve` has no `--as`; the name is a log label, not a credential | [`approve.rs`](../crates/cli/src/approve.rs), [#95](https://github.com/Keep-Shipping/harness/issues/95) |
| A member of nobody on the team | A separate `Directory::is_member` lookup in the same `decide`; a roster failure is an error, never a refusal | [`denial.rs`](../crates/engine/src/denial.rs) |
| Holding a runner open for a night | A run parks at the approval and a later job resumes it from the ticket | [#97](https://github.com/Keep-Shipping/harness/issues/97) |

## A compromised hosted service

The hosted approval adapter holds tickets in memory and carries two transports
(a web review form over a caller-minted session, and a Slack interaction). It
decides **who decided**, never **who may**: the engine's `denial::decide` runs
`accepts` and the `Directory` lookup itself, on every verdict including
refusals, so a service that answers with a confident `approved` releases
nothing. The first decision wins; nobody deciding is `Ok(None)`, never an
approval. `decide` has no call site yet, so today that is a property of the
library rather than of a shipped path.

A Slack user's identity is their immutable Slack id, and the request signature
is verified by the adapter itself, with a five-minute replay window. A web
approver is a session, never a form field — though that invariant is caller
discipline today, not a type-level guarantee, and there is no GitHub sign-in in
this tree to mint such a session yet.

Nothing in this repository stores a hosted credential. The waitlist venture
holds its own (`TURNSTILE_SECRET`, `OWLPOST_API_KEY`, `RESEND_API_KEY`). Only
the captcha closes: with no `TURNSTILE_SECRET` no captcha port is bound, and the
waitlist module refuses joins in `ENV=production`. The mail secrets are open by
design — with no mail key the join is still captured as `pending` and no mail
is sent. Its origin guard is a browser-CORS convenience restated as a refusal:
a CORS layer only adds headers and never rejects a request, so the writes are
refused before the handler runs on their own. It reads the `Origin` header only,
so it stops cross-origin browser writes, not a scripted client.

## Policy, credentials and the shipped artifact

- Effective policy is the org baseline intersected with the file's `policy:`
  block, the stricter answer winning, with a hard rule outside the intersection:
  a destroy never reaches an agent as an allow
  ([`policy.rs`](../crates/core/src/policy.rs)). Only `resume` enforces that
  intersection; `run` sees the file's own `policy:` and nothing else. The
  step-boundary and secrets-port gates are written and have no call site yet
  ([`policy_gate.rs`](../crates/engine/src/policy_gate.rs),
  [#101](https://github.com/Keep-Shipping/harness/issues/101),
  [#103](https://github.com/Keep-Shipping/harness/issues/103),
  [ADR 0012](adr/0012-policy-authority.md)).
- A cluster target names an authentication method and has no field a token could
  live in; a record carrying an inline credential is refused before anything
  else is read ([`k8s.rs`](../crates/core/src/k8s.rs),
  [#75](https://github.com/Keep-Shipping/harness/issues/75)).
- Per-step `role:` with OIDC; the run log records the role, never the token
  ([CREDENTIALS.md](CREDENTIALS.md), [#71](https://github.com/Keep-Shipping/harness/issues/71)).
- Registry digests are computed from bytes or read off the registry, never
  asserted by the caller; credential helpers are refused rather than run; a
  breaking release inside a published release line is refused
  ([`oci-distribution`](../adapters/oci-distribution/src/lib.rs),
  [`blocks_publish.rs`](../crates/cli/src/blocks_publish.rs),
  [#82](https://github.com/Keep-Shipping/harness/issues/82)).
- Attestations are in-toto statements signed as DSSE envelopes over the exact
  canonical bytes, keyed to the image digest
  ([`attestation.rs`](../crates/engine/src/attestation.rs)). Linking digest →
  run → commit → `ship.ks` is
  [#114](https://github.com/Keep-Shipping/harness/issues/114), and refusing in
  production anything that did not come from a signed digest of this pipeline is
  [#113](https://github.com/Keep-Shipping/harness/issues/113).
- The run log is a hash-chained JSONL file with `keepshipping log verify`
  ([`run_log.rs`](../crates/cli/src/run_log.rs)).

## Residual risks

Stated plainly. Each is a real limit, not a caveat with a plan attached.

- **`Origin` is not enforced, and nothing reaches it.** The Actions run context
  is `#[allow(dead_code)]` and the CLI builds no run context, so a fork run's
  guarantees rest entirely on GitHub withholding secrets and the OIDC token. So
  do the identity claims: that module decodes the token and takes its claims at
  face value, so `Strong` means "came from GitHub's token endpoint", not
  "verified". A consumer resting access control on this identity must check the
  JWKS itself ([`github_actions_run_context.rs`](../crates/cli/src/github_actions_run_context.rs),
  [#150](https://github.com/Keep-Shipping/harness/issues/150)).
- **The org baseline is enforced on `resume`, not on `run`.** `resume` is the
  only caller that builds a `PolicyGate` and runs `preflight`; `keepshipping run`
  builds none and gates only on the file's own `policy:`. Until a run gates on
  the baseline, `Baseline::conservative`'s `never: read secrets` and its destroy
  refusal are properties of `resume` alone ([`resume.rs`](../crates/cli/src/resume.rs),
  [`main.rs`](../crates/cli/src/main.rs),
  [#101](https://github.com/Keep-Shipping/harness/issues/101)).
- **The run log's tip is unsigned.** The chain catches an edit, a deletion or a
  reorder inside it; it cannot catch a truncation from the end or a writer that
  recomputes the chain ([#112](https://github.com/Keep-Shipping/harness/issues/112)).
- **No cross-process lock.** Two approvals landing at once can fork the chain,
  and the state read-modify-write takes no lock
  ([`approve.rs`](../crates/cli/src/approve.rs)).
- **No `PolicyStore` adapter.** Unconfigured, `resume` applies the built-in
  conservative baseline: secrets and destroys are `never` for everyone,
  everything else asks — except that an agent is explicitly allowed `check`,
  `build` and `plan`. It is a good default and it is not the organisation's
  policy ([`ports/policy.rs`](../crates/core/src/ports/policy.rs)).
- **`--actor ci` is accepted from a laptop.** It never yields a strong
  establishment and cannot widen the baseline. It is also latent rather than
  live: `subject_for` folds `Ci` into `Human`, so a CI-declared actor reads the
  same `policy:` section a person would ([`args.rs`](../crates/cli/src/args.rs),
  [`actor.rs`](../crates/cli/src/actor.rs),
  [`policy.rs`](../crates/core/src/policy.rs)).
- **Block trust has no call site yet.** `block_trust::verify` is written and
  unreachable; nothing resolves a block
  ([`block_trust.rs`](../crates/core/src/block_trust.rs)).
- **The engine's approval decision path has no call site yet.**
  `denial::decide` — which runs `accepts` and the membership lookup — is
  written and unreachable; the CLI's approval paths approve without it
  ([`denial.rs`](../crates/engine/src/denial.rs),
  [`approve.rs`](../crates/cli/src/approve.rs)).
- **Adapter crates are in-process.** `cargo build` puts them in the same address
  space as the engine. A compromised adapter is a compromised run; the port
  boundary is a discipline, not a sandbox.
- **A step error message bypasses the redactor.** `StepError` text reaches
  diagnostics verbatim, so an adapter that embeds a secret value in an error
  leaks it. The built-in adapters do not; a third-party one might
  ([`step.rs`](../crates/core/src/step.rs)).
- **Non-UTF-8 secret values are skipped by the redactor** rather than matched,
  and zeroisation is best-effort: `SecretValue`'s `Drop` overwrites its own
  allocation without `unsafe`, but not the copies the allocator made while the
  `Vec` grew ([`secrets.rs`](../crates/core/src/ports/secrets.rs),
  [#49](https://github.com/Keep-Shipping/harness/issues/49)).
- **`check` runs module bodies.** The check-time extractor imports the step's
  module under a bare host `node` — no sandbox, no permission model, ten-second
  timeout — because reaching the descriptor costs an import
  ([`scripts.rs`](../crates/cli/src/scripts.rs)). Checking a repository runs code
  from it.
- **The Deno sandbox's stated limits.** A workspace an attacker can write to
  while a step runs is not a sandbox this flag makes sound; the walk sees
  symlinks only, not hardlinks or bind mounts; non-Linux is refused rather than
  verified ([`deno-script-host`](../adapters/deno-script-host/src/lib.rs)).
- **An approval binds artifacts; it does not make a person read them.** The
  binding is exact and the approver is checked, but nothing in the design makes
  a careless human careful.
- **The production script-step gate is not checked on resume.**
  `keepshipping run` refuses an agent's run over an unapproved script step in
  `prod`; `keepshipping resume` drives the remaining steps without asking
  ([`script_step.rs`](../crates/core/src/script_step.rs),
  [#89](https://github.com/Keep-Shipping/harness/issues/89)).
- **`keepshipping run` does not execute steps yet**
  ([#45](https://github.com/Keep-Shipping/harness/issues/45)). Several controls
  above — `Origin` among them — are built and tested under a path the CLI does
  not yet drive.

## Reporting a vulnerability

Report privately, not in an issue. Email
[contact@keepshipping.run](mailto:contact@keepshipping.run).

That address is the published channel. It is what
[`https://keepshipping.run/.well-known/security.txt`](https://keepshipping.run/.well-known/security.txt)
carries (`Contact: mailto:contact@keepshipping.run`,
`Expires: 2027-09-23T00:00:00.000Z`, `Preferred-Languages: en`), and the file
names no other one. If the repository has private vulnerability reporting
switched on, its
[advisory form](https://github.com/Keep-Shipping/harness/security/advisories/new)
reaches the same mailbox; email works either way.

What helps: the version or commit, the `ship.ks` and the step, what the attacker
controls, and what they got. What to expect: an acknowledgement, then a fix or
a plain statement of why the report is not one.

## See also

- [CREDENTIALS.md](CREDENTIALS.md) — per-step cloud roles and OIDC
- [GITHUB_APPROVALS.md](GITHUB_APPROVALS.md) — the approval flow and its adapters
- [CLUSTERS.md](CLUSTERS.md) — what a cluster target may name
- [REGISTRIES.md](REGISTRIES.md) — digests, attestations and the honesty rule
- [ADR 0005](adr/0005-local-first-core-with-optional-hosted-services.md) — local core, optional hosted services
- [ADR 0008](adr/0008-github-actions-first.md) — running inside a CI system
- [TELEMETRY.md](TELEMETRY.md) and [ADR 0015](adr/0015-telemetry-policy.md) — no telemetry ships, and what a payload may contain if it ever does
- [ADR 0009](adr/0009-typescript-escape-hatch-runtime.md) — the script sandbox and its limits
- [ADR 0012](adr/0012-policy-authority.md) — a workflow file is a claim, not a control