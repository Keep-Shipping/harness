# Ports

A port is a trait a step asks for and never implements
([ADR 0002](adr/0002-ports-and-adapters.md)): `ks-core` declares the traits in
[`crates/core/src/ports/`](https://github.com/Keep-Shipping/harness/tree/main/crates/core/src/ports),
an adapter crate outside this workspace is the only code that knows how to
answer one for a particular vendor, and
[`HarnessBuilder::build`](https://docs.rs/ks-core) hands each step only the
ports it declared. The module's own documentation carries the inventory of
which ports exist today — this page does not repeat it.

What this page records is the **contract version**. `ks_core::STEP_API`
versions the port traits alongside the `StepKind` trait
([ADR 0014](adr/0014-release-and-contract-versioning.md)), and the harness
refuses to compose a step built against a different one. A fingerprint of the
port trait signatures is pinned against `STEP_API` in
`crates/testing/tests/compatibility.rs`, so changing a trait without bumping
the version fails CI rather than landing as a silent break. The generated
compatibility table is [COMPATIBILITY.md](COMPATIBILITY.md).

Adding a port, adding a method to one, or changing a signature is a contract
change: bump `STEP_API` in `crates/core/src/version.rs`, add a `## STEP_API`
entry below, update the pinned digest in the compatibility test, and
regenerate `COMPATIBILITY.md` with
`KS_BLESS=1 cargo test -p ks-testing --test compatibility`. Reformatting and
comment edits do not need any of that — the fingerprint normalises them away.

## Port reference

One row per port trait, verified against `crates/core/src/ports/`. **In `Port`**
is the question that matters to a step author, and it is checked here against
the `Port` enum and the `define_ports!` list in
`crates/core/src/step.rs`, which must agree in order: a step can only declare a
port that has a variant. The kit is the port's conformance function in
`ks-testing` — most are named `conformance`, but the two supply-chain ones are
`registry_conformance` and `signer_conformance`, and a few take extra arguments
beyond the trait (`cluster::conformance` a name and a manifest, `iac::conformance`
a directory). `—` means the module ships fakes but no kit. The implementor is
the in-tree `impl` of the trait.

### Ports a step can declare

| Trait | For | In `Port` | Kit | Implementor |
|---|---|---|---|---|
| `RunContext` | who and where a run is | yes | `run_context::conformance` | `ks-cli`'s `GithubActionsRunContext` |
| `Secrets` | resolving named secrets, redacting values | yes | `secrets::conformance` | core's `ActorGatedSecrets`, the engine's `PolicySecrets` |
| `ImageBuilder` | building a container image | yes | — | — |
| `Registry` | pushing and pulling by digest | yes | `supply_chain::registry_conformance` | `ks-oci-distribution` |
| `Signer` | signing, attestations, digests | yes | `supply_chain::signer_conformance` | — |
| `IacTool` | planning and applying infrastructure | yes | `iac::conformance` | `ks-tofu-cli` |
| `HttpClient` | bounded, policy-checked HTTP | yes | `http::conformance` | `ks-cli`'s `TcpHttpClient` |
| `Clock` | time and sleeping | yes | `clock::conformance` | `ks-cli`'s `SystemClock` |
| `IdGen` | minting fresh run ids | yes | `id_gen::conformance` | — |
| `ScriptHost` | running TypeScript escape-hatch steps | yes | `script_host::conformance` | `ks-deno-script-host` |
| `ApprovalChannel` | asking a team for approval | yes | `approval::conformance`, which takes the channel, a `Directory`, a team and an approver, and so covers `Directory` too | `ks-hosted-approvals`, `ks-github` |
| `Cluster` | applying manifests and watching rollouts | yes | `cluster::conformance`, which takes a name and a manifest | `ks-helm-cli` |
| `RemoteShell` | commands on a host the harness does not own | yes | `remote_shell::conformance` | — |
| `FunctionHost` | publishing a version, shifting traffic | yes | `function_host::conformance` | — |
| `DecisionModel` | asking a model a judgement it cannot be handed | yes | `decision_model::conformance` | `ks-jev` |

### Engine- and CLI-only ports

No `Port` variant, so no step can hold one and `STEP_API` does not move when
one changes. The **Implementor** column says which crate ships the one that
runs in production.

| Trait | For | Implementor | Kit |
|---|---|---|---|
| `BlocksIndex` | the metadata-only blocks index | CLI's `HostedBlocksIndex` | — |
| `BlockSource` | block content, resolved and fetched by digest | — | `block_source::conformance` |
| `PolicyStore` | the org baseline policy, read from outside the repository | — | `policy::conformance` |
| `RunLog` | the append-only record of what a run did | CLI's `JsonlRunLog` | — |
| `StateStore` | a parked run's state and its saved plans | engine's `LocalStateStore` | `state_store::conformance` |
| `ApprovalInbox` | the approver's side: what is waiting for me, and here is my answer | — | `approval::inbox_conformance`, which takes a channel and an inbox |

`health` is not a port: `crates/core/src/ports/health.rs` holds only the
`Health` / `HealthReport` vocabulary the deploy-target ports report in.

Writing an adapter? [STEP-AUTHORING.md](STEP-AUTHORING.md) has the crate shape
and the test-file pattern; changing one of the traits above? The changelog
below is where it goes.

## Changelog

Newest first, one heading per contract version, dated.

## STEP_API 6

- **2026-10-08** — `RunLock`
  ([#175](https://github.com/Keep-Shipping/harness/issues/175)) added, in
  [`crates/core/src/ports/run_lock.rs`](../crates/core/src/ports/run_lock.rs):
  mutual exclusion of runs that change one (account, module), as a lease —
  `acquire`, `renew` and `release` over a `Lease` carrying an expiry and a
  fencing token strictly increasing per key across every grant, so a run whose
  workflow resumed after its lease expired and was taken over acts with a
  lower token and is refused by whatever the lease guards. Re-acquire by the
  live holder is idempotent (the Worker restarted mid-run and the workflow
  resumes); a lapsed lease goes to the next taker at a higher token. Like
  `BlockSource`, `PolicyStore` and `ApprovalInbox`, it is engine/CLI-only —
  the engine holds it across plan-through-apply, a step never sees it — so it
  is in neither `Port` nor `define_ports!`, and no step-facing surface
  changed. The fingerprint covers every trait in `ports/`, so the digest is
  re-pinned under `STEP_API 6` without a bump.

- **2026-10-08** — `Event` gained `provenance`
  ([#126](https://github.com/Keep-Shipping/harness/issues/126)), with a
  [`Provenance`](https://github.com/Keep-Shipping/harness/blob/main/crates/core/src/ports/run_context.rs)
  enum beside it in
  [`crates/core/src/ports/run_context.rs`](../crates/core/src/ports/run_context.rs):
  where the code a run is *about* came from, as distinct from
  [`Establishment`](https://github.com/Keep-Shipping/harness/blob/main/crates/core/src/ports/run_context.rs),
  which says who is running it. `Repository`, `Fork` and `Target`
  (`pull_request_target`, `workflow_run` and `merge_group` — the events a
  privileged workflow follows untrusted code on) — the last two answer
  `is_untrusted()`. A push to the
  default branch and a fork pull request are both a `Ci` actor with an OIDC
  identity from GitHub's OIDC endpoint (which the adapter does not verify the
  signature of), and they are not the same amount of trust: the second runs a
  `ship.ks` somebody outside the organisation wrote, so a policy that gated on
  identity alone would hand it repository secrets and a cloud credential. The
  default is `Repository`, but the only value that grants those capabilities is
  the one an adapter has to claim affirmatively, so a missing value fails
  closed. This is source-breaking for anyone constructing an `Event` literally,
  so it is recorded here rather than landed as a silent change; `Event` is data
  a step reads rather than a trait it implements, so no trait signature moved
  and the fingerprint — which covers `pub trait` blocks in `ports/` — is
  unchanged, and it stays pinned under `STEP_API 6` rather than forcing a bump
  for a field the gate cannot see.

- **2026-10-08** — `ApprovalInbox`
  ([#95](https://github.com/Keep-Shipping/harness/issues/95)) added, in
  [`crates/core/src/ports/approval_inbox.rs`](../crates/core/src/ports/approval_inbox.rs):
  the approver's end of an approval, next to `ApprovalChannel` — what is
  waiting for me (`pending`) and here is my answer (`decide`). The inbox builds
  the `Verdict` itself, bound to the request's own artifacts, and checks it
  with `ApprovalRequest::accepts` before handing it over, so a proposer
  clicking approve on their own run fails at the click; a run with nothing
  open against it is the new `ApprovalError::NoOpenRequest`, which
  `ApprovalError` gained here. Like `BlockSource` and `PolicyStore` below, it
  is engine/CLI-only — the CLI holds the approver's side, so a run's author
  cannot reach it — and it is in neither `Port` nor `define_ports!`, so no
  step-facing surface changed and `STEP_API` does not move. The fingerprint
  covers every trait in `ports/`, so the digest is re-pinned under
  `STEP_API 6` without a bump.

- **2026-10-07** — [`ScriptHost::run`](https://github.com/Keep-Shipping/harness/blob/main/crates/core/src/ports/script_host.rs)
  takes a fourth argument, `log: &StepLog`
  ([#91](https://github.com/Keep-Shipping/harness/issues/91)): a script's log
  frames now go to the step's own redacting logger, so they pass through the
  run's [`Redactor`](https://github.com/Keep-Shipping/harness/blob/main/crates/core/src/ports/secrets.rs)
  exactly as a built-in step's lines do, and a script that logs a secret it
  revealed prints `***`. This closes the log side of the existing contract —
  secrets already reached scripts over a dedicated file descriptor, never
  argv, the environment or stdio — so an adapter no longer has to get
  redaction right on its own or not at all. The change is breaking for every
  `ScriptHost` implementor, which is why `STEP_API` moves.

  The other half is in the engine rather than the port: every step's outputs
  go through `reject_secret_outputs`, which fails the step
  (`InvalidOutput`) if a value the run resolved appears anywhere in them,
  including inside a longer string. Returning a secret is refused rather than
  redacted, because an output feeds wiring, cache keys and the run log, where
  a masked value helps nobody. Nothing about which ports exist changed, so
  `Port` and `define_ports!` are untouched.

## STEP_API 5

- **2026-10-07** — Additive: the `RemoteShell` port gained
  [`connect`](https://github.com/Keep-Shipping/harness/blob/main/crates/core/src/ports/remote_shell.rs)
  ([#76](https://github.com/Keep-Shipping/harness/issues/76)), opening a
  shell to a second pinned host over the same transport and credentials as
  the adapter's configured host. Each `connect` checks the caller-supplied
  [`HostKey`]; an unknown or mismatched host is
  [`ShellError::Unreachable`](https://github.com/Keep-Shipping/harness/blob/main/crates/core/src/ports/remote_shell.rs)
  / [`ShellError::HostKeyMismatch`], never accepted on trust (no TOFU). No
  existing method changed shape; `run`, `copy`, `probe` and `host` are as
  declared under `STEP_API 4`. The fingerprint covers every trait in
  `ports/`, so the digest is re-pinned under `STEP_API 5`.

## STEP_API 4

- **2026-10-07** — Breaking: the [`Cluster`](https://github.com/Keep-Shipping/harness/blob/main/crates/core/src/ports/cluster.rs)
  port's `upgrade` no longer takes a release *name*
  ([#74](https://github.com/Keep-Shipping/harness/issues/74)). A name cannot
  express "install this chart at this digest with these values", so the
  signature is now `fn upgrade(&self, request: &ChartUpgrade)`, and a
  `ChartUpgrade` carries the whole request: a `Chart` — an `ImageRef` by
  **digest** for an OCI chart, or a directory or packaged `.tgz` for a `Path` —
  an optional `namespace`, a `Values` document, a `--set` map, and an optional
  `ImagePin` that writes the container image's digest into the chart's values
  at a configurable key (`image.digest` by default).

  `Values` carries the security contract, which is why it is a type rather
  than a `String`: values built with `Values::secret` MUST be handed to the
  chart tooling by a temporary file with `0600` permissions, deleted once the
  call returns, and MUST NOT appear on a command line where another process
  could read them. A `set` entry is passed as a `--set` *argument*, so it must
  not carry a secret.

  `upgrade` is also now explicitly install-or-upgrade — an adapter installs a
  release the cluster does not have — and must roll back rather than report
  failure when an upgrade would leave the cluster worse than it found it.

  **Breaking for adapters**: every `impl Cluster` must be recompiled and its
  `upgrade` updated to read the request off `ChartUpgrade`.

- **2026-10-07** — Breaking: the "digest, never a tag" promise above is now
  enforced rather than documented. `ImagePin::new` returns
  `Result<Self, ClusterError>` (it was infallible) and both it and
  `ImagePin::at` reject a tag with the new `ClusterError::NotPinned { what }`;
  `Chart::oci(..) -> Result<Chart, ClusterError>` does the same for an OCI
  chart. `Values` no longer derives `Debug` — its hand-written one redacts the
  document, so an `assert_eq!` on a `ChartUpgrade` cannot print a secret.

## STEP_API 3

- **2026-10-08** — Additive: the `Port` enum gained a `DecisionModel` variant
  ([#104](https://github.com/Keep-Shipping/harness/issues/104)), so the
  `decide` step can declare and receive the port its trait has had since
  `STEP_API 2`. `DecisionModel` itself is untouched — the same `ask` and
  `profile` signatures, and the same `RedactedState` — so this is the
  `Port`/`define_ports!` half of the contract only, and the fakes in
  `ks-testing` work against it unchanged. The variant is optional for a step:
  `decide` with `model: none` declares it optional and never reaches for it,
  and a step that names a model with no adapter wired fails rather than
  defaulting.

## STEP_API 2

- **2026-10-07** — `BlockSource` and `PolicyStore`
  ([#56](https://github.com/Keep-Shipping/harness/issues/56)) added, both
  engine/CLI-only: `BlockSource` is how an online command resolves a block
  reference and fetches its content by digest, and `PolicyStore` is how the
  org baseline policy is read from outside the repository
  ([ADR 0012](adr/0012-policy-authority.md)). Neither is in `Port` nor in
  `define_ports!`, so `check` stays offline and no step can hold either, and
  `STEP_API` does not move. The fingerprint covers every trait in `ports/`,
  so the digest is re-pinned under `STEP_API 2` without a bump.

- **2026-10-07** — Additive: the [`StateStore`](https://github.com/Keep-Shipping/harness/blob/main/crates/core/src/ports/state_store.rs)
  port joined the contract
  ([#42](https://github.com/Keep-Shipping/harness/issues/42)), carrying a
  parked run's state and its saved plans. `StateStore` has two methods, `put`
  and `get`, both scoped to a `RunId` and a key the port validates
  (`check_key`), so no key can address anything outside its own run
  directory. Nothing existing changed shape, and no step sees the port: the
  engine uses the store directly, so `Port` and `define_ports!` are
  untouched. The remaining ports are as declared above.

- **2026-10-07** — Added the `DecisionModel` trait
  ([#54](https://github.com/Keep-Shipping/harness/issues/54)), in
  [`crates/core/src/ports/decision_model.rs`](../crates/core/src/ports/decision_model.rs).
  One `ask` call carries one `RedactedState` and a `BTreeMap<String, Question>`,
  and answers with `BTreeMap<String, Answer>` — so the model sees one picture and
  the answers are consistent with each other. `DecisionModel` also declares
  `profile()`, returning a `ModelProfile` naming the model, its pinned version,
  its calibration family and its `max_state_bytes` truncation bound.

  Like `BlocksIndex` before it, this is a trait plus fakes and a conformance
  kit: there is **no `Port` enum variant yet**, so a step cannot declare it and
  a harness cannot hand one to a step. The trait is versioned now so that adding
  the variant later is not itself a contract change.

- **2026-10-07** — Added the `ApprovalChannel` and `Directory` ports
  ([#53](https://github.com/Keep-Shipping/harness/issues/53)), so a run can ask
  a team and the engine can tell who was on it. `ApprovalChannel` requests,
  polls and waits; `Directory` answers membership. No existing trait signature
  changed — the ten ports from `STEP_API 1` are untouched, and `BlocksIndex`
  still is. The new `Port` variants `ApprovalChannel` and `Directory` are the
  only additions to the enum.

  The rule they encode: an approval is bound to the exact artifacts it was
  asked about, and a run can never approve itself. `ApprovalRequest::accepts`
  refuses an approver who proposed the run, an approver who is not human, and
  a verdict whose `bound_artifacts` differ by one digest — enforced in the
  engine, not in each adapter, so the same rule holds for every channel.
  Membership is checked separately, asynchronously, through `Directory` —
  and it is the verdict's own `approver` that gets looked up, never the
  approver the caller hoped for. The adapter conformance kit in `ks-testing`
  checks exactly that: an adapter that answers with somebody else's verdict,
  or binds a verdict to different artifacts, fails the kit rather than
  shipping.

- **2026-10-07** — The deploy-target ports
  ([#52](https://github.com/Keep-Shipping/harness/issues/52),
  [#78](https://github.com/Keep-Shipping/harness/issues/78)). Four modules land:
  the `Cluster` port (`apply`, `upgrade`, `rollout`, `health`, `rollback`,
  `handle`), the `RemoteShell` port (`run`, `copy`, `probe`, `host`), the
  `FunctionHost` port (`publish`, `shift`, `health`, `keep_warm`, `rollback`,
  `pinned`, `pin_is_detectable`), and the shared `Health` / `HealthReport`
  vocabulary they all report in. The three traits added to the port contract
  are `Cluster`, `RemoteShell` and `FunctionHost`; `health` adds no trait, only
  the value types every health call returns.

## STEP_API 1

- **2026-10-07** — The initial port contract
  ([ADR 0014](adr/0014-release-and-contract-versioning.md)). The port traits
  as declared in `crates/core/src/ports/` at this version are `RunContext`,
  `Secrets`, `ImageBuilder`, `Registry`, `Signer`, `IacTool`, `HttpClient`,
  `Clock`, `IdGen`, `ScriptHost` and `BlocksIndex`. `STEP_API` moved from
  `crates/core/src/step.rs` to `crates/core/src/version.rs`, which is now the
  single home for the three public contract versions; `ks_core::step::STEP_API`
  still resolves. Any later change to a port trait adds a `## STEP_API 2`
  heading above this one and bumps the constant.
- **2026-10-07** — `RunLog` ([#46](https://github.com/Keep-Shipping/harness/issues/46))
  added, engine-only: steps never receive it, so it is not in `Port` nor in
  `define_ports!`, and it does not move `STEP_API`. The fingerprint covers
  every trait in `ports/`, so the digest is re-pinned here without a bump.