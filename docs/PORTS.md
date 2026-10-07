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

## Changelog

Newest first, one heading per contract version, dated.

## STEP_API 2

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