# ADR 0002: Ports and adapters

Status: accepted, 2026-10-06

## Context
Keep Shipping talks to many vendors: OCI registries, BuildKit or Docker,
sigstore, OpenTofu and Terraform, Kubernetes, SSH hosts, serverless
platforms, CI systems, chat tools, TypeSafe's Jev. "Local = CI" means the
same step code has to run against a laptop's Docker socket and against a
CI runner's OIDC credentials, and the difference between the two is not
something a step should be able to see.

The Cratefield harness — whose dependency
this repository already carries for the hosted
venture, [ADR 0200](0200-hosted-venture-on-the-cratefield-harness.md) —
solves exactly this shape of problem with **ports**, object-safe `Send + Sync`
traits in core, and **adapters**, one crate per vendor, holding the only
vendor-aware code. Its rule is "modules only see ports". Keep Shipping's
rule is the same word for word, with steps where Cratefield has modules.

## Decision
- `ks-core` defines the port traits and the `StepKind` trait — Keep
  Shipping's equivalent of Cratefield's `Module`. A port is a trait a
  step asks for; an adapter is the only code that knows how to answer it
  for a particular vendor.
- A step declares what it needs: `requires()` for ports it cannot run
  without, `optional()` for ports it uses when they are there. The
  harness hands each step only what it declared, so declaring is what
  grants access.
- `Harness::builder().ports(..).step(..).build()` collects **every**
  composition error before failing — a required port nobody provides, a
  duplicate step name, a contract-version mismatch, a port in both
  lists, a mistyped default — in a deterministic order, never stopping at
  the first. One composition mistake is one round trip, not five.
- Adapters are **separate crates under `adapters/`**, one per vendor
  integration. A step crate never depends on an adapter crate, and no
  adapter is reachable from `ks-lang` or `ks-core`. Feature flags on the
  CLI binary choose which adapters are compiled into a build.
- The CLI binary is a composition, in the shape of a Cratefield venture:
  it picks step kinds, picks adapters, and picks a runtime — local or
  GitHub Actions — then builds. Swapping "my laptop" for "the CI runner"
  is a different composition, not a different code path through the same
  one.
- `ks-testing` ships a fake for every port plus the conformance kit every
  step and adapter must pass. The conformance kit is per-port free
  functions in `ks-testing` that take a `&dyn` port trait; the shipped
  fake passes the same kit, so the kit is a contract with two known-good
  implementations from the start. A port lands with its fake and its kit
  in the same change.
- The port list itself is
  [#47](https://github.com/Keep-Shipping/harness/issues/47), which
  derives it from the product rather than copying Cratefield's. Only
  `Signer`, `HttpClient`, `Clock` and `IdGen` exist in both systems, and
  `Signer` does not mean the same thing: Cratefield's authenticates a
  message with a shared HMAC secret, Keep Shipping's produces artifact
  and log signatures a third party verifies against a public identity.
- Ports are dyn-compatible and `Send + Sync`, and async methods return
  `BoxFuture` rather than `impl Future`. Steps hold ports as `&dyn`
  traits, which is what lets an adapter be swapped at build time; the
  hand-rolled alias is what keeps `ks-core` free of `async-trait` and of
  any async runtime, and therefore wasm-buildable.

## Consequences
- `ks-lang` and `ks-core` do no I/O — no tokio, no `std::fs`, no
  `std::net` — and build for `wasm32-unknown-unknown`. CI enforces it.
- `cargo test` needs no Docker, no cluster, no cloud account: unit tests
  run against fakes, and a step's whole test suite is a fake composition.
  An adapter's integration tests are a separate CI job against real
  services (zot, kind, OpenTofu) — slow, network-touching, and not what
  `cargo test` runs.
- Adding a port is one mechanical change in four places: the trait under
  `crates/core/src/ports/`, a variant and slot in `Port` and `define_ports!`,
  the fake, the conformance kit. `Port` is `#[non_exhaustive]`, so
  downstream matchers carry a wildcard arm and a new variant is not a
  breaking change for them.
- The price is more crates and one level of indirection: to read what a
  step does you follow a trait to an adapter, and a change to how a
  vendor behaves is a change in an adapter crate rather than in the
  engine.
- Where the seams are is settled here; what a step declares about itself
  is [ADR 0100](0100-step-contract-and-composition-checks.md), and the
  blocks, cluster, approvals and run-log ports land with the step epics
  that need them.
