# ADR 0100: Step contract and composition checks

Status: accepted, 2026-09-26

## Context
The engine must run steps written by many hands — built-ins, repository
authors, later step families — without any of them reaching past the ports
([#39](https://github.com/Keep-Shipping/harness/issues/39)). Steps need one
contract for what they declare (name, schema, ports, policy class), and the
harness must refuse bad compositions loudly and completely before anything
runs.

## Decision
- A step implements `ks_core::step::StepKind`: `name`, `version`, `step_api`,
  `schema`, `requires`/`optional` ports, `action`, `capabilities` and
  `run(ctx, inputs)`.
- `STEP_API` is an integer, bumped on breaking change; a step built against a
  different API than the harness speaks is refused at `Harness::build()`.
- `run` returns a `BoxFuture` — dyn-compatible, no async runtime dependency,
  consistent with the ports.
- `Version` is hand-rolled `major.minor.patch`; no semver crate.
- Schemas reference builtin `ValueType`s or named `TypeDef`s registered on
  the harness (e.g. `digest` = string): a small shared vocabulary.
- `Harness::build()` collects *every* composition error — missing clock,
  missing ports, ports in both lists, duplicate names, API mismatches,
  unknown types, null types, mistyped defaults — in a deterministic order,
  never stopping at the first. A field whose resolved type is `null` (builtin,
  or via a `TypeDef` with a null base) is refused: a null satisfies no
  contract, the same rule as the script host's schema validation.
- `Harness::check_outputs` is strict in both directions: every declared output
  present and typed, and no undeclared extras.
- `ActionClass` (build/plan/apply/…, optionally in an environment) is what
  policy ([#101](https://github.com/Keep-Shipping/harness/issues/101)) reads;
  a step may compute it from its inputs.
- `StepCapabilities` is what a step *needs* (CI-only, OIDC, network scope);
  distinct from `run_context::Capabilities`, what a run *has*.
- Cancellation is a polling `CancellationToken`; a waker-based future is
  future work.
- `docs/STEPS.md` is generated from the built-in steps and drift-checked by a
  test; `KS_BLESS=1 cargo test -p ks-engine --test steps_doc` regenerates it.

## Consequences
- Step authors get one trait and their composition errors all at once.
- Adding a port means extending the `Port` enum and the `Ports` slots next to
  it; `Port` is `#[non_exhaustive]`, so downstream matchers carry a wildcard
  arm.
- Every step log line passes through the run's `Redactor` before any sink.
