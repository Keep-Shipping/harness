# ADR 0001: Typed values and secret references

Status: accepted, 2026-09-27

## Context
Workflows pass values from step to step, and steps written by many hands
must agree on what those values are ([#24](https://github.com/Keep-Shipping/harness/issues/24),
[#27](https://github.com/Keep-Shipping/harness/issues/27)). A checker that
only knows `string` cannot tell a digest from a tag; a checker that
hard-codes every domain type cannot take third-party steps. Separately,
open ADR issue [#5](https://github.com/Keep-Shipping/harness/issues/5)
asked how secrets should appear in the language.

## Decision
- Values are typed. Primitives: `string`, `int`, `float`, `bool`,
  `duration`, `path`, `url`. Composites: `list`, `map`, `record`, `enum`,
  `optional`, with per-field defaults. Generics, and unions beyond
  enums/optionals, are out of scope.
- Nominal domain types — `oci.Digest`, `oci.Ref`, `oci.Tag`,
  `oci.Artifact`, `tofu.PlanFile`/`Changes`/`Outputs`,
  `k8s.Cluster`/`Namespace`, `vm.Hosts`, `fn.Version`, `Secret`, `Team`,
  `Env` — are declared by step families through step schemas
  (`StepKind::schema()`, `TypeDef`), not a hard-coded list in the checker.
  The checker's built-in catalog is just the first family's registrations;
  `Secret`, `duration`, `path`, `url` and `int` are built in so TS steps
  and third-party steps can declare them without registering anything.
- No implicit coercion — not between nominal types, and not from `string`
  to a nominal type. Literals are parsed into a type only where the
  declared input type says so: a pasted `sha256:…` literal where
  `oci.Digest` is declared is accepted, with a warning (pin by reference).
- A mismatch diagnostic names both types — `expected oci.Digest, got
  string` — and suggests a same-step output of the right type.
- Secrets are references resolved per environment (the recommendation of
  [#5](https://github.com/Keep-Shipping/harness/issues/5)). In `.ks` a
  secret is referenced as `secrets.<name>` — chosen over `secret("name")`
  because the grammar has no call syntax and dotted references already
  resolve — and has type `Secret`. A `Secret` flows only into inputs typed
  `Secret`; no language operation turns a `Secret` into a `string` (no
  interpolation, no `show:`), and step outputs cannot be `Secret` in v1.
  The only way out is a step or TS script declaring a `Secret` input,
  running in the adapter.
- `keepshipping check --secrets` lists each environment's requirements as
  `resolver:key` without touching any secret store.
- Policy `never: read secrets` for agents is enforced twice: statically, a
  check or run of a file that needs a secret is refused with a policy
  diagnostic before anything starts; dynamically, an agent run gets no
  resolver at all (`ActorGatedSecrets` in `ports/secrets.rs`).

## Consequences
- Third-party steps plug their types in; the checker stays family-agnostic.
- Mismatch wording changes from the backticked, capitalised form to
  `expected X, got Y`.
- Nothing ever materialises a secret at check time; `--secrets` prints
  names only.
