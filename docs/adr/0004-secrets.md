# ADR 0004: Secrets

Status: accepted, 2026-10-06

## Context
The product promise is that the same engine and the same step file run on a
laptop and in CI. Secrets are the one thing that legitimately differs per
environment, and issue [#5](https://github.com/Keep-Shipping/harness/issues/5)
asks where their values come from. A secret is a value the file refers to by
name and each environment resolves; it is never a plain string that can be
logged, interpolated, or handed to an agent.

[ADR 0001](0001-typed-values-and-secret-references.md) already decided the
language half: `secrets.<name>` in `.ks` is typed `Secret`. This ADR builds on
that type and does not repeat 0001's type rules; it decides the other half —
where the values come from and the rules around resolving them.

Three options were considered:

- **A. References plus a resolver chain behind the `Secrets` port.** The file
  names `resolver:key`; an adapter answers with bytes. Each environment picks
  its own store.
- **B. An encrypted secrets file in the repo** (sops/age style). One file,
  versioned, decryptable anywhere the key is.
- **C. A hosted secret store in a control plane.** The venture holds the
  secrets and hands them out.

## Decision
Option A. A `SecretRef` (`crates/core/src/ports/secrets.rs`) is a `resolver`
and a `key`; it displays as `resolver:key`, and a reference is not secret — it
appears in diagnostics and logs.

- A secret is a reference, never material in the repo. It is typed `Secret`
  (ADR 0001): only flows into inputs typed `Secret`, and interpolating a
  `Secret` into a `string` is a type error.
- Resolution happens at the step boundary, as late as possible, inside the
  adapter behind the `Secrets` port. The engine holds references and opaque
  handles only; steps never resolve themselves. `resolve_step_secrets`
  (`crates/engine/src/secrets.rs`) is the one funnel the run path is required
  to call, and it registers each value with the run's `Redactor` the moment it
  resolves — before the bundle is returned and before any step output is read,
  so a secret in stdout, stderr or a dependency's stack trace is already
  scrubbable. Today only its tests call it; the run path is not wired to it
  yet, and that wiring is what this rule is for. Values are zeroised on drop.
- Redacted values never reach the run log, the `StateStore` or any other
  persisted state; only the `resolver:key` reference does.
- Each environment declares its resolver under `envs: <name>: secrets:`, and
  `check --secrets` lists `resolver:key` plus the steps that need each, from
  the checked file alone — no resolver is constructed and no store is read
  (`crates/cli/src/check.rs`).
- Agent runs (`--actor agent`) get no resolver for secrets the policy
  forbids: the run path wraps its resolver in `ActorGatedSecrets`, which
  refuses with `SecretsError::ForbiddenForActor`, so the step fails closed.
  Statically, `policy: agents: never: read secrets` refuses an agent run that
  needs any `secrets.<name>` before anything starts (`CheckOptions::actor`,
  `crates/core/src/check.rs`).
- Prod secrets on laptops are off by default in the sense that matters: a prod
  environment declares `ci-only: true`, and such an environment's secrets
  resolve only when the `RunContext` is CI (e.g. a `GithubActionsRunContext`,
  whose `ActorKind::Ci` and `Establishment::CiOidc` come from the runner's
  OIDC endpoint). Locally such an environment fails closed with a diagnostic.
  The flag itself defaults to `false`; it is the declaration prod environments
  are expected to make. Opting a laptop into a ci-only environment's secrets
  is out of scope here — the risk and a possible opt-in are tracked as
  [#123](https://github.com/Keep-Shipping/harness/issues/123).
- The first two resolvers are `env` (the process environment; works on a
  laptop and in any CI) and GitHub Actions. Actions secrets already arrive as
  environment variables, but a `github` resolver answers only inside a
  verified GitHub Actions `RunContext` — that gate is what makes `ci-only`
  enforceable. Both are targeted at M1/M2.
- Later resolvers — macOS Keychain, 1Password CLI, Vault, cloud secret
  managers — are further adapters behind the same port. They need no new ADR
  unless they change these rules.
- What has landed with [#49](https://github.com/Keep-Shipping/harness/issues/49)
  is the port, the value type and redaction. What has *not* is any wiring:
  `resolve_step_secrets` is called only by its own tests, `ActorGatedSecrets`
  (`crates/core/src/ports/secrets.rs`) is constructed only by its own tests,
  no resolver adapter ships, `ci-only` is parsed (`Env::ci_only`) but never
  enforced, and `GithubActionsRunContext` reports an empty
`Capabilities::secret_resolvers`. The `StateStore` named in the redaction
  rule is likewise a decided port (ADR 0005) with no code yet; that rule binds
  it once it lands. The decision stands that `check` warns when a step needs a
  secret the current context cannot resolve:
  `SecretsError::NotAvailableInContext` already maps to
  `CheckSeverity::Warning` (`crates/core/src/ports/secrets.rs`), but the
  checker never calls `check_severity` — today `check --secrets` lists
  references statically only. The follow-up work this ADR unblocks —
  calling the funnel and wrapping the gate in a run, enforcing `ci-only`
  with its check diagnostic, calling `check_severity` from the checker,
  the two resolvers, and filling in the run context's resolvers —
  is not attributed to specific issues here, only the intent.
  The issues it unblocks are
  [#111](https://github.com/Keep-Shipping/harness/issues/111),
  [#49](https://github.com/Keep-Shipping/harness/issues/49) and
  [#91](https://github.com/Keep-Shipping/harness/issues/91).

## Consequences
- One workflow file everywhere; no secret material in the repo; each
  environment keeps its own store, in its own tool.
- We are not a secrets manager. No key distribution, no rotation, no
  revocation — which is why option B was rejected: putting ciphertext in the
  repo makes us responsible for the keys, and the laptop that holds the key
  then holds every secret too.
- No hosted availability dependency and no trust ask beyond the runner's,
  consistent with local-first; that is why option C was rejected. The cost is
  no central audit — who read what is audited by each store, not by us.
- Running prod steps locally means prod secrets on a laptop. That is a real
  risk, which is why prod environments are expected to declare `ci-only: true`
  and why [#123](https://github.com/Keep-Shipping/harness/issues/123) exists.
- Every resolver the run path uses must go through the funnel and the actor
  gate: registering values with the `Redactor` and refusing what policy
  forbids. There is to be no second, ungated path — a rule the wiring has yet
  to satisfy, not one it already satisfies.
- Redaction is best-effort on exact values. `Redactor` matches the literal
  UTF-8 value and merges overlapping spans, so no registered bytes survive in
  the clear — but a secret that appears transformed (base64-encoded, hashed,
  split across a line) is not caught, and non-UTF-8 values are skipped
  entirely. Redaction is a safety net, not a guarantee; the reason `Secret` is
  a type is what actually keeps values out of strings.
- Zeroisation is best-effort too, without `unsafe`: `Drop` overwrites the
  value's own allocation and pins the loop with `black_box`. Copies the
  allocator made while the `Vec` grew are not reached.