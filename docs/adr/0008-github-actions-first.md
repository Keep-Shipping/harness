# ADR 0008: GitHub Actions first

Status: accepted, 2026-10-06

## Context
Keep Shipping runs *inside* a CI system; it does not replace the runner. It
is a job step, given a checkout and a trigger. So "supporting" a CI system
means five specific things: a first-class action people can write in their
workflow, the CI's triggers mapped onto the plan's `on:`, a run identity the
cloud trusts, status the way the CI renders it, and a hand-off from the agent
to a human that the CI itself enforces. Without all five, a run on that CI is
a shell script that happens to print some lines.

M2 is where this is paid for: [README.md](../../README.md) puts "The same
file runs locally and on GitHub Actions. An agent run waits for a human." in
M2 Early-access alpha. The examples already assume GitHub's vocabulary — an
image tag like `ghcr.io/acme/api` in
[docs/LANGUAGE.md](../LANGUAGE.md) and an `on: push main` trigger in
[docs/ERRORS.md](../ERRORS.md) — and the project lives on GitHub. This ADR
decides which CI is *native* first, from
[#9](https://github.com/Keep-Shipping/harness/issues/9).

The port that decides most of this already exists. `RunContext`
(`crates/core/src/ports/run_context.rs`) is documented as "the one port that
differes between a laptop and CI", and it holds the actor, the event, the
capabilities and the workspace — everything that differs goes there and
nowhere else. Its module docs are also explicit about identity: only an
adapter that established `Establishment::CiOidc` may report `ActorKind::Ci`,
and that is the only `IdentityStrength::Strong` establishment; a local run
can never be CI, however its environment insists. Steps declare what they
*need* as `StepCapabilities` (`crates/core/src/step.rs`) — `ci_only`, `oidc`,
`network` — and what a run *has* is the `RunContext` port's `Capabilities`.

The GitHub Actions side of that port is already written:
`crates/cli/src/github_actions_run_context.rs` answers from the variables
GitHub Actions sets and mints the job's own ID token, reading `iss` and `sub`
into `Establishment::CiOidc`. It is honest about its own limits: the token's
signature is **not** verified there, so that establishment means "obtained
from GitHub's dedicated OIDC endpoint", not "cryptographically verified";
verifying it is the consumer's job
([#150](https://github.com/Keep-Shipping/harness/issues/150)).

## Decision
- GitHub Actions is the first native CI integration, in M2.
- A generic runner mode ships from M1: one binary plus environment detection,
  so any CI can run `keepshipping run` and get a verdict. It is the
  baseline every native integration must stay compatible with.
- GitLab CI is the second native integration, in M3. Buildkite and CircleCI
  stay on generic mode until someone asks.
- A native integration is an adapter, not a fork: it fills in the ports —
  `RunContext` above all — and the core never names a CI vendor. `ks-core`
  today mentions no CI system by name; that stays true.
- "Native" for GitHub Actions means all five:
  - a published action, so a workflow file is the supported entry point;
  - trigger mapping from the job's `on:` events onto the plan's `on:`, so a
    push and a pull request select the same runs they select on a laptop;
  - OIDC through the `RunContext` port, so a cloud credential handed to a
    step is minted for the job's identity;
  - status through the Checks API, with diagnostics inline on the commit or
    pull request rather than only in the log;
  - the approval hand-off through environments with required reviewers, which
    is what makes "an agent run waits for a human" a CI-enforced fact rather
    than a promise.
- Generic mode gives a CI the plan, the steps and the log. It does not give
  trigger mapping, status reporting or approvals — the run has to name its own
  triggers, report failure in its own way, and a human stops it by whatever
  means that CI has.
- Identity-wise, the rule this sets: only a native adapter that established
  the CI identity may report a CI actor with a strong establishment, so a
  step needing `ci_only` or `oidc` is refused on a generic run rather than
  half-served. A generic CI run answers the port from its environment the
  way a laptop does, and every establishment it produces is weak.
- The options, briefly:
  - GitHub Actions. For: the largest share of people who write "fix ci"
    commits; OIDC to AWS, GCP and Azure without a stored key; environments
    with required reviewers, which is an approval gate that already exists;
    the Checks API for inline diagnostics; GHCR for the images the examples
    already push to. Against: minutes are billed, so runs cost the user
    money; the approval UX is limited to what environments offer.
  - GitLab CI. For: strong where this lands in self-hosted enterprises;
    built-in environments and manual jobs are a good fit for the hand-off.
    Against: a smaller pool of developers for a developer-led launch, so
    GitHub's reach wins now even though GitLab's approval story is at least
    as good.
  - Generic "any shell" mode only. For: it works everywhere on day one, and
    it is cheap. Against: it is the absence of the integration — no trigger
    mapping, no status, no approvals — and to a user it reads as a script,
    not as a product.

## Consequences
- Users on GitHub Actions pay GitHub minutes. That is the price of the
  trigger mapping, the OIDC and the environment approval gate.
- The hand-off is a GitHub feature, not ours. "An agent run waits for a human"
  maps onto environment protection rules rather than a bespoke approval
  product, so a user who wants a different hand-off configures it in their
  workflow.
- GitLab users wait for M3; Buildkite and CircleCI users may wait
  indefinitely, on generic mode until then.
- Generic mode is the floor, so every native integration has to keep passing
  it. A workflow that runs on GitHub Actions and on a laptop is the same
  workflow, and that is the regression to guard against.
- Steps needing `ci_only` or `oidc` fail loudly on generic CI runs instead of
  degrading quietly — a stronger identity is not faked to make them pass.
- This unblocks [#127](https://github.com/Keep-Shipping/harness/issues/127).
- GitHub Actions first does not make it the only CI, or a hard dependency:
  the vendor-neutral core is what keeps that true, and a second native
  integration landing in M3 is the test of it.