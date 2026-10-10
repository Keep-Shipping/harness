# ADR 0203: Pricing not set

Status: proposed, 2026-10-10

## Context

The venture record (FZ-012) says "Pricing is not set" and "early access by
invite, in small batches", the landing site names no price, and the invite
deliberately leaves pricing out ([EARLY-ACCESS](../EARLY-ACCESS.md)).
[#15](https://github.com/Keep-Shipping/harness/issues/15) holds the decision
open until early-access teams are running real pipelines: the waitlist
collects only an email, so until the interviews in
[INTERVIEWS](../INTERVIEWS.md) run, every option rests on precedent from
other products, not on anything a Keep Shipping user has said. The two
decisions this one rested on are in: the licence
([ADR 0006](0006-licence-and-open-source-model.md), the issue's #7) makes the
core free and puts the paid parts in private repositories, and the hosted
scope ([ADR 0005](0005-local-first-core-with-optional-hosted-services.md),
the issue's #6) says what is hosted. What none of them says is *what is paid
for*. The candidates, with the arguments [#15](https://github.com/Keep-Shipping/harness/issues/15)
records:

| Model | For | Against |
| --- | --- | --- |
| Free CLI + paid hosted team features (web/chat approvals, run-log viewer, org policy, SSO) | Aligns price with the hosted cost; the core stays free | The hosted features must be good enough to pay for |
| Per active repository per month | Matches the growth metric, "repositories shipping through it" | Discourages trying more repos |
| Per seat (approvers) | Familiar | Agents are not seats; punishes adding reviewers, which works against safety |
| Usage (runs / `decide` calls) | Scales with value | Unpredictable; a `decide` call's model cost is mostly the Jev adapter's, which is bring-your-own-key anyway |

The Groove Guru precedent — a free open-source harness with a paid Pro tier —
is the argument most often reached for, and [#15](https://github.com/Keep-Shipping/harness/issues/15)
discounts it explicitly: it is evidence about Groove Guru, not about
Keep Shipping.

## Decision

- **Nothing is priced, and no price is published, until early-access teams
  are running real pipelines** (after M2). "Pricing is not set" is a state
  this ADR holds in place, not an omission waiting to be filled, and a guard
  test keeps the docs at zero prices until it is superseded.
- When the data exists, the first model to test is **free CLI + paid hosted
  team features**. It is the only candidate that prices what actually costs
  money — the hosted parts
  [ADR 0005](0005-local-first-core-with-optional-hosted-services.md) scopes
  and [ADR 0202](0202-billing-through-polar.md) bills — while the Apache-2.0
  core stays free ([ADR 0006](0006-licence-and-open-source-model.md)).
- The other three are ordered behind it, not rejected. Per repository becomes
  right if interviews show teams adopting it repo by repo rather than as one
  team; per seat if the buyer expects seats and the agent-is-not-a-seat
  objection falls away (it should not); usage if metering lands and answers
  to [INTERVIEWS](../INTERVIEWS.md) question 16 anchor on per-decision value.
- Interview answers are data, not copy: they go to the private notes and
  [#154](https://github.com/Keep-Shipping/harness/issues/154), and nothing
  priced enters this repository from them before the decision.
- Closing [#15](https://github.com/Keep-Shipping/harness/issues/15) means one
  change on every surface at once: a new ADR in this block superseding this
  one, the FZ-012 venture record and the landing site (both live in
  Keep-Shipping/website, outside this repository), and this repository's
  guard test.

## Consequences

- Nothing on docs.keepshipping.run states a price for Keep Shipping: no
  amount, no unit price, no plan table. `crates/testing/tests/pricing_guard.rs`
  fails CI if a file under `docs/` (outside `docs/research/`, which tracks
  competitors and is where prices are the data) states a currency amount.
  Naming and comparing models, as the interviews and this ADR do, stays
  allowed.
- [ADR 0202](0202-billing-through-polar.md)'s billing module keeps working
  without a usage component, and its one paid plan stays "not on sale yet"
  (`crates/core/src/built_with.json`).
- When the model is chosen, it lands everywhere at once: a superseding ADR in
  this block, the FZ-012 record and the landing site (Keep-Shipping/website),
  this guard relaxed deliberately, and — if the invite can then name a price
  — [EARLY-ACCESS](../EARLY-ACCESS.md) and
  [INTERVIEWS](../INTERVIEWS.md). Until then the docs' silence on price is a
  decision, not an omission.
