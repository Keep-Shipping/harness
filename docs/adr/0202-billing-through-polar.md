# ADR 0202: Billing through Polar

Status: accepted, 2026-10-08

## Context
The hosted venture ([ADR 0200](0200-hosted-venture-on-the-cratefield-harness.md))
needs to collect money for its one paid plan ([#177](https://github.com/Keep-Shipping/harness/issues/177)),
and the harness's billing lifecycle ([ADR 0025]) already fixed the shape:
provider-neutral `LifecycleEvent`s folded through a pure `transition` into a
`SubscriptionState`, entitlements derived from access, an append-only audit
trail. What was left open is everything a venture must decide: which provider
sells, which routes exist, what an account is, and what may never happen. The
core `Payments` port and the `cratefield-adapter-polar` adapter speak to
Polar; they deliberately do not decide any of those things.

## Decision
Sell through **Polar as Merchant of Record**: it carries the tax, invoice and
fraud burden a two-person venture cannot, while we keep the customer
relationship and the plan. The venture wires the adapter into the `Payments`
port from secrets (`POLAR_ACCESS_TOKEN`, `POLAR_WEBHOOK_SECRET`,
`POLAR_ENVIRONMENT`, sandbox by default); a missing token builds a `not
configured` adapter and every billing route answers a 503 problem — never a
panic, never a mis-bill.

The **account key is the venture's own account id** (the auth `Subject` id),
passed to Polar as its `external_customer_id` (`CustomerIds::External`): we
never store a Polar customer id, and every webhook resolves back through
that id, falling back through the subscription and order ids the row keeps.
Checkout and portal take the account from the verified caller, never from
the request body, and refuse (401, or 503 with no auth port) otherwise.

Three routes: `POST /v1/billing/webhook` (Standard Webhooks signature
verified through the adapter, normalized, mapped onto `LifecycleEvent`s,
folded through `transition`), `POST /v1/billing/checkout`
(`{"interval":"annual"|"monthly"}` — **annual is the default**, the plan the
venture sells first), and `POST /v1/billing/portal`.

**Only subscription events move the plan.** An `order.paid` records identity
(the order id a dispute resolves by) and an audit row, never access: Polar
redelivers, and a late order must not re-grant what a refund revoked. Writes
to a row are optimistic: each carries `WHERE version = ?`, the winner bumps
the version, and a loser commits nothing — not even its Inbox claim — and
answers 409 so Polar redelivers onto the state that won.

**Disputes are flag-only** (`DisputePolicy::RevokeOnLoss`): a dispute
opening flags the account but touches no plan — the card network has not
decided anything yet. Only a *lost* dispute downgrades to free, and a won
one restores. Because Polar sends no dispute webhooks, all three outcomes
are read by the hourly `list_disputes` poll (the cron in `wrangler.toml`),
deduplicated on the dispute's own poll key.

The free tier is a **state, not a deletion**: lapsed, unpaid, refunded,
revoked or dispute-lost accounts read as free through their stored
subscription state, while the row and the append-only `billing_audit` trail
survive for support, recovery and bookkeeping.

## Consequences
The module (`ventures/keepshipping/src/billing/`) is the only place that
knows what a plan means; the rest of the venture asks `Billing::plan` and
gets free or paid. Polar's redundancy (`subscription.active` and
`order.paid` for one payment) is absorbed by mapping only what carries
distinct meaning and by the Inbox claim making every application
idempotent. Before launch, the Terms of Service must name Polar as the
Merchant of Record and link its customer terms. Follow-ups, out of scope
here: usage metering (the venture's pricing, [#15](https://github.com/Keep-Shipping/harness/issues/15),
has no usage component yet) and any second plan beyond monthly/annual.
