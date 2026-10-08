# ADR 0015: Telemetry policy

Status: accepted, 2026-10-08

## Context
[#156](https://github.com/Keep-Shipping/harness/issues/156) asked for a
telemetry policy: opt-in, anonymous and documented — or none. The "or none"
was not a hedge. As of this ADR the harness ships no telemetry at all. A
grep for telemetry, analytics, tracking, metrics, sentry, posthog, amplitude,
mixpanel, phone-home and `DO_NOT_TRACK` across every `.rs`, `.toml`, `.md`
and `.ts` file in the workspace returns one hit, and it is an unrelated
JSON-RPC fixture string in `crates/lsp/src/server.rs`.

The question is therefore not "should we turn it on" but "what would we be
turning on". A deploy tool's users are the people who least want a stranger's
eye on their infrastructure, and the data a deploy tool could send is the
data that describes that infrastructure. The cost side is real too: with
nothing collected we cannot tell which commands matter, cannot prioritise
fixes from data, and cannot count adopters without asking them.

ADR 0005 already answers the local-first half — *What leaves the runner* is
an exhaustive per-request list, *What never leaves the runner* is its
complement, and anything outside the first list needs an architecture change
rather than a config flag. This ADR answers the question that list does not:
what a telemetry payload would have to be if one were ever allowed to exist,
and who decides.

## Decision
- **No telemetry.** No command, no config key, no outbound call outside
  ADR 0005's *What leaves the runner*. The absence is the decision; it is
  not a default awaiting a flag, and revisiting it means a new ADR
  superseding this one.
- **If** it is ever built, it is opt-in only: default off, an explicit
  `keepshipping telemetry on`, persisted per installation,
  `keepshipping telemetry off` to revoke in one command, and `DO_NOT_TRACK`
  honoured if set. None of those commands exist today.
- **Counts only**, and the payload is fixed in advance in
  [`docs/TELEMETRY.md`](../../TELEMETRY.md): one version constant, the
  binary's own semver, the top-level CLI word, three counts, a
  power-of-two duration bucket, and one map of counts keyed by the closed
  `ActionKind` vocabulary. No paths, contents, repository names, hosts,
  SHAs, environment variables, argument strings beyond the first word, step
  names, plan addresses, error text or install identifier — hashed or
  rotating.
- **The payload is a contract, and it is written before the sender.**
  `docs/TELEMETRY.md` specifies the fields, their types and the closed
  vocabularies they draw from. A sender that does not match it is a bug, and
  `crates/testing/tests/telemetry_policy.rs` is what notices. The open-ended
  set of step kinds is the reason the payload counts by action kind: an
  unrecognised kind lands in the fixed `other` bucket and is never sent as a
  name.
- **It would ride on Cratefield's `module-telemetry`** — aggregate counts,
  consent-first — in the hosted venture
  ([ADR 0200](0200-hosted-venture-on-the-cratefield-harness.md)), not as a
  facility of the runner.

## Consequences
- No code ships with this ADR. There is nothing to configure, nothing to
  disable, and nothing new that reaches the network.
- `docs/TELEMETRY.md` is written and enforced while the feature is absent,
  which is the only time a payload can be specified without an
  implementation to bargain with it.
- Changing the payload is a new ADR. Per ADR 0000 an accepted ADR is never
  edited, and the payload fields are versioned in `schema`, so a receiver
  refuses a shape it does not know rather than guessing at one.
- We accept blindness. Which commands matter stays a matter of issues filed
  by people who chose to file them; fixes stay a matter of judgement; the
  adopter count stays whatever people tell us when we ask. A number gathered
  silently is worth less to us than the word from a user who chose to send
  it, and is worth nothing at all to the users whose infrastructure it
  describes. If that trade ever looks wrong, the lever is a new ADR and a
  document that already says what a payload may contain.