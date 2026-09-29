# ADR 0200: Hosted venture on the Cratefield harness

Status: accepted, 2026-09-29

## Context
The early-access waitlist ([#146](https://github.com/Keep-Shipping/harness/issues/146))
is a small public API — join with a captcha, double opt-in by mail, status,
admin CSV export — that must exist before the site launches, while the
engine itself ([ADR 0100](0100-step-contract-and-composition-checks.md)) is
still under construction. Writing the waitlist as bespoke Workers code
would put a second HTTP stack, a second mail flow and a second captcha
integration into this repository, none of them the product we are building.

The `cratefield` ecosystem (Cratefield/harness, published on crates.io)
solves exactly this class of problem: a module mounts routes into a harness,
adapters bind the ports (Turnstile captcha, Resend mail), and a runtime
executes the composition on a platform (Cloudflare Workers). Its own
`ventures/cratefield-waitlist` is a working precedent of the shape.

## Decision
- The waitlist is a **hosted venture**: `ventures/keepshipping`, workspace
  member `keepshipping-waitlist`, deployed to Cloudflare Workers at
  `api.keepshipping.run`, backed by D1 and the Workers rate-limiter
  binding.
- The venture depends on **published `cratefield` crates from crates.io**
  (core, module-waitlist, runtime-cloudflare, adapter-resend,
  adapter-turnstile, testing), pinned to minor versions in the venture's
  own `Cargo.toml` — not `[workspace.dependencies]`, so sibling work on the
  engine never collides with the venture's dependency tree.
- This crate is **composition, not protocol**: the venture owns the name
  and domain, the product code, the site origins, the mail sender and the
  adapter wiring. Request handling, mail, captcha and rate limiting come
  from the crates.
- The venture adds one piece of code the harness deliberately does not:
  a **write-origin guard** in the worker entry point. CORS headers are
  response decorations, not authorisation; every write must carry an
  `Origin` of the site or is refused `403` before the harness runs
  (the guard is a pure function, unit-tested in `src/origin.rs`).
- Degradation is **safe by construction**: no `TURNSTILE_SECRET` ⇒ no
  captcha port ⇒ joins refused in production (fail-closed); no
  `RESEND_API_KEY` ⇒ the adapter reports `NotConfigured` ⇒ joins are
  captured as `pending` without mail.
- Tests mount **the same module composition the worker serves**
  (`keepshipping_waitlist::module()`) against the testing kit's fakes —
  the deployment's refusals are exactly the tests' refusals.

## Consequences
- The waitlist ships now, independent of engine milestones; the site can
  open signups without waiting for the harness.
- This repository gains an external dependency surface on the `cratefield`
  ecosystem: version bumps there are our upgrades, reviewed like any
  dependency (license allowlist and `cargo deny` cover them). It is
  contained to the venture crate.
- `cargo test --workspace` builds the venture natively; deployment
  (`worker-build`, `wrangler`) happens outside CI until a release pipeline
  wants it (issue #146's deployment tasks).
- The venture block (`0200`–`0299`) is the home of future hosted-part
  decisions.
