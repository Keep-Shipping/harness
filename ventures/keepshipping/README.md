# keepshipping-waitlist

Keep Shipping's early-access waitlist — a [Cratefield](https://crates.io/crates/cratefield-core)
venture ([#146](https://github.com/Keep-Shipping/harness/issues/146)). All
protocol work lives in published `cratefield` crates; this crate is the
composition: the venture's name and domain, the product code
(`keepshipping`), the origins writes may come from, and the mail sender.

## What serves

- `POST /v1/waitlist` — join. Writes (any `POST`/`PUT`/`PATCH`/`DELETE`)
  must carry an `Origin` of the site (`https://keepshipping.run`,
  `https://www.keepshipping.run`) or are refused `403` before the harness
  runs. A solve of the site's Turnstile widget is required (`captcha-failed`
  otherwise), per-IP rate limiting answers `429` with `retry-after`, and a
  solved join answers `202 {"ok": true}` with the entry captured as
  `pending`.
- `GET /v1/waitlist/status?...` — queue position for a confirmed entry.
- Confirm/expiry links point back at the API and then redirect to the site
  (`status_redirect`).
- `GET /v1/waitlist/admin/export.csv` — Bearer `ADMIN_TOKEN` CSV export.

## Deploy

```sh
npm install -g wrangler   # or npx wrangler
wrangler d1 create keepshipping-waitlist
#   → put the printed database_id into wrangler.toml
wrangler d1 migrations apply keepshipping-waitlist
wrangler secret put RESEND_API_KEY    # Resend key for no-reply@send.keepshipping.run
wrangler secret put TURNSTILE_SECRET  # Turnstile widget on keepshipping.run
wrangler deploy
```

Secrets degrade safely: with no `TURNSTILE_SECRET` the harness refuses
joins in production (fail-closed); with no `RESEND_API_KEY` the join is
still captured as `pending`, just without confirm mail. `ADMIN_TOKEN` is
the export credential — set it before pointing the admin tooling at the
API.

## Test

```sh
cargo test -p keepshipping-waitlist
```

The integration tests mount the same module composition `src/lib.rs`
serves, against the testing kit's fakes: captcha refusals, rate-limit
`429`, unknown-product `400`, clean `202` + pending row, and the
`NotConfigured` mailer path.

## Pending before launch

- Verify the `send.keepshipping.run` sending subdomain in Resend — until
  then mail cannot flow and entries stay `pending` (the double opt-in mail
  is the open question in #146).
- Create the Turnstile widget for `keepshipping.run`; the worker pins
  `expected_hostname` to the apex.
- Privacy notice on the site before the form goes live (website#4): the
  API deletes confirmed-or-not entries after the retention window
  (`retention_days_pending`), and `wrangler d1 execute` can erase one on
  request — but the notice is what makes that honest.
- Answers fields (company size, CI, IaC, deploy target): deferred until
  #146's question is answered; the module supports an answers schema when
  the copy exists.
