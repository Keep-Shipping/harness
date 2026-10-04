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
wrangler secret put OWLPOST_API_KEY   # preferred mailer; verify send.keepshipping.run in Owlpost
wrangler secret put RESEND_API_KEY    # fallback mailer, used when no Owlpost key is set
wrangler secret put TURNSTILE_SECRET  # Turnstile widget on keepshipping.run
wrangler deploy
```

The mailer is chosen by which secret is present, never by retrying a
failed send: `OWLPOST_API_KEY` selects [Owlpost](https://owlpost.to) (send
from `no-reply@send.keepshipping.run` — the sending domain
`send.keepshipping.run` must be verified there); with no Owlpost key the
mailer falls back to Resend on the same `RESEND_API_KEY` deployment.

Secrets degrade safely: with no `TURNSTILE_SECRET` the harness refuses
joins in production (fail-closed); with neither mail key the join is still
captured as `pending`, just without confirm mail. `ADMIN_TOKEN` is the
export credential — set it before pointing the admin tooling at the API.

## Mail theme

Mail renders in Keep Shipping's own theme, compiled in from
[`src/mail-theme.json`](src/mail-theme.json) — brand name, logo, light and
dark palettes, fonts, square corners (`radius: 0`), footer and contact.
The header logo is the hosted PNG at
`https://keepshipping.run/assets/email/logo-64.png` (serve it at twice the
displayed 32×32, and keep it in place: every mail references it).

A deployment can adjust any field without a rebuild by setting a
`MAIL_THEME` config value — a JSON object with any subset of the theme's
fields — as a `wrangler.toml` `[vars]` entry or a secret; it is merged
field by field (nested `light`/`dark` objects merge key by key) over the
composed theme at send time.

## Test

```sh
cargo test -p keepshipping-waitlist
```

The integration tests mount the same module composition `src/lib.rs`
serves, against the testing kit's fakes: captcha refusals, rate-limit
`429`, unknown-product `400`, clean `202` + pending row, and the
`NotConfigured` mailer path. `tests/mail.rs` snapshots the themed confirm
and confirmed mails (HTML and text) and round-trips the theme JSON.

## Pending before launch

- Verify the `send.keepshipping.run` sending domain in Owlpost (or
  Resend, on the fallback path) — until then mail cannot flow and entries
  stay `pending` (the double opt-in mail is the open question in #146).
- Create the Turnstile widget for `keepshipping.run`; the worker pins
  `expected_hostname` to the apex.
- Privacy notice on the site before the form goes live (website#4): the
  API deletes confirmed-or-not entries after the retention window
  (`retention_days_pending`), and `wrangler d1 execute` can erase one on
  request — but the notice is what makes that honest.
- Answers fields (company size, CI, IaC, deploy target): deferred until
  #146's question is answered; the module supports an answers schema when
  the copy exists.
