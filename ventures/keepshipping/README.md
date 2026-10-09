# keepshipping-waitlist (the Keep Shipping console)

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
- `GET /v1/console/search-console?zone=...` — the Search Console status
  page (#274): what the domain's verification and sitemap state is, the
  one-time service-account setup, and the change form. All console routes
  require a signed-in caller; an anonymous one gets the 401 shell.
- `GET /v1/console/gsc?zone=...` — the JSON twin of the page's status
  card: `{"zone", "verified", "sitemap_submitted", "sitemap",
  "last_read_at"}` for the Standard setup page to embed.
- `POST /v1/console/search-console/module` — generates the domain
  verification Terraform change from a form (`zone`, `owners`, `sitemap`):
  `text/x-terraform` attachment `search-console.tf` by default, or (with
  `Accept: application/json`) an edit-as-code payload. Reads only — no
  Google API call mutates anything; the submission itself stays the
  engine's `gsc.sitemap_submit` step.
- `GET /v1/setup` — the standard setup console (#273): a plain-words
  checklist per domain — Google Search Console, Gmail Postmaster Tools,
  Bing Webmaster Tools, SPF, DKIM, DMARC, MTA-STS, TLS-RPT — with a live
  chip per item (Done / Turning on / Needs you / Off) re-checked over
  DNS-over-HTTPS every few seconds. Every route needs a signed-in caller;
  the pages are served from the console host (`console.keepshipping.run`,
  see "Host" below).
  - `GET /v1/setup/{domain}` — the checklist; a first view seeds
    Google-Workspace defaults. `POST /v1/setup/{domain}` sends ONE change
    for everything ticked — a pull request (`setup/{domain}-…`, one
    `dns.tf`, a plain-words summary) against the infra repo, never a
    direct DNS API mutation; re-sending an unchanged checklist sends
    nothing. `POST /v1/setup/{domain}/confirmed` records an "I did this"
    for the outside services; `GET /v1/setup/{domain}/status` is the JSON
    the page polls.

Alongside the routes, the hourly cron (`[triggers] crons` in `wrangler.toml`,
shared with the billing module's dispute poll) runs the waitlist module's
sweeps: purging `pending` entries past
`RETENTION_DAYS_PENDING`, and pruning send-cooldown claims whose window has
closed. Without it nothing expires — the handler is mounted, but only a
declared trigger reaches it.

## Host

This Worker is the **console**: `keepshipping-console` at
`console.keepshipping.run`, with its own D1 database
(`keepshipping-console`), KV namespace (`keepshipping-console-fleet`) and
rate-limiter namespace (`2201`) on the Factory0 account.

It is deliberately *not* `api.keepshipping.run`. That host, and the Worker
name `keepshipping-waitlist`, belong to the separate live waitlist Worker in
[Keep-Shipping/waitlist-backend](https://github.com/Keep-Shipping/waitlist-backend),
which the site's form posts to and whose D1 holds the real waitlist.
Deploying this crate under that name or route would replace it.

The waitlist module is still mounted here (the composition is shared with
the tests), but it is inert in this deployment: its tables live in the
console's own database, so it never reads or writes the live list; the
site never posts to this host; and with no `TURNSTILE_SECRET` it refuses
joins in `ENV=production`. Leave `TURNSTILE_SECRET` and the mail keys
unset on the console.

The setup console's forms post back to `console.keepshipping.run`. The
origin guard accepts that once the same-origin rule from #332 (edit as
code) is in; before it, those writes answer `403`. The pages also need
`.auth_from_env()` on the runtime (also in #332) plus `AUTH_ISSUER` and
`AUTH_CLIENT_ID`, or they answer `503`.

The owner script `~/keepshipping-console-deploy.sh` (outside the repo)
applies the migrations, deploys, sets `HARNESS_SECRET` when missing, lists
the secrets that need a person, smokes `/__health`, and publishes the docs
site (`tools/deploy.sh`, Pages project `keepshipping-docs`).

## Deploy

```sh
npm install -g wrangler   # or npx wrangler
# The database (`keepshipping-console`), the FLEET KV namespace and the
# rate-limiter namespace (2201) already exist on Factory0 and are pinned
# in wrangler.toml; on a fresh account create them and replace the ids.
wrangler d1 migrations apply keepshipping-console --remote
wrangler secret put HARNESS_SECRET    # >= 32 bytes; signs confirm links (openssl rand -hex 32)
wrangler secret put ADMIN_TOKEN       # optional; the CSV export Bearer
wrangler secret put OWLPOST_API_KEY   # preferred mailer; verify send.keepshipping.run in Owlpost
wrangler secret put RESEND_API_KEY    # fallback mailer, used when no Owlpost key is set
wrangler secret put TURNSTILE_SECRET  # Turnstile widget on keepshipping.run
wrangler secret put SETUP_GITHUB_TOKEN # opens the setup console's pull requests
wrangler secret put GOOGLE_SERVICE_ACCOUNT_JSON  # Search Console status reads (#274)
wrangler deploy
```

The Search Console secret is a Google service-account key file's JSON,
pasted whole — its `private_key` signs the JWT that fetches the status.
Share the property once in Search Console ("Settings → Users", the
service account's `client_email` as an Owner); until then every domain
reads as "not verified yet". With the secret unset the status reads answer
a not-ready page and the Terraform generator still works.

The mailer is chosen by which secret is present, never by retrying a
failed send: `OWLPOST_API_KEY` selects [Owlpost](https://owlpost.to) (send
from `no-reply@send.keepshipping.run` — the sending domain
`send.keepshipping.run` must be verified there); with no Owlpost key the
mailer falls back to Resend on the same `RESEND_API_KEY` deployment.

Secrets degrade safely: with no `TURNSTILE_SECRET` the harness refuses
joins in production (fail-closed); with neither mail key the join is still
captured as `pending`, just without confirm mail. `ADMIN_TOKEN` is the
export credential — set it before pointing the admin tooling at the API.
The setup console needs `SETUP_GITHUB_REPO` (a var, `owner/repo`) plus
`SETUP_GITHUB_TOKEN` (a secret over that repo; `SETUP_GITHUB_BASE` names
the target branch, `main` by default) to file its pull requests — with
either missing it still serves, saves and answers status, and says on the
page that connecting to GitHub is needed before the change can be filed.

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

## Build

The Worker is built by `worker-build --release` (the `[build]` command in
`wrangler.toml`); `wrangler deploy` runs it for you. Run it locally to see
the same artefact CI checks:

```sh
cd ventures/keepshipping && worker-build --release
```

## Console fleet view

`/console/fleet` (issue #169) renders one screen of every zone, Pages site
and Worker the account's Terraform manages, plus a detail page per site.
It is read-only and fail-closed: it answers `GET`/`HEAD` only, and until
all three config values below are set it answers `503`.

- **Snapshot contract** — a pipeline (the nightly check) writes a JSON
  snapshot to KV binding `FLEET`, key `fleet.json`: `{account,
  generated_at, terraform: {repo, ref}, sites: [{id, name, kind:
  zone|pages|worker, venture, domains, defined_at: {path, line}, deploys,
  tls, dns, baseline, drift, resources}]}` with `deploys` newest first.
  Optional fields (`deploys`, `tls`, `dns`, `baseline`, `drift`,
  `resources`) render as "Not checked yet" / "Never deployed" until the
  pipeline fills them in. The shape is the `Fleet` struct in `src/fleet/`.
- **Auth** — `AUTH_ISSUER` + `AUTH_CLIENT_ID` build a token verifier
  (`cratefield-auth-client`); the token comes from `Authorization: Bearer`
  or the `ks_console` cookie, must have a verified `email` on the
  `CONSOLE_EMAILS` allowlist (comma-separated, case-insensitive), or the
  page answers `401`/`403`.

## Test

```sh
cargo test -p keepshipping-waitlist
```

The integration tests mount the same module composition `src/lib.rs`
serves, against the testing kit's fakes: captcha refusals, rate-limit
`429`, unknown-product `400`, clean `202` + pending row, and the
`NotConfigured` mailer path. `tests/harness.rs` asserts that the very
composition the Worker serves builds, and that `/__health` lists the
waitlist module with a version and the port declarations it reads. It
cannot check that a deployment *binds* those ports — those bindings exist
only on a real Workers `Env`. `tests/mail.rs` snapshots the themed confirm
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
