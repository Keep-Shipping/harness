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
- `GET /v1/edits` — edit as code (#170, [docs/EDIT_AS_CODE.md](../../docs/EDIT_AS_CODE.md)):
  console forms whose submit is a Terraform pull request against
  `EDITS_REPO`, never a Cloudflare API call. `GET /v1/edits/new?kind=...`
  renders a form, `POST /v1/edits` records the change and queues its pull
  request, `GET /v1/edits/{id}` shows the plan in words,
  `POST /v1/edits/{id}/plan` is the CI plan callback (Bearer
  `EDITS_RUNNER_TOKEN`), and `POST /v1/edits/{id}/approve` fires the apply
  dispatch for exactly the plan that was read. Every page needs a
  signed-in caller.
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
wrangler secret put EDITS_GITHUB_TOKEN   # opens the edit-as-code pull requests (#170)
wrangler secret put EDITS_RUNNER_TOKEN   # the CI plan callback's Bearer (#170)
wrangler deploy
```

### The master key for stored tokens (one-time)

The Cloudflare and GitHub tokens the console keeps are encrypted with a data
key per store, and that data key is wrapped under a master key (KEK). The
master key lives in a Cloudflare Secrets Store: generate it straight into the
store, so it is never printed or written to a file. `<STORE_ID>` is the store's
id, from `wrangler secrets-store store list --remote` (or create one with
`wrangler secrets-store store create <name> --remote`):

```sh
# Version 1 of the master key: 32 random bytes, piped in and never shown.
openssl rand -base64 32 | npx wrangler secrets-store secret create <STORE_ID> --name KS_CONSOLE_KEK_V1 --scopes workers --remote
# The version new wraps use. The value is the decimal version number.
printf 1 | npx wrangler secrets-store secret create <STORE_ID> --name KS_CONSOLE_KEK_CURRENT --scopes workers --remote
```

`--remote` is required: without it the command writes to a local development
store, not the one the Worker reads. `wrangler.toml` already binds both
secrets from Factory0's default store (`d9a352fe…`, secret names prefixed
`KS_CONSOLE_` because the store is shared by every Worker on the account), so
create them before deploying. Until the key exists, tokens saved before the
store existed are still read (read-only) and new tokens are refused with a
plain "set the master key" page.

**Which source is read.** The console uses one source per deployment. If
`wrangler.toml` declares any `HARNESS_KEK_*` Secrets Store binding, every
version is read from the store, and a version the store does not hold is
absent. Only a deployment with no such binding reads plain Worker secrets of
the same names (`wrangler secret put HARNESS_KEK_V1`, and so on). The two are
never mixed.

**Rotation.** (1) Create `HARNESS_KEK_V2` in the store with the command above
(`secret create --name HARNESS_KEK_V2`, or `secret update` to change it in
place). (2) Add a `[[secrets_store_secrets]]` block for `HARNESS_KEK_V2` to
`wrangler.toml`, with the same `store_id`. This must be done before the deploy:
without the block the Worker cannot read version 2. (3) Set
`HARNESS_KEK_CURRENT` to `2` in the store, and deploy. New data keys wrap under
version 2 from then on. (4) Open the Cloudflare connection page and press
**Re-encrypt with the current key**. That re-wraps every stored data key under
version 2 and reports how many it moved. The tokens themselves do not change.
(5) Only after that, remove `HARNESS_KEK_V1` from the store and its block from
`wrangler.toml`. Until step 4 runs, version 1 must stay. Removing a version
that a stored key still needs makes those tokens error on read, and the
console says it could not read them.

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
Edit as code reads `EDITS_REPO`, `EDITS_BASE_BRANCH` and `EDITS_INFRA_DIR`
(vars in `wrangler.toml`); until `EDITS_GITHUB_TOKEN` exists its pages
render and changes queue, but nothing is delivered — the cron picks the
queue up once the secret lands.

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

`/console/fleet` (issue #169) renders one screen of the account's zones,
Pages sites and Workers, plus a detail page per site. It is read-only and
fail-closed: it answers `GET`/`HEAD` only, and until all three config values
below are set it answers `503`.

- **Connect Cloudflare** — `GET /console/connect/cloudflare` explains the
  read-only token, links Cloudflare's pre-filled token page, and takes the
  pasted token (`POST` to the same path). The page's template link is
  `https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=…&accountId=*&zoneId=all&name=Keep%20Shipping%20console%20%28read-only%29`
  with these groups (`src/cloudflare/mod.rs`, `PERMISSIONS`; keys from
  Cloudflare's [API token templates](https://developers.cloudflare.com/fundamentals/api/how-to/account-owned-token-template/)
  permission reference): `zone`, `dns`, `ssl_and_certificates`,
  `workers_scripts`, `page` (Pages), `account_settings`, all `read`.
- **Storage** — the paste is checked (`/user/tokens/verify` must say
  `active`, and `/accounts` must list at least one account), then stored in
  the console's secrets vault under `cloudflare/read-token` (`cratefield-secrets`
  over the master key above; the encrypted row sits in D1, migration `0014`).
  The token is never logged, echoed, or put in a URL. A token sealed by the
  earlier scheme under `HARNESS_SECRET` (table `console_cloudflare_token`,
  migration `0009`) moves into the vault the first time it is read while
  `HARNESS_SECRET` is still set; that code path is legacy and is to be removed
  after one release.
- **Disconnect** — `POST /console/connect/cloudflare/disconnect` forgets the
  token (a soft delete in the vault: the encrypted value stays in D1,
  unreadable) and deletes the `fleet.json` snapshot.
- **Collector** — with a token stored, the collector lists every account
  the token can see (`CF_ACCOUNT_ID`, an optional var, narrows it to one), and
  for each, grouped by account on the page, its zones (with a certificate-pack
  check and the zone's `status`), its Pages projects (custom domains, the
  latest deployment, and the newest deployment of each of the five most
  recent preview branches), and its Workers scripts (the active deployment's
  version, message and trigger, and their custom domains). It writes the
  snapshot to KV `FLEET` / `fleet.json`. It runs on the hourly cron after the
  billing and waitlist sweeps, and from the "Refresh now" button on the fleet
  and empty-state pages. Failures are logged and the previous snapshot stays.
- **Endpoints read** — `GET /accounts`; `GET /zones?account.id=…` (paged);
  `GET /zones/{id}/ssl/certificate_packs`; `GET /accounts/{id}/pages/projects`
  (unpaged); `GET /accounts/{id}/pages/projects/{name}/deployments?env=preview&per_page=25`
  (one per Pages project); `GET /accounts/{id}/workers/scripts` and
  `/workers/domains` (unpaged); `GET /accounts/{id}/workers/scripts/{name}/deployments?per_page=1`
  (one per Worker script; the first listed is the one serving traffic).
- **Subrequests per snapshot** — with `Z` zones, `P` Pages projects, `W`
  Worker scripts and `A` accounts read: `1 + Σ over accounts of
  (⌈Z/50⌉ + Z + P + W + 3)` (the `+3` is the Pages, scripts and domains
  listings; `P` and `W` are per-item reads, `⌈Z/50⌉` is the zone pages). A
  listing failure does not add reads. Cloudflare caps the subrequests a single
  Worker invocation may make, so check a large account's count against the
  plan's limit before relying on the cron.
- **Gaps** — a refused or failed listing is a named gap. If every Worker
  deployments read fails, the gap is `Worker versions (Workers Scripts: Read)`;
  a partial failure falls back to each script's modified time without a gap.
  A failed preview read is the gap `Pages preview deployments (Cloudflare Pages: Read)`.
- **HTTPS and DNS from the zones** — no extra reads. A zone's HTTPS is
  "Secure" when an active certificate pack is found, else "Not checked yet";
  its DNS is "Healthy" when `status` is `active`, else a problem noting the
  status ("Zone is pending at Cloudflare"). A Pages or Worker site reads the
  worst state of its custom domains' zones (the longest zone name the domain
  ends in). `*.pages.dev` and `*.workers.dev` names read healthy. A domain
  whose zone is not in a connected account reads unknown with the note
  "Zone not in a connected account".
- **What the API cannot give** — Terraform definitions, baseline scores and
  code drift are not in the Cloudflare API. A collected snapshot has no
  `terraform`, its pages say "Not managed by Terraform yet", and their
  Baseline and Code cells read "Needs Terraform" (titled with the reason).
- **Deploy rows** — a Pages deploy shows its 7-character commit, branch and
  first line of the commit message when the trigger has them; a deployment
  with no commit (a Wrangler upload) shows its 8-character id labelled
  "upload". The trigger reads in words: `ad_hoc` is "uploaded with Wrangler",
  `github:push` is "git push". A Worker's row is its active version (8
  characters, "version …") with the deploy message and trigger (`upload` and
  `deployment` read "wrangler deploy"). A Worker with no read deployment
  shows only its modified time.
- **Environments** — a Worker named `<base>-staging`, `-test`, `-dev` or
  `-preview` is that environment and sorts beside `<base>`, which reads
  "production" when such a group exists. A Pages project with previews
  reads "production", and each preview branch is its own row labelled with
  its branch.
- **Dates** — every time reads `16 Oct 2026, 09:24 UTC` with a relative part
  ("3 days ago"; the snapshot's own time is its reference for the deploy
  rows, and the checked time reads "just now" by the same rule).
- **Snapshot contract** — a JSON snapshot in KV binding `FLEET`, key
  `fleet.json`: `{account, generated_at, terraform?: {repo, ref}, sites:
  [{id, name, kind: zone|pages|worker, environment?, venture, domains,
  defined_at?: {path, line}, deploys, tls?: {status, note?}, dns?: {status,
  note?}, baseline, drift, resources}]}`. `environment` is `production`, a
  Worker suffix (`staging`, `test`, `dev`, `preview`), or a Pages preview's
  branch. A deploy is `{commit, at, by, branch?, message?, refers_to?:
  commit|version|upload}`, `deploys` newest first. Pages preview rows have
  id `pages:{account}:{project}:{branch}`. A pipeline that writes Terraform
  can still fill those fields; the `Fleet` struct in `src/fleet/` is the shape.
- **Auth** — `AUTH_ISSUER` + `AUTH_CLIENT_ID` build a token verifier
  (`cratefield-auth-client`); the token comes from `Authorization: Bearer`
  or the `ks_console` cookie, must have a verified `email` on the
  `CONSOLE_EMAILS` allowlist (comma-separated, case-insensitive), or the
  page answers `401`/`403`. The connect page, the paste, disconnect and
  refresh all sit behind that same gate. Writes also pass the worker's
  same-origin check. The 401 page's "Sign in" goes to the console's own
  sign-in, below.
- **Operator steps** — apply migration `0009` to the console database, and
  nothing else: the token is pasted in the browser, not set as a secret.

## Sign-in

The console signs people in against a Cratefield auth instance with the
authorization-code flow and S256 PKCE (`src/signin.rs`):

- `GET /console/login?next=<path>` — a fresh `state` and PKCE verifier go
  into `ks_console_login` (signed with `HARNESS_SECRET`, 10 minutes,
  `Path=/console`), and the browser goes to
  `{AUTH_ISSUER}/v1/auth-core/authorize` with `client_id`, `redirect_uri =
  https://<console host>/console/callback`, `response_type=code`, `state`
  and the challenge. A browser that still holds a refresh cookie is renewed
  in place and sent straight to `next` instead.
- `GET /console/callback` — the `state` must match the login cookie; the
  code is exchanged (with the verifier, plus `AUTH_CLIENT_SECRET` for a
  confidential client) at `{AUTH_ISSUER}/v1/auth-core/token`; the access
  token must pass the verifier above and the allowlist (`403`, no cookie,
  otherwise). Then `ks_console` (the access token; `Path=/`, `Max-Age` = its
  lifetime, 10 minutes) and `ks_console_refresh` (the refresh token, sealed
  with a key derived from `HARNESS_SECRET`; `Path=/console`, 30 days) are
  set and the browser goes to `next`.
- When the access cookie has lapsed or no longer verifies, a `/console`
  page refreshes server-side (`grant_type=refresh_token`), always keeping
  the rotated refresh token, and sets both cookies again before falling
  back to the 401; a refused refresh clears both. `/v1` pages do not see
  the refresh cookie — their "Sign in" goes through `/console/login`,
  which renews the same way.
- `POST /console/logout` (the fleet pages' "Sign out"; same-origin, behind
  the origin guard) clears both cookies and links the auth service's own
  sign-out.

`next` is honoured only as a same-origin path under `/console`,
`/v1/edits`, `/v1/setup` or `/v1/console`; anything else lands on
`/console/fleet`. Every cookie is HttpOnly, Secure, SameSite=Lax and
host-only. Neither codes nor tokens are logged.

The deployment needs, beyond the three vars above: the `HARNESS_SECRET`
secret (already required by the harness); the console registered as a
client at the issuer with `https://console.keepshipping.run/console/callback`
as its redirect URI; and, only for a confidential client,
`wrangler secret put AUTH_CLIENT_SECRET`. Staging's issuer is
`https://auth-staging.keepshipping.run` (a public client); production's is
`https://auth.keepshipping.run`.

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
