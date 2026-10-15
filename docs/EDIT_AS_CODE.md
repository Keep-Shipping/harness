# Edit as code

The Keep Shipping console's forms write Terraform pull requests — never
Cloudflare API calls. A signed-in person fills a plain-words form; the worker
turns it into one additive HCL file in the infrastructure repository's
per-zone module, opens a pull request through the outbox, and the
repository's own workflow plans the change and posts the plan back. A person
reads the plan in words on the change's page — removals and replacements make
them type the zone's name — and approval fires a `repository_dispatch` so the
same workflow applies the exact plan that was checked. The pull request is
the review; nothing applies without one.

The behaviour lives in
[`ventures/keepshipping/src/edits/`](../ventures/keepshipping/src/edits/)
(`mod.rs` routes and outbox, `change.rs` the form→HCL generators,
`github.rs` the REST calls, `page.rs` the server-rendered pages); the
integration tests are
[`ventures/keepshipping/tests/edits.rs`](../ventures/keepshipping/tests/edits.rs).

## The flow

1. `GET /v1/edits` lists every change with its status chip (opening the pull
   request → checking the plan → ready for approval → approved — applying /
   failed) and the "Make a change" chooser. Everything requires a signed-in
   caller; anonymous requests get a 401 page.
2. `GET /v1/edits/new?kind=dns` renders one form. `POST /v1/edits` validates
   it in plain words, records the edit, enqueues the pull request, and
   redirects to `GET /v1/edits/<id>`.
3. The outbox opens the pull request: branch `ks-edit/<edit id>` off the base
   branch, one commit per file, then the PR. The edit's page links it.
4. The repository's workflow plans the PR and posts the plan back (below).
   The page shows it as coloured rows — `N to add · N to change · N to
   remove` — with every removal and replacement red.
5. `POST /v1/edits/<id>/approve` records who approved and when, and enqueues
   the dispatch in the same database batch. The form carries the digest of
   the plan the person read; if a newer plan has arrived since, approval is
   refused (409) and the page asks them to look again. A plan that removes
   anything additionally refuses approval until the zone's name is typed
   back.
6. The workflow receives the dispatch, verifies the plan digest, and applies.

## The forms

Eight kinds, each writing exactly one resource (or, for `variable`, the exact
lines to merge into a Worker's bindings):

| kind | resource |
| --- | --- |
| `dns` | `cloudflare_dns_record` (A, AAAA, CNAME, TXT) |
| `redirect` | the zone's one `http_request_dynamic_redirect` ruleset |
| `domain` | `cloudflare_workers_custom_domain` |
| `route` | `cloudflare_workers_route` |
| `email` | `cloudflare_email_routing_rule` |
| `setting` | `cloudflare_zone_setting` (a fixed allowlist of settings and values) |
| `variable` | a Worker binding: merge-snippet plus a `sensitive` variable declaration |
| `raw` | Advanced: a file name and Terraform, written as given |

Files land under `EDITS_INFRA_DIR` in the zone's module directory
(`modules/<zone>/edit-<id>.tf`, the layout the Cloudflare adapter generates).
The console never sees a Cloudflare zone id: the file looks the zone up by
name with a `data "cloudflare_zone"` read, which plans as no change.

A secret variable's value never enters the repository: the form refuses
secret-looking names (`*KEY`, `*TOKEN`, `*SECRET`, `*PASSWORD`) that carry a
value, caps plain-text values at 1024 bytes, and the empty-value path emits
`var.<NAME>` with a `sensitive` declaration — the value is set out of band
(`wrangler secret put`, or `TF_VAR_<NAME>` through the harness Secrets port).

## Sign-in

Every console page needs an identified caller. The venture wires the
harness's token verifier (`AUTH_ISSUER` + `AUTH_CLIENT_ID`); with both unset
the port is `Unconfigured` and the pages answer 503 rather than serve
anonymously. Browsers may present the credential two ways: an
`Authorization: Bearer` header (a page's `fetch`), or the session cookie the
console sign-in (`/console/login`, see the venture README) sets:

- name `ks_console`, holding the same JWT a Bearer header would carry;
- scoped to the console host (host-only), `Path=/`, `HttpOnly`, `Secure`,
  `SameSite=Lax`, for the token's lifetime.

SameSite=Lax plus the worker's origin guard (writes must carry an allowlisted
or same-origin `Origin`) are what keep a cookie-bearing form post safe
against cross-site forgery. The 401 page links to the console sign-in,
`/console/login?next=<where the visitor was>`, which comes straight back —
renewing silently from the refresh cookie when the session has only lapsed.
Setting `EDITS_SIGN_IN_URL` points the link at another sign-in page instead,
with `return=<where the visitor was>`.

## Configuration

| variable | meaning |
| --- | --- |
| `EDITS_REPO` | the infrastructure repository, `owner/name` (required) |
| `EDITS_BASE_BRANCH` | the branch pull requests target, usually `main` (required) |
| `EDITS_INFRA_DIR` | directory the zone modules live under; empty = repository root |
| `EDITS_SIGN_IN_URL` | another sign-in page for the 401 link (optional; default: the console's own `/console/login`) |
| `EDITS_GITHUB_TOKEN` | secret: the token that opens pull requests and fires dispatches. Until it is set the pages render and the queue waits — nothing fails |
| `EDITS_RUNNER_TOKEN` | secret: the Bearer the CI plan callback must present |
| `EDITS_GITHUB_API_BASE` | overrides `https://api.github.com` (tests, self-hosted) |

Secrets are not in `wrangler.toml`: `wrangler secret put EDITS_GITHUB_TOKEN`
and `wrangler secret put EDITS_RUNNER_TOKEN`.

## The CI contract

The infra repository owns one workflow. On `pull_request` (paths under the
zone modules) it plans and posts back; on `repository_dispatch` it applies.

**Post the plan** — after `tofu plan -out=tfplan` and `tofu show -json tfplan`:

```
POST /v1/edits/<edit id>/plan            # the edit id is in the branch name
Authorization: Bearer $EDITS_RUNNER_TOKEN
Content-Type: application/json

{ "head_sha": "<40-hex commit the PR is at>",
  "plan_file_sha256": "<sha256 of tfplan, when the workflow saves it>",
  "plan": { … the tofu show -json document … } }
```

The body is capped at 512 KiB; the worker stores only the per-resource
changes it renders (at most 200) plus the body's sha256. A callback for an
already approved edit is refused with 409 — the plan is frozen once approved.
`head_sha` must be the commit the pull request is at, so approval and apply
speak about the same code. The path is exempt from the browser `Origin`
guard because a machine credential cannot be forged cross-site — a browser
never sends that Bearer by itself.

**Apply on approval** — the dispatch carries what the workflow needs to be
sure it applies what was checked:

```json
{ "event_type": "keepshipping-edit-approved",
  "client_payload": { "edit_id": "01J…", "pr_number": 7,
    "head_sha": "…", "plan_sha256": "…", "plan_file_sha256": "…",
    "approver": "person_1", "zone": "example.com" } }
```

The workflow checks out exactly `client_payload.head_sha`, re-plans, and
applies only when the fresh plan file's sha256 equals
`client_payload.plan_file_sha256` (or, absent that, when the fresh
`tofu show -json` matches what was posted). If it runs the apply through
Keep Shipping, the same discipline is one `ship.ks`:

```yaml
steps:
  plan:     tofu.plan
    dir:    ./modules/example.com
  review:   approval
    show:   plan.changes
    from:   @platform
  apply:    tofu.apply
    plan:   plan.file        # the exact plan that was checked
```

**Alternative: approve on GitHub, not in the console.** The
[`ks-github` adapter](GITHUB_APPROVALS.md) implements the `ApprovalChannel`
port — a run parks at an `approval` step, posts one PR comment, and a team
answers with a slash command; membership is checked against the GitHub team.
That flow keeps approval where the code review already happens; the console
flow above keeps the plan's plain-words rendering and the typed confirmation
for removals. They are alternatives, not dependencies — the edits module
never calls it.

## Not covered yet

- One dynamic-redirect ruleset per zone: the `redirect` form owns it, so a
  second redirect needs an Advanced (`raw`) change.
- `variable` bindings are merge-snippets, not resources — Worker bindings
  live on `cloudflare_workers_script`, and adding to it is not a one-file
  additive change. The PR carries the exact lines; a person merges them.
- No drift detection: the console shows what was planned when the workflow
  posted, not what the zone looks like now.
- The runner token is one shared secret; rotating it revokes every runner at
  once. Per-repo tokens would be finer-grained.
