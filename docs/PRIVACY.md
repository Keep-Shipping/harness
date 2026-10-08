# Data inventory: what the hosted service holds

Every field the hosted Keep Shipping service receives, why we hold it, how
long we keep it, and how it is deleted. It covers three modules — the
early-access waitlist, which is written and deployable but **not deployed**,
and web approvals and the run log, which are further from that — and a fourth
group of items the hosting edge holds rather than we do: rate limits,
captcha, Cloudflare's own logs. The fourth hosted surface in
[ARCHITECTURE.md](ARCHITECTURE.md), the blocks index, is deliberately out of
scope here; see the Gaps section.

Four things this document does not do. It does not wire
`cratefield-module-privacy`; that crate is not a dependency of this
repository, and the declarations under `ventures/keepshipping/privacy/` are
the contract it will consume, committed ahead of the code. It does not
schedule the retention sweep — no cron is wired, so nothing is swept today. It
does not claim the service is running: `wrangler.toml` binds a placeholder
`database_id`, so no waitlist data has ever been collected. And it does not
describe the site's own privacy notice, which is still pending (website#4);
this document is the input to that notice, not a substitute.

## How to read this

The runner is local-first: plan bytes, secrets and source never leave the
machine that runs them. What crosses the runner → hosted boundary is a closed
allowlist, ratified in [ADR 0005](adr/0005-local-first-core-with-optional-hosted-services.md);
this document covers the other side of that boundary, what the hosted service
ends up holding.

The governance rule is the ADR's: egress is a closed allowlist, and adding a
field means amending the ADR. The mirror of that rule governs this file —
adding a field to a hosted module means adding a row here and a key to the
module's declaration in `ventures/keepshipping/privacy/`, and both are reviewed
together. A field that reaches a hosted module without a row here is a
defect, not an oversight.

The Waitlist retention cells say "no sweep is scheduled" rather than a window
wherever the window is not in force. A retention window that no code applies is
not a retention policy. The other modules say what their own store does with
the row: in-process for approvals, on disk for the run log, and whatever the
hosting edge does for the rest.

## The inventory

| Module | Field | What it is | Why we hold it | Retention | Deletion path |
|---|---|---|---|---|---|
| Waitlist | `id` | ULID, primary key | Identifies the entry without exposing who it is; confirm tokens bind to it | no sweep is scheduled | With the row: anonymise, or delete by `id` |
| Waitlist | `email` | The address given at signup, as typed | The only address we mail | no sweep is scheduled | Anonymised to `NULL` |
| Waitlist | `email_normalized` | Lowercased form of the same address, for the per-product uniqueness constraint | Uniqueness; a second signup cannot claim a place twice | no sweep is scheduled | Anonymised to `NULL` |
| Waitlist | `product` | The product code the entry is for (`keepshipping`) | A queue is per product | no sweep is scheduled | Kept on anonymise |
| Waitlist | `status` | `pending` or `confirmed` | Distinguishes a captured address from one that proved it | no sweep is scheduled | Kept on anonymise |
| Waitlist | `position` | Dense per-product join order, never recomputed | The number `status` reports to the person waiting | no sweep is scheduled | Kept on anonymise — deleting a confirmed row would change a count others can see |
| Waitlist | `referral_code` | Unique code the person shares | Attribution for the referral credit | no sweep is scheduled | Kept on anonymise |
| Waitlist | `referred_by` | The `referral_code` of whoever invited them | Credits the inviter | no sweep is scheduled | Kept on anonymise — deleting would orphan every referral pointing at it |
| Waitlist | `referrals` | Count of referrals already credited to this row | The score the waitlist page ranks by | no sweep is scheduled | Kept on anonymise — it is a credit already granted to somebody else |
| Waitlist | `answers` | Opaque text. Its field list is **unspecified**: no answers form is defined yet, and every field will be named here before the form goes live ([#146](https://github.com/Keep-Shipping/harness/issues/146)) | Answers questions the form asked; none are asked today | no sweep is scheduled | Anonymised to `NULL` |
| Waitlist | `created_at` | Text timestamp of the signup | Ordering the queue | no sweep is scheduled | Kept on anonymise |
| Waitlist | `confirmed_at` | Text timestamp of the double opt-in, if it happened | Tells a captured address from a proven one | no sweep is scheduled | Kept on anonymise |
| Waitlist | `generation` | Integer, starts at 1; confirm tokens bind to `(id, generation)` | Makes a replayed confirm token inert | no sweep is scheduled | Kept on anonymise |
| Approvals | `seq` | Monotonic ticket counter | Ticket ids are `ha-1`, `ha-2`, …; not a credential | Process lifetime | Process exit |
| Approvals | `request.run` | Run id the request belongs to | Binds a ticket to one run | Process lifetime | Process exit |
| Approvals | `request.step` | Step name awaiting a decision | Says what is being approved | Process lifetime | Process exit |
| Approvals | `request.summary` | **Free prose**, rendered for a person to read before deciding | An approver cannot judge a diff from a hash | Process lifetime | Process exit |
| Approvals | `request.artifacts` | The `(kind, digest)` pairs — the digest is the identity an approval binds to. The plan file is itself just an artifact of kind `PlanFile` | Lets the approval be bound to exact bytes without holding them | Process lifetime | Process exit |
| Approvals | Masked `PlanSummary` | Per ADR 0005: `add`/`change`/`destroy` counts and the `risky` and `others` entries, each with `kind`, `address`, `reason` and attributes `path`, `before`, `after`, `forces_replacement`, masked once by `summarize`, bounded by `HOSTED_BODY_LIMIT` | An approver judges a change, not a hash. **This is a disclosure**: resource addresses and non-secret attribute values reach the hosted side, which ADR 0005 says plainly is real | In flight to the review page; not written to the store | Nothing stored; gone when the request ends |
| Approvals | `ActionClass` | The gated step's class — its `kind` and, when it has one, `env` | Says what sort of action is being authorised | In flight to the review page; not written to the store | Nothing stored; gone when the request ends |
| Approvals | `full_plan_url` | Optional URL to the full plan, when set | Lets a person see the unmasked plan without the service holding it | In flight to the review page; not written to the store | Nothing stored; gone when the request ends |
| Approvals | Decision `Signature` | ADR 0005's returning decision carries `approved`, a `by` handle with the verified identity, a timestamp, the plan digest it binds, and a `Signature { bytes, identity }` | The service says *who decided*, never *who may* | In flight to the review page; not written to the store | Nothing stored; gone when the request ends |
| Approvals | `request.from` | The team that asked | An approval is scoped to a team | Process lifetime | Process exit |
| Approvals | `request.reason` | **Free prose**, the proposer's case | Why now, for the approver | Process lifetime | Process exit |
| Approvals | `request.proposed_by` | `Identity`: a handle plus `Human` or `Service`. No email, no display name, no account id | Names who asked | Process lifetime | Process exit |
| Approvals | `verdict.approver` | `Identity` of the person who answered | Names who said yes | Process lifetime | Process exit |
| Approvals | `verdict.at` | `SystemTime` of the verdict | Orders answers | Process lifetime | Process exit |
| Approvals | `verdict.outcome` | `Outcome::Approved` or `Outcome::Refused` | The decision itself. (`Granted`/`Denied` are the *run-log* wire names, a different vocabulary) | Process lifetime | Process exit |
| Approvals | `verdict.comment` | **Free text the approver wrote.** The one field here most likely to contain anything personal | Why somebody approved or refused | Process lifetime | Process exit |
| Approvals | `verdict.bound_artifacts` | The `(kind, digest)` pairs the verdict was bound to | A verdict answers for specific bytes, not for a step name | Process lifetime | Process exit |
| Approvals | `channel` | `web` or `slack` | Which front end the answer arrived through | Process lifetime | Process exit |
| Approvals | `GitHubSession.login` | The GitHub login carried by the session. **Request-scoped**: the submit handler converts it to `Identity::human(...)` and the session is dropped. It is never put in the ticket store | A web answer needs a verified human | Held for the request only; never stored | Process exit, or the request ends |
| Approvals | Slack `team_id`, `user_id` | Slack's own identifiers. **Request-scoped**: resolved to a handle at submit time, and only the handle is kept | Resolves a Slack answer to a person | Held for the request only; only the handle is stored | Process exit |
| Run log | `run.started` | `file_hash`, trigger, `actor` handle, `is_agent` | Who ran it | Local only; nothing is uploaded | Delete the run file |
| Run log | `step.started` | Step name only | Progress | Local only | Delete the run file |
| Run log | `step.finished` | Step name, `ok`, output **names**, duration, redacted error text | Progress and failure | Local only | Delete the run file |
| Run log | `step.rolled-back` | Step name, policy, status, `reverted_to`, reason text | A failed deploy was undone and what it went back to | Local only | Delete the run file |
| Run log | `approval.requested`, `approval.expired` | Step, channel, artifact hashes | Shows a run parked and released | Local only | Delete the run file |
| Run log | `approval.granted` | Approver **handle**, channel, artifact hashes | The claim that a person looked at this | Local only | Delete the run file |
| Run log | `approval.denied` | Approver **handle** plus `reason`, the approver's **own words** or the engine's one line | The refusal and its grounds | Local only | Delete the run file |
| Run log | `approval.aborted` | `proposer` handle, channel, artifact hashes | Distinguishes "we stopped asking" from "we were told no" | Local only | Delete the run file |
| Run log | `approval.rejected` | `detail` — which rule held, no `approver` to blame | Records that an answer was thrown away | Local only | Delete the run file |
| Run log | `decide.sent` | Redacted plan state and questions shown to a model | `keepshipping decide --explain` shows exactly what left | Local only | Delete the run file |
| Run log | `decide.answered` | Model answer, confidence, and `question_hash` / `state_hash` — sha256 of what was sent, so a decision can be matched to its inputs without the log holding either | Calibration | Local only | Delete the run file |
| Run log | `credentials.resolved` | Cloud, role, and how credentials were got | Shows the shape of the assumption; the token is never here | Local only | Delete the run file |
| Run log | `decision.overridden` | `by` **handle** and `reason` **free text** — a human disagreeing with a recorded decision | The override and its reason | Local only | Delete the run file |
| Run log | `attestation.attached` | Image digest and pushed attestation envelope digest | Provenance | Local only | Delete the run file |
| Run log | `policy.refused` | An optional step name (`None` before any step ran) and the `rule` that held. Carries no digest and no resource address | The run stopped and which rule stopped it | Local only | Delete the run file |
| Run log | `plan.stale` | `PlanStale { step, cause, approved, replanned, differs }`: the step that was applying, the `cause` (`state` when the tool found state moved, `drift` when a pre-apply recheck found the change set differs), `approved` and `replanned` — sha256 digests of the approved plan and of the fresh one the run asks about now, both `None` for `replanned` when the re-plan itself failed — and `differs`, whether the fresh change set differs, also `None` when there was no fresh plan to compare | An approved plan could not be applied as approved | Local only | Delete the run file |
| Run log | `run.finished` | Status and shipped artifact names | The closing state | Local only | Delete the run file |
| Edge | Rate-limit key | Per-IP counter under the `RATE_LIMITER` binding, 30 requests per 60 seconds | Abuse prevention | Cloudflare's own lifecycle; we do not set it | Expires with the counter's own window |
| Edge | Turnstile token | The captcha solve posted with a join, checked against `TURNSTILE_SECRET`. With that secret unset there is no captcha port at all, and `ENV=production` then refuses every join — fail-closed | Stops automated signups | Held per request; not stored in D1 | Not retained by us |
| Edge | `Origin` header | Checked against the site's origins on every write; refused `403` otherwise | Stops cross-origin writes | Held per request; not stored in D1 | Not retained by us |
| Edge | `Authorization: Bearer ADMIN_TOKEN` | The export credential on `GET /v1/waitlist/admin/export.csv` | Gates the CSV export | Held per request; the secret itself is a Worker binding | Rotating the secret revokes it going forward. It does **not** retract a header already captured in a Cloudflare request log; no purge path for those exists in this repository |
| Edge | Cloudflare request logs | `[observability] enabled = true`, so the platform retains request logs | Platform operability | Cloudflare's retention; no value is set in this repo | Cloudflare's own lifecycle |
| Edge | Worker secrets | `ADMIN_TOKEN`, `TURNSTILE_SECRET`, `OWLPOST_API_KEY`, `RESEND_API_KEY`, optional `MAIL_THEME` | Mail, captcha and export access | Held as bindings for the life of the deployment | `wrangler secret put` replaces; deletion is Cloudflare's |
| Edge | Mail transport | The address and template are handed to Owlpost or Resend to send confirm mail | Sending requires a mailer | The mailer's own retention | A request to that mailer |

## Waitlist

Declaration: [`privacy/waitlist.toml`](../ventures/keepshipping/privacy/waitlist.toml).

The only hosted module written, and it is **not deployed**. It is a Cloudflare
Worker at `api.keepshipping.run` over a D1 database, and it cannot be serving:
`wrangler.toml` binds `database_id = "0000...0000"`, a documented placeholder,
and no deploy workflow exists in `.github/workflows/`. No waitlist entry has
therefore ever been collected, and the retention and erasure rows below
describe a design rather than a live corpus.

Its store is `waitlist_entries` (the 13 rows in the table above), plus two
further tables. `waitlist_position_lock` holds `product`, `updated_at` and
`next_position`, and its rows migration 0004 records as never pruned. Whether
`waitlist_send_cooldown` holds personal data is **not verifiable from this
repository**: its only definition here is migration 0003, `subject TEXT PRIMARY
KEY, last_sent_at TEXT NOT NULL`, and in a module that mails confirm links
`subject` is plausibly the recipient address. The code that writes it is in
`cratefield-module-waitlist`: it is on crates.io and `cargo fetch` resolves it,
but its source is not in this working tree, so its behaviour cannot be read
from here without fetching. Confirm against that crate before launch; this
document does not assert either way.

Retention is not running, and the sweep itself is upstream. The
`#[event(scheduled)]` handler in `src/lib.rs` is unwired — `wrangler.toml`
declares no `crons` trigger — so nothing fires. The pending-entry sweep it
would call is `cratefield-module-waitlist`'s design, on a
`retention_days_pending` clock; that crate is on crates.io and resolvable, but
its source is not in this working tree, so the only evidence in this repository
is a doc comment on the handler, which is a claim rather than a thing you can
point at. And `retention_days_pending` is a setting
that no `[vars]` entry in this repository supplies, so the window's value is
not even visible here. Both are gaps, listed below.

## Approvals

Declaration: [`privacy/approvals.toml`](../ventures/keepshipping/privacy/approvals.toml).

No hosted approvals service is deployed. What exists is the in-process adapter
`ks-hosted-approvals`, whose ticket store is a `Mutex<BTreeMap<..>>` — in
memory, per process, with no database and no network client. The store holds
exactly `Entry { seq, request, verdict, channel }`, so every field marked
"process lifetime" above dies with the process, and an access or erasure
request needs no restart and no operator action: the data was never stored in
the first place. The two request-scoped fields, and the four that only render
the review page, are the exceptions and are never stored at all.

The identity in the core type is a handle plus a kind. `Identity` is
`{ handle, kind }` where kind is `Human` or `Service` — no email, no display
name, no avatar, no account id. `GitHubSession` carries a GitHub login and its
constructor is an unrestricted `pub fn new(login: impl Into<String>)`: the
restriction to the venture's OAuth exchange is a documented *intent* on the
type, not a constraint any code enforces here, and no OAuth exchange exists in
this repository. Slack answers resolve through `(team_id, user_id)` to a
handle, and only the handle is kept.

## Run logs

Declaration: [`privacy/runlog.toml`](../ventures/keepshipping/privacy/runlog.toml).

Local only. Run events are appended as hash-chained JSONL under
`.keepshipping/runs` on the runner. No hosted run-log viewer exists.

Two redactions stand between a run and its log, and both run before an
adapter ever sees an event. `RunEvent::redacted` scrubs every variant, spelled
out field by field on purpose, because an or-pattern binds only the fields
every arm shares — which is how `approver` went unscrubbed the first time
this was written. Underneath, `VALUE_ALLOWLIST` names exactly nine attribute
paths whose values may leave (`count`, `desired_count`, `instance_type`,
`instance_class`, `min_size`, `max_size`, `node_count`, `replicas`,
`engine_version`), matched against the whole path and capped at 64 bytes.
Everything else renders `(withheld)`; a summarised plan renders names only.

## Access and erasure requests

Write to [contact@keepshipping.run](mailto:contact@keepshipping.run) — the
address the venture's mail already carries, and the one
[SECURITY.md](SECURITY.md) uses for disclosure.

Today, an erasure on the waitlist is manual: an operator runs
`wrangler d1 execute` against the `keepshipping-waitlist` database. There is no
self-service route and no request queue; the person who writes has to be the
person who can act. Note that the venture
[`README.md`](../ventures/keepshipping/README.md) says the API "deletes
confirmed-or-not entries after the retention window" — that sentence is
**stale**: no `crons` trigger is wired, so no deletion happens on any window.
The window's value is not even set in this repository.

Once `cratefield-module-privacy` is wired, it carries that out as

```sql
UPDATE waitlist_entries SET email = NULL, email_normalized = NULL, answers = NULL WHERE id = ?
```

Anonymise, not delete, and the reason is structural rather than cautious.
Migration `0005_waitlist_anonymisable_entry.sql` states it: `position` is a
dense per-product join order that is never recomputed and `referrals` is a
credit already granted to somebody else, so deleting a confirmed row changes a
count other people can see and orphans every `referred_by` that points at its
code. Keeping the row and taking the person out of it answers the request
without rewriting anyone else's place in the queue. The same migration is why
`email` and `email_normalized` are nullable: without it, the statement the
declaration promises would have failed on the first request.

## What never leaves

Read the closed list in
[ADR 0005](adr/0005-local-first-core-with-optional-hosted-services.md) — "What
never leaves the runner". It is not restated here, because a partial copy of a
closed list is a list that will drift.

The three points a reader of *this* document most needs: plan bytes and their
raw values never cross (there is no hosted adapter for them, ever); customer
secrets and environment variable *values* never cross, though a variable *name*
may leave as an `Establishment` marker; and what a hosted approval service does
receive is the plan digest *plus* the masked `PlanSummary` — resource addresses
and non-secret attribute values — which ADR 0005 itself calls a real
disclosure.

## Gaps

None of these are done. Following [SECURITY.md](SECURITY.md), they are
written as gaps rather than described as controls.

1. The waitlist is not deployed. `wrangler.toml` binds a placeholder
   `database_id` and no deploy workflow exists, so the module cannot be
   serving and no entry has been collected. ([#146](https://github.com/Keep-Shipping/harness/issues/146))
2. The retention sweep has no schedule, and the sweep is upstream. A
   `#[event(scheduled)]` handler exists but `wrangler.toml` has no `crons`
   trigger, and the sweep itself is `cratefield-module-waitlist`'s, whose
   source is not in this working tree. Nothing is swept.
   ([#151](https://github.com/Keep-Shipping/harness/issues/151))
3. `retention_days_pending` is unset in this repository, so even once a cron
   fires the window's value is not visible here. It is a
   `cratefield-module-waitlist` setting. ([#146](https://github.com/Keep-Shipping/harness/issues/146))
4. Whether `waitlist_send_cooldown` holds personal data cannot be read from
   this working tree; migration 0003 only says `subject TEXT`, and the crate
   that writes it is on crates.io but its source is not here. Confirm against
   `cratefield-module-waitlist` before launch.
   ([#146](https://github.com/Keep-Shipping/harness/issues/146))
5. The waitlist `answers` field list is undecided; no answers form exists, and
   every field will be named here before the form goes live.
   ([#146](https://github.com/Keep-Shipping/harness/issues/146))
6. `GitHubSession::new` is an unrestricted public constructor. The documented
   intent that only the venture's OAuth exchange may build one is not enforced
   by any code here, and no OAuth exchange exists in this repository.
   ([#151](https://github.com/Keep-Shipping/harness/issues/151))
7. Hosted approvals, the run-log viewer and the blocks index are not deployed.
   Of the four hosted surfaces in [ARCHITECTURE.md](ARCHITECTURE.md), only
   the waitlist is written. ([#151](https://github.com/Keep-Shipping/harness/issues/151))
8. `cratefield-module-privacy` is not a dependency of this repository. The
   declarations are the contract, committed ahead of the wiring; nothing reads
   them yet. ([#151](https://github.com/Keep-Shipping/harness/issues/151))
9. The site's own privacy notice is a separate document, in Keep-Shipping/website
   ([website#4](https://github.com/Keep-Shipping/website/issues/4)). This
   document is its input, not the notice; nothing here is published on the site
   yet.

## See also

- [SECURITY.md](SECURITY.md) — the security model and how to report a vulnerability
- [ADR 0005](adr/0005-local-first-core-with-optional-hosted-services.md) — local core, optional hosted services
- [ARCHITECTURE.md](ARCHITECTURE.md) — the four hosted surfaces
- [CREDENTIALS.md](CREDENTIALS.md) — what credentials do and do not cross
- [GITHUB_APPROVALS.md](GITHUB_APPROVALS.md) — the approval flow and its adapters
- [The module declarations](../ventures/keepshipping/privacy/) — waitlist, approvals and run log; one file per hosted module
