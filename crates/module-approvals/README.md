# `ks-module-approvals`

Hosted approvals as a Cratefield module ([#147](https://github.com/Keep-Shipping/harness/issues/147)):
a runner parks a step, a signed-in human approves or denies it, and the decision goes back to the
run as a GitHub `repository_dispatch`. Mounted at `/v1/approvals`.

| Route | Who | What |
| --- | --- | --- |
| `POST /requests` | runner | Park a step. `201 {ticket, review_url, expires_at}`. |
| `GET /requests/{ticket}` | runner | `pending` \| `approved` \| `denied` \| `expired`, with the decision and its signature once given. |
| `GET /requests/{ticket}/review` | signed-in | The HTML review page: escaped summary, artifacts, expiry, approve/deny form. |
| `POST /requests/{ticket}/decision` | signed-in | `{decision, comment}` as `application/json`, or urlencoded from the review page's own form. Any other content type is a 415, and an `Origin` that is not ours is a 403 — the CSRF guard, on both. Checks in order: exists, undecided, unexpired, not the proposer, a GitHub login, active team member. |

`POST /requests` takes `{run_id, repo, step, summary, artifacts: [{name, sha256}], team,
proposed_by, reason, ttl_secs}`. `run_id` and `step` are `[A-Za-z0-9._:-]{1,128}`, `repo` and `team`
are `owner/name` with GitHub names on each side, `proposed_by` is a GitHub login, and a `sha256` is
64 lower-case hex digits — every field that reaches a signature or a GitHub URL is held to a charset
(`src/validate.rs`), so none can carry a newline or aim the token at another repository. `ttl_secs` is
clamped to the server ceiling. The runner's two routes carry `APPROVALS_RUNNER_TOKEN` as a bearer;
the approver's two need a signed-in login, checked against the team's membership at the click. A
GitHub outage while checking is a `503 membership-unchecked`, never a refusal.

## Configuration

`APPROVALS_RUNNER_TOKEN`, `APPROVALS_SIGNING_SECRET`, `APPROVALS_GITHUB_TOKEN`,
`APPROVALS_PUBLIC_BASE_URL` (the prefix review links are built under), and
`APPROVALS_GITHUB_ORGS` (a comma-separated allow-list; a request naming a repository or a team
outside it is refused, so the token cannot be aimed at an organisation this deployment was not given
for). Optionally `APPROVALS_GITHUB_API_BASE` (GitHub Enterprise) and `APPROVALS_MAX_TTL_SECS`.

## The runner's flow

1. Render the plan with `plan_summary::Limits { max_bytes: plan_summary::HOSTED_BODY_LIMIT }` and
   `POST` it. A summary over 64 KiB is refused as `413 summary-too-large`, naming the limit and the
   size rather than leaving the runner to guess.
2. Give the `review_url` to the team, and `GET /requests/{ticket}` until the state is `approved` or
   `denied`.
3. On the `keepshipping-approval` dispatch, verify `client_payload.signature` — the HMAC binds the
   ticket, run, repo, step, outcome, approver, timestamp and the sorted artifact digests, all of
   which `client_payload` carries, so it can be checked from the dispatch alone — then compare the
   bound digests against the plan's own before releasing anything.

The decision, its signature and the queued dispatch commit together. A dispatch GitHub refuses for
good (any 4xx but `408`/`429`) is dropped with a trace rather than retried for ever.