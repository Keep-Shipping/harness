# GitHub approvals

How a run asks a team of people for permission on a pull request, and how the
answer comes back. The adapter is [`ks-github`](https://github.com/Keep-Shipping/harness/tree/main/adapters/github)
([#96](https://github.com/Keep-Shipping/harness/issues/96)); it implements two
ports from `ks-core`:

- [`ApprovalChannel`](https://docs.rs/ks-core/latest/ks_core/ports/approval/trait.ApprovalChannel.html)
  — `request` / `poll` / `wait`
- [`Directory`](https://docs.rs/ks-core/latest/ks_core/ports/approval/trait.Directory.html) —
  `members` / `is_member`

It speaks plain HTTP through an `HttpClient` the caller hands it and nothing
else. The socket, TLS and host allowlist belong to that client
([ADR 0002](adr/0002-ports-and-adapters.md)); this crate holds the protocol.

## The flow

1. A run reaches a step that policy says needs a human. The engine parks the
   step and calls `request` with an `ApprovalRequest`: which run, which step,
   the rendered plan summary, the exact artifact digests, which team, and who
   proposed it.
2. `request` posts **one** PR comment carrying the summary and the instructions,
   and returns a `Ticket` — which is the id of that comment.
3. The run writes its state and exits. The ticket is all a later process needs.
4. A team member reads the comment and answers with a slash command.
5. A resume process calls `poll` with the ticket. The adapter re-reads the
   request comment, recovers the artifacts from the hidden marker, checks the
   answerer's membership, and returns a `Verdict` — or `Ok(None)` if nobody has
   answered yet.
6. The engine applies its own `ApprovalRequest::accepts` check before the run
   continues.

Steps 3 and 5 are separate processes on purpose: the adapter is stateless
across them ([ADR 0005](adr/0005-local-first-core-with-optional-hosted-services.md)),
so a run can park for a night and resume in a fresh job.

The engine's `approval` step and the `keepshipping approve` command line are
landing separately ([#94](https://github.com/Keep-Shipping/harness/issues/94),
[#95](https://github.com/Keep-Shipping/harness/issues/95)); this file documents
the adapter underneath them, and the workflow sketch below is a sketch.

## The comment

`request` posts a body like this:

````markdown
## Approval needed: production deploy

@platform must approve this run before it can continue.

- Run: `<run id>`
- Step: apply-infra
- Reason: production deploy
- Proposed by: @ada
- Team: @platform
- Artifacts: sha256:1a2b…

```
3 to create, 1 to destroy
```

---

To approve, comment `/keepshipping approve`.
To refuse, comment `/keepshipping refuse <reason>`.
You must be a member of @platform and not the proposer.

<!-- keepshipping:approval v1
run: <run id>
step: apply-infra
from: @platform
proposed_by: ada
artifacts: plan:sha256:1a2b…
-->
````

The team is printed as a bare handle — `@platform`, never `@Keep-Shipping/platform`.
The channel checks membership through the `Directory` port, which does not
expose the organization, so an org-qualified handle would be a guess — and a
wrong one whenever the repository owner and the team's organization differ, as
they can on GitHub Enterprise Server.

The last block is the **marker**: an HTML comment GitHub does not render, and
the only part `poll` trusts. It carries one field per line — `run`, `step`,
`from`, `proposed_by`, `artifacts` — so a value may contain spaces. `artifacts`
is a comma-separated list of `plan:` / `image:` / `other:` entries, each ending
in the artifact's digest.

The marker is trusted because only the token owner can post it. Everything a
caller controls — the summary, the reason, the step name, each marker field —
is stripped of `<!--` and `-->` (and of newlines in the marker), so none of it
can open a second marker or close the real one; the summary is fenced with
more backticks than it contains so it cannot break out of its code fence; and
`parse_marker` believes a body only when it carries *exactly one* marker.

Commands are read from the **first line** of a comment: it must be
`/keepshipping approve` or `/keepshipping refuse`, optionally followed by free
text that becomes the verdict's comment.

## The ticket is the comment id

`request` returns `Ticket::new(comment_id.to_string())` — the whole ticket. A
ticket that does not parse as a number, or a comment id GitHub answers `404`
for, is `ApprovalError::UnknownTicket`, never a scripted answer.

## Configuration

Both constructors take an `HttpClient` and a `Token`:

```rust
let directory = Arc::new(GitHubDirectory::new(http, token.clone(), "Keep-Shipping"));
let approvals = GitHubApprovals::new(http, token, "Keep-Shipping", "harness", pr, directory);
```

- `GitHubDirectory::new(http, token, org)` — teams are org-scoped. A `Team`
  handle is a **slug** (`@platform` → `/orgs/{org}/teams/platform/…`); the
  `Team` charset excludes `/`, so `@org/slug` is not a representable `Team`
  and the org lives on the directory, where membership is actually read.
- `GitHubApprovals::new(http, token, owner, repo, pr, directory)` — the
  channel is bound to one pull request and holds the `Directory` it checks
  membership through.

Optional builders: `with_api_base` (for GHES, e.g.
`https://github.example/api/v3`), `with_user_agent`, and `with_clock(clock,
interval)` for in-process polling in `wait`. The default interval is 15s.

The adapter never reads the environment. It has no notion of `GITHUB_TOKEN`:
the caller supplies the token, as `GithubActionsRunContext::from_env` takes a
`&BTreeMap<String, String>` rather than reading ambient variables itself.

**Scopes.** The token needs `issues:write` (or `pull-requests:write`) on the
repository, to post the request comment and the replies, and `read:org`, to
read team membership. A token that has lost `read:org` makes every membership
lookup fail, which parks the run rather than approving it. `Token`'s `Debug`
prints `Token(<redacted>)`, and neither adapter's `Debug` prints it.

## The rules

These are the engine's rules, enforced once in `ApprovalRequest::accepts` and
`Directory::is_member` so that they hold identically for every adapter. The
GitHub adapter re-checks membership first and never re-derives the rest:

- **Only a human may approve.** A comment from a bot is ignored.
- **The proposer may not approve their own request.** A command from the
  handle in the marker's `proposed_by` is ignored.
- **The answerer must be on the team in the marker** — the `from` field, not the
  team the request happened to name. Membership is `state == "active"`; a
  `pending` invitation is not a membership.
- **A failed membership lookup parks the run.** A GitHub 5xx or a token without
  `read:org` reads as *not a member*, so it can never approve anything.
- **The verdict is bound to the artifacts in the marker.** `poll` returns them
  verbatim as `bound_artifacts`, and the engine's `accepts` refuses a verdict
  whose list differs by one digest.
- **A command answers the newest request.** Only comments made after the most
  recent marker comment on the PR are considered, so an approve written for one
  parked request is not consumed by another's poll.

An ignored command gets one reply saying why, carrying
`<!-- keepshipping:ignored comment=ID -->` so repeated polls — and repeated
jobs — never reply twice.

## A GitHub Actions sketch

Two jobs. This is a sketch, not shipped wiring: the engine's `approval` step
and the CLI half are still landing
([#94](https://github.com/Keep-Shipping/harness/issues/94),
[#95](https://github.com/Keep-Shipping/harness/issues/95)).

```yaml
jobs:
  plan:
    runs-on: ubuntu-latest
    steps:
      - run: keepshipping run ship.ks --env prod
        # parks at the approval step; exits 4
  resume:
    if: github.event_name == 'issue_comment'
    runs-on: ubuntu-latest
    steps:
      - run: keepshipping run ship.ks --env prod --resume
        # re-polls the ticket from the parked run state
```

`plan` exits **4** (`waiting_for_approval` — see [CLI.md](CLI.md)) once it has
posted the request comment, having written the ticket into its run state.
`resume` is triggered by `issue_comment` and re-polls the ticket.

`wait` is the other half of this: **with** a `Clock` it polls every interval
until a verdict arrives or the timeout elapses. **Without** one it polls once
and returns `ApprovalError::Undecided` with `after: 0s` — nothing was waited
for, so it does not claim the timeout elapsed. The caller is expected to
re-poll across jobs, which is what the sketch above does.

## Known limits

- **Line-level review comments are not commands.** The adapter reads *issue
  comments*. A `/keepshipping approve` left as a PR review comment on a line is
  invisible to it; the command must be a comment on the conversation.
- **A parked request cannot be retracted.** Nothing closes or withdraws the
  comment, so a request stays outstanding on the PR until something answers it
  or a newer marker supersedes it.
- **Approval is scoped to the PR it was asked on.** The channel is bound to one
  `pr` and one team, and grants nothing beyond that request's artifacts.
- **`wait` without a clock is a park, not a wait.** See above — it returns
  immediately and the caller must re-poll.
- **Pagination and rate limits are not special-cased.** Comments and team
  members are followed through `Link: rel="next"` at 100 per page; anything else
  GitHub returns is `ApprovalError::Unavailable`.

## See also

- [ADR 0005](adr/0005-local-first-core-with-optional-hosted-services.md) — the
  stateless-across-jobs split this design follows
- [PORTS.md](PORTS.md) — the `ApprovalChannel` and `Directory` port contract
- [CLI.md](CLI.md) — exit code 4, `waiting_for_approval`
- [REGISTRIES.md](REGISTRIES.md) — the same honesty rule for a sibling adapter