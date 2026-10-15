# Early-access interviews: the six questions that decide pricing, scope and the second CI

The waitlist collects an email and nothing else — no company size, no CI system, no IaC tool, no
deploy target ([`ventures/keepshipping/README.md`](../ventures/keepshipping/README.md), "Answers fields
… deferred"). That is why this file exists: the six questions below are the ones whose answers change
what gets built, and the waitlist cannot supply them.

Every block below asks about *their* pipeline, their history and their CI — except two questions that
ask what they would **pay** for: (10) picks the hosted surface, and (16) prices a decision. Those two are
the point of the batch, and a prospect answering them is telling us what to charge. Nothing asks what
they think of a *demo*, because there is none to react to.

## What these interviews are for

One batch has to settle three decisions:

1. **What to price.** There is no price per call and no price per token anywhere in this
   repository, and nothing in the MIT code is the paid part: [ADR 0006](adr/0006-licence-and-open-source-model.md)
   puts "the hosted control plane, team-only features" in private repositories, and accepts fork
   risk because "the moat is the **hosted service and the adapters**". The number we are missing is
   the one a prospect says out loud in question 6.
2. **What to build first.** Scope, ranked by blast radius rather than by how easy it is to demo.
3. **Whether the second native CI is GitLab or Buildkite.** [ADR 0008](adr/0008-github-actions-first.md)
   says "GitLab CI is the second native integration, in M3. Buildkite and CircleCI stay on generic mode
   until someone asks." Buildkite is reachable today through the generic runner, which reads its
   `BUILDKITE_*` variables ([docs/CI.md](CI.md)). Question 5 is the evidence for that commitment.

**The product does not run yet.** [README.md](../README.md) says "Nothing here runs yet", and
[docs/CLI.md](CLI.md) says two of three subcommands are implemented end to end and `run` is not —
"No step kind is executable from the CLI yet". The site's workflow files, CLI output and timings
are **not measurements**. So no question below asks what they think of a demo: there is nothing to
react to. Every question asks about their situation, their pipeline and their history.

## How to run one

- **Thirty minutes.** Five of context from you, twenty-five of them talking. Still talking at
  minute twelve, the interview is going badly.
- **One interviewer, one note-taker**, if two are free. One asks, one writes; asking and writing at
  once loses the exact wording, and the exact wording is the deliverable.
- **Do not record.** Consent for notes is not consent for a recording, and a recording has to be
  stored, requested, deleted and eventually disclosed. Notes in a private document are a smaller
  promise you can keep, and names, companies, repos and infra details stay in that document.
- **The interviewer does not defend the design** — not the language, not the step families, not the
  pinned model. If a prospect asks "why doesn't it just…", the answer is "I don't know, that's a
  good question", followed by silence.

## The questions

Six blocks, numbered and quotable. Record answers **verbatim**: the ranking in block 2 and the
boundary in block 3 beat any summary you could write afterwards.

### 1. Current pipeline pain

> 1. Walk me through the last deploy that went wrong. What happened, and what did you have to do
>    about it?
> 2. How do you find out that CI is broken — before a deploy, or after?
> 3. I'm going to give you a command. Run it on a repo of yours and read me the number.

The exercise in (3) produces a fact, not an opinion. Have them run it themselves, and read you the
number; write it down next to how many engineers are on the team.

```sh
git log --since="90 days ago" --pretty=format:"%h %s" | grep -icE '(fix|fixes|fixed|fixing|hotfix|repair|patch|retry).*(ci|pipeline|build|workflow|jenkins|github actions?|gitlab)'
```

One line, and portable: no `\b`, which GNU grep treats as a word boundary and BSD/macOS grep treats as a
literal backspace, and `actions?` so "GitHub Actions" matches — the repos this sizes most are exactly
the ones that say it. It counts commit *subjects* whose shape suggests CI repair, so read it as a
prompt for question 1, not as a measurement: the engineer-hours come from the person, not the number.

*What it decides:* whether this is a real problem at a real frequency, and how big it is in
engineer-days — the denominator for anything the pricing question produces.

*What a good answer sounds like:* a specific story with a name attached — "we rolled back at 2am because
the staging tag was wrong" — plus a rough hours-per-month figure. A number nobody expected, from
somebody who owns the problem.

*What a bad answer sounds like:* "CI is fine, we're pretty good at it." Either a team of three with no
deploys yet, or one that has normalised the pain. Ask which. **Zero is an answer, not a rejection**: a
fact about their scale — a low-commit repo, a pipeline living somewhere other than `master`, or a
monorepo whose fixes sit in one subdirectory. Say that out loud, so the number is not read as a
disqualification.

### 2. Which steps they'd move first

> 4. List the steps your pipeline runs, in order.
> 5. Now rank them by blast radius — if this one step is wrong, how bad is it? Worst first.
> 6. Which one would you be least willing to hand to anything automated, and why?

*What it decides:* the scope input for the alpha. Their ranking, not [our step-family
list](STEPS.md), decides what gets built first. The record is the ranking **as they say it**; the
normalisation is ours, and happens later.

*What a good answer sounds like:* disagreement with themselves, corrected on the spot. "Actually no,
migrate is worse — migrate is what pages me." The self-correction says they thought about blast radius
rather than recited a pipeline diagram.

*What a bad answer sounds like:* they sort by frequency, not blast radius — deploy first because it runs
most often. Push back once: *"most often" is not "worst when wrong"*. If it stays frequency, ask block 3
instead; that boundary beats the ranking.

### 3. Would they let agents run plan and apply

The approval question, and the highest-value block in the file: the control is already designed, so the
answer decides how much of it must exist.

**Before you ask.** The mechanics below are the *design*, not a demo. [docs/CLI.md](CLI.md): "No step
kind is executable from the CLI yet" — so no run today reaches an approval, parks, or exits 4. Ask what
they *would* allow; do not describe a run they could watch.

> 7. Take your pipeline. Which steps would you hand to an agent that had to stop for a human you
>    approved — and which would you not, no matter what?
> 8. When it parks waiting for you, what are you doing when the answer comes back? At a terminal,
>    or gone home?
> 9. Who is the person who presses the button, and what do they need to see to press it?

One word of vocabulary first, because they will say it back to you: `plan` and `apply` are **step names,
not CLI commands**. The CLI has no `plan` subcommand and no `apply` subcommand; you select them with
`keepshipping run ship.ks --until plan` or `--only apply` ([docs/CREDENTIALS.md](CREDENTIALS.md)). A
prospect who writes an `apply` subcommand in their notes has invented it — our wording leaking, not their
misunderstanding.

The designed mechanics, so you can answer the follow-ups. An agent run **parks at its first approval,
because an agent may not answer its own** — a human runs `keepshipping approve <run>`
([docs/CLI.md](CLI.md)). A parked run exits 4, which `exec.rs` names "The run stopped for an approval
nobody gave", and carrying it on is a new job. `apply` re-hashes its plan and refuses with `StalePlan`
if the state moved ([docs/STALE_PLANS.md](STALE_PLANS.md)) — the answer to "what if I approve the wrong
thing".

*What it decides:* the scope boundary for the alpha. Not "would you use this" — the boundary they draw,
in their own words, of which steps cross it.

*What a good answer sounds like:* a drawn line with a reason on each side. "Read is fine, apply is not,
until it does the plan diff for me." The reason matters more than the line.

*What a bad answer sounds like:* "sure, whatever you think" — an agreeable answer to a hypothetical they
are still inventing an opinion for, and worse than no answer. Say: *"concretely, of the steps you just
listed, name the one you would not hand over."* If they cannot, they have no boundary yet, and the answer
goes down as unresolved. **Record the boundary, not the yes**: the list of step names they would and
would not hand over is the finding.

### 4. Hosted approvals or a run-log viewer

[#15](https://github.com/Keep-Shipping/harness/issues/15) picks one to build first. Make them choose, out
loud.

> 10. Two things we could build first. (a) Approve a run from your phone, from chat, from a web
>     page — the run parks overnight and someone outside the CI job answers it. (b) A hosted page
>     showing every run, every approval and every artifact digest, with the same local verification
>     behind it. Pick one to pay for. Why that one?
> 11. If I only build one, which one breaks if it is missing?

Give them the honest state of both first. **Hosted approvals: the GitHub adapter exists, the hosted
surface does not** — `ks-github` posts one PR comment as a ticket and is stateless across processes, so
a run can park overnight ([docs/GITHUB_APPROVALS.md](GITHUB_APPROVALS.md)); the engine's `approval` step
and `keepshipping approve` are landing separately ([#94](https://github.com/Keep-Shipping/harness/issues/94),
[#95](https://github.com/Keep-Shipping/harness/issues/95)). Web and Slack `ApprovalChannel` adapters are
written ([#98](https://github.com/Keep-Shipping/harness/issues/98)), but **the hosted service they would
talk to does not** — under [ADR 0005](adr/0005-local-first-core-with-optional-hosted-services.md) those
approvals exist only for teams who turn the hosted service on, and nothing is running to turn on.
**Hosted viewer: none exists either, and the local thing is already real** — `keepshipping log`,
`keepshipping log verify --key FILE` and `keepshipping log seal` verify a hash-chained JSONL log
offline, with ed25519 seals, no network and no store ([docs/DIAGNOSTICS.md](DIAGNOSTICS.md)). The hosted
version adds *copies*: ADR 0005's "entries are small, and summaries, not step logs".

*What it decides:* the ordering inside #15, and the shape of the first paid surface.

*What a good answer sounds like:* one option, with a cost attached to the other. "Approvals — we lose
sleep when a run parks and the only person who can answer is at their laptop." Or from an auditor: "the
viewer — nobody trusts a log they cannot open."

*What a bad answer sounds like:* "both, obviously" — the non-answer. Take (11) and push until they name
the one that **breaks** rather than the one that is nicer. If they refuse the trade, record the refusal
and ask (11) anyway: the refusal is the finding.

### 5. GitLab or Buildkite

[#9](https://github.com/Keep-Shipping/harness/issues/9) asks which CI is second. ADR 0008 already says
GitLab; this is the evidence check, not a re-opening.

> 12. Which CI runs your deploys today — GitHub Actions, GitLab, Buildkite, something else?
>     Self-hosted runners or a vendor?
> 13. Does it matter that the harness *verified* the identity of the job, or is a job that
>     declares who it is good enough for non-prod?
> 14. What would you run in prod, and what would you run everywhere else?

The state of the three answers you are about to give: **neither native adapter is wired into dispatch
yet** — the GitHub Actions and GitLab CI run-context adapters are both built and tested but unreachable
from `run`, so no CI reaches a step execution at all ([docs/CI.md](CI.md),
[docs/GITLAB_CI.md](GITLAB_CI.md)), and GitLab's OIDC token signature is **not verified**. *Native* is
the target rather than today's state: [ADR 0008](adr/0008-github-actions-first.md) means GitHub
Actions in M2 and GitLab CI second in M3, and all five things a native integration owes — a published
action, trigger mapping, OIDC, Checks status, the approval hand-off — are **none of them done yet**
([docs/GITHUB_ACTIONS.md](GITHUB_ACTIONS.md)). Buildkite works in the **generic** adapter and is
explicitly **not native** ([docs/CI.md](CI.md)). Generic mode gives a CI the plan, the steps and the log, and it
**verifies no OIDC identity** — the run says so on stderr, one line, before it starts ("self-declared;
generic mode verifies no OIDC identity"). Say that sentence to the prospect in (13) rather than
paraphrasing it.

*What it decides:* whether ADR 0008's "GitLab CI is the second native integration, in M3" survives the
batch, and whether verifying the job's identity is a prod-only requirement — which decides whether
Buildkite stays on generic mode, which ADR 0008 says holds "until someone asks".

*What a good answer sounds like:* a split they have already thought about. "Generic is fine for
everything except the prod apply" is a precise requirement. So is "we are a GitLab shop".

*What a bad answer sounds like:* "GitLab, obviously" from someone who has not heard of Buildkite. Ask
(12) twice — once for the pipeline, once for what the *platform team* runs. In a lot of shops those are
two systems, and the second is the answer.

### 6. Jev, and what a decision is worth

[#8](https://github.com/Keep-Shipping/harness/issues/8) is the data-leaving question. Ask it in the
prospect's language.

**Before you ask.** The `decide` step is not built yet ([docs/CLI.md](CLI.md): "The decide step itself
is not built yet, so until it lands no run contains the line"), so no step calls a model today. Ask what
they *would* allow; do not describe a decision being made for them.

> 15. Suppose a step asked a hosted model whether a plan was safe. Only the **names** of the attributes
>     that change would leave the machine — every value withheld, except a short list of
>     machine-shaped ones. Would you let that run for a plan you are about to apply? What would you
>     need to see first?
> 16. What would you pay for one decision? Per person, per month, or per call — whatever is the
>     unit you would actually buy on.

Say the data boundary precisely, because precision is the whole product. The model is **pinned** to
`jev-1.13.0`; aliases like `jev-latest` are refused because they "make a decision unreproducible"
(`adapters/jev/src/lib.rs`, `PINNED_MODEL`). What would leave is **attribute names only, every value
withheld** — a value appears only for an allowlisted name (`count`, `instance_type`, `replicas` and a
short list of others), and only if it is 64 bytes or fewer and made only of ASCII alphanumerics and
`.` `_` `:` `/` `+` `-` ([docs/CLI.md](CLI.md), `crates/core/src/redact.rs`). `keepshipping decide
--explain` exists to "tell you truthfully what left your machine", and verifies the log chain first —
but the `decide` step is not built, so today it prints "no decide step sent anything" and exits 0.
State is capped at 32 KiB. And one thing we cannot tell you: **what a decision costs** — there is no
price per call or per token anywhere in this repository, which is why question 16 is asked at all.

*What it decides:* the pricing unit, and whether data-egress is a blocker or a checkbox. Both.

*What a good answer sounds like:* a condition. "Not until I can see the explain output for my own plan" —
a real condition, and one the command is designed to satisfy, though the step behind it is not built yet.
Or "not for prod, yes for staging", a scope decision.

*What a bad answer sounds like:* a shrug on (15) followed by a confident number on (16). A number without
a reaction to the data question is a number about nothing — flag the pair low-confidence.

## What to do with the answers

Blocks map to questions as 1→1–3, 2→4–6, 3→7–9, 4→10–11, 5→12–14, 6→15–16.

| Block | The decision it feeds | Where the answer goes |
|---|---|---|
| 1 — pipeline pain | How big the problem is, and whether this is a real frequency | Private notes; the median in the summary |
| 2 — blast-radius ranking | What to build first for the alpha ([#154](https://github.com/Keep-Shipping/harness/issues/154)) | Verbatim ranking, private notes |
| 3 — the approval boundary | The scope line for agent-run steps; how much of #94/#95 is load-bearing | Verbatim boundary, private notes |
| 4 — approvals or viewer | The ordering inside [#15](https://github.com/Keep-Shipping/harness/issues/15) | Verbatim reason; counts only |
| 5 — CI | Whether ADR 0008's "GitLab CI is the second native integration, in M3" holds ([#9](https://github.com/Keep-Shipping/harness/issues/9)) | Verbatim answer; counts only |
| 6 — data leaving and price | The pricing unit, and whether egress blocks adoption | Verbatim number; **ranges only** |

Everything raw lands in the private notes. Nothing raw lands on the issue.

## The batch summary

Fixed shape. Fill it in, then read the posting rule before you post it.

```markdown
## Interview batch <N> — <date>

**Interviews:** <N>, from the waitlist, run between <date> and <date>.

**Pricing.** <N> of <N> gave a number for a decision. Range: <low>–<high> <unit per>.
Units offered: <per person / month>, <per call>, <org licence>. <N> would not say.

**Scope.** Most-cited first step by blast radius: <step>. Least-cited: <step>.
<N> drew a line at apply; <N> drew it at deploy; <N> would hand over nothing without a diff view.

**Second CI.** GitLab <N>, Buildkite <N>, GitHub Actions only <N>, other <N>.
Identity verification required for prod: <N> of <N>. Generic mode good enough for non-prod: <N>.

**What surprised us.** <the thing the batch said that we did not predict>

**What we could not answer.** <the question a prospect asked that the docs do not answer>
```

### The posting rule

This summary is posted on a public issue. So:

- **Aggregate counts and quotes. Never names.** No company, no person, no domain.
- **Never a repository name.** Question 3 gets run on a real repository; nothing about it is quotable.
- **Never a quote that identifies the company.** If "we're a 40-person fintech and our compliance
  people…" identifies the company, it is not a quote, it is a name. Paraphrase or cut it. When in doubt,
  cut it — a summary is worth nothing next to a breach of trust with the first three prospects.
- **Prices as ranges, never one person's number.** One number from one interview is an anecdote with a
  decimal point; a range over N is a finding.
- **Never quote their infrastructure**, IaC or deploy target. That is reconnaissance.

## What not to do

- **No promises.** Not of dates, not of features, not of "that will be in the alpha". The honest
  sentence is "that is what we are trying to decide, and you are one of the people we are asking".
- **No collecting credentials, keys or real infrastructure access.** Nothing on the call is connected to
  anything. A prospect who volunteers a token has not been asked for one, and it goes in no document,
  including the private one — it goes in the user's password manager, and you say so.
- **No pitching.** Every question is about their situation. If you spend more of the thirty minutes on us
  than they do, the interview is lost even when the answers are good.
- **A "yes" is not a commitment.** "Yes, I'd use that" is not a signup, and a batch summary is not a
  pipeline.
- **Do not demo the site as a product.** [README.md](../README.md): nothing here runs yet, and the
  site's workflow files, CLI output and timings are not measurements.