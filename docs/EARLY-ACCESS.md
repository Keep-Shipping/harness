# Early access

How Keep Shipping admits its first users: who goes in each batch, the one email
they get, and what happens after they say yes.

> **Internal.** This is the team's runbook, not user documentation. It is not
> linked from the site or the README, and nothing in it is a promise to anyone
> outside the team. The promises that bind us are the ones quoted under
> [The promise](#the-promise).

## The promise

The site makes one promise about email, in its closing call to action:

> Early access opens in small batches. One email when your invite is ready,
> nothing else.

Everything below is built to keep that sentence true. Read it as: **the invite
is the only email we send that the person did not just ask for.** Concretely:

- One invite per person. No reminder if they don't answer, no "last chance", no
  newsletter, no product update, no survey.
- Onboarding starts only after they accept. Everything after the invite is a
  reply to something they sent, or happens in the channel they agreed to join.
- A person who says no, or says nothing, never hears from us again unless they
  write first.

Two mails go out before the invite, and both answer something the person just
did: the double opt-in confirm mail on join (`waitlist/confirm`,
`ventures/keepshipping/tests/snapshots/mail__confirm_text.snap`) and the position
mail when they click it (`waitlist/confirmed`,
`ventures/keepshipping/tests/snapshots/mail__confirmed_text.snap`). The site's
own success panel tells joiners to expect the first. We read the promise as
covering what comes after; see [Open questions](#open-questions) for the
stricter reading.

The confirm mail also says "Keep Shipping is admitting members in join order."
Batch selection below respects that.

## Batch 1

**Size: 5 teams.** Small enough that every team gets a session and a shared
channel with two of us in it, and that their blockers can be fixed before batch
2.

**Who:** teams that deploy with **Terraform or OpenTofu and Kubernetes, from
GitHub Actions.** That is the stack of the hero file
(`crates/cli/tests/fixtures/hero/ship.ks`: `oci.image` → `tofu.plan` →
`approval` → `tofu.apply` → `k8s.rollout`), and it is what M2 covers (`README.md`
milestone table, "M2 Early-access alpha": "The same file runs locally and on
GitHub Actions"). VMs and serverless are on the site's list of targets, and
GitLab CI is documented in `docs/GITLAB_CI.md`; none of the three is a batch-1
target.

**This is an assumption.** We think these teams fit best because the alpha was
built against their file. It has not been checked against the waitlist: the
waitlist form does not ask about stack yet
(`ventures/keepshipping/src/lib.rs`: "no `answers` schema yet — issue #146
defers those fields"). How we check it is part of the batch — see
[Checking the assumption](#checking-the-assumption).

### Selecting the batch

1. Export the list: `GET /v1/waitlist/admin/export.csv`.
2. Keep `confirmed` entries only. A `pending` entry never proved its address,
   and the confirm mail told them nothing happens until the link is opened.
3. Sort by `position`. The position is assigned when the address was confirmed
   (`ventures/keepshipping/migrations/0006_waitlist_position_counter.sql`), and
   that is the "join order" the confirm mail promises.
4. If stack answers exist by then ([#146](https://github.com/Keep-Shipping/harness/issues/146)),
   skip entries whose answers say they don't fit. A skipped entry keeps its
   position for a later batch; it is not an invite and costs them nothing.
5. Take the first five. Without stack answers, take the first five in order: the
   invite names the stack, and a team that doesn't fit can say so (see the
   invite).
6. Record who was invited, when, and at what position in the team's private
   tracker, **not in this repository.** The repo never holds waitlist names or
   addresses.

### Before the first invite goes out

Batch 1 does not start until all of these hold:

- [ ] M2 is done, including "the first invite batch can follow the docs alone".
- [ ] The getting-started guide
      ([#140](https://github.com/Keep-Shipping/harness/issues/140)) is merged.
      Until it is, the docs are `docs/INSTALL.md`, `docs/GITHUB_ACTIONS.md` and
      `docs/COEXISTENCE.md`, and that is not "the docs alone".
- [ ] No open High findings from the security review
      ([#117](https://github.com/Keep-Shipping/harness/issues/117));
      `docs/SECURITY.md` is current.
- [ ] The invite text below has been re-read against the site, in case the site
      changed.
- [ ] Two people are named for the batch: one runs sessions, one owns the
      channel.

## The invite email

Sent by hand, one message per team, from contact@keepshipping.run so replies
reach a person — not from the transactional sender
(`no-reply@send.keepshipping.run`), not BCC'd to a list. Fill the brackets;
change nothing else without re-running the review below.

```text
Subject: Your Keep Shipping invite is ready

Hi,

You joined the Keep Shipping early-access list, and your invite is ready.
This is the one email we said we would send.

This first batch is five teams who deploy with Terraform or OpenTofu and
Kubernetes from GitHub Actions. That is the stack the alpha covers today.

What it is: an alpha. One typed workflow file, ship.ks, that builds an
image, plans and applies OpenTofu, waits for a human to approve, and rolls
out to Kubernetes, the same way on a laptop and in GitHub Actions. Expect
rough edges; finding the ones that block you is the point.

What we would ask of you: a 30-minute setup session, a shared channel with
us, and feedback on a schedule we agree together.

To accept, reply to this email and we will take it from there.
If your stack is different, reply and say so: you keep your place.
If you would rather not, ignore this. We will not email you again.

[Name]
Keep Shipping
```

### Reviewed against the site

| The site says | The invite | Holds? |
|---|---|---|
| "One email when your invite is ready" | One message, sent when the team is in a batch; says "This is the one email" | Yes |
| "nothing else" | No reminder, no follow-up; silence ends it ("We will not email you again") | Yes, if the no-reminder rule is kept |
| "Early access opens in small batches" / "invites go out in small batches" | "This first batch is five teams" | Yes |
| "In development, not generally available" | "an alpha", "Expect rough edges" | Yes |
| Admitting "in join order" (confirm mail) | Selected by position; a declined team keeps its place | Yes |
| Site lists VMs and serverless as targets | The invite names only the batch-1 stack | Yes — the invite promises nothing the alpha cannot do |

What the invite deliberately leaves out: dates, pricing, "production-ready" or
"secure" claims, and any link that adds the person to another list. Everything
after this message is a reply.

## Onboarding

Starts when a team replies yes. Every step is a reply in their thread or a
message in the shared channel.

- [ ] **Record** the team in the tracker: contact, waitlist position, IaC tool
      and version, Kubernetes distribution, GitHub Actions runner type (hosted
      or self-hosted).
- [ ] **Send the getting-started guide**
      ([#140](https://github.com/Keep-Shipping/harness/issues/140)) as the reply
      to their acceptance, with a link to `docs/SECURITY.md` (Residual risks and
      Reporting a vulnerability).
- [ ] **Book the 30-minute session** within a week of acceptance. Agenda:
      install and verify (`docs/INSTALL.md`), write `ship.ks` for one service,
      run it locally, run it in GitHub Actions, approve one run. They drive; we
      watch and write down every place they stop.
- [ ] **Open the shared channel** with both named people in it. Blockers go
      there as they happen, not saved for the check-in.
- [ ] **Agree the feedback cadence** and write it in the tracker. Default
      proposal: a 20-minute call every two weeks for the six weeks of the batch,
      plus whatever comes up in the channel. The team may pick something lighter;
      what matters is that it is agreed, not imposed.
- [ ] **Start in shadow** — one environment at a time, beside their existing
      pipeline (`docs/COEXISTENCE.md`). No production on day one.
- [ ] **File every blocker** as an issue in this repo with the `early-access`
      label and the batch number, in our words, without the team's name unless
      they agree.
- [ ] **Leaving:** a team can stop at any time by saying so in the channel. We
      archive the channel and remove their entry from the tracker; nothing else
      follows.

## Before the next batch

Batch N+1 is not invited until batch N meets all of these:

- [ ] **No open High security findings**
      ([#117](https://github.com/Keep-Shipping/harness/issues/117)), including
      any a batch team reported.
- [ ] **The top onboarding blockers are fixed** — merged and in a release.
      "Top" means: anything that stopped a team from reaching a first deploy
      from GitHub Actions, plus the three blockers that came up most often.
- [ ] Every team has either deployed from GitHub Actions or told us why not.
- [ ] Every team has given feedback at least once on the agreed cadence.
- [ ] The next batch's size and stack are decided and written into this file.

### Checking the assumption

After batch 1, write down here: how many of the first teams by position fit the
stack, how many declined because it didn't, and what the declines ran instead.
If fewer than half fit, the batch-1 stack was the wrong guess for this waitlist,
and batch 2's stack follows what the declines told us rather than the hero file.

## Open questions

- **The stricter reading of "one email".** If "nothing else" is meant to cover
  the confirm and position mails too, the position mail (`waitlist/confirmed`,
  "You are #42") is the one to drop or fold into the confirmation page; the
  confirm mail is the double opt-in and has to stay. That is a site and service
  change, not part of this runbook.
- **Stack answers.** Selection is blind until
  [#146](https://github.com/Keep-Shipping/harness/issues/146) adds answers to
  the form. Asking later would cost the one email.
- **No unsubscribe or deletion path** is wired into the waitlist service yet.
  Until it is, an erasure is handled by hand with `wrangler d1 execute`, per
  `ventures/keepshipping/README.md`.