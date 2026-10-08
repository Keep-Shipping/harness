# Agents: what the policy decides, and what it does not

A workflow file says what a coding agent may do alone, what waits for a
named human, and what is refused outright. This page says exactly how that
is decided, what a `decide` step sends and receives, and — as important —
which parts of the site's promise are not delivered by the code yet.

The behaviour lives in three places: [`crates/core/src/policy.rs`](../crates/core/src/policy.rs)
for the effective policy, [`crates/core/src/ports/run_context.rs`](../crates/core/src/ports/run_context.rs)
for who counts as an agent, and
[`crates/engine/src/decide.rs`](../crates/engine/src/decide.rs) for the
`decide` step. Each section below cites the code it describes.

## Who counts as an agent

Agent detection is a pure function over the facts of the machine, not a
claim the run makes about itself.
`detect_local_actor` (`run_context.rs:386`) applies five rules in order and
stops at the first that matches:

1. **An agent marker in the environment wins over everything, including a
   declared `Human`.** `KNOWN_AGENT_MARKERS` (`run_context.rs:43`) is
   `CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT`, `CODEX_SANDBOX`, `CURSOR_AGENT`,
   `GEMINI_CLI`, `AIDER_MODEL`, `OPENHANDS`. Any one set to a non-empty
   value classifies the run as an agent.
2. **`--as agent` is a self-declaration**
   (`Establishment::SelfDeclared`, `run_context.rs:401`). The type's own
   doc is blunt: *declaration is not proof*.
3. **No TTY *and* an agent-typical environment**
   (`AGENT_TYPICAL_ENV`, `run_context.rs:58` — `GIT_EDITOR=true`,
   `GIT_PAGER=cat`, `PAGER=cat`, `NO_COLOR`, `TERM=dumb`).
4. **No TTY and no evidence: the organisation baseline decides.**
5. **Otherwise, a human**, attributed to the local git config.

Three things follow, and they are the limits rather than the features.

**Only the environment and the TTY are read.** Git config supplies a display
name and nothing else. Branch names, commit messages, PR metadata and git
history are not consulted on the local path, so renaming a branch to
`agent/...` changes nothing.

**Every local establishment is `IdentityStrength::Weak`**
(`run_context.rs:167`). Only `Establishment::CiOidc` is `Strong`, and the
module doc says why: a local run has nothing cryptographic behind it.
Nothing in the current tree branches on `IdentityStrength` — it is
metadata today, not an access-control input.

**Markers are forgeable in both directions.** A human who exports
`CLAUDECODE=1` is labelled an agent; that direction is the safe one, because
an agent run parks instead of asking. But the reverse is equally available:
unset the markers, give the process a TTY, and an automated run presents as
a person and is asked. `detect_local_actor` can never return `ActorKind::Ci`
(`run_context.rs:383-385`) — `CI=true` on a laptop is trivially spoofable, so
a local run claiming to be CI does not survive detection into a CI actor.

## `--as agent`

`--as agent` is the value `agent` parsed by `actor::parse_as`
(`crates/cli/src/actor.rs:24`); there is no separate flag. `agent:<name>`
attaches a display name, and it is applied **only** when the actor kind is
an agent — *a human never borrows that name* (`actor.rs:216`).

What it changes, in order of consequence:

- **The run cannot approve itself.** An agent run is given
  `drive::AgentRun` as its approver (`main.rs:253-257`) and parks at its
  first approval instead of reaching a terminal. The reason is stated in the
  code (`main.rs:188-190`): an agent that approved its own run would be
  approving itself.
- **`check` enforces the `agents:` rules against it.** `forbid_agent_actions`
  (`crates/core/src/check.rs:2861`) refuses the file for any action class the
  `agents:` section forbids.
- **Detection only escalates.** `main.rs:131-132` keeps a detected agent
  even if the flag said otherwise; the reverse never demotes a detection.
- **An agent may not run an unapproved script step** — one with no `action:`
  and no prior approval is refused (`main.rs:387`).

`crates/cli/tests/as_agent.rs` exercises both `--as agent:claude` and a
bare `CLAUDECODE=1`, and both produce `policy forbids agents from reading
secrets`.

## The effective policy

`policy:` is a top-level block whose subjects are `agents` and `humans`,
whose directives are `can:` (allow), `before:` (ask), `never:` (refuse) and
`ask:` (handles), and whose values are comma-lists of `<verb> [<env>]`.
An unknown verb is an error (`check.rs:2527-2530`), and an environment the
file has not declared is an error (`check.rs:2580`), so a typo in a `policy:`
block stops the run before the environment is even selected.

The verbs are wider than the site's list:
`check build test plan apply deploy destroy publish read run`
(`check.rs:300`).

The answer for an action is `decide_policy` (`policy.rs:156-233`), a pure
function. In order:

1. **The file's own answer.** The strictest matching rule wins —
   `Never` beats `Ask` beats `Allow` (`policy.rs:139`).
2. **An unlisted action gets the leash** (`policy.rs:195-196`): an agent
   gets `Ask`, everyone else gets `Allow`, with the source recorded as
   `default`.
3. **The organisation baseline may only narrow.** It can turn an `Allow`
   into an `Ask` or a `Never`; it can never widen one
   (`policy.rs:207-208`).
4. **The destroy hard rule** (`policy.rs:218-221`), below.

`keepshipping policy explain` prints the result as step / action /
decision / source, with a line and column for any rule that came from the
file. Its first line is always `NO_BASELINE` (`cli/src/policy.rs:24`),
because there is no `PolicyStore` adapter to load one from.

**That is the single most important caveat in this section.** With no
adapter, `effective_baseline(None)` is `Baseline::conservative()`
(`ports/policy.rs:363`), and the CLI passes `ActorBaseline::default()`
(`main.rs:127`). So the baseline every run sees is the built-in one, and
`require_human` and the baseline's agent list — the two fields an
organisation would set — are unreachable in the shipped binary. The ADR
resolves this hole ([ADR 0012](adr/0012-policy-authority.md)).

The conservative baseline is not empty. It refuses `destroy` outright, and
refuses `secrets` under **every verb it would otherwise allow** — `read`,
`check`, `build`, `plan` — because a refusal naming only the literal word
`read` is one an adapter walks around by naming the same read something
else (`ports/policy.rs:239-258`). Agents may `check`, `build` and `plan`;
everything else is `Ask`, never `Allow`.

## The hard rules

Three rules sit outside the file-and-baseline intersection.

**A destroy never reaches an agent as an allow** (`policy.rs:216-225`).
Whatever the file and the baseline say, `destroy` for `ActorKind::Agent`
is rewritten to `Ask`, with the source reported as `hard rule`. Note the
condition: this is **actor-conditional**. The default for an unlisted action
under a human is `Allow` (`policy.rs:196`), so a human run can destroy
without asking unless the file says `humans: never: destroy`. The accurate
statement is that destroys never auto-approve *for an agent*, not that they
always reach a human.

**Destroys never auto-approve** (`auto_rule.rs:39-41`):

```rust
pub fn auto_approves(rule_holds: bool, destroys: usize) -> bool {
    rule_holds && destroys == 0
}
```

No actor parameter, and `resolve` conjoins the destroys guard last —
*because it is the clause the engine owns* (`auto_rule.rs:302-305`). This
guard is unconditional and is the reason a file's `auto:` rule cannot
approve a plan that destroys anything, whether or not the file wrote the
clause. It is a different code path from the rule above, and it is worth not
conflating them: `policy.rs` decides whether a destroy is *permitted* for an
actor, and this guard decides whether an `auto:` *rule* may approve one. A
destroy refused by `policy.rs` never reaches `resolve` to be approved.

**An untrusted decision never auto-approves** (`auto_rule.rs:274-292`). For
every `decide` step the rule actually read, a model answer contributes
nothing (`DecisionSource::Model => continue`), while an answer with no model
behind it or a failed model call forces `Ask`. The comment explains the
choice: checking *what was read* rather than what was written is what stops
a rule that hides a decision inside a comparison from approving on it.

A `Never` rule in the baseline is declared **first** because `decide` is
first-match-wins. Ordering is the author's obligation, not a property of the
type: an `Allow` declared *after* a matching `Never` does rescue it
(`ports/policy.rs:307-319`, tested in both directions at
`ports/policy.rs:544`).

## `decide`: what is sent, and what comes back

A `decide` step asks a model one question about a plan. What leaves the
machine is deliberately small.

**What is sent** (`decide.rs:104-130`):

- the redacted summary of a plan's `resources` — addresses, masked
  attribute paths and counts. A `decide` step over anything other than a
  plan is an error that names the limitation:
  *only a plan's `changes` are summarised so far; this is not one (#107)*;
- the step's `ask:` string, verbatim, as the question's instructions;
- the `returns:` list as option ids.

`escalate` is always injected as an option (`decide.rs:293`) and a file that
declares it is an error (`decide.rs:280-282`) — the answer *a human decides*
has to be available so an adapter that can decide nothing still has a legal
reply.

**What is not sent:** repository contents, file contents, secrets, the git
ref or sha, the actor, and the policy. Secrets cannot be sent because
`RedactedState` has no public constructor and only `summarise` builds one
(`ports/decision_model.rs:247-257`); the plan summary masks sensitive
attribute paths (`plan_summary.rs:229-234`). The state is truncated against
the profile's `max_state_bytes` and the truncation is logged, because
*a state trimmed with no line in the log is the worst failure mode a
decision model has* (`ports/decision_model.rs:17-21`).

The one real adapter is `ks-jev`, which POSTs
`{"state": …, "model": …, "questions": …}` to TypeSafe. The API key travels
in the `Authorization` header and nowhere else, is resolved once per call,
and never appears in an error, a `Debug` or a log. The model must be pinned
and a response naming a different model is rejected; a provider outage is a
red step, never a fabricated `escalate` dressed up as a judgement
(`adapters/jev/src/lib.rs:7-26`). Neither the adapter nor the step that
would call it is compiled into a stock binary; see "auto: and else:" below.

**The `reason` is built by the engine, never by the model**
(`decide.rs:15-19`):

> A model asked to explain itself writes prose that reads as evidence; the
> engine can write the evidence.

The model returns `{choice, probabilities, confidence}` and nothing else.
The step then composes `"{answer} {confidence:.2} {facts}"`, where `facts`
names up to three risky entries as `replaces <address>` or
`destroys <address>`, or falls back to the plan's counts
(`decide.rs:192-200`). A model cannot write its own justification because it
is never asked for one.

**Thresholds are the file's, not the tool's.** There is no built-in
confidence threshold anywhere in the crate. `risk is low ≥ 0.95` is a
sentence the author writes, parsed at `auto_rule.rs:436-440` and applied as a
comparison; written without a threshold it tests the answer and nothing
else. `ModelProfile::calibration_family` records the family a confidence is
measured on and is not the same number as `probabilities[choice]`, but no
calibration has been measured or fitted in this repository — which is why
the step is feature-gated.

## `auto:` and `else:`

`auto:` is an expression over `decide` answers and step outputs; `else:` is
restricted to exactly `ask @handle` and `show <reference>`, and any other
verb is an error (`check.rs:2090`, `check.rs:2142`). The grammar on the site
is accurate — `≥` and `>=` both parse, `plan.destroys == 0` is right, and
`risk.reason` is a genuine `decide` output (`auto_rule.rs:488`).

**None of it is evaluated by a run today.** `auto_rule::resolve`
(`auto_rule.rs:268`) has no production call site; its only callers are
`crates/core/tests/auto_rule.rs`. There is no `Approval` step kind in
`builtin_steps()` (`crates/engine/src/steps.rs:28-47`) — the module doc
records the intent as future work — so an `approval` step fails a run with
*`approval` steps are not built in yet* before an approver is ever consulted.
The one production consumer of the module is a checker warning
(`check.rs:1006`) that a file's `auto:` rule omits the destroys guard, and
its own comment says what that is worth: *this warns about the file, not the
run*.

## The run log

Two of the site's three logging claims hold and one does not.

- **"Which agent proposed it"** — carried by `RunStarted { actor }` and
  `ApprovalAborted { proposer }`, not by the approval record.
- **"Which human approved it"** — `ApprovalGranted { step, approver,
  channel, artifacts }` (`ports/run_log.rs:51`) records the approver and the
  channel.
- **"Every decision is logged with its score"** — `DecideAnswered` carries
  the model, the answer, the confidence, the full distribution, the
  threshold and the outcome (`run_log.rs:77-85`). Its one emitter is
  `engine/src/journal.rs:182`, which a stock binary cannot reach.
- **"With the reason attached" is true of a denial, not of a grant.**
  `ApprovalGranted` has no `reason` field; only `ApprovalDenied` carries one
  (`run_log.rs:60`). The `reason` typed at `keepshipping deny --reason` is
  printed and not persisted anywhere.

## What this does not protect against

A plain list, because the rest of this page is easy to read as more than it
is.

- **A human who edits the policy.** `ship.ks` is the file coding agents can
  write, and it is also the file the policy is read from. An agent that can
  add a step can move `apply` from `ask:` to `can:`, delete
  `never: read secrets`, or lower a threshold. ADR 0012 is the record of
  this hole and of the plan to close it; it is `proposed`, not accepted.
- **An agent pretending to be a person.** Detection reads environment
  variables and a TTY. Clear the markers, attach a terminal, and an
  automated run is asked rather than parked — and then its approval is a
  keystroke.
- **A person pretending to be an agent.** Also possible, and also
  indistinguishable. Nothing locally is cryptographic.
- **Your organisation's policy.** There is no `PolicyStore` adapter, so
  every run sees the built-in conservative baseline, and the two fields an
  organisation would configure are unreachable.
- **A confident wrong answer.** No calibration against real plans has been
  done (#108), and the confidence the model reports is not the same number
  as the probability of the choice it made.
- **Wiring mistakes in code it cannot read.** The checker catches a
  mistyped step, an image tag where a digest belongs, an undeclared
  environment. It cannot tell you the tests are wrong or the registry is
  down.
- **The difference between your laptop and CI.** The engine and the steps
  are the same; hardware, network and secrets are not.
- **Changes made outside the pipeline.** A console edit made between a plan
  and an apply is caught only as a stale plan, and only as far as
  [`STALE_PLANS.md`](STALE_PLANS.md) describes.
- **A run you are watching.** A human at a terminal is asked; a person
  watching a parked run is not an approval, and a typed `y` at a prompt is.

## Site wording

The relevant section of the site reads:

> **07 / Safe for AI agents**
>
> **Let agents ship. Keep a human on the button.**
>
> Coding agents can write, check and run your workflow. They can't guess
> their way into prod: a file that doesn't type-check never runs, and
> anything risky waits for a person.

That much holds. `keepshipping run` loads and checks the file before it does
anything, and exits 1 on any error diagnostic (`main.rs:133`, `main.rs:142`),
so a file that does not type-check does not run. One qualification: warnings
alone do not block a run, and `--warnings-as-errors` is `check`-only
(`args.rs:204`).

> `⏸ review  waiting on a human`
>
> `@platform notified, plan attached`

**The notification is not sent.** An agent run does park
(`main.rs:257`), but the approver it is given is
`drive::AgentRun { notified: None, … }`, and `notified` is `None` at both
call sites. The line the site quotes is a formatter
(`progress.rs:115`) that only fires when a name is present, and the name in
the test fixture is the test's own constant (`drive.rs:647`). Nothing in the
CLI reads the `ask:` handles into it. A parked agent run currently reaches a
person only through `keepshipping approve` against a shared state store.

> **Ask a human only when it matters.**
>
> Low-risk, high-confidence changes go through on their own. Everything else
> waits for a reviewer, with the reason attached.

**No change goes through on its own yet.** The two halves of the mechanism
are real and tested — the `auto:` expression resolves correctly and the
destroys guard is unconditional — but `auto_rule::resolve` has no production
call site and there is no `Approval` step kind for a run to reach it
through. And the `decide` step it would read is behind a cargo feature that
is off by default, which the CLI does not enable.

> `✓ review  auto-approved by policy`

This line is unreachable today, for the two reasons above. The engine's own
note is that an approval recorded as `policy:auto` rather than by a person is
*an audit line that reads like a person said yes, which is a lie the log
cannot correct* (`auto_rule.rs:116-117`) — the honest spelling is already
in the code.

> A `decide` step sends the plan to Jev

The step sends a **summary** of the plan — addresses, masked attribute
paths, counts — not the plan. `plan_summary` masks sensitive attributes and
strips control characters, and the state is a `RedactedState` with no public
constructor. The claim is true in substance and loose in the noun.

> The reviewer sees the plan and the diff

`ApprovalGranted` carries an `artifacts` list, but the out-of-band
`keepshipping approve` path leaves it empty in both outcomes
(`crates/cli/src/approve.rs:191`, `:229`) — the local channel binds nothing,
and the code says why: inventing a digest for an event that has no such
artifact *would be a lie the log could never be caught on*
(`crates/cli/src/approve.rs:55`). So "the reviewer sees the plan and the
diff" does not describe the shipped CLI yet.

> **Approval where it matters** — approve from chat, CLI or web.

There is no chat channel. `ApprovalChannel` is a real port and
`ks-hosted-approvals` implements `Web` and `Slack`
(`adapters/hosted-approvals/src/lib.rs:32-39`), but `ks-hosted-approvals` is
not a dependency of `crates/cli`. What `run` can actually construct is
three things (`main.rs:253-264`): an agent park, a local TTY prompt, or an
unwatched park. The CLI is the only one that ships.

So the section's fine print — *Jev can be wrong; a confidence score is a
number, not a promise; you set the threshold; destroys always go to a human;
every decision is logged with its score* — is honest about the model's
limits and inaccurate about the wiring. Three of its five clauses hold as
library functions, one of them holds only for an agent, and none of them
is reachable from a stock `keepshipping run` — the `auto:` rule has no
production call site and the `decide` step is compiled out. A wording that
matches what ships today:

> A workflow file declares what agents may do alone and what waits for a
> person. Keep Shipping enforces that on the run, but today the approvals are
> enforced at the step boundary rather than by an auto-approve rule, and
> `decide` — which sends a plan summary to a model and reads back a typed
> answer with a confidence score — is not compiled into the shipped binary.
> What ships: the agent detection, the effective policy, the destroy and
> secrets guards, and the run log.

Or, in one sentence for a reader who does not want the detail:

> The policy, the detection and the hard rules run today; the model in the
> loop does not yet.
