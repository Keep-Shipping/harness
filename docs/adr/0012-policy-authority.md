# ADR 0012: Policy authority

Status: proposed, 2026-10-07

## Context
The site says a workflow file declares who may do what: `policy:` is a
top-level block in `ship.ks`, its subjects are `agents` and `humans`, and
each takes `can:` / `before:` / `never:` tuples of actions `<verb> [<env>]`
plus `ask:` handles (`docs/LANGUAGE.md:218-237`). The nine verbs —
`check`, `build`, `test`, `plan`, `apply`, `deploy`, `destroy`, `publish`,
`read` — are the action classes, the same vocabulary
[ADR 0100](0100-step-contract-and-composition-checks.md) forward-references
as `ActionClass` (0100:32-34).

The problem is that `ship.ks` is the file coding agents can write. An agent
that can add a step can edit the file the step's own policy is read from: it
can move `apply` from `ask:` to `can:`, delete `never: read secrets`, or
lower a threshold. Nothing in the language says otherwise — the policy
lives inside the thing it governs.

What is enforced today is smaller than the block suggests. `pub struct
Policy` (`crates/core/src/workflow.rs:94`) holds one field, a private
`never: Vec<NeverRule>` (:95), and its own doc comment says so
(:88-92): "The workflow's policy, as far as static checks enforce it: the
`never:` rules a declared subject must respect. The checker enforces the
agents' `read secrets` rule against agent runs
([#27](https://github.com/Keep-Shipping/harness/issues/27)); nothing else
is refused yet." `check_policy` (`crates/core/src/check.rs:1314`,
dispatched from :294) records the rules it reads — `forbid` (check.rs:1458)
builds a `NeverRule` and pushes it, it does not refuse anything.
`enforce_actor_policy` (check.rs:1473) is the only enforcement site in the
repository; it is hardcoded to the single rule `(Agent, "read", "secrets")`
and is called once, from `finish_all` (check.rs:1513). `can:`, `before:`
and `ask:` are parsed and validated — an undeclared environment is an error
— and grant nothing and gate nothing.

The rest of the surface is a diagram and a name. `PolicyStore` appears
exactly twice elsewhere in the repository — both on the ports line of one
ASCII picture, at `docs/ARCHITECTURE.md:15` and `README.md:24` — and in no
Rust file at all. There is no `policy.rs` under `crates/core/src/ports/`.
The CLI has three subcommands and no fourth
(`pub enum Command { Check, Run, BlocksSearch }`,
`crates/cli/src/args.rs:29-34`), so there is no `keepshipping policy
explain` subcommand at all, and `--actor human|agent|ci` is the only lever
an operator has over policy today: `check` and `run` both take it, since
`run` threads the flag into `check::load`
(`crates/cli/src/main.rs:58`) and an agent run is refused by that same
path. And `crates/engine/src/lib.rs:1` mentions policy only in its crate
doc comment; there is no policy code in `crates/engine/src/`.

The options, briefly:

- **A. Trust the file; lean on code review.** Put `CODEOWNERS` on
  `ship.ks` and require a human to approve changes to it.
  For: zero new machinery, and the policy stays in one readable file.
  Against: the policy change and the risky deploy land in the same pull
  request, and a branch's own CI runs the branch's own file — so the
  reviewer is asked to catch an escalation in the same view that is being
  edited.
- **B. An org baseline outside the repo, and narrowing only.** A baseline
  policy lives in an org `.keepshipping` repository, a CI variable, or a
  hosted `PolicyStore`. The in-file policy may only tighten it: effective
  policy is the baseline intersected with the file.
  For: a real control that an agent editing `ship.ks` cannot lift, and
  the file's policy is still readable where the workflow is.
  Against: one more thing to configure, and `can:`/`before:`/`ask:` are
  inert today so there is nothing yet for a baseline to narrow.
- **C. Read the policy from the default branch only.** The file's policy is
  evaluated from `main`, never from the branch under test.
  For: stops the same-PR escalation, which is the sharpest version of the
  problem, with no new storage.
  Against: still editable by anyone who can merge, so the merge is the only
  remaining control; and it is confusing when a branch legitimately
  tightens the policy.

This ADR records the decision
[#13](https://github.com/Keep-Shipping/harness/issues/13) raised.

## Decision
Option B for the baseline, option C for the in-file half. The effective
policy is the org baseline intersected with the `policy:` block as it
stands on the **default branch**, and the in-file block may only narrow
what the baseline allows.

- **Effective policy = baseline ∩ default-branch policy.** A rule present
  in the baseline applies unless the file permits the action; a rule the
  baseline forbids applies whatever the file says. There is no widening
  path from a branch. `Policy` (`crates/core/src/workflow.rs:94`) stays the
  type the checker reads; the intersection produces a second `Policy` and
  enforcement consults only that one. There is no intersection code in the
  repository today. This ADR decides the semantics;
  [#101](https://github.com/Keep-Shipping/harness/issues/101) implements
  them.
- **The baseline is a `PolicyStore` port** — a new
  `crates/core/src/ports/policy.rs`, in the directory that
  [ADR 0002](0002-ports-and-adapters.md) already governs. Three adapters,
  in the order a company would adopt them: an org `.keepshipping`
  repository read by ref; a CI variable carrying the baseline as text; a
  hosted store. The port is a read of one baseline document — it has no
  write path, because a workflow file must never be able to author the
  thing that constrains it.
- **`PolicyStore` ships unimplemented.** Nothing in this repository
  implements it, and the name exists only in the two diagrams that already
  carry it. This ADR introduces the port and says plainly that it is empty:
  until an adapter lands, `check` enforces the file's own `never:` rules and
  only the single `(Agent, "read", "secrets")` rule, exactly as
  `workflow.rs:88-92` describes today.
- **A pull request that changes `policy:` gets a `check` warning and a
  required human approval.** The warning is not a failure — `check` stays
  the offline, fast command — but the change cannot merge unapproved. This
  is the one place where the branch's file is read at all, and it is read
  as a diff against the default branch, never as authority.
- **Two hard rules that no policy may loosen.** Destructive actions —
  `destroy` — go to a human, never to an agent, regardless of what the file
  or the baseline says. And an agent never receives secret material the
  baseline forbids: the existing `read secrets` refusal
  ([#27](https://github.com/Keep-Shipping/harness/issues/27)) is the floor,
  and a baseline can only add secrets to that set. Secret resolution itself
  stays behind the Secrets port
  ([ADR 0004](0004-secrets.md)); this ADR changes who may ask it for what,
  not how a value is resolved. Both rules sit outside the baseline ∩ file
  computation entirely: neither is derived from the effective policy and
  neither is loosened by it, in the configured case or the unconfigured
  one.
- **No baseline configured means no baseline — stated, not assumed.** The
  effective policy is then the file's own policy. That is the fail-open
  answer, and it is chosen purely on availability grounds: failing closed
  would mean an org with no baseline cannot run anything, which on day one
  is all of them, and the failure would look like a bug. It is a real
  weakening and it is owned rather than excused. The mitigation that
  would make it tolerable — `check` warns that no baseline is configured,
  and `keepshipping policy explain` leads with it — does not exist yet;
  it is owed by [#101](https://github.com/Keep-Shipping/harness/issues/101),
  and until that lands the choice is aspirational, not mitigated.
- **`keepshipping policy explain` prints the effective policy and where each
  line came from** — baseline, default branch, or the file — so that "what
  is this run allowed to do" is one command, and "who widened this" is
  answerable without reading git history. It is a fourth subcommand
  alongside `Check`, `Run` and `BlocksSearch`
  (`crates/cli/src/args.rs:29-34`); like `check`, it must stay offline once
  the baseline is resolved, and a missing baseline is a diagnostic rather
  than a network call, per [ADR
  0005](0005-local-first-core-with-optional-hosted-services.md).

### Why not the other two

- **Not A alone.** `CODEOWNERS` on `ship.ks` asks a reviewer to catch a
  policy widening in the same file the widening is written in, in a pull
  request that is also carrying the deploy the widening enables. It is a
  process control over a self-authored artifact; the branch's own CI runs
  the branch's own copy, so the check that would catch the escalation is
  itself edited by it. It stays as a belt alongside this decision, not
  instead of it.
- **Not C alone.** Reading from the default branch removes the same-PR
  escalation, which is the worst case, and leaves the merge as the only
  place policy can change. That is a thinner control than a baseline that
  lives outside the repository entirely, and it costs less. C is therefore
  adopted for the in-file half — it is free there, and it means a branch's
  `policy:` edit is a proposal rather than an instruction — while the
  baseline in B is what survives the merge.

### Before acceptance
The parts of this ADR that can be true today are decided; the parts that
need code cannot be, because `PolicyStore` is unimplemented and
`can:` / `before:` / `ask:` are inert. A baseline with nothing to narrow is
a baseline with no teeth, so this ADR stays proposed until the first
adapter and the intersection exist. It becomes accepted once:

1. `crates/core/src/ports/policy.rs` exists with the baseline read port, and
   `Policy` (`crates/core/src/workflow.rs:94`) can be intersected with it in
   a test that starts from a baseline and a file that tries to widen it.
2. A file that moves an action from `ask:` to `can:` produces a `check`
   warning naming the baseline rule it would widen, and a run against the
   branch's own file is refused where the default branch's file would be
   refused.
3. A pull request touching `policy:` is detected as such — the warning
   exists in `check`, and the approval is a required check in a CI
   configuration the repository documents.
4. `keepshipping policy explain` prints the effective policy with each
   rule attributed to baseline, default branch or file, and with the
   "no baseline configured" case stated in its first line.
5. With no baseline configured, `check` warns, `explain` says so loudly, and
   the effective policy equals the file's own policy — the behaviour this
   ADR chose, asserted by a test rather than assumed.

## Consequences
- `PolicyStore` becomes a port with no adapter behind it for the life of
  this ADR's `proposed` status. Anything that reads the effective policy
  must handle "there is no baseline" as a first-class state, not as an
  error.
- Enforcement gets a second input. `enforce_actor_policy`
  (`crates/core/src/check.rs:1473`) consults a policy that is computed, not
  the one it reads off disk, and the golden fixture
  (`crates/lang/tests/fixtures/site-policy.ks`) gains a baseline counterpart
  so the intersection is tested rather than asserted.
- `can:`, `before:` and `ask:` stop being documentation the moment
  [#101](https://github.com/Keep-Shipping/harness/issues/101) lands; until
  then they are still inert, and a reader of `ship.ks` can still be misled
  by a `can:` that grants nothing. `check` does not say so out loud today
  and never has: `warn_hint` (`crates/core/src/check.rs:533`) is called
  from two places only, `Code::PastedDigest` (:516) and
  `Code::OptionalAbsent` (:841), and there is no baseline to warn about
  because no `PolicyStore` exists. The warning that no baseline is
  configured is a consequence [#101] has to deliver, not a property of
  the binary as it stands — the same gap
  [ADR 0004](0004-secrets.md) records for `check_severity`.
- A tightening still has to go through the default branch to take effect,
  which is the friction option C buys and the reason the diff warning and
  the required approval exist.
- The CLI grows a subcommand. `Command` (`crates/cli/src/args.rs:29-34`)
  gains a fourth variant, and `explain` is the command that makes this
  whole decision auditable by someone who did not write the baseline.
- The engine's mention of "policy gates" in its crate doc comment
  (`crates/engine/src/lib.rs:1`) stays ahead of the code until this
  ADR's implementation lands; this decision does not make it true.
- This ADR blocks [#101](https://github.com/Keep-Shipping/harness/issues/101)
  and [#118](https://github.com/Keep-Shipping/harness/issues/118), because
  both read a policy whose authority this record changes.
- The honest cost is that the strongest statement this ADR can make is one
  about code that does not exist. `PolicyStore` is a name in two
  diagrams, the intersection is unimplemented, `can:` / `before:` /
  `ask:` still grant nothing, and `check` today refuses exactly one rule.
  Until an adapter and
  [#101](https://github.com/Keep-Shipping/harness/issues/101) both land, a
  branch that edits `ship.ks` can still edit its own policy, and this
  record is the only thing standing between that fact and a reader's
  assumption that it cannot.