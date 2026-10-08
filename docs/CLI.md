# The `keepshipping` command line

`keepshipping` type-checks a site file and runs it. Two of the three subcommands are
implemented end to end today; `run` is not.

- `keepshipping check [FILE]` — type-check the file (default `ship.ks`), or with `--all` every
  `ship.ks` in a tree. Prints findings in `--format human|json|github`; `--warnings-as-errors`
  fails on warnings, `--secrets` lists the file's environments and their secret names. How
  findings are printed, and how a run fails, is in [DIAGNOSTICS.md](DIAGNOSTICS.md).
- `keepshipping run [FILE]` — check the file, choose an environment (`--env NAME`,
  `--event "push main"`, `--actor human|agent|ci`, `--non-interactive`), print it, and stop.
  Execution is not wired to the CLI yet: the planner and executor exist in `ks-engine` and
  `run` will hand them the plan.
- `keepshipping blocks search <QUERY>` — search the metadata-only blocks index (`--index URL` or
  `KEEPSSHIPPING_BLOCKS_INDEX`, `--limit N`, `--format human|json`). It asks the index; it never
  downloads a block.
- `keepshipping policy explain [FILE]` — the effective policy for one actor (`--as agent|human|ci`,
  default `agent`; `--env NAME`), each row attributed to the document that decided it. Below.

## `policy explain`

What this file's policy allows for one actor, each row attributed to the document that decided it
([ADR 0012](adr/0012-policy-authority.md)). Offline, so it shares `check`'s exit codes. The **first
line** says whether an org baseline is configured — no `PolicyStore` adapter yet, so always no.

```
$ keepshipping policy explain --as agent
no baseline configured: the effective policy is this file's own policy
ship.ks — actor: agent

step    action          decision       source
build   build           can            file ship.ks:34
plan    plan            can            file ship.ks:34
review  —               not governed   —
apply   apply           ask @platform  file ship.ks:36
        destroy*        ask @platform  file ship.ks:36
deploy  deploy staging  can            file ship.ks:34
deploy  deploy prod     ask @platform  file ship.ks:36

* an apply whose plan destroys or replaces anything is a destroy
```

**decision** — `can`, `ask @handle, @handle` (`ask a human` when none is named), or `never`.
**source** — `file FILE:LINE`, `default` (the leash, for an agent), `baseline`, or `hard rule`. An
`apply` also gets a `destroy*` row, footnoted below the table; steps outside the vocabulary
(`approval`, `decide`, …) get `not governed`. Without `--env`, a step deciding the same everywhere
gets one env-less row and one that differs gets a row per environment. `--as human` is the same
file minus the leash.

## Exit codes

Codes 0–3 are the CLI's own and are stable. 4, 5 and 130 come from `ks_engine::exec::RunStatus`
— they are what a run will return once `run` is wired to the executor.

| Code | Status | Meaning |
|---|---|---|
| 0 | `succeeded` | every step that ran, ran; for `check`, the file checks clean — warnings alone still pass |
| 1 | `failed` | `check` found errors (or warnings with `--warnings-as-errors`); a run failed: a step failed, a step timed out, or the run hit its own timeout |
| 2 | — | usage: an unknown flag or format, a missing value, a file that cannot be read, or no environment could be chosen |
| 3 | — | internal: an unexpected I/O error or a panic — a bug in keepshipping, never in your file |
| 4 | `waiting_for_approval` | a step needs an approval nobody gave; its dependants were skipped, the rest of the run carried on |
| 5 | `policy_refused` | policy refused the run: the refused step and everything that needs it are skipped, and anything else in the run still runs |
| 130 | `cancelled` | the run was cancelled (Ctrl-C, a cancelled CI job) — 128 + `SIGINT`, as a shell reports it |

## Failure semantics

These are the executor's rules (`ks_engine::exec`). A step that does not succeed — it failed,
timed out, was cancelled, was refused, or is waiting for an approval — is **skipped** for
everything that needs it, transitively. Independent steps still run.

**Timeouts.** Every attempt gets a deadline, and the run's remaining time caps it. The default
comes from what the step does:

| Action | Default timeout |
|---|---|
| `build` | 30m |
| `plan` | 15m |
| `apply` | 60m |
| `deploy` | 30m |
| `destroy` | 60m |
| `read-secrets` | 1m |
| `other` | 10m |

A step that overruns is cancelled, given **30 seconds of grace** to stop, and then dropped; its
record says `TimedOut`. A retry gets the whole budget again — it is a fresh run of the step, not
the remainder of what the last one left. The run itself is capped at **6 hours** — GitHub's
per-job limit. When the run runs out of time, nothing further is scheduled: unstarted steps are
recorded as cancelled and the run exits 1.

**Steps must yield.** Timeouts and cancellation are cooperative, not preemptive: a step that
never returns control cannot be interrupted, only recorded as having overrun its deadline once
it does. Steps must therefore reach a suspension point (a port call, a sleep) between units of
work, and watch the cancellation token they are given; the conformance kit checks this
([#21](https://github.com/Keep-Shipping/harness/issues/21)).

**Cancellation.** Ctrl-C, or a cancelled CI job, cancels the run's token. The executor watches
it — re-checking every second, so a step parked on nothing still sees it within about a second
— and cancels the token it handed that attempt, which is the token the step gets. A step that
stops is recorded `Cancelled`; one that ignores it keeps its 30 seconds of grace and is then
dropped. Unstarted steps are recorded `Cancelled` too, and the run exits 130.

**Retries.** A step is retried only if it is **idempotent** — running it twice is the same as
running it once — and only after a failure or a timeout, never after a cancellation, a refusal
or a request for approval. `tofu.apply`, and anything whose action is `apply` or `destroy`, is
never retried automatically whatever the file declares: re-running them can leave
infrastructure half-changed. The wait between tries is fixed and does not grow.

**Fail fast.** By default a run keeps going: one branch failing does not cost you another.
`--fail-fast` — an executor option today, arriving as a flag with the `run` wiring — stops the
run at the first failure and skips every step that had not started.

**Rollback.** A `deploy` that failed or timed out is rolled back, and what rollback reported is
recorded on the step. Nothing else is.
