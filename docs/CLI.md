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

## Exit codes

Codes 0–3 are the CLI's own; 10–12 are the states a run can end in and stop at. 130 comes from
`ks_engine::exec::RunStatus` — the shell's own report of `SIGINT`, which no branch here can
return. Every code is also named in `ks_cli::exit`, and each of the four codes a run can exit
with is spelled the same way in its JSON `status` — except 0, where the engine's `RunStatus`
says `succeeded` and the JSON says `shipped`.

| Code | Status | Meaning |
|---|---|---|
| 0 | `succeeded` | every step that ran, ran; for `check`, the file checks clean — warnings alone still pass |
| 1 | `failed` | `check` found errors (or warnings with `--warnings-as-errors`); a run failed: a step failed, a step timed out, or the run hit its own timeout |
| 2 | — | usage: an unknown flag or format, a missing value, a file that cannot be read, or no environment could be chosen |
| 3 | — | internal: an unexpected I/O error or a panic — a bug in keepshipping, never in your file |
| 10 | `waiting_for_approval` | the run stopped at an approval **nobody could answer** — an agent, a pipe, CI, `--non-interactive`, or a closed stdin. A state, not a verdict: the run is parked, and it is a person's to move |
| 11 | `denied` | a person **was** asked and said no. A verdict, already given; asking again asks the same person again |
| 12 | `policy_refused` | policy refused the run: the refused step and everything that needs it are skipped, and anything else in the run still runs |
| 130 | `cancelled` | the run was cancelled (Ctrl-C, a cancelled CI job) — 128 + `SIGINT`, as a shell reports it |

### What an agent should do with 10

Exit 10 is the one code that asks something of the caller. The run is not broken and nothing
was refused: it is sitting at an approval, and no part of re-running it will answer the
question. **Stop, report, and hand it to a person.**

Report the three things the run printed: its **run id**, the **step** it stopped at, and the
**team** that has to answer (`review` is waiting on `@platform` in the transcript below). Then
check on it later with `keepshipping runs status <RUN-ID>`.

Two ways this comes up, and both are deliberate:

- `--actor agent` never prompts. An agent cannot approve a change to infrastructure, so asking
  it would hang on a prompt no one will ever answer; it waits instead.
- A run with nothing to ask it — a pipe, `--non-interactive`, `CI` in the environment, a closed
  stdin — reaches the same state.

If you see **11** instead, a human already declined. That is a decision, not a wait: do not
retry, and do not ask again on the same plan.

`keepshipping runs status` and `keepshipping policy explain` are named here and in the JSON as
the things to reach for, and **neither is built yet** — they arrive with the local adapter. Until
then the run's own output is the whole report.

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

## JSON output

Four commands write JSON for tools: `check --format json`, `graph --format json`,
`log --format json` and `run --format json`. Everything else a command has to say goes to
stderr — a check's human findings, a dry run's step listing — so stdout is the machine form
and nothing else. `run --format github` and `blocks search --format github` are usage errors
(exit 2): GitHub annotations describe source spans, and neither has any.

### The versioning rule

Every object carries `"version": 1`. **Fields are only ever added within a version**: a new
optional key, or a new value for an open-ended one like `type`, is not a breaking change and
does not bump the number. A **rename or a removal** bumps `"version"`, because a reader
following v1 must not silently lose a field it was reading. Readers should ignore keys they do
not know, and writers must not reorder keys they already emit.

### `check --format json`

One object per diagnostic, one per line. Positions follow the source: `start`/`end` are byte
offsets; `line`/`column` are 1-based and count characters; `end_line`/`end_column` are
exclusive, the first position past the span.

| Field | Type | Notes |
|---|---|---|
| version | number | 1 |
| code | string | the stable `KSxxxx` code (see [ERRORS.md](ERRORS.md)) |
| severity | string | `error` or `warning` |
| file | string | the path as given |
| subject | string \| null | a short name for what the finding is about |
| message | string | the finding itself |
| span | object | `start`, `end` (bytes), `line`, `column`, `end_line`, `end_column` (1-based, end exclusive) |
| labels | array | secondary spans: `message` (string), `span` (object, as above) |
| hints | array of string | what to do about it |
| fixes | array | `span` (object), `replacement` (string), `machine_applicable` (bool) — safe for `--fix` to apply |

### `graph --format json`

One object for the whole plan — the file as it would run, without running it. Pretty-printed,
one step per line.

| Field | Type | Notes |
|---|---|---|
| version | number | 1 |
| file | string | the path as given |
| env | string | the environment chosen |
| triggers | array of string | one per `on:`, as written |
| steps | array | each `{seq, name, kind, deps, gate}` |
| steps[].seq | number | 1-based, in run order |
| steps[].name | string | the step name |
| steps[].kind | string \| null | the step's kind, `null` when it declared none |
| steps[].deps | array of string | step **names**, not seq numbers |
| steps[].gate | object | one of `{"kind":"run"}`, `{"kind":"skip","reason":string}`, `{"kind":"runtime","when":string}` |

### `log --format json`

The stored JSON Lines of a run's log, **byte for byte as written to
`.keepshipping/runs/<RUN-ID>.jsonl`** — not re-serialized. A tool that re-checks the hash chain
hashes exactly these bytes, so a re-rendered entry would not verify. Keys are alphabetically
sorted at every level, because the hash must not depend on the order they were written in.

Every entry carries `at` (unix milliseconds), `hash` (sha256 of the entry without `hash`),
`prev` (the previous entry's hash, 64 zeros for the first), `run` (the ULID), `seq` (0-based)
and `type`. Each type adds its own: `run.started` adds `file_hash`, `trigger`, `actor`,
`is_agent`; `step.started` adds `step`; `step.finished` adds `step`, `ok`, `outputs`,
`duration_ms` and `error` (present only when there was one); `approval.requested` adds `step`,
`channel`, `artifacts`; `approval.granted` and `approval.denied` add `step`, `approver`,
`channel`, `artifacts`; `policy.refused` adds `step` (only when it named one) and `rule`; and
`run.finished` adds `status` and `shipped`.

`log verify` checks the chain and prints `ok: {n} entries, chain intact` (exit 0), or names the
line the chain broke at (exit 1).

### `run --format json`

One object per line, in the order things happened. Every line carries `version` and `type`;
for a run that starts, **the first line is `run.started` and the last is `run.finished`**, so a
reader that reads only those two knows the run's id and its outcome without tracking state. A
run refused before it starts — a check error, an unmet context, usage — writes nothing to
stdout and everything to stderr. The closing `exit_code` is the code the process itself
returns, so the two can never disagree.

| type | Fields (besides `version`, `type`) |
|---|---|
| run.started | `run` (ULID), `env` |
| step.started | `step` |
| step.log | `step`, `line` |
| step.finished | `step`, `summary`, `took_ms` |
| step.failed | `step`, `error`, `took_ms` |
| approval.asked | `step`, `question` |
| approval.answered | `step`, `approved` (bool), `by` (string \| null) |
| run.finished | `run`, `status`, `exit_code`, and what the status adds |

`status` is one of `shipped`, `failed`, `denied`, `waiting_for_approval`, and each adds its
own: `shipped` adds `what` and `took_ms`; `failed` and `denied` add `step`;
`waiting_for_approval` adds a `waiting` object — `{step, team, check}`, where
`team` is the approval's `from:` handle (`null` when it declared none) and `check` is the
command that reports where the run got to. Nobody answered, so there is no
`approval.answered` line before it: the run was asked, and parked. `step.failed` is
terminal, so it is immediately followed by the closing `run.finished`.

Ticks print nothing: a spinner would be a line of escape codes between two objects.

### A run, as an agent sees it

The site's run, JSON, under `--actor agent`. It builds and plans, reaches the approval, and
stops there — nobody to ask — and exits **10**. This is
`crates/cli/tests/fixtures/run/site.json`, golden:

```
{"version":1,"type":"run.started","run":"01ARZ3NDEKTSV4RRFFQ69G5FAV","env":"prod"}
{"version":1,"type":"step.started","step":"build"}
{"version":1,"type":"step.log","step":"build","line":"build: working"}
{"version":1,"type":"step.finished","step":"build","summary":"sha256:9f2c…e1  signed","took_ms":38000}
{"version":1,"type":"step.started","step":"plan"}
{"version":1,"type":"step.log","step":"plan","line":"plan: working"}
{"version":1,"type":"step.finished","step":"plan","summary":"+2 ~1 -0","took_ms":11000}
{"version":1,"type":"step.started","step":"review"}
{"version":1,"type":"step.log","step":"review","line":"review: working"}
{"version":1,"type":"approval.asked","step":"review","question":"approve 3 changes?"}
{"version":1,"type":"run.finished","run":"01ARZ3NDEKTSV4RRFFQ69G5FAV","status":"waiting_for_approval","exit_code":10,"waiting":{"step":"review","team":"@platform","check":"keepshipping runs status 01ARZ3NDEKTSV4RRFFQ69G5FAV"}}
```

Read that as: run `01ARZ3NDEKTSV4RRFFQ69G5FAV` is parked at `review`, waiting on `@platform`.
There is no `approval.answered`: nobody answered, so nobody refused anything. The agent's
next move is to say so and stop — not to re-run.
