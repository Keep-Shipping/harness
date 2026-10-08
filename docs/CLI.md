# The `keepshipping` command line

`keepshipping` type-checks a site file and runs it. Two of the three subcommands are
implemented end to end today; `run` is not.

- `keepshipping check [FILE]` — type-check the file (default `ship.ks`), or with `--all` every
  `ship.ks` in a tree. Prints findings in `--format human|json|github`; `--warnings-as-errors`
  fails on warnings, `--secrets` lists the file's environments and their secret names. How
  findings are printed, and how a run fails, is in [DIAGNOSTICS.md](DIAGNOSTICS.md).
- `keepshipping run [FILE]` — check the file, choose an environment (`--env NAME`,
  `--event "push main"`, `--actor human|agent|ci`, `--as human|agent[:name]|ci`,
  `--non-interactive`), print it, and stop. `--input KEY=VALUE` (repeatable; a value beginning
  `@secret:` names a secret rather than carrying one) is checked before the run starts and echoed
  by `--dry-run`; no step is handed one yet. With `--only STEP` it names the inputs for one script
  step — see [DIAGNOSTICS.md](DIAGNOSTICS.md) for the grammar.
  Execution is not wired to the CLI yet: the planner and executor exist in `ks-engine` and
  `run` will hand them the plan.
- `keepshipping blocks search <QUERY>` — search the metadata-only blocks index (`--index URL` or
  `KEEPSSHIPPING_BLOCKS_INDEX`, `--limit N`, `--offline`, `--format human|json`). It asks the
  index; it never downloads a block.
- `keepshipping blocks publish <FILE>` — push a `.ks` block file to an OCI registry (`--version
  X.Y.Z`, `--to <host>/<namespace>`, `--readme PATH`), refusing a breaking interface change inside a
  release line. [Publishing blocks](#publishing-blocks) below.
- `keepshipping runs pending` — the runs parked waiting for a person, one line each: run id, the
  step it waits on, and the environment it is headed for. Prints `nothing is waiting for approval`
  (and exits 0) when the queue is empty, or when nothing has ever run here.
- `keepshipping approve RUN-ID [--comment TEXT]` — release the parked step, recording the approval
  in the state and as `approval.granted` in the run's hash-chained log. The comment is printed back
  to you; the log event has no field for it.
- `keepshipping deny RUN-ID --reason TEXT` — refuse it. `--reason` is required. The run stays parked
  — what a refusal means for the run is the engine's decision, not this command's — and the
  refusal is recorded as `approval.denied` in the run log.
- `keepshipping resume RUN-ID [FILE]` — carry on a run that parked (exit 4), from the `ship.ks` it
  parked from (default `ship.ks`). [Parking and resuming](#parking-and-resuming) below.
- `keepshipping policy explain [FILE]` — the effective policy for one actor (`--as agent|human|ci`,
  default `agent`; `--env NAME`), each row attributed to the document that decided it. Below.

There is **no `--as` flag** on `approve` or `deny`. The approver named in the state and the log is
the environment's own (`$USER`, then `$USERNAME`, then `local`): a label for the run log, not a
credential. An approver that could be named on the command line is one an agent could name too,
which is what the approval port exists to prevent.

Each successful online search is cached under `$XDG_CACHE_HOME/keepshipping/blocks` (or
`$HOME/.cache/keepshipping/blocks`), keyed by index URL, query and limit; a search that fails
stores nothing. `--offline` answers from that cache without touching the network — a query with
nothing cached exits 2, never an empty result.

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

## Publishing blocks

```sh
keepshipping blocks publish blocks/web-service.ks --version 1.0.0 --to localhost:5001/acme/blocks
```

- `--version X.Y.Z` — the version to publish at. Strictly `MAJOR.MINOR.PATCH`: no `v` prefix, no
  pre-release, no partial version.
- `--to <host>/<namespace>` — the registry host (port included) and the namespace inside it. The
  block's own `block:` name is the last path element. A **loopback** registry (`localhost`,
  `127.0.0.1`, `::1`) is spoken to over plain `http`; any other host is `https`. Credentials come
  from the docker config when one names the host.
- `--readme PATH` — the README to publish with the block. Only when named: a `README.md` that
  happens to sit beside the block file may be about something else.

Exit 0 prints `published <name> <version> to <repository>@<digest>`. A usage problem — no block
file, no `--version`, a version that is not `MAJOR.MINOR.PATCH`, a `--to` without a namespace, a
`block:` name a registry could not hold — is exit 2. A refusal, or a registry that would not take
the push, is exit 1.

One OCI image manifest, `artifactType` `application/vnd.keepshipping.block.v1`, with layers in a
fixed order — the interface (JSON: the block's `summary`, `inputs` and `outputs`, each field with
its `name`, `type` and `required`), the `.ks` file verbatim, and the README when one was given. The
manifest carries `org.opencontainers.image.title`, `org.opencontainers.image.version` and
`io.keepshipping.block.layers` (`interface,definition[,readme]`), so a reader can see what the
layers are instead of trusting position.

### The compatibility rule

A published version is immutable, so re-publishing one is refused rather than moving a tag
consumers pinned by name. Within a **release line** — the major, or while the major is `0` the
minor, the way cargo treats `0.x` — the interface is held still. **Breaking:** an input removed or
retyped, an input that is new and required or went from optional to required, an output removed or
retyped. **Compatible:** a new optional input, a required input that became optional, a new output.

A breaking change inside a line is refused, with the changes listed and the version to use instead
named. A new line is a new interface and is accepted whatever it changes — so after `1.0.0`,
removing an input is a `2.0.0`, and a `0.9.0` beside them is its own line. A version *below* the
highest published in its own line goes backwards and is refused too. Tags that are not
`MAJOR.MINOR.PATCH` are not versions and are ignored. There is no signing flag yet: no `Signer`
adapter is wired into the CLI, so a published block carries no signature.

## Exit codes

Codes 0–3 are the CLI's own and are stable. 4, 5 and 130 come from `ks_engine::exec::RunStatus`.
4 is what a run returns when it parks, and `keepshipping resume` returns it for a run that is
still waiting; 5 is what `resume` returns when policy refuses what is left of the run. Otherwise
they are what a run will return once `run` is wired to the executor.

| Code | Status | Meaning |
|---|---|---|
| 0 | `succeeded` | every step that ran, ran; for `check`, the file checks clean — warnings alone still pass |
| 1 | `failed` | `check` found errors (or warnings with `--warnings-as-errors`); a run failed: a step failed, a step timed out, or the run hit its own timeout |
| 2 | — | usage: an unknown flag or format, a missing value, a file that cannot be read, or no environment could be chosen |
| 3 | — | internal: an unexpected I/O error or a panic — a bug in keepshipping, never in your file |
| 4 | `waiting_for_approval` | a step needs an approval nobody gave: the run wrote itself down and stopped there, and nothing after the approval ran. `keepshipping resume <run>` carries it on; an agent's run (`--as agent`) needs `keepshipping approve <run>` from a human first |
| 5 | `policy_refused` | policy refused the run: the refused step and everything that needs it are skipped, and anything else in the run still runs |
| 130 | `cancelled` | the run was cancelled (Ctrl-C, a cancelled CI job) — 128 + `SIGINT`, as a shell reports it |

## Parking and resuming

A run that reaches an approval it cannot have answered does not wait. It writes the run down under
`.keepshipping/runs/<run>/state.json`, prints where it left off, and **exits 4**. Nothing is running
while it waits: a CI job that sat on an approval would spend runner minutes and run into its own
timeout, so carrying on is a *new* job. Two kinds of run park, and the record says which:

- **nobody to ask** — CI, a pipe, `--non-interactive`, a closed stdin. Whoever runs
  `keepshipping resume <run>` is the approver: the resume records the approval, with who gave it,
  an expiry 24 hours on (`expires_at`, RFC 3339) and the artifacts it covers, then carries on.
- **an agent's run** (`--as agent`, or detected) parks at its first approval, because an agent may
  not answer its own. `resume` will not answer it: a human runs `keepshipping approve <run>`, and
  `resume` then carries on past the recorded answer. Nor does a resume an agent is running answer
  anything — it exits 4 and says who can.

At a terminal a person's run still asks, and a typed `n` declines; a person watching is not a park.
Once step kinds are built in, a run nobody is watching ends like this:

```
$ keepshipping run --non-interactive
▸ build   sha256:9f2c…e1  signed    38s
▸ plan    +2 ~1 -0                  11s
▸ review  approve 3 changes? n
⏸ parked at review (run 01HF7YAT00R3M2XK7A9B4CDEF)
parked at review; run 01HF7YAT00R3M2XK7A9B4CDEF is waiting for an approval
nothing is running while it waits — approve and continue with:
  keepshipping resume 01HF7YAT00R3M2XK7A9B4CDEF
$ echo $?
4
```

Before `resume` changes anything it re-checks, and any refusal leaves the record exactly as it was,
so the same run can still be resumed where it can finish:

- **the binding** — `ship.ks` must still hash to what the run started with, no approval in the
  record may have expired, and every approval must still cover the artifacts the run holds (a
  rebuilt image or a re-planned plan is refused). Exit 1.
- **the context** — a run parked on a runner and resumed on a laptop is refused the way a fresh
  `run` on the laptop would be. The gate covers the approval step itself: a `ci-only` approval is
  not granted without CI. Exit 1.
- **policy** — the steps left are decided again against the organisation's baseline and the
  file's own `never:` rules ([#103](https://github.com/Keep-Shipping/harness/issues/103)), for the
  actor the run was recorded as (an agent if an agent is resuming). A step policy refuses refuses
  the resume. Exit 5. No `PolicyStore` adapter exists yet, so the baseline is the conservative
  built-in, which never lets a step read secrets.

A resume that passes drives what is left; an approval further on parks the run again. Steps the
record says are done are not run again. No step kind is executable from the CLI yet, so today a
resumed run stops at its first remaining step with `` `{kind}` steps are not built in yet `` and
exits 1 — past the approval, which is the part this covers.

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
