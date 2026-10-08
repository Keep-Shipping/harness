# Running alongside an existing pipeline

Your repo already deploys. Keep Shipping is going to arrive next to it, one
environment at a time, and the old pipeline keeps shipping until you say
otherwise.

This page is the whole migration. It is written for the engineer whose repo has
a `deploy.yml` that works, who does not want to break it on day one, and who
will be asked — by the first incident — whether the new thing was the reason.

The method is one rule, applied four times: **each stage adds a thing beside the
old pipeline, never inside it, and the old pipeline is not edited until the last
stage.** Because nothing existing is edited until the end, every stage's undo is
one line — delete a file, or flip a job back on. That is what makes the migration
reversible at every point rather than only at the end.

## The example repo

`acme/api`, a fictional service that deploys on merge today:

```
infra/prod/                  OpenTofu: the ECS service and its task definition
Dockerfile                   the service image
.github/workflows/deploy.yml plans and applies to prod on merge, and works
```

`.github/workflows/deploy.yml` is the thing that must not break. It stays exactly
as it is through stages 0, 1 and 2. You will add files next to it, not change it.

What you add is `ship.ks`, which describes the same release as a graph instead
of a YAML file:

```ks
keepshipping: 0.1
name:  api
on:    push main

envs:
  staging:
    ci-only: true
  prod:
    ci-only: true

steps:
  build:   oci.image
    from:  ./Dockerfile
    push:  ghcr.io/acme/api:{git.sha}
    sign:  true

  plan:    tofu.plan
    dir:   ./infra/prod

  review:  approval
    show:  plan.changes
    from:  @platform

  apply:   tofu.apply
    plan:  plan.file
```

Ordering is not written; it is read off the data. `review` reads `plan.changes`
and `apply` reads `plan.file`, so the edges are `plan → review`, `plan → apply`
and `review → apply`. Note what is *not* an edge: `build` reads nothing, so
nothing runs before it and `--until plan` will not reach it. The two
environments and their five properties are in
[LANGUAGE.md](LANGUAGE.md#triggers-and-environments).

`keepshipping check ship.ks` passes this file clean today — exit **0**, no
diagnostics:

```
$ keepshipping check ship.ks
✓ ship.ks
0 steps ran. Nothing was touched.
```

The last line is not decoration: `check` runs no steps and never will, so every
human report from it ends that way. A warning alone still passes; only errors
make it exit 1 ([CLI.md](CLI.md#exit-codes)).

## Stage 0: read only, on day one

**What you add.** One workflow file. No credentials, no environment, no writes.

`.github/workflows/keepshipping-shadow.yml`:

```yaml
name: keepshipping (shadow)

on:
  push:
    branches: [main]

permissions:
  contents: read                # read the repo; nothing else

jobs:
  shadow:
    runs-on: ubuntu-latest
    continue-on-error: true     # the shadow can never block a merge
    steps:
      - uses: actions/checkout@v4

      - name: Check the site file
        run: keepshipping check ship.ks

      - name: Graph the run without running any of it
        run: keepshipping run ship.ks --env staging --dry-run

      - name: Plan, stopping before anything is applied
        run: keepshipping run ship.ks --env staging --until plan --non-interactive
```

Four properties, and each one is load-bearing:

- **`permissions: contents: read`, and no `id-token: write`.** This is the
  whole point of the job. Without an OIDC token, no step in it can exchange
  anything for a cloud credential, so the worst a bug here can do is print a
  wrong answer. Adding `id-token: write` is what turns a shadow into a second
  deploy path.
- **No `environment:` key.** An environment is where environment-scoped secrets
  and reviewers live. A job with no environment gets neither.
- **`continue-on-error: true`.** The shadow job is not a gate, so a mistake in
  `ship.ks` cannot hold up a release. If you do want the file checked, add a
  separate `check` job *without* `continue-on-error` to your required checks and
  leave this one advisory.
- **`--non-interactive`.** Belt-and-braces rather than load-bearing on a runner:
  `interactive()` already needs both a tty and an unset `CI`, so a GitHub runner
  takes the unwatched path anyway. It earns its place on a self-hosted runner
  someone has attached a pty to.

**How to tell it worked.** The `check` step printed `✓ ship.ks` and the
`--dry-run` step printed `0 steps ran. Nothing was touched.` The third step is
*expected* to fail today — see below — and the job's result is advisory either
way.

**How to undo it.** Delete `.github/workflows/keepshipping-shadow.yml`.

### `--dry-run` is the free one

```
$ keepshipping run ship.ks --env staging --dry-run
environment: staging
▸ build   oci.image
▸ plan    tofu.plan
▸ review  approval
▸ apply   tofu.apply
0 steps ran. Nothing was touched.
$ echo $?
0
```

It graphs the run, checks it, prints the steps in the order they would run, runs
nothing, and exits **0**. The last line is a promise, not a description: no step
executor was reached.

`--env staging` is not decoration. This file declares two environments, and with
no `--env` and no `--event` the CLI has nothing to choose between them:

```
$ keepshipping run ship.ks --dry-run
error: this file declares several environments (staging, prod); pass --env <name>
$ echo $?
2
```

The workflow-level `on: push main` does not settle it — only `--event` feeds the
selector, and it disambiguates only when **exactly one** environment matches. Two
environments carrying the same `on: push main` are still ambiguous. Give each
one a different `on:` *and* pass `--event`, or, in CI, just always pass `--env`.
Two is [usage](CLI.md#exit-codes), not failure.

### A real run does not succeed yet

Stated plainly rather than buried. `run` does drive steps — it graphs the
workflow, checks it, and hands the steps to a runner. That runner refuses every
kind that is not a script kind, and the only script kind is a relative path to a
`.ts` file ([#45](https://github.com/Keep-Shipping/harness/issues/45) tracks the
executors that will fill it in). So the message names whichever step came first:

```
$ keepshipping run ship.ks --env staging --until plan --non-interactive
environment: staging
✗ plan    `tofu.plan` steps are not built in yet
$ echo $?
1
```

and `approval` is in the same position, so **exit 4 is unreachable from a fresh
`keepshipping run` today** — a run cannot reach the park, because the step that
would park it has no executor either. Nothing is half-applied, because nothing
ran.

Two consequences for this page. The shadow job expects exit 1, which is why
`continue-on-error: true` is there on day one and not as an afterthought. And
when the executors land the workflow does not change — but read `--until` as
"this step and what it depends on": with no edge from `build` into `plan`, that
command starts *planning*, not building. If you want the plan and nothing else,
`--only plan` is the command that says so. `--skip build` does not: it drops
`build` from a full run and selects `plan, review, apply`, which is neither a
plan-only run nor a run that produces an image. To get the image *and* the
planning, use `--until apply`, which runs that step and everything it depends on
— `build` included.

## Stage 1: shadow one environment

**What it may and may not do.** Once an executor exists it may read cloud state
and produce a plan. It may not apply anything: `apply` is downstream of
`review`, which is downstream of `plan`.

**How to tell it worked.** Not by the job being green — by comparing its plan to
the old pipeline's:

| Compare | What a difference means |
|---|---|
| Which resources the plan would change | A resource the old pipeline does not know about is drift; the two files describe different infrastructure |
| Which resources it would **destroy** | The one that matters. A destroy the old pipeline would not do is the stop-ship case |
| The diff, line for line | Attribute differences show up as churn; a plan that is right but noisy still works |
| Which steps ran before the stop | If the plan step is not reachable, the graph is wrong, not the infrastructure |

Run it in shadow for **one full release cycle** — long enough to have seen at
least one infrastructure change, which exercises the plan, and one ordinary
application deploy, which exercises the image. **Undo:** delete the job. Nothing
was written.

## Stage 2: one environment for real

**What you add.** `--until plan` becomes a plain run, with the credential and
the environment that stage 1 was careful not to have.

`.github/workflows/keepshipping-staging.yml`:

```yaml
name: keepshipping (staging)

on:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  ship:
    runs-on: ubuntu-latest
    environment: staging        # this makes the OIDC subject environment-scoped
    permissions:
      contents: read
      id-token: write          # without this, `role:` cannot be federated
    steps:
      - uses: actions/checkout@v4

      # No `continue-on-error: true` here, unlike stage 0. This job ships to a
      # real environment: the day the step kinds are wired it is a real gate,
      # and a gate that cannot go red is not a gate. Until then it will be red —
      # `build` has no executor, so the run exits 1 and the `case` re-fails it.
      - name: Ship to staging
        run: |
          set +e
          output=$(keepshipping run ship.ks --env staging --non-interactive 2>&1)
          code=$?
          set -e
          printf '%s\n' "$output"
          case "$code" in
            0|4) ;;            # 4 is a park, not a failure
            *) exit "$code" ;;
          esac
```

`environment: staging` is what scopes the OIDC subject to
`repo:ORG/REPO:environment:staging`, so the token cannot be minted for anything
else. The `case` is stage 3's, needed here too: `ship.ks` carries a `review`
step, so once the step kinds are wired a staging run parks — exit **4** — just
as prod does, and without the guard this job goes red the first time it works.
Neither path happens yet; today the command stops at `build` and exits **1**.

One thing this job deliberately does *not* claim: it is a single job, so there
is no credential split. The plan/apply separation in
[CREDENTIALS.md](CREDENTIALS.md) only exists once the steps declare `role:`, and
`ship.ks` declares none — there is one identity for the whole run. Adding
`role:` to `plan` and `apply` is the change that makes the two-job shape the
right one.

### One pipeline writes to an environment at a time

This is the single most dangerous mistake in the whole migration, so it gets its
own section rather than a clause.

**Enabling the new job and disabling the old staging path must happen in the
same pull request.** Not in two. Not "turn the new one on, watch it, then turn
the old one off". Overlapping them applies staging twice from two pipelines with
two opinions, and neither one's log explains the other's change.

Two things make this safe in practice:

- **One environment at a time.** Staging goes over before prod. They are
  separate jobs, separate `environment:` keys and separate OIDC subjects, so
  staging being done is not a warm-up for prod — it is a different question.
- **The old pipeline's prod path keeps running.** If the new staging job is
  wrong, the rollback is reverting one PR, and prod was never touched by it.

The check before you merge: grep your diff for the old job and confirm the same
PR disables it. A reviewer should never have to hold both states in their head.

**Undo:** revert the PR. The old staging path comes back exactly as it was.

## Stage 3: prod

**What you add.** The same job with `environment: prod`, and the approval in the
middle of it. `review` parks the run; carrying it on is a separate job.

This is the target wiring, written out now so it is decided before it is needed.
Today the `plan` job exits **1** at `build` and the sequence below is inert.

`.github/workflows/keepshipping-prod.yml`:

```yaml
name: keepshipping (prod)

on:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  plan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@v4

      - name: Plan and stop at the approval
        id: ship
        run: |
          set +e
          output=$(keepshipping run ship.ks --env prod --non-interactive 2>&1)
          code=$?
          set -e
          printf '%s\n' "$output"
          case "$code" in
            0|4) ;;
            *) exit "$code" ;;
          esac
          echo "run-id=$(printf '%s' "$output" | grep -oE 'run [A-Z0-9]{26}' | head -1 | cut -d' ' -f2)" >> "$GITHUB_OUTPUT"

  resume:
    needs: plan
    # Nothing parked, so there is no run to resume: a failed `plan` already
    # failed this workflow. An empty argument would be a usage error.
    if: needs.plan.outputs.run-id != ''
    runs-on: ubuntu-latest
    environment: prod
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@v4

      - name: Carry on from the parked run
        run: keepshipping resume "${{ needs.plan.outputs.run-id }}" ship.ks
```

`resume` is its own subcommand — `keepshipping resume RUN-ID [FILE]`, not a flag
on `run`. It re-checks before it changes anything: `ship.ks` must still hash to
what the run started with and every approval must still cover the artifacts the
run holds.

### Exit 4 is not a failure, and must not be retried

A run that reaches `review` and cannot answer it does **not** wait. It writes
itself down under `.keepshipping/runs/<run>/state.json`, prints where it left
off, and exits **4** (`waiting_for_approval`, in the
[exit-code table](CLI.md#exit-codes)). Nothing is running while it waits — a job
that sat there would burn runner minutes until its own timeout — so carrying on
is a **new** job, not a longer one.

**A CI job must not retry it.** A retry re-plans from scratch and parks again
under a new run id; it does not answer the approval already open, and the second
run's plan is not the one anybody is looking at. Approve and resume instead:

```
$ keepshipping runs pending
$ keepshipping approve 01HF7YAT00R3M2XK7A9B4CDEF0
$ keepshipping resume 01HF7YAT00R3M2XK7A9B4CDEF0 ship.ks
```

Those ids are 26 characters, because that is what a ULID is — a shorter one is a
usage error, not a "no such run". Do not hand-write one: `keepshipping runs
pending` prints the real ones. A human can also approve by commenting on the
pull request ([GITHUB_APPROVALS.md](GITHUB_APPROVALS.md)).

**Undo:** revert the PR. The old prod path comes back.

## What each stage holds

| Stage | Credential surface | Blast radius | Undo |
|---|---|---|---|
| 0 — read only | none | none | delete the file |
| 1 — shadow staging | none | none | delete the job |
| 2 — staging for real | OIDC into staging | staging | revert the PR |
| 3 — prod | OIDC into prod | prod | revert the PR |

The row that matters is that stages 0 and 1 hold **no** credential at all. They
are not low-risk versions of a deploy; they cannot deploy.

## Rolling back

Every stage's undo is one line, and nothing existing is edited until stage 3 —
which is the entire reason rollback is free. One thing is not free: anything the
new pipeline already applied to a real environment. A prod apply that
half-landed is not undone by reverting a workflow file. That is the argument for
the shape above — stages 0 and 1 write nothing at all.

## Things that will surprise you

- **Exit 4 is not a failure.** And the inverse: no fresh `run` parks yet, so a
  job going red on an approval today means something else is wrong.
- **`--dry-run` is the only invocation that touches nothing and exits 0.**
  Everything else that reaches a step stops on it. A gap, not a design.
- **KS0611 is CI-only.** A file with no `keepshipping:` header warns on a
  pipeline and stays silent on a laptop ([ERRORS.md](ERRORS.md)).
- **`ci-only: true` on a *step* refuses a local run** — `check` warns `KS0602`,
  `run` refuses to start:

  ```
  refusing to start: step `deploy` (2 of 2) needs CI (not available locally); pass --allow-partial, or run with `--skip deploy` or `--until build`
  ```

  `--allow-partial` is for a run you have already decided may be partial. On an
  **environment** the same key does something quieter — it only moves the plan
  guard's recheck default ([STALE_PLANS.md](STALE_PLANS.md)) — so do not expect
  the two to behave alike.
- **A parked run is bound to what it held.** If the world moved between the park
  and the resume, the resume stops and asks again
  ([STALE_PLANS.md](STALE_PLANS.md)).

## Where to read more

| For | Read |
|---|---|
| Every flag, every exit code | [CLI.md](CLI.md) |
| The plan/apply OIDC split, per-cloud roles | [CREDENTIALS.md](CREDENTIALS.md) |
| The approval ticket and the comment commands | [GITHUB_APPROVALS.md](GITHUB_APPROVALS.md) |
| `envs:`, `on:`, and how ordering is read off the data | [LANGUAGE.md](LANGUAGE.md#triggers-and-environments) |
| What happens when the world moved between plan and apply | [STALE_PLANS.md](STALE_PLANS.md) |
| Every `KS****` code | [ERRORS.md](ERRORS.md) |