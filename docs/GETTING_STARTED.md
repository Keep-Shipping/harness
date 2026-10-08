# Getting started

From a fresh clone to a site file that checks, explains itself and gates CI. This walks the
example service in [`examples/example-api/`](../examples/example-api/) from install to the
policy a person would be held to — and stops where the binary stops today: **`run` cannot
execute a step yet**, so the journey ends at a plan, not at a deploy.

Every `$`-prompt transcript below was captured from the real binary and can be re-run. The
approval section is the one exception, and it says so where you reach it: `run` cannot park a run
today, so no reader can produce the record those commands act on, and that section quotes
[CLI.md](CLI.md) instead of showing output.

## What you need

- a clone of this repository, and the `keepshipping` binary (below);
- a Rust toolchain ([rustup](https://rustup.rs)) if you build from source — not needed if you
  download a release archive;
- about ten minutes.

Nothing else. You do not need a registry, a cluster, a cloud account or a container runtime to
follow this guide: no step is ever executed.

## Install

There are two ways in, and **there is no `cargo install keepshipping`**. The workspace is
`publish = false` and nothing is published to crates.io
([ADR 0014](adr/0014-release-and-contract-versioning.md)), so there is nothing to install from.
The binary is `keepshipping`; the crates are named `ks-*`, which trips people up.

**From source** — about 30 seconds once the dependencies are built:

```sh
cargo build --release -p ks-cli --bin keepshipping
```

The binary lands at `target/release/keepshipping`.

**From a release** — the release workflow builds archives for `x86_64` and `aarch64`, `.tar.xz`
on Linux and `.tar.gz` on macOS, beside a cosign-signed `SHA256SUMS`:

```sh
VERSION=0.1.0
TARGET=x86_64-unknown-linux-gnu
base="https://github.com/Keep-Shipping/harness/releases/download/v${VERSION}"
mkdir -p dist
curl -fsSL -o dist/SHA256SUMS "${base}/SHA256SUMS"
curl -fsSL -o "dist/keepshipping-${VERSION}-${TARGET}.tar.xz" \
  "${base}/keepshipping-${VERSION}-${TARGET}.tar.xz"
( cd dist && sha256sum -c --ignore-missing SHA256SUMS )
tar -C dist -xf "dist/keepshipping-${VERSION}-${TARGET}.tar.xz"
add_to_path=$(echo dist/keepshipping-*/keepshipping)
"$add_to_path" check
```

The archive unpacks **one directory deep**: `dist/keepshipping-<version>/keepshipping`, beside
the `LICENSE` and `README.md` that travel with it ([ADR 0006](adr/0006-licence-and-open-source-model.md)).
So the binary is not at `dist/keepshipping`, and the glob above is what finds it without
hardcoding the version string — `./dist/keepshipping check` fails with `ls: cannot access
'dist/keepshipping': No such file or directory`. To skip the prefix, put it on your `PATH`:

```sh
add_to_path=$(echo dist/keepshipping-*/keepshipping)
export PATH="$(dirname "$add_to_path"):$PATH"
keepshipping check
```

**There is no `--help`.** `keepshipping --help`, `-h`, `help`, and running it with no arguments
at all all print the same usage block — the full list of subcommands and flags — and exit 2.
That block is the reference: [CLI.md](CLI.md) explains what each one does, and this guide covers
the four you need. If you need `check` and there is no file in the directory, it says so and
exits 2: `error: no ship.ks in the current directory; pass the file to check`.

## The example repo

[`examples/example-api/`](../examples/example-api/) is a small HTTP service with the workflow
that ships it. This guide runs every command from inside it.

```
examples/example-api/
├── ship.ks                        the workflow — build, plan, review, apply, deploy
├── app.py                         the service: standard library only
├── Dockerfile                     FROM python:3.12-alpine
├── infra/prod/main.tf             a local kind cluster, and the output naming it
├── .github/workflows/ship.yml     the CI gate (Step 6)
└── README.md
```

`ship.ks` is 32 lines and is the whole product surface. Five steps: `build` (`oci.image`) builds
the Dockerfile and pushes it to `ghcr.io/example/example-api`; `plan` (`tofu.plan`) plans
`infra/prod`; `review` (`approval`) shows the plan's changes and asks `@platform`; `apply`
(`tofu.apply`) applies **the exact plan that was approved**; `deploy` (`k8s.rollout`) rolls the
built image out to the cluster the apply produced. The file format and every step kind is in
[LANGUAGE.md](LANGUAGE.md).

The last line of every successful command in this guide is `0 steps ran. Nothing was touched.`
That is not decoration. **It is the safety property**: `check`, `graph`, `run --dry-run` and
`policy explain` are read-only, and they say so out loud.

## Step 1 — check it

From `examples/example-api/`:

```
$ keepshipping check
✓ ship.ks
0 steps ran. Nothing was touched.
$ echo $?
0
```

One tick, one file, exit 0. `check` type-checks the file: every value an input carries has the
type the step kind declares, every reference resolves, every step name is unique. The language
is in [LANGUAGE.md](LANGUAGE.md); the checks and their codes are in [ERRORS.md](ERRORS.md).

## Step 2 — break it on purpose

A type-checker is only worth having if it catches the mistake you were going to make. The
example ships with one deliberate trap: `deploy` rolls out an image, and the file references the
build step's **tag** rather than its **digest**.

Open `ship.ks` and change line 24:

```
    image:  build.digest     # oci.Digest, never a tag
```

to

```
    image:  build.tag        # oci.Digest, never a tag
```

Now check it:

```
$ keepshipping check
✗ ship.ks:24  deploy.image  expected oci.Digest, got oci.Tag
  │
24 │     image:  build.tag     # oci.Digest, never a tag
  │             ^^^^^^^^^
  hint: use build.digest so prod runs
        exactly the image you built
0 steps ran. Nothing was touched.
$ echo $?
1
```

Read it properly, because every part is load-bearing:

- **`ship.ks:24`** — the file and the line, so your editor can jump to it.
- **`deploy.image`** — the *subject*: the step, and the input on it. Not "somewhere in the file".
- **`expected oci.Digest, got oci.Tag`** — the two types, in that order. `build.digest` is an
  `oci.Digest` (the content hash of the image, which cannot be re-pointed at something else);
  `build.tag` is an `oci.Tag` (a mutable name, which can). `k8s.rollout` declares it wants a
  digest, so the reference does not type-check.
- **`^^^^^^^^^`** — the span, under the exact nine characters that are wrong.
- **the hint** — why it matters in your words, not just what mismatched. `build.digest` means prod
  runs exactly the image this run built; `build.tag` means prod runs whatever the tag points at
  *now*, which is a different image from the one that passed the review.

**Why a type checker and not a lint:** a tag is what you build, a digest is what you ship.
Accepting a tag here would let prod deploy something nobody reviewed, and a type error is the
last place that can be stopped before the file runs. This is `KS0101`; the family is in
[ERRORS.md](ERRORS.md).

Change it back and it checks clean again. Or let the tool do it — the diagnostic carries a
machine-applicable fix:

```
$ keepshipping check --fix
ship.ks: applied 1 fix
✓ ship.ks
0 steps ran. Nothing was touched.
```

### For CI: the other two formats

`--format json` prints one JSON object per finding — code, severity, span, hints and the fix.
`--format github` prints one GitHub Actions annotation per finding, which lands on the diff:

```
::error file=ship.ks,line=24,col=13,endLine=24,endColumn=22,title=KS0101 deploy.image::expected oci.Digest, got oci.Tag%0Ahint: use build.digest so prod runs exactly the image you built
```

`%0A` is the percent-escape GitHub wants for a newline in a workflow command. **On a clean file
both formats print nothing at all** and exit 0, which is what makes them safe in a pipeline.

## Step 3 — read the plan

```
$ keepshipping graph --format text
ship.ks — 5 steps, env: default
seq  step    kind         deps          gate
  1  build   oci.image    —             run
  2  plan    tofu.plan    —             run
  3  review  approval     plan          run
  4  apply   tofu.apply   plan, review  run
  5  deploy  k8s.rollout  build, apply  run

route: push → build → plan → review → apply → deploy
0 steps ran. Nothing was touched.
```

`deps` is what a step waits for, inferred from what it references: `apply` references `plan.file`
and sits behind `review`, so it waits for both; `deploy` references `build.digest` and
`apply.out.cluster`, so it waits for both. `gate` is what may run it — `run` here, with no
`ci-only` or approval gate narrowing it.

**`graph` reads `ship.ks` in the current directory and takes no file argument**, so run it from
the directory holding the file.

## Step 4 — run it

`--dry-run` chooses the environment, resolves the route and prints it, touching nothing:

```
$ keepshipping run --dry-run
environment: default
▸ build   oci.image
▸ plan    tofu.plan
▸ review  approval
▸ apply   tofu.apply
▸ deploy  k8s.rollout
0 steps ran. Nothing was touched.
$ echo $?
0
```

That is the plan a run *would* take: the `on: push main` trigger matches, the environment is
`default`, and the five steps come out in dependency order with the kind each one is.

Now drop `--dry-run`:

```
$ keepshipping run
environment: default
✓ check   ship.ks is valid
✗ build   `oci.image` steps are not built in yet
$ echo $?
1
```

**This is where the journey ends today.** The file is valid, the route resolves, and the run
stops at its first step because **no step kind is executable yet** — not `oci.image`
specifically; every kind, including `approval`, returns this. The planner and executor are
written and tested in `ks-engine`; `run` is not wired to them yet. Nothing about your file caused
this, and nothing you can write in `ship.ks` gets past it. So today you can install, check, read
the plan, read the policy and wire CI — and you cannot deploy with this binary, which this guide
will not pretend otherwise.

## Step 5 — who may do what

Every step is decided for an actor. `policy explain` prints the effective policy for one of them
and attributes each row to the document that decided it ([ADR 0012](adr/0012-policy-authority.md)):

```
$ keepshipping policy explain --as agent
no baseline configured: the effective policy is this file's own policy
ship.ks — actor: agent

step    action    decision       source
build   build     can            file ship.ks:30
plan    plan      can            file ship.ks:30
review  —         not governed   —
apply   apply     ask @platform  file ship.ks:31
        destroy*  ask @platform  default
deploy  deploy    ask @platform  default

* an apply whose plan destroys or replaces anything is a destroy

0 steps ran. Nothing was touched.
```

Four columns: the step, the action it performs, the decision, and the source that decided it
(`file ship.ks:LINE`, or `default` — the built-in leash applied to an agent). The first line says
no organisation-wide baseline is configured; there is no `PolicyStore` adapter yet, so the file's
own policy is all there is.

The example's `policy:` block says an agent may `can: build, plan` and must `ask: @platform`
`before: apply` — rows 1, 2 and 4. A person is governed by the leash, not by the file:

```
$ keepshipping policy explain --as human
no baseline configured: the effective policy is this file's own policy
ship.ks — actor: human

step    action    decision      source
build   build     can           default
plan    plan      can           default
review  —         not governed  —
apply   apply     can           default
        destroy*  can           default
deploy  deploy    can           default

* an apply whose plan destroys or replaces anything is a destroy

0 steps ran. Nothing was touched.
```

**The `review` step is `not governed` for either actor.** `approval` is outside the policy
vocabulary: asking a human is not a permission the policy grants, it is the port the answer
comes back through. The `destroy*` row is the extra one every `apply` gets — an apply whose plan
destroys or replaces anything is held to the destroy rule, not the apply rule.

The port contract is in [PORTS.md](PORTS.md). Per-step credentials are in
[CREDENTIALS.md](CREDENTIALS.md) — a plan step and an apply step hold separate, separate roles.

## Step 6 — the same checks in CI

The example's [`ship.yml`](../examples/example-api/.github/workflows/ship.yml) is a working
gate. It downloads the release archive, verifies it against the signed `SHA256SUMS`, and runs
the two read-only commands on every push and every pull request:

```sh
keepshipping check --format github   # findings land on the diff as annotations
keepshipping run --dry-run            # the route, printed
```

`permissions: contents: read` is all it needs — checking a file requires no secrets.

**There is no packaged GitHub Action.** Nothing with an `action.yml` is published, so there is
no `uses: Keep-Shipping/...` to write; the workflow downloads the binary itself, and when a
packaged action ships that step becomes the `uses:` and the download goes away. If you are
copying this into your own repo, copy the download.

## Step 7 — the first approval, when it exists

`ship.ks` has a `review` step of kind `approval`, and there is a real command line underneath
it. **You cannot reach it from `run`, and this section shows no captured output.** Every step
kind — `approval` included — returns "not built in yet" before the drive loop ever reaches the
parking branch, so `run` never parks, exit 4 is unreachable from `run`, and no reader can
produce the parked record the commands below act on. The machinery is written and tested; today
it is reachable only by resuming a record that is already parked, which is exactly the thing you
cannot create.

So what follows is the **documented command line**, quoted from [CLI.md](CLI.md) — not a
transcript. Treat it as the contract the code already implements, and expect to meet
`error: run <id> has no parked state` (exit 2) if you try it today, for any id.

### The queue

This one you can run, and it is the empty case:

```
$ keepshipping runs pending
nothing is waiting for approval
$ echo $?
0
```

Empty, and 0 — the same line prints when nothing has ever run in the directory at all, so a 0
here means "no queue", not "a queue I found".

With a run parked, each line is the run id, two spaces, the step it waits on left-padded to
twelve, two spaces, and the environment it is headed for — so a six-character step name like
`review` is followed by eight spaces before the environment (`{run}  {step:<12}  {where_to}`):

```
<run-id>  review        default
```

That is the **format**, not a run you can see: `<run-id>` is 26 characters (a ULID; anything
shorter or longer is a usage error, not a lookup miss).

### Answering

The first two answer a park and **neither takes an `--as` flag** — there is no flag because
the approver named in the log is the environment's own (`$USER`, then `$USERNAME`, then
`local`), because an approver an agent could name on the command line is one an agent could
approve itself with.

- `keepshipping approve <run-id> [--comment TEXT]` — release the parked step. On success it
  prints `approved <run-id> at <step> as <who> — <comment>`, and records the answer as
  `approval.granted` in the run's hash-chained log. **Approving clears the park**: the record
  is no longer waiting, so a second `approve` or a `deny` on the same run is refused with
  `error: run <run-id> is not waiting for approval` (exit 2). Approve once, or deny; they are
  not two halves of one demonstration.
- `keepshipping deny <run-id> --reason TEXT` — refuse it. `--reason` is required. The run stays
  parked — what a refusal means for the run is the engine's decision, not this command's — and
  the refusal is recorded as `approval.denied`. On success it prints
  `denied <run-id> at <step> as <who> — <reason>`.
- `keepshipping resume <run-id> [ship.ks]` — carry the run on from the step it parked at.

`resume` on a still-parked run an **agent** is resuming refuses rather than answering the
approval, and says who may:

```
error: run <run-id> is still waiting at <step>: an agent is resuming it, and an agent may not answer an approval; a human approves it with `keepshipping approve <run-id>`, then `keepshipping resume <run-id>` carries it on
```

and exits **4**.

What a run writes down when it parks, why nothing holds a runner open while it waits, and how a
resume is re-bound to the artifacts it approved: [CLI.md](CLI.md#parking-and-resuming). How a
team answers on a pull request: [GITHUB_APPROVALS.md](GITHUB_APPROVALS.md).

Exit codes, for whatever you wire to a pipeline, are in [CLI.md](CLI.md#exit-codes). The ones you
will meet by running this guide are **0** (clean), **1** (`check` found errors) and **2**
(usage). **4** — a run waiting for an approval — is the one this guide can only describe, for
the reason given in Step 7.

## See also

- [CLI.md](CLI.md) — every subcommand and flag, and what each one does
- [LANGUAGE.md](LANGUAGE.md) — the file format, step kinds and inputs
- [ERRORS.md](ERRORS.md) — the checks and their codes, `KS0101` among them
- [GITHUB_APPROVALS.md](GITHUB_APPROVALS.md) — approvals on a pull request
- [ONBOARDING-NOTE.md](ONBOARDING-NOTE.md) — this walkthrough, timed, and what it could not answer
- [ADR 0014](adr/0014-release-and-contract-versioning.md) — why there is no `cargo install`
- [#140](https://github.com/Keep-Shipping/harness/issues/140) — the issue this guide answers
- [#155](https://github.com/Keep-Shipping/harness/issues/155) — timing it with early-access users