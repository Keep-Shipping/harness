# Running on any CI

`keepshipping run` works on a laptop and in a CI job, on any CI system that can run a binary
([#130](https://github.com/Keep-Shipping/harness/issues/130)). Pass `--ci` and the run answers for
the CI it is in, from the variables that CI exports:

```
$ keepshipping run ship.ks --ci
environment: prod
note: --ci buildkite: actor=ada event=push ref=refs/heads/main sha=9f2c1e4…93a4 (self-declared; generic mode verifies no OIDC identity)
```

One line, on stderr, before the run starts. It names what was detected and, in the same line, that
none of it is verified. A value the CI did not provide prints as `-`; nothing is invented to fill it.

## What generic mode is, and what it is not

Generic mode gives a CI the **plan, the steps and the log**: a run that starts, picks its
environment, drives its steps and reports a verdict, with the same `ship.ks` a laptop runs.

It does **not** give:

| | In generic mode |
|---|---|
| Trigger mapping | None. The CI's events are not mapped onto the plan's `on:`; the run is told what it is for with `--event`. |
| Status reporting | None. There is no Checks API to write to; the job fails because the binary's exit code is non-zero. |
| Approvals from inside the job | None. An approval **parks** the run and the job ends (exit 4). See [Approvals and parking](#approvals-and-parking). |
| A verified CI identity | None. See [Identity](#identity). |

This is deliberate, and
[ADR 0008](adr/0008-github-actions-first.md) commits to it: GitHub Actions is the *native*
integration, where an action, trigger mapping, OIDC, the Checks API and the approval hand-off are
all wired up. Generic mode is the floor that runs everywhere, and every native integration has to
keep passing it. A run on Buildkite and the same run on a laptop are the same run.

## Detection

One marker variable per system, checked in that order — a job may carry another system's
leftovers, and the system that names itself outright is the one whose variables describe the job.

| System | Marker | Commit (`sha`) | Ref | Trigger | Actor |
|---|---|---|---|---|---|
| GitHub Actions | `GITHUB_ACTIONS=true` | `GITHUB_SHA` | `GITHUB_REF` | `GITHUB_EVENT_NAME`: `pull_request*` from `refs/pull/<n>/`, `workflow_dispatch`/`repository_dispatch`/`schedule` → `manual`, `push` → `push`, else by ref | `GITHUB_ACTOR` |
| GitLab CI | `GITLAB_CI` | `CI_COMMIT_SHA` | `refs/tags/$CI_COMMIT_TAG`, else `refs/heads/$CI_COMMIT_REF_NAME` | `CI_PIPELINE_SOURCE`: `merge_request_event` → `pr $CI_MERGE_REQUEST_IID`, `web`/`api`/`trigger`/`schedule` → `manual`, `push` → `push`, else by ref | `GITLAB_USER_LOGIN` |
| Buildkite | `BUILDKITE` | `BUILDKITE_COMMIT` | `refs/tags/$BUILDKITE_TAG`, else `refs/heads/$BUILDKITE_BRANCH` | `BUILDKITE_EVENT`: `pull_request` → `pr` (from `BUILDKITE_PULL_REQUEST`'s `!123`), `manual`/`api` → `manual`, `push` → `push`, else by ref | `BUILDKITE_BUILD_AUTHOR` |
| CircleCI | `CIRCLECI` | `CIRCLE_SHA1` | `refs/tags/$CIRCLE_TAG`, else `refs/heads/$CIRCLE_BRANCH` | `CIRCLE_PULL_REQUEST`'s `/pull/<n>` → `pr <n>`, else by ref | `CIRCLE_USERNAME` |
| Jenkins | `JENKINS_URL` | `GIT_COMMIT` | `refs/tags/$GIT_TAG_NAME`, else `refs/heads/$GIT_BRANCH` (the `origin/` and `refs/heads/` prefixes come off; a hex `GIT_BRANCH` is a detached HEAD, not a branch, so no ref) | `CHANGE_ID` → `pr <n>`, else by ref | `BUILD_USER_ID` |
| Anything else | `CI` | — | — | `manual` | `unknown` |

"By ref" means: a `refs/tags/<name>` ref is a tag, anything else is `manual`. A branch ref is not
a push — a schedule, a nightly build and a pipeline someone re-ran all check out a branch exactly the
way a push does, so a ref alone cannot say which happened. Where a system *does* name the event
(`GITHUB_EVENT_NAME=push`, `CI_PIPELINE_SOURCE=push`, `BUILDKITE_EVENT=push`), that is read as a
push; `--event` overrides either way.

A bare `CI=true` yields **nothing but `unknown`**:

```
$ CI=true keepshipping run ship.ks --ci
note: --ci unknown: actor=unknown event=manual ref=- sha=- (self-declared; generic mode verifies no OIDC identity)
```

That is the honest answer. `CI=true` names no system, names no commit, names nobody and says
nothing about why the job is running; a run that filled those in would be claiming to be about a
commit and an event it cannot identify. The actor and the `ci` key a parked run records are one
name — `unknown` — so the note and the record cannot call one CI two different things.

## Identity

The identity a generic run reports is **self-declared and weak**. There is no OIDC token to verify:
GitLab, Buildkite, CircleCI and Jenkins each mint identity tokens at their own endpoints, in their
own formats, with their own audience rules, and generic mode has no way to reach or check any of
them.

So a `--ci` run reports `ActorKind::Ci` with a **weak** establishment —
`Detected { marker: "ci:<system>" }` where a named system's marker says so, and `SelfDeclared` where
only the flag did — and `Capabilities::oidc` is `false`. `keepshipping` will not mint a token on a
generic run, and a step kind that needs one is refused rather than half-served.

**A policy that requires a strong CI identity must not trust generic mode.** Use the native GitHub
Actions integration where the identity has to carry weight; see [GITHUB_ACTIONS.md](GITHUB_ACTIONS.md).

## Per-system snippets

Each of these is a complete job. Install the binary however you like; these show only the run.

### GitLab CI

```yaml
# .gitlab-ci.yml
ship:
  script:
    - keepshipping run ship.ks --ci
```

A merge request pipeline reports `--ci gitlab: … event=pr <iid>`. To fail the job on a parked run,
treat exit 4 as what it is — an approval a person has to answer somewhere else:

```yaml
ship:
  script:
    - |
      keepshipping run ship.ks --ci --event "pr $CI_MERGE_REQUEST_IID"
      case $? in
        0|1) exit 0 ;;                       # shipped, or a step failed
        4) echo "parked; approve with: keepshipping approve <run>" ; exit 0 ;;
        *) exit $? ;;
      esac
```

### Buildkite

```yaml
# pipeline.yml
steps:
  - label: "keepshipping"
    command: keepshipping\ run\ ship.ks\ --ci
```

Buildkite exports `BUILDKITE_EVENT`, `BUILDKITE_BRANCH` and `BUILDKITE_COMMIT`, which is everything
the note needs.

### CircleCI

```yaml
# .circleci/config.yml
jobs:
  ship:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
      - run:
          name: keepshipping
          command: keepshipping run ship.ks --ci
workflows:
  ship:
    jobs: [ship]
```

`CIRCLE_SHA1`, `CIRCLE_BRANCH` and `CIRCLE_PULL_REQUEST` are read automatically; a pull request build
reports `event=pr <n>`.

### Jenkins

Scripted, so nothing depends on a plugin beyond the git one:

```groovy
// Jenkinsfile
node {
  stage('keepshipping') {
    checkout scm
    sh 'keepshipping run ship.ks --ci'
  }
}
```

`GIT_COMMIT` and `GIT_BRANCH` come from the git plugin; `CHANGE_ID` is set on a multibranch
pipeline building a change request, and reports `event=pr <n>`.

### Any shell

Nothing to detect, nothing to export — the flag is the assertion:

```sh
keepshipping run ship.ks --ci
```

This is the "any CI that can run a binary" promise, and it holds: `--ci` forces the CI context (so
`ci-only:` steps run), forces the run non-interactive (so an approval parks rather than waiting on a
terminal that is not there), and prints the `unknown` note.

## Flags

All of these are on `keepshipping run` alone.

| Flag | What it overrides |
|---|---|
| `--ci` | Nothing detected: it *is* the assertion that a CI is in charge. Forces the `ci` context, forces the run non-interactive, and builds the run context above. |
| `--event "push main"` / `"pr 42"` / `"tag v1.2.3"` / `"manual"` | The trigger detected from the CI's variables. This is how a generic run names its own triggers. A `"tag v1.2.3"` also names its ref, so the note never calls the run a tag and a branch at once. |
| `--actor human\|agent\|ci` (`--as human\|agent[:name]\|ci`) | The actor detected from the CI's login. A declared actor is self-declared, and that is what it is labelled. `--as agent:<name>`'s name carries into the note, the way it does on a laptop. |
| `--sha SHA` | The commit the CI names no variable for. Needs `--ci`, since the CI run context is what it states it to; on its own it is a usage error. |

An explicit value always beats a detected one. What nothing provides stays empty (`-` in the note)
rather than being invented.

`--context local|ci` still sets what a run here could do; `--ci` is a claim about *where* the run is
happening, and forces the CI context over a detected laptop.

## Approvals and parking

In a `--ci` run nobody is watching, so an `approval` step **parks the run and the job ends** — exit
`4`, with the run id and the command that carries it on:

```
$ keepshipping run ship.ks --ci
note: --ci buildkite: actor=ada event=push ref=refs/heads/main sha=9f2c1e4…93a4 (self-declared; generic mode verifies no OIDC identity)
⏸ parked at review
parked at review; run 01HF7YAT00R3M2XK7A9B4CDEF is waiting for an approval
nothing is running while it waits — approve and continue with:
  keepshipping resume 01HF7YAT00R3M2XK7A9B4CDEF
```

Nobody spends runner minutes waiting. The CI reports failure (exit 4 is non-zero), a human runs
`keepshipping approve <run>` and `keepshipping resume <run>` from somewhere with the file, and the
run carries on. An agent's own run parks the same way and needs the `approve` first — see
[CLI.md](CLI.md#parking-and-resuming).

The record the run parks carries `actor`, `environment` and `ci` (the system that parked it), so
`keepshipping runs pending` and a resumed job can see where the run came from without re-deriving it
from the machine it lands on.

## What this does not do yet

The CLI never hands a run context to a step, so none of the above reaches step execution: the note,
the `ci` context and the parked record are what `--ci` changes today. Plumbing the port into steps
is separate work. The GitHub Actions adapter that does answer the port with a real OIDC identity is
in `crates/cli/src/github_actions_run_context.rs` and is not yet wired into dispatch either.