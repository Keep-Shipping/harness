# Error codes

Every diagnostic the `ks` parser and checker emit carries exactly one code,
stable forever: tools and agents match on the code, not on the message. Codes
are grouped by block — `KS00xx` syntax, `KS01xx` types, `KS02xx` names and
references, `KS03xx` workflow structure, `KS04xx` policy, `KS05xx` secrets,
`KS06xx` environment, file format and CI warnings, `KS07xx` approval safety, `KS08xx`
build reproducibility — with gaps left for growth.

This file is generated from the registry in `crates/core/src/registry.rs`;
edit the registry, never this file. Regenerate with:

```
UPDATE_GOLDEN=1 cargo test -p ks-core --test registry
```

## Contents

- [KS0001 — unexpected syntax](#ks0001-unexpected-syntax)
- [KS0002 — unclosed string or interpolation](#ks0002-unclosed-string-or-interpolation)
- [KS0003 — invalid interpolation](#ks0003-invalid-interpolation)
- [KS0004 — tab in indentation](#ks0004-tab-in-indentation)
- [KS0005 — unsupported file format](#ks0005-unsupported-file-format)
- [KS0101 — type mismatch](#ks0101-type-mismatch)
- [KS0102 — digest pinned by value](#ks0102-digest-pinned-by-value)
- [KS0201 — unknown reference](#ks0201-unknown-reference)
- [KS0202 — unknown input](#ks0202-unknown-input)
- [KS0203 — unknown output](#ks0203-unknown-output)
- [KS0204 — unknown answer](#ks0204-unknown-answer)
- [KS0205 — unknown action](#ks0205-unknown-action)
- [KS0206 — missing block input](#ks0206-missing-block-input)
- [KS0301 — duplicate step](#ks0301-duplicate-step)
- [KS0302 — reserved step name](#ks0302-reserved-step-name)
- [KS0303 — unknown trigger](#ks0303-unknown-trigger)
- [KS0304 — environment problem](#ks0304-environment-problem)
- [KS0305 — cycle](#ks0305-cycle)
- [KS0306 — blocks nest too deep](#ks0306-blocks-nest-too-deep)
- [KS0401 — unknown policy declaration](#ks0401-unknown-policy-declaration)
- [KS0402 — unknown policy action](#ks0402-unknown-policy-action)
- [KS0403 — policy forbids the run](#ks0403-policy-forbids-the-run)
- [KS0404 — policy rule for an action no step can do](#ks0404-policy-rule-for-an-action-no-step-can-do)
- [KS0405 — a block may not carry policy](#ks0405-a-block-may-not-carry-policy)
- [KS0501 — secret in a string](#ks0501-secret-in-a-string)
- [KS0502 — secret shown](#ks0502-secret-shown)
- [KS0601 — optional value may be absent](#ks0601-optional-value-may-be-absent)
- [KS0602 — step needs more than this context has](#ks0602-step-needs-more-than-this-context-has)
- [KS0603 — unknown step kind](#ks0603-unknown-step-kind)
- [KS0610 — file format is one behind](#ks0610-file-format-is-one-behind)
- [KS0611 — file format not declared](#ks0611-file-format-not-declared)
- [KS0701 — `auto:` could destroy](#ks0701-auto-could-destroy)
- [KS0702 — artifact used after an approval that does not show it](#ks0702-artifact-used-after-an-approval-that-does-not-show-it)
- [KS0801 — image build is not reproducible](#ks0801-image-build-is-not-reproducible)

## KS0001: unexpected syntax

Severity: error.

The parser could not make sense of a line or expression: a missing value, a misplaced token, an indentation matching no open block. The tree still round-trips the source; fix the line the span points at.

Not ok:

```ks
steps:
  build: oci.image
    from:
```

Ok:

```ks
steps:
  build: oci.image
    from: ./Dockerfile
```

## KS0002: unclosed string or interpolation

Severity: error.

A string was opened with `"` but never closed on its line, or a `{` interpolation was never closed with `}`. Everything up to the end of the line is treated as part of the broken piece.

Not ok:

```ks
steps:
  risk: decide
    ask: "How risky
```

Ok:

```ks
steps:
  risk: decide
    ask: "How risky?"
```

## KS0003: invalid interpolation

Severity: error.

Inside `{...}` there must be a dotted name to resolve — `{git.sha}`, `{build.digest}`. Empty braces or prose leave nothing to look up.

Not ok:

```ks
steps:
  risk: decide
    ask: "plan {} is ready"
```

Ok:

```ks
steps:
  risk: decide
    ask: "plan {git.sha} is ready"
```

## KS0004: tab in indentation

Severity: error.

A tab sits in a line's indentation. Tabs advance to editor-dependent columns, so they break block alignment; indent with spaces instead. `keepshipping fmt` converts them.

Not ok:

```ks
steps:
	build: oci.image
		from: ./Dockerfile
```

Ok:

```ks
steps:
  build: oci.image
    from: ./Dockerfile
```

## KS0005: unsupported file format

Severity: error.

The file declares a `keepshipping:` format this keepshipping does not read, or the header is not a format version or is not the file's first entry. A file whose meaning moved on is refused rather than reinterpreted: raise the file to a format this build reads.

Not ok:

```ks
keepshipping: 0.9
steps:
  build: oci.image
    from: ./Dockerfile
```

Ok:

```ks
keepshipping: 0.1
steps:
  build: oci.image
    from: ./Dockerfile
```

## KS0101: type mismatch

Severity: error.

The value an input carries does not have the type the step kind declares. Reach for an output of the right type; when the workflow produces one, the hint names it.

Not ok:

```ks
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: build.tag
```

Ok:

```ks
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: build.digest
```

## KS0102: digest pinned by value

Severity: warning.

A well-formed sha256 digest is pasted straight into the input. It pins every run to the image that existed when the file was written; referencing the build step's `digest` output keeps prod on exactly the image each run built.

Not ok:

```ks
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
```

Ok:

```ks
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: build.digest
```

## KS0201: unknown reference

Severity: error.

The first segment of a dotted reference names no step declared in this file and no context namespace (`git`, `pr`, `run`, `env`, `ci`, `secrets`). Check the spelling; the hint suggests the closest step name.

Not ok:

```ks
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: buld.digest
```

Ok:

```ks
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: build.digest
```

## KS0202: unknown input

Severity: error.

The step kind declares no input with this name. Check the spelling against the kind's contract; the hint suggests the closest declared input.

Not ok:

```ks
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    imagee: build.digest
```

Ok:

```ks
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: build.digest
```

## KS0203: unknown output

Severity: error.

The step produces no output with this name. Check the spelling against the kind's contract; for kinds whose outputs are known only at run time, read `{name}.out.<name>` instead.

Not ok:

```ks
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: build.sha
```

Ok:

```ks
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: build.digest
```

## KS0204: unknown answer

Severity: error.

A `decide` step is compared against, or tested for, an answer it does not declare under `returns:`. Spell one of the declared answers, or add the new one to `returns:`.

Not ok:

```ks
steps:
  plan: tofu.plan
    dir: ./infra
  risk: decide
    model: typesafe/jev
    ask: "How risky is the plan?"
    returns: low | medium | high
  gate: approval
    auto: risk is huge
         and plan.destroys == 0
```

Ok:

```ks
steps:
  plan: tofu.plan
    dir: ./infra
  risk: decide
    model: typesafe/jev
    ask: "How risky is the plan?"
    returns: low | medium | high
  gate: approval
    auto: risk is low
         and plan.destroys == 0
```

## KS0205: unknown action

Severity: error.

An `else:` action must be `ask @handle` or `show reference` — the two things a human needs to decide. Anything else is not an action the language knows.

Not ok:

```ks
steps:
  plan: tofu.plan
    dir: ./infra
  risk: decide
    model: typesafe/jev
    ask: "How risky is the plan?"
    returns: low | high
  gate: approval
    auto: risk is low
         and plan.destroys == 0
    else: notify ops
```

Ok:

```ks
steps:
  plan: tofu.plan
    dir: ./infra
  risk: decide
    model: typesafe/jev
    ask: "How risky is the plan?"
    returns: low | high
  gate: approval
    auto: risk is low
         and plan.destroys == 0
    else: show risk.reason
```

## KS0206: missing block input

Severity: error.

A block use leaves out an input the block requires. Only an input with a default may be left out — pass the value, or give the input a default so leaving it out means something. The hint suggests the closest name when the missing one is a misspelling of another.

Not ok:

```ks
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: acme/web-service@v3
    image: build.digest
```

Ok:

```ks
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: acme/web-service@v3
    image: build.digest
    domain: api.acme.dev
```

## KS0301: duplicate step

Severity: error.

Two steps share a name, so references to it are ambiguous. Merge the declarations or rename one; the label points at the first definition.

Not ok:

```ks
steps:
  build: oci.image
    from: ./Dockerfile
  build: oci.image
    from: ./Dockerfile
```

Ok:

```ks
steps:
  build: oci.image
    from: ./Dockerfile
```

## KS0302: reserved step name

Severity: error.

The step is named like a context namespace (`git`, `pr`, `run`, `env`, `ci`, `secrets`), which would make `name.output` references ambiguous. Rename the step.

Not ok:

```ks
steps:
  git: oci.image
    from: ./Dockerfile
```

Ok:

```ks
steps:
  build: oci.image
    from: ./Dockerfile
```

## KS0303: unknown trigger

Severity: error.

A trigger must be `push [glob]`, `pr [glob]`, `tag [glob]` or `manual`; `schedule` is not supported yet. Check the spelling against those kinds.

Not ok:

```ks
on: pussh main
steps:
  build: oci.image
    from: ./Dockerfile
```

Ok:

```ks
on: push main
steps:
  build: oci.image
    from: ./Dockerfile
```

## KS0304: environment problem

Severity: error.

An environment is referenced but not declared (`env is prod`, a policy action naming it), or its declaration uses an unknown property or a bad value. Declare the environment under `envs:` or fix the spelling.

Not ok:

```ks
envs:
  prod:
    ci-only: true
steps:
  build: oci.image
    from: ./Dockerfile
  ship: k8s.rollout
    image: build.digest
    when: env is stagging
```

Ok:

```ks
envs:
  prod:
    ci-only: true
steps:
  build: oci.image
    from: ./Dockerfile
  ship: k8s.rollout
    image: build.digest
    when: env is prod
```

## KS0305: cycle

Severity: error.

The steps depend on each other in a circle, so no order can run. Break the circle: the message spells the path, the span points at the reference that closes it.

Not ok:

```ks
steps:
  a: decide
    model: typesafe/jev
    ask: "Ship it?"
    input: b.answer
    returns: low | high
  b: decide
    model: typesafe/jev
    ask: "Ready?"
    input: a.answer
    returns: low | high
```

Ok:

```ks
steps:
  a: decide
    model: typesafe/jev
    ask: "Ship it?"
    input: b.answer
    returns: low | high
  b: decide
    model: typesafe/jev
    ask: "Ready?"
    returns: low | high
```

## KS0306: blocks nest too deep

Severity: error.

Blocks use other blocks, and a nest deeper than four cannot be resolved: there is no order to expand it in, and a file that nests that deep is not worth a reader's time either. Split the innermost block in two. The examples below are one block per file, separated by `---`; only the last one is checked against the rest.

Not ok:

```ks
block: a
steps:
  use: b
---
block: b
steps:
  use: c
---
block: c
steps:
  use: d
---
block: d
steps:
  use: e
---
block: e
steps:
  build: oci.image
    from: ./Dockerfile
```

Ok:

```ks
block: a
steps:
  use: b
---
block: b
steps:
  use: c
---
block: c
steps:
  use: d
---
block: d
steps:
  build: oci.image
    from: ./Dockerfile
```

## KS0401: unknown policy declaration

Severity: error.

A `policy:` block names a subject other than `agents` or `humans`, or declares a property other than `ask`, `can`, `before` or `never`.

Not ok:

```ks
policy:
  robots:
    never: read secrets
steps:
  build: oci.image
    from: ./Dockerfile
```

Ok:

```ks
policy:
  agents:
    never: read secrets
steps:
  build: oci.image
    from: ./Dockerfile
```

## KS0402: unknown policy action

Severity: error.

A policy rule must name a known action — `check`, `build`, `test`, `plan`, `apply`, `deploy`, `destroy`, `publish`, `read` — optionally bound to an environment (`deploy prod`). `read` takes exactly one object: `secrets`.

Not ok:

```ks
envs:
  prod:
    ci-only: true
policy:
  humans:
    never: delete prod
steps:
  build: oci.image
    from: ./Dockerfile
```

Ok:

```ks
envs:
  prod:
    ci-only: true
policy:
  humans:
    never: deploy prod
steps:
  build: oci.image
    from: ./Dockerfile
```

## KS0403: policy forbids the run

Severity: error.

The run starts as an agent, and the file's policy says `agents: never: read secrets` — but the workflow reads a secret. The run is refused before it starts: give the run a human actor, or have the step take the value without a secret.

Not ok:

```ks
envs:
  prod:
    secrets: env
policy:
  agents:
    never: read secrets
steps:
  migrate: db.migrate
    url: secrets.db_url
```

Ok:

```ks
envs:
  prod:
    secrets: env
policy:
  agents:
    never: deploy prod
steps:
  migrate: db.migrate
    url: secrets.db_url
```

## KS0404: policy rule for an action no step can do

Severity: warning.

A `can:` or `before:` rule names an action class no step in this file can produce, so the rule binds nothing. It is a warning rather than an error: the rule may well be for a step kind another environment, a plugin or a future change brings in. Nothing is warned about under `never:` — forbidding what the file does not do is defensible policy.

Not ok:

```ks
envs:
  prod:
    ci-only: true
policy:
  agents:
    can: deploy prod
steps:
  build: oci.image
    from: ./Dockerfile
```

Ok:

```ks
envs:
  prod:
    ci-only: true
policy:
  agents:
    can: deploy prod
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: build.digest
```

## KS0405: a block may not carry policy

Severity: error.

A block definition declares a `policy:` block of its own. A block is someone else's pipeline code: letting it ship rules into your run would let the publisher decide what constrains it. Policy belongs to the repository and to the org baseline, so move these rules to the workflow file that uses the block.

Not ok:

```ks
block:  web-service
inputs:
  image:    oci.Digest
policy:
  agents:
    never: destroy prod
```

Ok:

```ks
block:  web-service
inputs:
  image:    oci.Digest
```

## KS0501: secret in a string

Severity: error.

A `secrets.*` reference is interpolated into a string. Anything a string can reach — a log, an URL, an error message — can leak the secret; pass it to an input typed `Secret` instead.

Not ok:

```ks
steps:
  risk: decide
    model: typesafe/jev
    ask: "Is {secrets.db_url} reachable?"
    returns: yes | no
```

Ok:

```ks
steps:
  risk: decide
    model: typesafe/jev
    ask: "Is the database reachable?"
    returns: yes | no
```

## KS0502: secret shown

Severity: error.

A `secrets.*` reference is passed to `show:`, which displays it to the approver and into the run log. Show a non-secret fact instead; the secret itself stays an input.

Not ok:

```ks
steps:
  build: oci.image
    from: ./Dockerfile
  ok: approval
    show: secrets.api_key
    from: @platform
```

Ok:

```ks
steps:
  build: oci.image
    from: ./Dockerfile
  ok: approval
    show: build.digest
    from: @platform
```

## KS0601: optional value may be absent

Severity: warning.

The context value used here is optional — it has no value on a laptop or outside a pull request. Handle the absent case instead of assuming a value.

Not ok:

```ks
steps:
  risk: decide
    model: typesafe/jev
    ask: "Deploy tag {git.tag}?"
    returns: yes | no
```

Ok:

```ks
steps:
  risk: decide
    model: typesafe/jev
    ask: "Deploy commit {git.sha}?"
    returns: yes | no
```

## KS0602: step needs more than this context has

Severity: warning.

The step asks for something the context it would run in cannot give: CI itself, an OIDC token, or network access. Checked with `--context local` a `ci-only: true` step warns here; checked with `--context ci` it is clean. Run it on CI, or bound the run before the step with `--until` or `--skip`.

Not ok:

```ks
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: build.digest
    ci-only: true
```

Ok:

```ks
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: build.digest
```

## KS0603: unknown step kind

Severity: warning.

The step's kind is not in the catalog — usually a misspelling, sometimes a kind another build, a plugin or a harness registers. The file still checks, but the step's inputs are not verified, so a typo in an input name or a value of the wrong type passes silently on this step; its outputs type `any`, read bare or through `.out.`. Check the spelling (the hint suggests the closest known kind) or register the kind's schema; where CI should refuse unknown kinds, run `keepshipping check --warnings-as-errors`.

Not ok:

```ks
steps:
  plan: tofu.plna
    dir: ./infra
  apply: tofu.apply
    plan: plan.changes
```

Ok:

```ks
steps:
  plan: tofu.plan
    dir: ./infra
  apply: tofu.apply
    plan: plan.file
```

## KS0610: file format is one behind

Severity: warning.

The file declares the format before the one this keepshipping writes. It still checks — the previous format stays readable until the format after next drops it — but `keepshipping fmt --upgrade` rewrites it mechanically, comments and all.

Not ok:

```ks
keepshipping: 0.1
steps:
  build: oci.image
    from: ./Dockerfile
```

Ok:

```ks
keepshipping: 0.2
steps:
  build: oci.image
    from: ./Dockerfile
```

## KS0611: file format not declared

Severity: warning.

The file declares no `keepshipping:` header, so it is read as the latest format this keepshipping knows. Pin it: a declared format is what tells the next breaking change what it has to migrate.

Not ok:

```ks
steps:
  build: oci.image
    from: ./Dockerfile
```

Ok:

```ks
keepshipping: 0.1
steps:
  build: oci.image
    from: ./Dockerfile
```

## KS0701: `auto:` could destroy

Severity: warning.

The `auto:` rule of an `approval` step approves without asking anyone, and it does not say what happens to a plan that destroys. Destroy goes to a human, always — the engine conjoins `and plan.destroys == 0` whatever the file says — so this is a warning about the file reading as more permissive than the run is. Write the clause: a guard inside an `or` does not count.

Not ok:

```ks
steps:
  plan: tofu.plan
    dir: ./infra
  risk: decide
    model: typesafe/jev
    ask: "How risky is this plan?"
    input: plan.changes
    returns: low | medium | high
  review: approval
    auto: risk is low ≥ 0.95
```

Ok:

```ks
steps:
  plan: tofu.plan
    dir: ./infra
  risk: decide
    model: typesafe/jev
    ask: "How risky is this plan?"
    input: plan.changes
    returns: low | medium | high
  review: approval
    auto: risk is low ≥ 0.95
         and plan.destroys == 0
```

## KS0702: artifact used after an approval that does not show it

Severity: error.

An `approval` is a promise about particular hashes: the approver is shown the plan file and the image digests, and says yes to those. A step the file orders after the approval consumes an artifact the approval never showed, so the thing being deployed is not the thing that was approved. Add the artifact to `show:`, or order the step before the approval.

Not ok:

```ks
steps:
  plan: tofu.plan
    dir: ./infra
  build: oci.image
    from: ./Dockerfile
  review: approval
    show: plan.changes
    from: @platform
  deploy: k8s.rollout
    image: build.digest
    after: review
```

Ok:

```ks
steps:
  plan: tofu.plan
    dir: ./infra
  build: oci.image
    from: ./Dockerfile
  review: approval
    show: plan.changes, build.digest
    from: @platform
  deploy: k8s.rollout
    image: build.digest
    after: review
```

## KS0801: image build is not reproducible

Severity: warning.

Two independent builds only produce the same image digest when every input is pinned: base images and downloaded files by digest or checksum, package indexes by snapshot date, timestamps fixed (SOURCE_DATE_EPOCH), and the same builder version. Otherwise the digest CI reports matches your local one only because CI *promotes* — it reuses the digest it built rather than building again — and the file is free to drift until it does. Reported by `keepshipping check --repro`, which reads the Dockerfiles an `oci.image` step names; the examples below are Dockerfiles, not `ship.ks`.

Not ok:

```dockerfile
FROM node:20
RUN apt-get update && apt-get install -y curl
ADD https://example.com/tool.tar.gz /usr/local/bin/tool
```

Ok:

```dockerfile
FROM node:20@sha256:1a79a4d60de6718e8e5b326e338ae533b95b6e5b4c7d0b6a9b0e3e6b6c5d4e3f2
RUN sed -i s/deb.debian.org/snapshot.debian.org/ /etc/apt/sources.list && apt-get update && apt-get install -y --no-install-recommends curl
ADD --checksum=sha256:5f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f https://example.com/tool.tar.gz /usr/local/bin/tool
```
