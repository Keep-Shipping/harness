# Error codes

Every diagnostic the `ks` parser and checker emit carries exactly one code,
stable forever: tools and agents match on the code, not on the message. Codes
are grouped by block — `KS00xx` syntax, `KS01xx` types, `KS02xx` names and
references, `KS03xx` workflow structure, `KS04xx` policy, `KS05xx` secrets,
`KS06xx` environment and CI warnings — with gaps left for growth.

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
- [KS0101 — type mismatch](#ks0101-type-mismatch)
- [KS0102 — digest pinned by value](#ks0102-digest-pinned-by-value)
- [KS0201 — unknown reference](#ks0201-unknown-reference)
- [KS0202 — unknown input](#ks0202-unknown-input)
- [KS0203 — unknown output](#ks0203-unknown-output)
- [KS0204 — unknown answer](#ks0204-unknown-answer)
- [KS0205 — unknown action](#ks0205-unknown-action)
- [KS0301 — duplicate step](#ks0301-duplicate-step)
- [KS0302 — reserved step name](#ks0302-reserved-step-name)
- [KS0303 — unknown trigger](#ks0303-unknown-trigger)
- [KS0304 — environment problem](#ks0304-environment-problem)
- [KS0305 — cycle](#ks0305-cycle)
- [KS0401 — unknown policy declaration](#ks0401-unknown-policy-declaration)
- [KS0402 — unknown policy action](#ks0402-unknown-policy-action)
- [KS0403 — policy forbids the run](#ks0403-policy-forbids-the-run)
- [KS0501 — secret in a string](#ks0501-secret-in-a-string)
- [KS0502 — secret shown](#ks0502-secret-shown)
- [KS0601 — optional value may be absent](#ks0601-optional-value-may-be-absent)

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
  risk: decide
    model: typesafe/jev
    ask: "How risky is the plan?"
    returns: low | medium | high
  gate: approval
    auto: risk is huge
```

Ok:

```ks
steps:
  risk: decide
    model: typesafe/jev
    ask: "How risky is the plan?"
    returns: low | medium | high
  gate: approval
    auto: risk is low
```

## KS0205: unknown action

Severity: error.

An `else:` action must be `ask @handle` or `show reference` — the two things a human needs to decide. Anything else is not an action the language knows.

Not ok:

```ks
steps:
  risk: decide
    model: typesafe/jev
    ask: "How risky is the plan?"
    returns: low | high
  gate: approval
    auto: risk is low
    else: notify ops
```

Ok:

```ks
steps:
  risk: decide
    model: typesafe/jev
    ask: "How risky is the plan?"
    returns: low | high
  gate: approval
    auto: risk is low
    else: show risk.reason
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
