//! The diagnostics registry: one documented, compile-time-exhaustive
//! [`Explanation`] per [`Code`] — what it means, a bad example and a good
//! one — and [`errors_md`], which renders them as `docs/ERRORS.md`.
//!
//! Adding a `Code` variant without documenting it here fails to compile, so
//! the docs can never fall behind the checker.

use ks_lang::{Code, Severity};

/// What a [`Code`] means, with a minimal bad and good example. All fields
/// are static: the registry holds documentation, not state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Explanation {
    /// The code being explained.
    pub code: Code,
    /// A short name, as in the `## KS0101: type mismatch` heading.
    pub title: &'static str,
    /// What the problem means and why it matters.
    pub summary: &'static str,
    /// A minimal, complete `ks` source that triggers the code.
    pub bad: &'static str,
    /// The same file, fixed: the code is not emitted and nothing errors.
    pub good: &'static str,
    /// The severity every diagnostic of this code carries.
    pub severity: Severity,
}

/// The explanation for `code`. Exhaustive over [`Code`]: no wildcard, so a
/// new code without documentation does not compile.
#[must_use]
pub fn explain(code: Code) -> Explanation {
    match code {
        Code::Syntax => Explanation {
            code,
            title: "unexpected syntax",
            severity: Severity::Error,
            summary: "The parser could not make sense of a line or expression: a missing value, \
                a misplaced token, an indentation matching no open block. The tree still \
                round-trips the source; fix the line the span points at.",
            bad: "steps:\n  build: oci.image\n    from:\n",
            good: "steps:\n  build: oci.image\n    from: ./Dockerfile\n",
        },
        Code::Unclosed => Explanation {
            code,
            title: "unclosed string or interpolation",
            severity: Severity::Error,
            summary: "A string was opened with `\"` but never closed on its line, or a `{` \
                interpolation was never closed with `}`. Everything up to the end of the line \
                is treated as part of the broken piece.",
            bad: "steps:\n  risk: decide\n    ask: \"How risky\n",
            good: "steps:\n  risk: decide\n    ask: \"How risky?\"\n",
        },
        Code::BadInterp => Explanation {
            code,
            title: "invalid interpolation",
            severity: Severity::Error,
            summary: "Inside `{...}` there must be a dotted name to resolve — `{git.sha}`, \
                `{build.digest}`. Empty braces or prose leave nothing to look up.",
            bad: "steps:\n  risk: decide\n    ask: \"plan {} is ready\"\n",
            good: "steps:\n  risk: decide\n    ask: \"plan {git.sha} is ready\"\n",
        },
        Code::TabIndent => Explanation {
            code,
            title: "tab in indentation",
            severity: Severity::Error,
            summary: "A tab sits in a line's indentation. Tabs advance to editor-dependent \
                columns, so they break block alignment; indent with spaces instead. \
                `keepshipping fmt` converts them.",
            bad: "steps:\n\tbuild: oci.image\n\t\tfrom: ./Dockerfile\n",
            good: "steps:\n  build: oci.image\n    from: ./Dockerfile\n",
        },
        Code::FormatUnsupported => Explanation {
            code,
            title: "unsupported file format",
            severity: Severity::Error,
            summary: "The file declares a `keepshipping:` format this keepshipping does not \
                read, or the header is not a format version or is not the file's first \
                entry. A file whose meaning moved on is refused rather than \
                reinterpreted: raise the file to a format this build reads.",
            bad: "keepshipping: 0.9\nsteps:\n  build: oci.image\n    from: ./Dockerfile\n",
            good: "keepshipping: 0.1\nsteps:\n  build: oci.image\n    from: ./Dockerfile\n",
        },
        Code::TypeMismatch => Explanation {
            code,
            title: "type mismatch",
            severity: Severity::Error,
            summary: "The value an input carries does not have the type the step kind \
                declares. Reach for an output of the right type; when the workflow produces \
                one, the hint names it.",
            bad: "\
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: build.tag
",
            good: "\
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: build.digest
",
        },
        Code::PastedDigest => Explanation {
            code,
            title: "digest pinned by value",
            severity: Severity::Warning,
            summary: "A well-formed sha256 digest is pasted straight into the input. It pins \
                every run to the image that existed when the file was written; referencing \
                the build step's `digest` output keeps prod on exactly the image each run \
                built.",
            bad: "\
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: \"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"
",
            good: "\
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: build.digest
",
        },
        Code::UnknownRef => Explanation {
            code,
            title: "unknown reference",
            severity: Severity::Error,
            summary: "The first segment of a dotted reference names no step declared in this \
                file and no context namespace (`git`, `pr`, `run`, `env`, `ci`, `secrets`). \
                Check the spelling; the hint suggests the closest step name.",
            bad: "\
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: buld.digest
",
            good: "\
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: build.digest
",
        },
        Code::UnknownInput => Explanation {
            code,
            title: "unknown input",
            severity: Severity::Error,
            summary: "The step kind declares no input with this name. Check the spelling \
                against the kind's contract; the hint suggests the closest declared input.",
            bad: "\
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    imagee: build.digest
",
            good: "\
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: build.digest
",
        },
        Code::UnknownOutput => Explanation {
            code,
            title: "unknown output",
            severity: Severity::Error,
            summary: "The step produces no output with this name. Check the spelling against \
                the kind's contract; for kinds whose outputs are known only at run time, \
                read `{name}.out.<name>` instead.",
            bad: "\
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: build.sha
",
            good: "\
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: build.digest
",
        },
        Code::UnknownAnswer => Explanation {
            code,
            title: "unknown answer",
            severity: Severity::Error,
            summary: "A `decide` step is compared against, or tested for, an answer it does \
                not declare under `returns:`. Spell one of the declared answers, or add the \
                new one to `returns:`.",
            bad: "\
steps:
  risk: decide
    model: typesafe/jev
    ask: \"How risky is the plan?\"
    returns: low | medium | high
  gate: approval
    auto: risk is huge
",
            good: "\
steps:
  risk: decide
    model: typesafe/jev
    ask: \"How risky is the plan?\"
    returns: low | medium | high
  gate: approval
    auto: risk is low
",
        },
        Code::UnknownAction => Explanation {
            code,
            title: "unknown action",
            severity: Severity::Error,
            summary: "An `else:` action must be `ask @handle` or `show reference` — the two \
                things a human needs to decide. Anything else is not an action the language \
                knows.",
            bad: "\
steps:
  risk: decide
    model: typesafe/jev
    ask: \"How risky is the plan?\"
    returns: low | high
  gate: approval
    auto: risk is low
    else: notify ops
",
            good: "\
steps:
  risk: decide
    model: typesafe/jev
    ask: \"How risky is the plan?\"
    returns: low | high
  gate: approval
    auto: risk is low
    else: show risk.reason
",
        },
        Code::DuplicateStep => Explanation {
            code,
            title: "duplicate step",
            severity: Severity::Error,
            summary: "Two steps share a name, so references to it are ambiguous. Merge the \
                declarations or rename one; the label points at the first definition.",
            bad: "\
steps:
  build: oci.image
    from: ./Dockerfile
  build: oci.image
    from: ./Dockerfile
",
            good: "\
steps:
  build: oci.image
    from: ./Dockerfile
",
        },
        Code::ReservedStepName => Explanation {
            code,
            title: "reserved step name",
            severity: Severity::Error,
            summary: "The step is named like a context namespace (`git`, `pr`, `run`, `env`, \
                `ci`, `secrets`), which would make `name.output` references ambiguous. \
                Rename the step.",
            bad: "\
steps:
  git: oci.image
    from: ./Dockerfile
",
            good: "\
steps:
  build: oci.image
    from: ./Dockerfile
",
        },
        Code::BadTrigger => Explanation {
            code,
            title: "unknown trigger",
            severity: Severity::Error,
            summary: "A trigger must be `push [glob]`, `pr [glob]`, `tag [glob]` or `manual`; \
                `schedule` is not supported yet. Check the spelling against those kinds.",
            bad: "\
on: pussh main
steps:
  build: oci.image
    from: ./Dockerfile
",
            good: "\
on: push main
steps:
  build: oci.image
    from: ./Dockerfile
",
        },
        Code::EnvProblem => Explanation {
            code,
            title: "environment problem",
            severity: Severity::Error,
            summary: "An environment is referenced but not declared (`env is prod`, a policy \
                action naming it), or its declaration uses an unknown property or a bad \
                value. Declare the environment under `envs:` or fix the spelling.",
            bad: "\
envs:
  prod:
    ci-only: true
steps:
  build: oci.image
    from: ./Dockerfile
  ship: k8s.rollout
    image: build.digest
    when: env is stagging
",
            good: "\
envs:
  prod:
    ci-only: true
steps:
  build: oci.image
    from: ./Dockerfile
  ship: k8s.rollout
    image: build.digest
    when: env is prod
",
        },
        Code::Cycle => Explanation {
            code,
            title: "cycle",
            severity: Severity::Error,
            summary: "The steps depend on each other in a circle, so no order can run. Break \
                the circle: the message spells the path, the span points at the reference \
                that closes it.",
            bad: "\
steps:
  a: decide
    model: typesafe/jev
    ask: \"Ship it?\"
    input: b.answer
    returns: low | high
  b: decide
    model: typesafe/jev
    ask: \"Ready?\"
    input: a.answer
    returns: low | high
",
            good: "\
steps:
  a: decide
    model: typesafe/jev
    ask: \"Ship it?\"
    input: b.answer
    returns: low | high
  b: decide
    model: typesafe/jev
    ask: \"Ready?\"
    returns: low | high
",
        },
        Code::PolicyDecl => Explanation {
            code,
            title: "unknown policy declaration",
            severity: Severity::Error,
            summary: "A `policy:` block names a subject other than `agents` or `humans`, or \
                declares a property other than `ask`, `can`, `before` or `never`.",
            bad: "\
policy:
  robots:
    never: read secrets
steps:
  build: oci.image
    from: ./Dockerfile
",
            good: "\
policy:
  agents:
    never: read secrets
steps:
  build: oci.image
    from: ./Dockerfile
",
        },
        Code::PolicyAction => Explanation {
            code,
            title: "unknown policy action",
            severity: Severity::Error,
            summary: "A policy rule must name a known action — `check`, `build`, `test`, \
                `plan`, `apply`, `deploy`, `destroy`, `publish`, `read` — optionally bound \
                to an environment (`deploy prod`). `read` takes exactly one object: \
                `secrets`.",
            bad: "\
envs:
  prod:
    ci-only: true
policy:
  humans:
    never: delete prod
steps:
  build: oci.image
    from: ./Dockerfile
",
            good: "\
envs:
  prod:
    ci-only: true
policy:
  humans:
    never: deploy prod
steps:
  build: oci.image
    from: ./Dockerfile
",
        },
        Code::PolicyForbidden => Explanation {
            code,
            title: "policy forbids the run",
            severity: Severity::Error,
            summary: "The run starts as an agent, and the file's policy says `agents: never: \
                read secrets` — but the workflow reads a secret. The run is refused before \
                it starts: give the run a human actor, or have the step take the value \
                without a secret.",
            bad: "\
envs:
  prod:
    secrets: env
policy:
  agents:
    never: read secrets
steps:
  migrate: db.migrate
    url: secrets.db_url
",
            good: "\
envs:
  prod:
    secrets: env
policy:
  agents:
    never: deploy prod
steps:
  migrate: db.migrate
    url: secrets.db_url
",
        },
        Code::SecretInString => Explanation {
            code,
            title: "secret in a string",
            severity: Severity::Error,
            summary: "A `secrets.*` reference is interpolated into a string. Anything a \
                string can reach — a log, an URL, an error message — can leak the secret; \
                pass it to an input typed `Secret` instead.",
            bad: "\
steps:
  risk: decide
    model: typesafe/jev
    ask: \"Is {secrets.db_url} reachable?\"
    returns: yes | no
",
            good: "\
steps:
  risk: decide
    model: typesafe/jev
    ask: \"Is the database reachable?\"
    returns: yes | no
",
        },
        Code::SecretShown => Explanation {
            code,
            title: "secret shown",
            severity: Severity::Error,
            summary: "A `secrets.*` reference is passed to `show:`, which displays it to the \
                approver and into the run log. Show a non-secret fact instead; the secret \
                itself stays an input.",
            bad: "\
steps:
  build: oci.image
    from: ./Dockerfile
  ok: approval
    show: secrets.api_key
    from: @platform
",
            good: "\
steps:
  build: oci.image
    from: ./Dockerfile
  ok: approval
    show: build.digest
    from: @platform
",
        },
        Code::OptionalAbsent => Explanation {
            code,
            title: "optional value may be absent",
            severity: Severity::Warning,
            summary: "The context value used here is optional — it has no value on a laptop \
                or outside a pull request. Handle the absent case instead of assuming a \
                value.",
            bad: "\
steps:
  risk: decide
    model: typesafe/jev
    ask: \"Deploy tag {git.tag}?\"
    returns: yes | no
",
            good: "\
steps:
  risk: decide
    model: typesafe/jev
    ask: \"Deploy commit {git.sha}?\"
    returns: yes | no
",
        },
        Code::FormatDeprecated => Explanation {
            code,
            title: "file format is one behind",
            severity: Severity::Warning,
            summary: "The file declares the format before the one this keepshipping writes. \
                It still checks — the previous format stays readable until the \
                format after next drops it — but `keepshipping fmt --upgrade` \
                rewrites it mechanically, comments and all.",
            bad: "keepshipping: 0.1\nsteps:\n  build: oci.image\n    from: ./Dockerfile\n",
            good: "keepshipping: 0.2\nsteps:\n  build: oci.image\n    from: ./Dockerfile\n",
        },
        Code::FormatUndeclared => Explanation {
            code,
            title: "file format not declared",
            severity: Severity::Warning,
            summary: "The file declares no `keepshipping:` header, so it is read as the \
                latest format this keepshipping knows. Pin it: a declared format \
                is what tells the next breaking change what it has to migrate.",
            bad: "steps:\n  build: oci.image\n    from: ./Dockerfile\n",
            good: "keepshipping: 0.1\nsteps:\n  build: oci.image\n    from: ./Dockerfile\n",
        },
    }
}

/// The GitHub-style anchor of a section heading: lowercased, punctuation
/// dropped, spaces folded to dashes.
fn anchor(heading: &str) -> String {
    let mut out = String::new();
    for c in heading.chars() {
        match c {
            'a'..='z' | '0'..='9' => out.push(c),
            'A'..='Z' => out.push(c.to_ascii_lowercase()),
            ' ' => out.push('-'),
            _ => {}
        }
    }
    out
}

/// Render `docs/ERRORS.md`: a table of contents, then one section per code
/// with its severity, summary and a bad/good example pair. The registry test
/// compares this against the committed file.
#[must_use]
pub fn errors_md() -> String {
    let mut out = String::from(
        "# Error codes

Every diagnostic the `ks` parser and checker emit carries exactly one code,
stable forever: tools and agents match on the code, not on the message. Codes
are grouped by block — `KS00xx` syntax, `KS01xx` types, `KS02xx` names and
references, `KS03xx` workflow structure, `KS04xx` policy, `KS05xx` secrets,
`KS06xx` environment, file format and CI warnings — with gaps left for
growth.

This file is generated from the registry in `crates/core/src/registry.rs`;
edit the registry, never this file. Regenerate with:

```
UPDATE_GOLDEN=1 cargo test -p ks-core --test registry
```

## Contents

",
    );
    for code in Code::ALL {
        let e = explain(*code);
        let heading = format!("{}: {}", e.code, e.title);
        out.push_str(&format!("- [{} — {}](#{})\n", e.code, e.title, anchor(&heading)));
    }
    for code in Code::ALL {
        let e = explain(*code);
        out.push_str(&format!("\n## {}: {}\n\n", e.code, e.title));
        out.push_str(&format!("Severity: {}.\n\n", e.severity));
        out.push_str(e.summary);
        out.push_str("\n\nNot ok:\n\n```ks\n");
        out.push_str(e.bad);
        out.push_str("```\n\nOk:\n\n```ks\n");
        out.push_str(e.good);
        out.push_str("```\n");
    }
    out
}
