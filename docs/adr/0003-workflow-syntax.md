# ADR 0003: Workflow syntax

Status: accepted, 2026-10-06

## Context
The site shows a workflow file, and the pitch is "deploys you can read" and
"no copy-pasted YAML". What it shows is indentation-based `key: value` with
aligned columns, a step header that puts the kind on the same line
(`build:   oci.image`), typed declarations (`replicas: int = 2`), references
(`build.digest`), interpolation (`{git.sha}`), team handles (`@platform`),
duration tuples (`healthy, 5m`), enum literals (`low | medium | high`) and
small boolean expressions (`risk is low ≥ 0.95 and plan.destroys == 0`). It
reads like YAML and is not YAML: `build:   oci.image` followed by indented
keys is not a YAML mapping.

The question ([#4](https://github.com/Keep-Shipping/harness/issues/4),
blocking [#22](https://github.com/Keep-Shipping/harness/issues/22)) is whether
that is what we commit to, and two details have to be settled with it:

- **Output access.** The site uses both `build.digest` and
  `apply.out.cluster`. Two spellings for the same idea is a question every
  reader has to answer per file.
- **Unicode operators.** `≥` is on the site. If both it and `>=` are valid,
  the file stops being a canonical artefact and diffs start to churn.

The front end already exists: `ks-lang` parses this syntax with a hand-written
lossless tree, and `docs/LANGUAGE.md` carries the EBNF the parser was written
from. The decision is therefore partly a ratification and partly a statement
of what the syntax may never grow into.

## Decision
- **Option A: our own syntax**, as shown on the site. Not YAML, not a YAML
  superset, not CUE, Starlark or a TypeScript DSL. The options are rejected
  for the reasons the issue lists — YAML's own pitfalls are the thing being
  sold against, and the embedded languages are programs where we promise a
  readable file.
- The syntax stays **small and non-Turing-complete**: no loops, no user
  functions, no general recursion. Reuse is blocks; logic that needs a loop is
  a TypeScript step. A workflow file is a *description* of a deploy, and a
  file that can compute is a file nobody can review at a glance.
- **The grammar is written before the parser**, in EBNF, in
  [`docs/LANGUAGE.md`](../LANGUAGE.md). That document is the spec `ks-lang`
  implements; where the parser and the document disagree, the document wins
  and the parser is a bug. The EBNF closed as the checklist item of this
  issue.
- **The examples the site shows are golden tests.** The hero file, the block
  definition, the policy file and the `decide` step are fixtures under
  `crates/lang/tests/fixtures/site-*.ks`, each with a `.cst` golden tree
  compared byte-for-byte, so the syntax the site displays cannot drift from
  the parser without a failing test.
- **One rule for outputs.** Outputs a step kind declares statically are read
  as `<step>.<output>` (`build.digest`, typed `oci.Digest`). Outputs that
  exist only at run time — Terraform outputs, script and block returns — are
  read as `<step>.out.<name>`, typed `any`, with the name not verified at
  check time. Reading a run-time output without `out.` is a diagnostic that
  names the `out.` form. So `apply.out.cluster` is right and `apply.cluster`
  is an error; `build.digest` is right and `build.out.digest` is redundant.
- **ASCII is canonical; Unicode operators are aliases.** `>=` and `<=` are
  the canonical spellings, `≥` and `≤` are accepted and mean the same thing.
  The canonical spelling is what diagnostics quote. When `keepshipping fmt`
  lands it normalises aliases to canonical; until then the parser preserves
  the spelling it read, so a `≥` in a fixture stays a `≥` in its golden tree.
- **Types are in the file, from the ground up.** A checker that only knows
  `string` cannot tell a digest from a tag, and typed declarations
  (`replicas: int = 2`) are the site's own example — so the type vocabulary of
  [ADR 0001](0001-typed-values-and-secret-references.md) is reachable from a
  workflow file rather than bolted on from outside it.

## Consequences
- We own a grammar, a formatter, a highlighter and an LSP. Editors do not
  know `.ks` on day one; `ks-lsp` today is a pure hover function and grows
  from there, one piece at a time.
- `docs/LANGUAGE.md` is normative for syntax and must be updated with the
  parser, not after it. Where it still records provisional choices, it now
  points here.
- `fmt` is the thing that makes a file canonical, and it does not exist yet.
  Until it does, two files with the same meaning can differ in spelling —
  the parser is defined to accept that, and `fmt` is the answer.
- `out.` is a one-word rule rather than two conventions to remember: statics
  are direct fields, run-time values are namespaced. Nothing about
  `apply.out.` is special-cased to Terraform; any step kind can declare
  run-time outputs.
- Because the language cannot loop, the boundary for real code is the TS
  step. It is a typed boundary — the file declares what goes in and what
  comes out — which is what keeps the escape hatch from eating the whole
  file.