# The Keep Shipping language

A site file is a line-oriented, indentation-scoped `key: value` entry tree.
This document specifies what `ks-lang` parses; `ks-core` decides meaning.
[0003](adr/0003-workflow-syntax.md) accepts this grammar, fixing the output
and operator rules; see [Decisions pending ADRs](#decisions-pending-adrs).

```ks
# deploy the api: image → infra → prod
name:  api
steps:
  deploy:  k8s.rollout
    image: build.digest     # oci.Digest, never a tag
    wait:  healthy, 5m
```

## File name and association

A site file is named `ship.ks`. The extension alone does not identify it:
`.ks` belongs to Red Hat/Fedora Kickstart, so GitHub Linguist and most
editors read a `ship.ks` as Kickstart until something claims the name
itself ([#14](https://github.com/Keep-Shipping/harness/issues/14)).

Association is therefore by file name, never by extension:

- `keepshipping` reads the file at the repository root, or at the path
  given to `--file`. It never scans a directory for `*.ks`.
- Editor grammars, the tree-sitter grammar and Linguist must register
  `ship.ks` and `*.ship.ks`, and nothing else. A grammar that claims
  `*.ks` is wrong: it would take Kickstart files away from the people who
  own them. The per-editor setup is in [EDITORS.md](EDITORS.md).
- Parsing does not depend on the name. Any path given to `--file` is
  parsed the same way; the name selects highlighting and discovery, not
  meaning.

Renaming the file later would change the site, the README and the language
listing together, so the name is fixed here before the editor extension
ships.

## Lexical grammar

```ebnf
file       = { line };
line       = [ indent ] [ content ] newline
           | [ indent ] comment newline;
indent     = { " " | "\t" };            (* tabs are diagnosed, see recovery *)
newline    = "\n" | "\r\n";
comment    = "#" , { any-char-except-newline };
key        = ident , ":" ;              (* colon ends the key *)
ident      = letter | "_" , { letter | digit | "_" | "-" };
word       = word-char , { word-char }; (* a bare scalar, see below *)
string     = '"' , { escaped | any-char-except-quote-newline }, '"' ;
escape     = "\\" , ( '"' | "\\" );
interp     = "{" , dotted-name , "}" ;  (* inside words and strings *)
op         = "==" | "!=" | ">=" | "<=" | "≥" | "≤" | "<" | ">" | "=" ;
keyword    = "and" | "or" | "not" | "is";   (* reserved *)
```

- A `key:` is only recognised at the start of a line's content; its `:` must
  be followed by whitespace, a comment, or the end of the line. Anywhere else
  a colon is an ordinary word character.
- Operators are only operators when whitespace-delimited (`a == b`, not
  `a==b`); `#` only starts a comment at line start or after whitespace, so
  both may appear inside words (`ghcr.io/acme/api:{git.sha}`).
- `and`, `or`, `not`, `is` are reserved and cannot be bare scalars.
- An interpolation name must be a dotted name: `ident {. ident}`. `{}` and
  `{1bad}` are errors; the surrounding word still parses.
- A leading byte-order mark (U+FEFF) is trivia: kept in the tree, ignored by
  the grammar.

## Indentation

- The first entry fixes the root indent; entries may start at any column.
- Siblings must match the previous sibling's indent exactly.
- A deeper line attaches to the nearest open entry: a deeper `key:` line is a
  child entry; a deeper non-`key:` line continues the previous value
  (continuation) or is an error where a child was required.
- A dedent must match an outer level exactly; anything else is an error and
  the line is parsed at the current level.

## Comments

`#` to the end of the line, at line start or after whitespace. Comments are
kept in the tree (the CST is lossless) but carry no meaning.

## Values, expressions and precedence

An entry's value is a tuple with an optional default, parsed by precedence
from loosest to tightest:

```ebnf
value    = tuple , [ "=" , tuple ];        (* `replicas: int = 2` *)
tuple    = expr , { "," , expr };          (* `wait: healthy, 5m` *)
expr     = and  , { "or"  , and  };
and      = not  , { "and" , not  };
not      = "not" , not | compare;
compare  = union , [ cmp-op , union ]
           | union , "is" , union , [ threshold-op , union ];
cmp-op       = "==" | "!=" | ">=" | "<=" | "≥" | "≤" | "<" | ">" ;
threshold-op = "≥" | ">=";
union    = phrase , { "|" , phrase };      (* `low | medium | high` *)
phrase   = atom , { atom };                (* juxtaposition: `deploy staging` *)
atom     = word | string | interp | "(" , [ value ] , ")" ;
```

A continuation line (deeper, not `key:`) splices into the value, so

```ks
auto:    risk is low ≥ 0.95
         and plan.destroys == 0
```

is one expression: `risk is low ≥ 0.95 and plan.destroys == 0`.

### Scalar classes

A bare word is classified, in order: `Bool` (`true`, `false`), `Duration`
(`5m`, `500ms`), `Number` (`0`, `-12.5`), `Handle` (`@platform`,
`@acme/on-call`), `Path` (`./x`, `../x`, `/x`, `~/x`, `.`, `..`),
`DottedName` (`build.digest` — dot-separated idents), `Ident`, else `Text`.
Quoted values are `String`; a word containing an interpolation keeps its raw
parts (`Word::parts()`).

### Block strings

If a value region is exactly `|`, every following line indented deeper than
the key becomes part of a block string, blank lines included. The AST exposes
the raw lines verbatim (`BlockString::raw()`) and the dedented text
(`BlockString::text()`, first non-blank line's indent stripped).

```ks
notes: |
  first line

  second line
```

## Error recovery

Parsing never fails, never panics and always terminates: every byte of the
input lands in exactly one token, `parse(src).syntax().to_string()` is `src`
for any `&str`, and each recovery produces a `Diagnostic` (severity, span,
message, hint) while parsing continues:

- Tab in indentation: error with a hint; the line still parses (a tab counts
  as one character, so `\tb:` is one level deeper).
- `key:` with no value, no block string and no children: ``missing value for
  `key` ``; the entry stays in the tree.
- Deeper line that is not `key:` where an entry was required: ``expected
  `key:` ``; the lines are kept.
- Dedent to an unmatched level: ``indentation doesn't match any outer
  level``; the line is parsed as an entry at the current level.
- Unclosed string or `{`: error at the end of the line; the token is kept.
- A `()` group with nothing inside — closed or not: ``empty `()` ``; a group
  with a value but no closing `)`: ``missing `)```. The paren atom spans
  `(`..`)` either way.
- A value that stops making sense: ``unexpected `x` `` for the first
  leftover token; the rest are kept silently.
- Nesting past a fixed cap (hundreds of nested `(` groups, `not`s or
  indentation levels — deep enough to threaten the stack): ``expression
  nests too deep`` in a value; deeper lines are parsed at the capped block
  level. Every byte is kept either way.

The typed AST normalises the tree for consumers, at every level: a
single-item tuple collapses to its item and a single-atom phrase to that
atom, so `auto:` above is an `and`-expression, not a one-element tuple, and
`show: a, b` has two atoms for items, not two one-atom phrases.

## References and interpolation

A reference is `<step>.<output>[.<field>…]` or a context value. The checker
(`ks-core`) resolves them; the parser only recognises the shape.

**Where a dotted name is a reference.** Always inside `{…}` interpolation and
in the expression inputs (`auto`, `when`, `show`, `else`, `input`). In other
inputs it depends on the input's declared type: a typed input (`oci.Digest`,
`Bool`, `Handle`, …) requires the dotted name to resolve; in a `String`,
`Path` or unchecked position it is a reference only when its first segment
names a step or a context namespace, else it is literal text
(`domain: api.acme.dev`). A step header's kind (`oci.image`) is never a
reference.

**Steps and outputs.** Each kind declares its inputs and outputs (see the
built-in catalog in `ks-core`: `oci.image`, `tofu.plan`, `approval`,
`tofu.apply`, `k8s.rollout`, `decide`); unknown kinds are unchecked, their
outputs type `any`. **`out.` rule**: outputs the kind declares statically are
read as `<step>.<output>`; outputs that exist only at run time (tofu
outputs, script and block returns) are read as `<step>.out.<name>[.<field>…]`
— typed `any`, name not verified. Reading `apply.digest` on a run-time-only
kind is an error pointing at `apply.out.`. Misspelled steps, outputs, context
values and enum answers get a did-you-mean hint.

**Context namespaces.** `git.{sha,ref,branch}`, `git.tag?`, `pr.number?`,
`pr.base?`, `run.{id,actor}`, `run.is_agent`, `env.name`, `ci.provider?`,
`secrets.<name>`, plus `env.<var>` for every variable a declared environment
lists under `vars:`. Values marked `?` are optional: using one warns (it has
no value on a laptop or outside a pull request), and an optional value
compares against its bare type (`git.tag != ""` asks whether the tag is set).
A step may not be named like a namespace.

**Interpolation** is allowed only in `String` and `oci.Tag` positions
(including quoted strings there); elsewhere it is an error, reported once per
value. Interpolating a secret is always an error, and so is `show:`ing one:
pass a secret to an input that takes one — secrets never go into strings or
logs.

**The graph.** Every reference from step T to step S adds the edge S → T;
forward references are fine because order comes from the data, not from
position. An `approval` step that `show:`s outputs of S also gates every
*other* consumer of S, except steps it (transitively) depends on — that is
what turns the hero file into `build → deploy`, `plan → review → apply →
deploy` (plus the direct data edge `plan → apply`). A cycle, self-reference
included, is an error that shows the path: `cycle: review → risk → review`.

**`ci-only:` under a step** marks a step that refuses to run off CI. It is
the one property a step takes that is not an input. Checked with
`--context local` it warns (`KS0602`) that the step will be skipped or fail,
and suggests `--skip <step>` or `--until <earlier step>`; checked with
`--context ci` it is silent. `run` refuses to start a run that would reach
such a step unless `--allow-partial` is passed. This warning covers the step
property; an environment's `ci-only:` is not part of it.

**Ordering without data.** `after:` is a reserved input on every step, like
`when:`. It takes one step name or a list of them, bare or quoted (`after:
review`, `after: "review"`, `after: build, apply`), and adds the edges
`name → this step` — the same edges a reference adds, so a name that does
not exist gets a did-you-mean, `after: <itself>` and a loop report the
cycle, and a value that is not a name at all is a type error rather than an
edge that quietly orders nothing. Nothing else about the file changes: an
`after:` edge carries no data, so it does not make a consumer of what it
names — an `approval` that shows a step gates the steps that *read* that
step's outputs, not the steps that merely follow it. Use it when two steps
must not overlap but neither reads the other's output.

**The order is a function of the file.** Steps are numbered 1..n in a
topological order of those edges, ties broken by position in the file
(declaration order, not the order the edges were discovered). Independent
steps may run in parallel, but a run's sequence numbers, the run log and the
outputs are the same whatever the timing was: a step's records are only
written once every lower-numbered step has finished
([#40](https://github.com/Keep-Shipping/harness/issues/40)).

## Triggers and environments

`on:` is a tuple of `push [<branch-glob>]` | `pr` | `tag [<glob>]` |
`manual`; `schedule` is diagnosed as not supported yet, anything else gets a
did-you-mean. (Which triggers a CI adapter supports is that adapter's
business, checked later.)

`envs:` children are environment names. Each environment takes:

- `secrets:` — the secrets resolver it reads from;
- `ci-only:` — `true` or `false`;
- `approvers:` — handle(s);
- `on:` — the triggers that select this environment;
- `vars:` — child entries, available everywhere as `env.<name>`.

Unknown properties get a did-you-mean. A file without `envs:` has one
implicit environment `default`.

`when: env is prod` is the one non-decision `is` test: `prod` must be a
declared environment.

**When a `when:` is settled.** A condition that reads only context — a
boolean literal, `env is <name>`, `not` over either — is settled before the
run starts: a false one takes the step out of the plan for this environment,
and everything that waits on it. A condition that reads a step's output
(`when: build.signed`) can only be settled once that step has run, so the
plan marks it as settled at run time and the run log says so. Nothing is
guessed: a context-only condition the language has no shape for is treated
as run-time rather than assumed false.

**Selection.** An explicit request wins; otherwise the run's event selects
the unique environment whose `on:` matches (simple `*` globs); otherwise a
single environment is chosen; several candidates are ambiguous and a human
picks. This is `ks_core::select_env`.

## Policy

`policy:` children are subjects: `agents`, `humans` (did-you-mean otherwise).
Each subject takes:

- `can:` / `before:` / `never:` — tuples of actions `<verb> [<env>]`; verbs
  are the action classes: `check`, `build`, `test`, `plan`, `apply`,
  `deploy`, `destroy`, `publish`, `read`. `read` takes the object `secrets`;
  every other verb takes an optional environment, which must be declared.
- `ask:` — handle(s) to ask.

An environment named in a policy action must be declared under `envs:`
(`error: undeclared environment \`prod\``, with a hint to declare it).

When the actor is known (`keepshipping check --actor human|agent|ci`, default
`human`), the policy binds that actor: an `agents: never: read secrets` rule
refuses an agent run that needs any `secrets.<name>` — an error at the
reference (`policy forbids agents from reading secrets, but this run needs
secrets.db_url`) plus a diagnostic on the rule's own line, so the run stops
before it starts. Human, CI and unknown-actor checks are unaffected.

## Types and secrets

Every value has a type, and types never convert implicitly
([#24](https://github.com/Keep-Shipping/harness/issues/24)):

- Primitives: `string`, `int`, `float`, `bool`, `duration`, `path`, `url`;
  composites `list[T]`, `map[T]`, records, `low | medium` enums, `T?`
  optionals. Only `int` → `float` widens; a `string` is never a `path` or a
  digest. An annotation word must spell a real type: an unknown bare word is
  taken as a nominal type name (`web.Cluster`), so a misspelled primitive
  (`itn`) names a nominal type no value satisfies rather than checking as
  the primitive it was meant to be.
- Nominal types (`oci.Digest`, `tofu.PlanFile`, ...) come from step schemas:
  they coerce only to themselves, and a mismatch diagnostic names both types
  (`expected oci.Digest, got oci.Tag`) and suggests a same-workflow output of
  the wanted type (`use build.digest so prod runs exactly the image you
  built`). A well-formed `sha256:…` *literal* where a digest is declared is
  accepted with a warning: pin by reference, not by pasted digest.
- `secrets.<name>` is typed `Secret`
  ([#27](https://github.com/Keep-Shipping/harness/issues/27)). A `Secret`
  flows only into an input declared `Secret`; interpolating one into a word
  or string, or `show:`ing one, is an error — secrets never reach strings or
  logs. Step outputs cannot be `Secret`.
- `keepshipping check --secrets` prints, per environment, every reference
  the run needs as `resolver:key` plus the steps that need it
  (`staging: vault:db_url (migrate)`; `default: (none)` when nothing is
  needed; `[no \`secrets:\` resolver]` when the environment declares none).
  It is a pure projection of the checked file: no resolver is constructed
  and no store is read.
- `keepshipping check --fix` applies the edits the checker is sure of — a
  misspelled input, output or step name, or the output of the wanted type —
  and re-checks. It never edits `policy:`: a policy change needs a human
  ([ADR 0012](adr/0012-policy-authority.md)). See
  [DIAGNOSTICS.md](DIAGNOSTICS.md) for the `fixes` shape in `--format json`.

## Format version and stability

A file declares the format it is written in with an optional header, which
must be its first entry (comments and blank lines above it are fine):

```
keepshipping: 0.1
```

Before 1.0 the format version is spelled `0.N`, so the current format is
`0.1`. A file with no header is read as the latest format this keepshipping
knows — which works, but nobody has written down what the file was written
for, so a CI run warns (`KS0611`) until the header is there. "CI" here is
either `check --actor ci` or a non-empty `CI` environment variable; the
variable only ever widens this advisory warning, because the actor — the
thing policy binds — is never inferred from the environment.

The CLI reads the current format and the one before it. A file on the
previous format still checks, with a warning (`KS0610`) naming
`keepshipping fmt --upgrade`; anything else — a newer format, an older one
this build cannot migrate from, a header that is not a version, a header
that is not first — is an error (`KS0005`) rather than a reinterpretation.

`keepshipping fmt --upgrade <paths...>` rewrites a file mechanically, from
the CST: comments, blank lines and layout survive because every byte the
migration does not name is copied over exactly. It pins the header if there
was none, applies the migration for the format the file declares, and prints
what it could not rewrite instead of guessing at it; when anything is left
over — or a file is refused — it exits 1, having left that file untouched.

Versioning is per thing, not one number: built-in step schemas move with
the CLI, while blocks and third-party steps carry versions of their own
([#79](https://github.com/Keep-Shipping/harness/issues/79)).

Before 1.0 the promise is narrow and stated: a breaking change to the
language — a renamed key, a changed default — bumps the format, and every
bump arrives with a migration and a fixture pair that runs it. Additive
changes (a new key, a new step kind, a new trigger) do not bump it. A bump
is announced in the release notes of the release *before* the one that
breaks anything, and the previous format keeps checking until the format
after next drops it, and for at least 90 days.

## Decisions pending ADRs

The language's design is tracked by the ADRs indexed in `docs/adr/`. ADR
[0003](adr/0003-workflow-syntax.md) accepts this grammar and settles the two
questions it left open; the bullets below that it covers are kept here
unchanged, and the rest are this front end's own choices. Each is easy to
revisit:

- Generic entry tree: no top-level key is reserved; the checker assigns
  meaning (`name`, `steps`, `policy`, ...).
- The root indent is set by the first entry, not fixed at column 0.
- Sibling indentation must match exactly (no alignment tolerance).
- Tabs are diagnosed wherever they appear in indentation, with a `fmt`
  hint; they still count as one indent character.
- Reserved words `and`, `or`, `not`, `is`; comparison operators in ASCII and
  Unicode spellings (`>=` / `≥`, `<=` / `≤`); `=` introduces a default.
- `is` compares with an optional `≥`/`>=` threshold (`risk is low ≥ 0.95`).
- `|` block strings follow YAML's shape and claim every deeper line until a
  line at or above the key's indent.
- Interpolation `{dotted.name}` is allowed inside bare words and strings.
- Tuples are comma-separated; juxtaposition (`deploy staging`) is a phrase,
  `|` a union of alternatives.
- Run-time outputs are namespaced under `<step>.out.`; statically declared
  outputs are read directly (`<step>.<output>`).
- An approval that shows a step's outputs gates every other consumer of that
  step (approval gating adds graph edges). A step that only follows another
  with `after:` is not one of those consumers.
- A file without `envs:` has one implicit environment `default`, so a hero
  file keeps running unchanged.
- `env` as an `is` subject tests the selected environment
  (`when: env is prod`); every other `is` subject is a decision.
- `when:` is a reserved input on every step; its expression must type `Bool`.
- `after:` is reserved too: it names the step(s) that must run before this
  one, ordering without data, and adds exactly the edges a reference would.
- Interpolation is allowed only in `String` and `oci.Tag` positions;
  interpolating a secret is an error everywhere.
- Environment selection order: explicit request → event matches one `on:` →
  single environment → ambiguous, a human picks.
- Policy subjects are `agents` and `humans`; action verbs are the classes
  `check build test plan apply deploy destroy publish read` (#101).
- A site file is `ship.ks` and is found by file name, never by the `.ks`
  extension ([File name and association](#file-name-and-association)).
