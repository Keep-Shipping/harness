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
auto: risk is low >= 0.95
      and plan.destroys == 0
```

is one expression: `risk is low ≥ 0.95 and plan.destroys == 0`.

That `0.95` is an example, not a recommendation. No confidence threshold is recommended as safe
until a calibration report for the pinned model version exists — see
[CALIBRATION.md](CALIBRATION.md).

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

## Formatting

`keepshipping fmt` rewrites a `.ks` file into one canonical form. `fmt
--check` reports the same rewrite as a diff and exits 1 without writing; `fmt
-` formats stdin to stdout, for an editor's format-on-save. A file that does
not parse is refused and left untouched — `fmt` never reformats around a
value it does not understand — and a problem with the command line or with
reading a file is a usage error (exit 2).

The formatter rebuilds every line from tokens, so only the whitespace
*between* tokens changes: a string keeps its bytes, and only these are
rewritten.

- Indentation is two spaces per level, from the file's own leftmost entry —
  a fragment indented for a surrounding block keeps its shape.
- A file uses two value columns. Top-level entries share one, as wide as the
  widest of their keys; every entry below them shares a second. Each is
  measured from its own indentation, plus one space.
- Consecutive lines carrying a trailing comment are aligned into one column,
  as far right as the widest of them already reached — at least one space
  separates a comment from its code. A blank line, a comment on a line of its
  own, or a line with no comment ends the run and starts a new one.
- A run of blank lines collapses to one, and no blank line is ever added
  where the author wrote none.
- Tabs in indentation become spaces; they are the one parse error `fmt`
  still fixes, because replacing them is its job. A tab also widens an
  editor's formatting request: a range handed to the language server becomes
  a whole-file edit, because turning a tab into spaces can move the entries
  around it.
- `≥` and `≤` are rewritten as `>=` and `<=`.
- Line endings become LF: a CRLF file is rewritten with plain newlines. A `\r`
  that no `\n` follows is not a line ending here, so one in whitespace or
  indentation is refused, exactly as a parse error is.
- The file ends with exactly one newline.

Formatting twice changes nothing the second time, and the formatter's
output always parses — it re-parses what it built and refuses rather than
handing back source it would not accept. Its output must also carry the same
significant tokens, and the same comments in the same order, as the file it
read; if a rewrite would change either, the result is refused too — declining
to answer is a better answer than dropping a comment.

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
`tofu.apply`, `k8s.rollout`, `decide`, and a TypeScript module's path — see
**Script steps** below); unknown kinds are unchecked, their
outputs type `any`. **`out.` rule**: outputs the kind declares statically are
read as `<step>.<output>`; outputs that exist only at run time (tofu
outputs, script and block returns) are read as `<step>.out.<name>[.<field>…]`.
Reading `apply.digest` on a run-time-only kind is an error pointing at
`apply.out.`. Misspelled steps, outputs, context values and enum answers get
a did-you-mean hint.

**Script steps.** A step whose kind is a relative path to a `.ts` file
(`./ship/migrate.ts`, read against the directory holding the `ship.ks`) is a
script step: the escape hatch for the work the language has no name for. The
path may not reach outside that directory — a `..` component or an absolute
path is an error (KS0101). Its inputs are unchecked for now and its outputs
type `any`, like any unknown kind; both come from the script's own schema
(ADR 0009).

A script step's `action:` says what kind of run it is — one of `build`,
`plan`, `apply`, `deploy`, `destroy`, `read-secrets`, `other`. It defaults to
`other`, and declaring it is what lets an agent run one in `prod` or
`production`: a run of either environment as an agent refuses to start when a
script step declares no `action:` and no `approval` step comes before it.
`action:` is reserved on script steps only; on every other kind it is an
ordinary input.

**Typed IaC outputs.** When the `tofu.plan` a `tofu.apply` applies has a
literal `dir:`, `check` reads the `*.tf` files in that directory (no tofu, no
network) and types `<step>.out.<name>` from what they declare, so a missing
output is a check-time error (KS0203), not a run-time surprise. The type
comes from the first of these:

1. an `outputs:` mapping on the apply step — `cluster: k8s.Cluster`, one name
   to a type per line;
2. a `# keepshipping:type <Type>` comment (or `//`) on the lines above the
   `output` block, or on a line directly inside it;
3. the shape of `value = { … }`: the keys `endpoint`, `ca` and `auth` make a
   `k8s.Cluster` — an API server, its CA and an exec auth method (`eks`,
   `gke`, `aks`), never a credential — and any other object a record of its
   keys.

Anything else is `any`. A `dir:` that is absent, unreadable or holds no `.tf`
files says nothing, and its outputs stay unchecked: `check` never fails for a
file it did not see.

**Script steps.** A step whose *kind* is the path of a TypeScript module —
`migrate: ./ship/migrate.ts` — is a script step, and there is no kind to
register: the kind is the module. `check` reads what that module declares by
importing it with `@keepshipping/sdk` resolved to a bundled stub (no
`npm install`, no network) and taking the `step()` descriptor off the default
export. `run` is never called; the module's body does run, because reaching
the descriptor means importing the module. The declared constructors map to
ks types like this:

| In the module | In ks |
|---|---|
| `int()`, `float()`, `string()`/`String`, `bool()`/`Boolean`, `secret()`, `path()`, `url()`, `duration()` | the same type |
| `list(x)`, `optional(x)` | `list(x)`, `optional(x)` |
| `Number` | an error: `int` and `float` are different types and only the module knows which it meant |
| anything else | an error naming what it was |

A declared output is then read as `<step>.<output>`, typed as the table says,
and one the module does not declare is KS0203 with the module named and a
did-you-mean. A declared output that is not a ks type is an error at the
read, since the declaration is not in this file. Two limits worth knowing:
the module's `inputs:` are extracted but not checked yet, and only a declared
`outputs:` is known — nothing is inferred from the body.

The extraction is cached per site under
`.keepshipping/cache/scripts/<sha256 of the extractor + the module>.json`, so
the second check reads one file and spawns nothing. A module that is not
there, a `node` that cannot be found, and an import that fails all leave the
step's outputs unchecked and say nothing at all: `check` never fails for a
file it did not see, exactly as for an unreadable `dir:` above.

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

**`rollback:` under a step** says what a deploy does when it does not come up
healthy. Like `ci-only:` it is a reserved step property, read with the
declaration rather than as an input a step kind has to declare. It takes one
of three values: `auto` (the default — revert to the last known-good version
without asking), `manual` (stop the run and wait for a human; nothing has
changed yet), and `none` (never revert — the step leaves the failed state as
it is, for a human or for a later step).

It only matters for a step whose action is `deploy`, and only when that step
failed or timed out. A build that fails has nothing to revert, and a deploy
that came up healthy has nothing to undo.

A rollback is its own run-log event, `step.rolled-back`, not a field on
`step.finished`. It carries the policy, the status — `reverted`, `failed`,
`pending` or `unsupported` — and the version traffic actually went back to.
That version is the target's own answer, not what the caller meant to revert
to: a rollback that could not finish records its reason and no version, because
no version was reached. `pending` and `unsupported` are different claims.
`pending` means a person is being asked, under a `manual` policy: nothing has
changed yet and a rollback is outstanding. `unsupported` means the runner has no
rollback facility for that step at all, so it did not try — no version, no
reason, and nobody waiting. The vocabulary is `ks_core::step::RollbackPolicy`
and `ks_core::step::Rollback`.

`rollback:` is specified here and reserved for the executor. `check` carries
the key in its reserved step-property list, so a file that spells it under a
step is no longer refused as an unknown input, and it checks the value against
the three policies above — anything else is a type error (`KS0101`), quoted or
in a list just as much as a word the policies do not name. What it parses it
puts on the step, and the plan carries it from there to the executor: a file
that says `rollback: manual` is run as `manual`.

**A rollback never covers infrastructure.** A failed deploy after a successful
`tofu.apply` does **not** roll the infrastructure back. `tofu.apply` is its
own step: it has its own plan, it carries its own approval, and whatever it
created — a cluster, a bucket, a database — exists once it has returned. A
deploy step that failed cannot know how to reverse any of that, and does not
try: what a deploy reverted is the version it deployed, and infrastructure is
not part of that. Tearing it down on the way out would destroy whatever the
next deploy expects to find, which is a worse failure than the one being
handled.

So say `rollback: none` on the deploy and put the teardown in a separate step
of its own, behind its own `when:` and its own approval — a step whose kind is
whatever your target calls a destroy. The operator then decides when
infrastructure comes down, from a step that says what it does, instead of a
deploy step pretending to undo something it never created.

**Data is not rolled back either.** A database restore rewinds every write
since the snapshot, customers' included, so it is not a thing an automated
path may do. A step that touches data declares `rollback: manual`, which stops
the run and asks rather than reverting; `none` is right when the write itself
cannot be rewound. Either way the run log says what the step declared and what
the harness did about it, and nothing was changed. `manual` records a
`pending` rollback with no version, so a reader can see a human is being
consulted and no code is being reverted; `none` records no rollback at all,
because none was ever begun, and the step's own failure is the whole of the
record. What the log does not yet carry is the restore point itself:
recording where a human can rewind the data to is not implemented, so
the log tells a reader that a restore is outstanding and leaves them to take it
from the target's own tooling.

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

## Blocks

A **block** is a file that declares a named, typed contract other files use
instead of copying its steps. It is a normal `.ks` file with one extra
top-level key:

```ks
# acme/blocks · web-service@v3
block:  web-service
inputs:
  image:    oci.Digest
  domain:   string
  replicas: int = 2
```

Any file uses it as a step:

```ks
steps:
  build:   oci.image
    from:  ./Dockerfile
  deploy:  acme/web-service@v3
    image:  build.digest
    domain: api.acme.dev
```

**Inputs.** Each `inputs:` child is a name and a type; `name: type = value`
gives it a default. A use must spell every input without a default
(`KS0206`, naming the block and the input, with the block's own inputs as the
near misses) and may not spell one the block does not declare. Defaults are
filled in where the use left them out: `replicas` above is `2` whether or not
the use writes it, and the checked workflow records what the run will get.
A value of the wrong type is the same type mismatch any other input has.

**A block file reads its own inputs.** Its internal steps read them as
`inputs.<name>`, and nothing else: `inputs.` is a namespace in block files
only, so no workflow has to give the name up. An input no step or output
reads is what a linter would say to; the checker only refuses the ones that do
not exist.

**Outputs.** A block may declare `outputs:` — a name, a type and the step
output it maps (`ref: oci.Ref = pack.ref`) — checked against the block's own
steps, so an output nothing produces is an error. A use reads them as
`<step>.out.<name>`, exactly as a run-time-only step's outputs.

**A use is checked against the signature alone.** It never sees the steps
inside the block: what it may pass, and what it may read back, is what the
signature says. Signatures are resolved by the caller and injected into
`check` (`ks_core::block::block_signatures`, `CheckOptions::blocks`), keyed
by the use's kind as written — resolving `acme/web-service@v3` to a version
is [#81](https://github.com/Keep-Shipping/harness/issues/81). A use of a
kind nothing resolves is checked like any unknown kind: no inputs, no
outputs. `keepshipping check` resolves the `blocks/*.ks` beside the file it
checks — a file inside `blocks/` sees its siblings — and matches a use by the
name its `block:` declares, so `deploy: web-service` finds
`blocks/web-service.ks`.

**Blocks may use blocks**, and a nest may be four deep
(`ks_core::block::MAX_BLOCK_DEPTH`). A use of another block contributes that
block's actions to its use, so the whole nest is visible to policy: an
`agents: never: deploy prod` rule refuses a `deploy:` that reaches a rollout
to prod three blocks down, exactly as it refuses one written out. A nest
that closes a circle, or reaches past the limit, is reported once with the
path that gets there. A block's steps name their environment with
`when: env is prod`, which is what gives an action its environment.

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
- `vars:` — child entries, available everywhere as `env.<name>`;
- `require-verified:` — `true` or `false`.

Unknown properties get a did-you-mean. A file without `envs:` has one
implicit environment `default`.

`when: env is prod` is the one non-decision `is` test: `prod` must be a
declared environment.

**`require-verified:` makes verification an environment's condition, not a
step's habit.** A deploy step (`k8s.rollout`, `vm.deploy`) says what it ships
must be signed by with a `verify:` input — `verify: "signed-by key:release-key"`,
or `verify: "signed-by <subject> from <issuer>"`. The property means that every
deploy which can reach this environment has to say so:

```
envs:
  dev:
  prod:
    require-verified: true
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: build.digest
    verify: "signed-by key:release-key"
```

A `k8s.rollout` with no `verify:` under such an environment is an error
(`KS0304`), naming both the environment and the step. So is one with
`verify: ""`: the empty string is what a deploy that verifies nothing spells,
and reading it as a request would let a step claim verification by writing
nothing.

**Which deploys it covers.** A step's `when: env is <name>` is what puts it in
an environment; a deploy with no such gate is in scope for *every* environment,
including the ones that demand verification. That is deliberate — the gate is a
declaration of scope, its absence is not an exemption, and treating silence as
one would make the strongest statement in the file also the cheapest to evade
by deleting a line. A deploy that really belongs elsewhere says so:
`when: env is dev` puts it out of scope for `prod`, visibly.

A block use is judged as the use: it carries the actions of the steps inside it,
so a use that reaches a deploy inherits the deploy's obligation, and `verify:`
passed to it (or defaulted by its signature) is what satisfies it. Report it
against the use's name.

`require-verified:` is a pre-flight check on the client, not a control on the
cluster: it refuses the workflow, not a deployment made by somebody else. See
[DEPLOY_VERIFICATION.md](DEPLOY_VERIFICATION.md) for what it does not cover and
how to mirror the same rule cluster-side with Kyverno or Sigstore.

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

- `can:` / `before:` / `never:` — tuples of actions `<verb> [<object>]`. `can:`
  allows the action outright, `before:` asks the subject's `ask:` handles first,
  `never:` refuses it. Verbs are the action classes: `check`, `build`, `test`,
  `plan`, `apply`, `deploy`, `destroy`, `publish`, `read`, `run`. `read` takes
  exactly `secrets`, `run` exactly `scripts`, `publish` `blocks` or an
  environment; every other verb takes an optional environment, and a verb naming
  no object binds every environment.
- `ask:` — handle(s) to ask. Part of what a `before:` rule means, so "ask" with
  nobody named is still an ask.

An environment named in a policy action must be declared under `envs:`
(`error: undeclared environment \`prod\``, with a hint to declare it).

**An action class is what a step kind does.** `oci.image`/`oci.artifact` build, `tofu.plan` plans,
`tofu.apply` applies, `k8s.rollout` deploys; everything else — `approval`, `decide`, any
unclassified kind — is outside the vocabulary and so not governed. **`destroy` is read from the
plan, not the header**: an apply whose plan destroys anything, a replacement included, *is* a
destroy.

**Humans follow the same file, minus the leash.** An agent reads `agents:`, and anything it does not
name is an **ask** — an allowlist that defaults to allow is not one. A human (or a CI run) reads
`humans:`, and an action that section does not name is allowed.

**A `never:` rule refuses at check time**, for whichever actor is being checked
(`keepshipping check --actor human|agent|ci`, default `human`): every step it covers is refused where
the step is declared, plus a diagnostic on the rule's own line. An `ask` is not an error — an
approval is a thing the run does. A rule naming an environment decides only that environment, so
`never: deploy prod` never refuses every deploy; `keepshipping policy explain` shows it per env.

**A rule for an action nothing does is a warning** (`KS0404`): a `can:` or `before:` rule no step can
produce binds nothing. Only verbs a step kind *can* produce are warned about (`destroy` once any
apply step exists, `read secrets` once the file references a secret); a verb no step kind produces
yet is vocabulary ahead of the step kinds. `never:` is never warned about.

**The effective policy is the baseline ∩ the default branch ∩ this file**
([ADR 0012](adr/0012-policy-authority.md)): a file may only narrow. The org baseline lives outside the
repository (`ports::policy::PolicyStore`, no adapter yet), so where they disagree the stricter answer
wins and the answer records which document it came from. **No baseline configured means the effective
policy is this file's own** — a first-class state, not an error. One hard rule sits outside the
intersection: **destroy never reaches an agent as an allow**.

**The default branch's copy of this file is part of the intersection** — an agent on a branch edits
the policy that constrains it, so the branch's `policy:` block is a proposal and the block `main` has
is the authority. Where the two disagree the stricter answer wins, and where they agree the file's own
rule is the one that is reported, because the run is reading this file. `keepshipping policy explain`
names the base it folded in; `--base REF` (or `$KEEPSHIPPING_BASE`, or the first of
`origin/$GITHUB_BASE_REF`, `origin/HEAD`, `origin/main`, `main`, `master` that resolves) says which
one. A base that resolves but has no copy of the file contributes an empty policy — a widening
nothing takes effect. A widening only takes effect once it is merged. Silence on the default branch
is a decision too: a branch that `can:`s something the default branch says nothing about has proposed
something nobody reviewed, so it is still an ask.

**The base is only as trustworthy as whoever names it.** `--base` and `$KEEPSHIPPING_BASE` decide
which document is the authority, so they belong to the CI workflow running the change, not to the
command line an agent writes for itself — an agent that may pass `--base HEAD` may choose its own
policy.

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

```ks
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
- The root indent is set by the first entry, not fixed at column 0; `fmt`
  keeps it ([Formatting](#formatting)).
- Sibling indentation must match exactly (no alignment tolerance); `fmt`
  writes the canonical two-space-per-level form.
- Tabs are diagnosed wherever they appear in indentation, with a `fmt`
  hint; they still count as one indent character, and `fmt` replaces them
  with spaces.
- Reserved words `and`, `or`, `not`, `is`; comparison operators in ASCII and
  Unicode spellings (`>=` / `≥`, `<=` / `≤`); `=` introduces a default.
- `is` compares with an optional `≥`/`>=` threshold (`risk is low ≥ 0.95` — an example; see
  [CALIBRATION.md](CALIBRATION.md) before treating any threshold as safe).
- `|` block strings follow YAML's shape and claim every deeper line until a
  line at or above the key's indent.
- Interpolation `{dotted.name}` is allowed inside bare words and strings.
- Tuples are comma-separated; juxtaposition (`deploy staging`) is a phrase,
  `|` a union of alternatives.
- Run-time outputs are namespaced under `<step>.out.`; statically declared
  outputs are read directly (`<step>.<output>`).
- A `tofu.apply` step's `out.` names are typed from what the `.tf` files
  behind its plan's `dir:` declare: an `outputs:` mapping on the step, else a
  `# keepshipping:type <Type>` comment in the `.tf`, else the shape of an
  object value. A directory `check` cannot read types nothing (#70).
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
