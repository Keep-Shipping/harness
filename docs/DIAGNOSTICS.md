# Diagnostics: output formats, exit codes, colour

`keepshipping check` reports every problem it finds and never runs a step.
Every finding carries a stable `KSxxxx` code — what each one means lives in
[ERRORS.md](ERRORS.md); this file pins how findings are printed.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | the file checks clean — warnings alone still pass |
| 1 | the check found errors, or warnings with `--warnings-as-errors` |
| 2 | usage: an unknown flag or format, a missing value, a file that cannot be checked (missing, a directory, not UTF-8, permission denied), or no `ship.ks` to check |
| 3 | internal: an unexpected I/O error, or a panic — a bug in keepshipping, never in your file |

`run` keeps the same scale: 1 when the file fails the check, when a step
fails, or when an approval is declined; 2 for usage and environment-selection
problems. The full list, including the codes a *run* will add once `run` is
wired to the engine (4 waiting for an approval, 5 policy refused, 130
cancelled), is in [CLI.md](CLI.md).

## `fmt --upgrade`

`keepshipping fmt --upgrade [PATH...]` brings each file to the format this
build writes. `fmt` on its own lays files out canonically instead (see
[LANGUAGE.md](LANGUAGE.md)); `--upgrade` with `--check` or `-` is a usage
error (exit 2), because an upgrade always rewrites in place. Each path is a
file or a directory to walk for `ship.ks`, on the same terms `check --all`
walks; no path at all means `ship.ks` in the working directory.

```
$ keepshipping fmt --upgrade ship.ks
pinned ship.ks: keepshipping 0.1
$ keepshipping fmt --upgrade ship.ks
unchanged ship.ks: 0.1
```

- One line per file on stdout: `pinned {path}: keepshipping {version}` when
  the header was inserted, `upgraded {path}: {from} → {to}` when a migration
  moved it, `unchanged {path}: {version}` when neither applied — in which
  case nothing was written.
- What a migration could not rewrite is printed as `⚠ {path}:{line}  {message}`
  for a person to finish, and a file this build cannot migrate from as
  `error: {path}:{line}  {message}` on stderr. Both exit 1, and neither file
  is written: a refusal is the run's result, not something to work around.
- A file that cannot be read or written is exit 2, as in `check`.
- Exit 0 when every file is done. The rewrite is its own inverse: a second
  run writes the same bytes again.

Diagnostics in a file are sorted by position; with `--all`, files are sorted
by path.

## `--format human` (default)

```
✗ ship.ks:21  deploy.image  expected oci.Digest, got oci.Tag
  │
21 │     image: build.tag
  │            ^^^^^^^^^
  hint: use build.digest so prod runs
        exactly the image you built
0 steps ran. Nothing was touched.
```

- Header `✗ {path}:{line}  {subject}  {message}` — two spaces between the
  parts; the subject is omitted when the checker does not know it; warnings
  use `⚠`. A file that passes prints `✓ {path}`.
- The snippet shows the offending line with `^` under the span; a multi-line
  span underlines its first line. Secondary labels follow with `-` and their
  message under the place they point at.
- Hints word-wrap so no line exceeds 40 columns, the `  hint: ` prefix and
  the 8-space continuation indent counting towards the budget alike. A word
  longer than the budget gets a line of its own — words are never broken.
- The footer `0 steps ran. Nothing was touched.` closes every `check`
  report: checking reads the file and nothing else. With `--secrets` the
  listing is printed for the file's environments — still a pure projection,
  no store is ever read.

Human output goes to stdout; usage and internal errors go to stderr.

## `--format json` (JSON Lines, schema v1)

One self-contained object per diagnostic, one per line, stable key order,
nothing else on stdout — no footer, no listing:

```json
{"version":1,"code":"KS0101","severity":"error","file":"ship.ks","subject":"deploy.image","message":"expected oci.Digest, got oci.Tag","span":{"start":363,"end":372,"line":21,"column":12,"end_line":21,"end_column":21},"labels":[],"hints":["use build.digest so prod runs exactly the image you built"],"fixes":[{"span":{"start":369,"end":372,"line":21,"column":18,"end_line":21,"end_column":21},"replacement":"digest","machine_applicable":true}]}
```

- `file` is the path as printed — relative to the `--all` walk root there.
- `subject` is `null` when the checker does not know the dotted subject.
- `span.start`/`span.end` are 0-based byte offsets; `line`/`column` are
  1-based and count characters (a multi-byte character is one column);
  `end_line`/`end_column` are exclusive — the first position past the span.
  `labels` carry the same span shape plus their message.
- `hints` are the plain strings, unwrapped.
- `fixes` are the suggested edits, in the order they apply: a `span` in the
  encoding above naming the bytes to replace, the `replacement` to put
  there, and `machine_applicable` — whether the suggestion is unambiguous
  enough for a tool to apply without asking. A fix rewrites the smallest
  span that is wrong: the output segment of `build.tag`, not the whole
  reference. Populating `fixes` does not change the schema version; the key
  was reserved for it and no other key moves.

## `--fix`

`keepshipping check --fix` applies exactly the fixes marked
`machine_applicable`, writes the file, and re-checks it. The re-check alone
decides the exit code and the report; an applied edit is never rolled back
if it turns out to surface a new diagnostic — that diagnostic is simply the
next finding. `--fix` writes files, so it says what it did on stderr,
leaving stdout to the report: `{path}: applied N fixes`, and for every edit
it held back `{path}: N fixes inside \`policy:\` need a human and were not
applied` or `{path}: N fixes overlapped an edit already applied and were
not applied`.

Two kinds of edit are never applied. An edit whose span overlaps another
already applied, because the first would move the bytes the second names.
And any edit inside a `policy:` entry: whether a run may do something is a
human's decision, not a spelling the machine gets to settle ([ADR
0012](adr/0012-policy-authority.md)). A held-back edit stays in the
re-check output as the diagnostic it came from, hint and fix intact.

## `--format github`

GitHub Actions workflow commands, one annotation per diagnostic, so findings
show up on the pull request:

```
::error file=ship.ks,line=21,col=12,endLine=21,endColumn=21,title=KS0101 deploy.image::expected oci.Digest, got oci.Tag%0Ahint: use build.digest so prod runs exactly the image you built
```

`line`/`col`/`endLine`/`endColumn` follow the JSON rules; warnings are
`::warning`. Escaping follows GitHub's rules: message data escapes `%`,
`\r` and `\n`; property values additionally `:` and `,`. Hints are appended
as `%0Ahint: …`.

## `run`

`keepshipping run` picks an environment and then runs the steps the file
declares, one line per step:

```
▸ build   sha256:9f2c…e1  signed    38s
▸ plan    +2 ~1 -0                  11s
▸ review  approve 3 changes? y
▸ apply   3 resources               42s
▸ deploy  4/4 pods healthy          27s
✓ shipped api@a41c9e in 2m 18s
```

- A step line is `▸ {step:<8}{summary:<25} {duration}`; widths count
  characters, so a `…` in a summary is one column, and a summary past its
  column is cut with an `…` rather than pushing the time out of line. A
  duration is `38s` under a minute and `2m 18s` from a minute on, in whole
  seconds.
- The closing line is `✓ shipped {what} in {duration}`, where `what` is the
  workflow's `name:` or, for a file that declares none, its name without the
  extension.
- An approval writes its question on the step's own line and waits for `y` or
  `yes`. The approver's name, from `$USER` or `$USERNAME` and falling back to
  `local`, is carried on the run's answer for the run log to record. A
  declined approval writes `✗ declined at {step}` and nothing after it runs.
  A run with nobody to ask — a pipe, `--non-interactive`, CI, a closed
  stdin — always declines, and writes the answer itself so the prompt is not
  left open.
- A failing step writes `✗ {step:<8}{error}` and the run stops there.

One renderer reads the events, and the same lines come out either way. At a
terminal, the step in flight gets a spinner and a running clock, redrawn in
place and replaced by its summary and its real duration. Anywhere else — a
pipe, a CI log, `TERM=dumb` — the same lines are written once each, with no
escape codes and no cursor movement. `-v` adds each step's own output,
indented four spaces; the default shows summaries only. The plain stream
writes the approval's answer itself, since input is not echoed into a log, so
a captured run reads like a terminal's.

| Flag | Meaning |
|---|---|
| `--until STEP` | run `STEP` and everything it depends on |
| `--only STEP` | run `STEP` and the steps it depends on; repeatable |
| `--skip STEP` | drop `STEP` and everything downstream of it; repeatable |
| `--input KEY=VALUE` | hand the steps this run takes an explicit input; repeatable |
| `--dry-run` | graph the run and check it; run nothing |
| `-v` | stream each step's own output |

`--skip` takes the consumers with the step: skipping an approval can never
leave a step running on a plan nobody approved. `--only` is the flag that
could, so it refuses. Naming a step whose dependency you left out exits 2,
naming the missing step and the way through: `apply` waits on approval
`review`; use --until apply`, or `deploy` needs `build`; use --until deploy`
where there is no approval in the way. An unknown step name exits 2 naming
it, and a selection nothing is left of (`--only plan --skip plan`) exits 2
with `nothing left to run` rather than shipping a run of no steps.

`--dry-run` prints one `▸ {step:<8}{kind}` line per selected step in
topological order, closes with the same `0 steps ran. Nothing was touched.`
footer `check` uses, and exits 0. Given `--input`, an `inputs:` block
follows the graph and comes before that footer — one
`  input {key} = {value}` line per override, last-write-wins per key, and a
`@secret:` value printed as `  input {key} = @secret:{reference} (reference)`
so it cannot read as a value that was read. Without `--input` there is no
block and the output is exactly what it was before the flag existed:

```
environment: default
▸ build   oci.image
inputs:
  input db = @secret:dev-db (reference)
0 steps ran. Nothing was touched.
```

`KEY=VALUE` is the whole grammar: the key ends at the first `=`, so a value
may contain more of them; a repeated key is an override and the last one
wins; a value that begins `@secret:` is a reference to a secret rather than
one, and nothing resolves it, because nothing does yet. A malformed pair is
a usage error before the run starts, each naming the way out — and each
refusing what would forge or blur a line of the report, which is
line-oriented: a `\n` or `\r` in a key or a value, and whitespace at
either end of either. Interior whitespace is left to the value, so
`--input "message=two words"` is a value; a key is one name and takes no
whitespace at all. An empty value is a value — `--input tag=` hands a step
an empty string, which it can act on — where `@secret:` with nothing after
it names nothing and is refused.

The flag is inert outside `--dry-run` today: a run checks every pair, and no
step is handed one yet. Unit-testing a script step with hand-picked inputs
and no real secrets is the SDK's `@keepshipping/sdk/testing` helper
([sdk/ts/README.md](../sdk/ts/README.md)).

No step kind is executable yet, so a run stops on its first step with
`` `{kind}` steps are not built in yet `` and exits 1. Nothing is built and
nothing is touched until the engine has steps.

## Colour

Human output is coloured only when stdout is a terminal and `NO_COLOR` is
unset or empty — any non-empty value disables colour, per
[no-color.org](https://no-color.org). Errors: bold red `✗` and carets;
warnings: yellow; gutter and `hint:`: blue and cyan. The `json` and
`github` formats are never coloured.

## `--all`

Walks the current directory — or the directory named — for every `ship.ks`,
skipping hidden directories, `target` and `node_modules`; checks each; prints
paths relative to the walk root; prints the footer once; and exits with the
worst result across files. No `ship.ks` anywhere is a usage error (exit 2).

## `--repro`

Reads the Dockerfiles an `oci.image` step names through its `from:`, resolved
beside the site file, and warns (KS0801) about the inputs that can move
between two builds: a base image without a `@sha256:` digest, an `apt` index
read without a snapshot, an `ADD` of a URL without `--checksum=`. The
findings are reported against the Dockerfile, with its own path and source,
in whichever format was chosen — so snippets and annotations point at the
lines of the file that actually carries the defect.

Without the flag the Dockerfiles are never opened and the check reads the
site file alone. A `from:` naming a file that cannot be read is a warning in
its own right, reported against the `from:` itself. What each rule counts as
pinned is written out in
[REPRODUCIBILITY.md](REPRODUCIBILITY.md#checking-a-dockerfile-today).

## What check reads

The check path reads the files it checks and nothing else — no network, no
store, and no environment variables beyond `NO_COLOR` (the colour switch)
and `CI` (which only widens the advisory "no format declared" warning, never
what is enforced) — and resolution uses the built-in step catalog. `--repro`
widens "the files it checks" to the Dockerfiles those site files name, and
opens nothing else. CI proves the no-network part by running `check` on the
fixtures inside a network
namespace with no interfaces (the `offline` job).

`--fix` is the one exception, and it is the flag's whole purpose: it writes
back the files it checks, and only those. It still opens no socket and
reads no store.

## `keepshipping log`

`keepshipping log [RUN-ID]` prints a run's events, one line per entry —
`HH:MM:SS  type  field=value …`, with the time in UTC:

```
22:13:20  run.started  actor=ci  file_hash=sha256:aa  is_agent=false  trigger=push main
22:13:20  step.started  step=build
22:13:20  step.finished  duration_ms=1.2s  ok=true  outputs=digest  step=build
22:13:20  approval.requested  artifacts=sha256:bb  channel=github  step=deploy
22:13:20  run.finished  shipped=sha256:cc  status=shipped
```

With no run id the most recent run under `.keepshipping/runs/` is printed — a
ULID sorts by time, so the newest is simply the last.

`--format json` prints the entries as stored, byte for byte: a tool that
re-checks the chain hashes exactly those lines. `github` is rejected — an entry
has no source span to annotate. Printing never verifies, so a log that was
edited still prints and can be read.

`keepshipping log verify [RUN-ID]` checks the chain offline and prints
`ok: N entries, chain intact`, or, at the first entry that does not hold,
`<path>:<line>: chain broken: <reason>` on stderr and exit 1. Editing a field,
deleting an entry and reordering two are caught, because every entry names the
hash of the one before it. Truncating entries off the end is not — a prefix of
a good chain is still a good chain, and telling that from a run that genuinely
ended needs a signature over the tip ([#112]). It needs nothing but the file — no
network, no store — so a CI job can fetch the log as an artifact and verify it
there.

## `keepshipping graph`

`keepshipping graph [FILE] [--env NAME] [--event "push main"]` prints the
plan — the steps in sequence order with their dependencies, what this
environment would skip and why — and runs nothing. It reads the file exactly
as `check` does, so the exit codes are the same: 1 when the file has errors,
2 for usage, environment-selection and event problems, 0 otherwise. The
diagnostics are `check`'s, in the human format: on stdout for `text`, and on
stderr for the machine formats, which leave stdout parseable. Its `--format`
names the plan, not a diagnostic, so they are its own:

```
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

- `text` (the default) is the report above. `gate` is `run`, `skip: …` with
  the reason the step is out for this environment, or
  `when: … (at run time)` for a condition only the run can settle. The route
  line is the event the plan is for — `--event` if one was given, otherwise
  the file's triggers joined by `|` because they are alternatives, not a
  chain — and then the steps that would run, in sequence order. A file that
  declares no `on:` has no event to lead with, so the line is the steps
  alone.
- `dot` is a `digraph` with one node per step (numbered, dashed when skipped)
  and one edge per dependency, for Graphviz.
- `json` is the same plan with a stable key order — `version`, `file`,
  `env`, `triggers`, and `steps` (`seq`, `name`, `kind`, `deps`, `gate`) —
  and nothing else on stdout, no footer. The dependencies are on the steps;
  there is no second copy of them.

An unknown `--format` value is a usage error (exit 2), for `graph` and
`check` alike: `check --format dot` is not a thing. So is an `--event` no
`on:` in the file reaches: a route no trigger can enter is not a plan, and
`graph` says which triggers the file declares instead of printing one.

