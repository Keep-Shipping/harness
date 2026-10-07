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

`run` keeps the same scale: 1 when the file fails the check, 2 for usage and
environment-selection problems. The full list, including the codes a *run*
will add once `run` is wired to the engine (4 waiting for an approval, 5
policy refused, 130 cancelled), is in [CLI.md](CLI.md).

## `fmt --upgrade`

`keepshipping fmt --upgrade [PATH...]` brings each file to the format this
build writes, and is the only thing `fmt` does yet — `fmt` on its own is a
usage error (exit 2), because there is no formatter to run. Each path is a
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
✗ ship.ks:21  deploy.image  expected oci.Digest, got string
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
{"version":1,"code":"KS0101","severity":"error","file":"ship.ks","subject":"deploy.image","message":"expected oci.Digest, got string","span":{"start":363,"end":372,"line":21,"column":12,"end_line":21,"end_column":21},"labels":[],"hints":["use build.digest so prod runs exactly the image you built"],"fixes":[{"span":{"start":369,"end":372,"line":21,"column":18,"end_line":21,"end_column":21},"replacement":"digest","machine_applicable":true}]}
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
::error file=ship.ks,line=21,col=12,endLine=21,endColumn=21,title=KS0101 deploy.image::expected oci.Digest, got string%0Ahint: use build.digest so prod runs exactly the image you built
```

`line`/`col`/`endLine`/`endColumn` follow the JSON rules; warnings are
`::warning`. Escaping follows GitHub's rules: message data escapes `%`,
`\r` and `\n`; property values additionally `:` and `,`. Hints are appended
as `%0Ahint: …`.

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

## What check reads

The check path reads the files it checks and nothing else — no network, no
store, and no environment variables beyond `NO_COLOR` (the colour switch)
and `CI` (which only widens the advisory "no format declared" warning, never
what is enforced) — and resolution uses the built-in step catalog. CI proves
the no-network part by running `check` on the fixtures inside a network
namespace with no interfaces (the `offline` job).

`--fix` is the one exception, and it is the flag's whole purpose: it writes
back the files it checks, and only those. It still opens no socket and
reads no store.
