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
{"version":1,"code":"KS0101","severity":"error","file":"ship.ks","subject":"deploy.image","message":"expected oci.Digest, got string","span":{"start":363,"end":372,"line":21,"column":12,"end_line":21,"end_column":21},"labels":[],"hints":["use build.digest so prod runs exactly the image you built"],"fixes":[]}
```

- `file` is the path as printed — relative to the `--all` walk root there.
- `subject` is `null` when the checker does not know the dotted subject.
- `span.start`/`span.end` are 0-based byte offsets; `line`/`column` are
  1-based and count characters (a multi-byte character is one column);
  `end_line`/`end_column` are exclusive — the first position past the span.
  `labels` carry the same span shape plus their message.
- `hints` are the plain strings, unwrapped.
- `fixes` is reserved for machine-applicable fixes and is always `[]` in v1.

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
store, and no environment variables beyond `NO_COLOR` (the colour switch) —
and resolution uses the built-in step catalog. CI proves the no-network part
by running `check` on the fixtures inside a network namespace with no
interfaces (the `offline` job).
