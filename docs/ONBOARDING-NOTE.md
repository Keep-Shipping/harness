# Onboarding note: [GETTING_STARTED.md](GETTING_STARTED.md)

The record behind the acceptance criterion on
[#140](https://github.com/Keep-Shipping/harness/issues/140) — "someone who hasn't seen the
project completes it without help".

## Who walked it

**An agent did. No human has.** Every `$`-prompt transcript in the guide was captured by running
the real binary from a clean shell against a copy of `examples/example-api/`, but the agent had
the repository open, knew where to look, and had every fact it needed handed to it. **The
criterion is not yet met** — it is met by a scripted dry run of the walkthrough, not by a
first-timer finishing it. Treat every duration below as an estimate until someone unassisted has
done it.

What that means concretely: the agent could not be surprised by anything, so it could not
measure comprehension, and it could not answer the questions in the last section. It could only
record which facts the walkthrough needed and whether the text supplied them.

**The guide's approval section is the exception, and it is labelled as such in the guide itself.**
Those commands are quoted from [CLI.md](CLI.md), not captured — see stuck point 8. An earlier
draft of the guide did not say so: it presented the `approve` / `deny` / `resume` blocks as
captured transcripts under a blanket "every transcript below was captured from the real binary"
claim, and an auditor checking that claim against a real binary would find it false. The header
now states the actual basis, and the approval section leads with the reason it cannot show
output.

## The walkthrough, step by step

Measured figures are the agent's own runs. Estimated figures are for a human reading and typing
each command for the first time, and are **not** measured.

| Step | What the reader does | Expected output | Exit | Time |
|---|---|---|---|---|
| Install (source) | `cargo build --release -p ks-cli --bin keepshipping` | `target/release/keepshipping` exists | 0 | ~30 s warm, several minutes cold — **measured** |
| Install (archive) | download `keepshipping-<v>-<target>.tar.xz`, verify `SHA256SUMS`, untar | `sha256sum: keepshipping-…: OK` | 0 | ~1 min — **measured** for the commands, not for a reader's network |
| Read the example | open `examples/example-api/ship.ks` | 32 lines, five steps | — | 2 min — **estimated** |
| 1. Check | `keepshipping check` | `✓ ship.ks` / `0 steps ran. Nothing was touched.` | 0 | <1 s — **measured** |
| 2. Break it | edit line 24 to `build.tag`, then `keepshipping check` | `✗ ship.ks:24 deploy.image expected oci.Digest, got oci.Tag` | 1 | 30 s — **estimated** (the reading of the diagnostic, not the run) |
| 2. Fix it | `keepshipping check --fix` | `ship.ks: applied 1 fix` / `✓ ship.ks` | 0 | <1 s — **measured** |
| 3. Plan | `keepshipping graph --format text` | the 5-step table and the route line | 0 | <1 s — **measured** |
| 4. Dry run | `keepshipping run --dry-run` | 5 `▸` lines | 0 | <1 s — **measured** |
| 4. Run it | `keepshipping run` | `✗ build \`oci.image\` steps are not built in yet` | 1 | <1 s — **measured** |
| 5. Policy | `keepshipping policy explain --as agent`, then `--as human` | two decision tables | 0 | <1 s each — **measured** |
| 6. CI | read `ship.yml`, adapt it | — | — | 10–20 min — **estimated**, and untested end to end |
| 7. Approvals | read; only `runs pending` can execute | `nothing is waiting for approval` | 0 | 5 min — **estimated** |

Total for a reader who builds from source and stops at Step 5: **roughly ten minutes**, of which
the build is most. That figure is an estimate built from measured command times plus estimated
reading time; it has not been observed on a human.

## Where a reader would get stuck

Every one of these is a fact that was **not written down anywhere in the repository** and that
the walkthrough had to be told. Each is now in the guide; the list is the debt.

1. **The binary is `keepshipping`; the crates are `ks-*`.** Every build instruction in the repo
   and its issues says `-p ks-cli`. A reader who greps for the crate name installs nothing.
2. **There is no `cargo install`.** `publish = false`, nothing on crates.io (ADR 0014). The
   obvious first command is wrong, and fails in a way that looks like a missing toolchain.
3. **There is no `--help`.** `--help`, `-h`, `help` and no arguments all print the usage block
   and exit 2. A reader types `--help`, sees exit 2, and reasonably concludes the binary is
   broken. The usage block is the only in-binary documentation and it is undocumented as such.
4. **`graph` takes no file argument**, despite `graph [FILE]` in the usage string. `keepshipping
   graph ship.ks` prints the usage block and exits 2. The guide uses the cwd form only; the
   usage string still advertises a form that does not work.
5. **`run` does not run.** `run --dry-run` works, so a reader who trusts the dry run reasonably
   expects the real one to work, and meets "not built in yet" at exit 1. This is the single
   biggest surprise in the walkthrough, and it is the reason the guide's title promises a
   *checked* file rather than a *shipped* one.
6. **There is no packaged GitHub Action.** Nothing with an `action.yml` is published, so
   `uses: Keep-Shipping/...` — the first thing anyone would write — does not exist. The example
   workflow downloads the release tarball, and says so in a comment, but the comment is the only
   place that fact lives.
7. **A diagnostic's line number is your file's line number.** The KS0101 the guide teaches
   reports `ship.ks:24` because `deploy.image` is on line 24 of *the example*. A reader's own
   file puts it somewhere else. A first-timer could conclude the checker is pointing at the
   wrong line.
8. **`keepshipping approve <id>` exits 2 from a fresh clone.** With no parked record — which is
   every record a reader can have today — `approve` and `deny` both print
   `error: run <id> has no parked state` and exit 2, for any id, including a well-formed ULID.
   **The `approved <id> at <step> as local` line could not be produced by any of the commands in
   this walkthrough**, and an earlier draft of the guide claimed otherwise: it showed that line,
   and a `deny` line, and a `resume` refusal, inside `$`-prompt blocks under a claim that every
   transcript had been captured. The run id in those blocks was 25 characters where
   `RunId::parse` requires 26, so every one of them was a usage error at exit 2, not the output
   shown; the `deny` line also named `apply` for a run `approve` had just cleared the park on.
   The guide now quotes [CLI.md](CLI.md) for this section, marks it as documented rather than
   demonstrated, and states why before it shows anything. A reader who tries `approve` today
   still gets an error that does not obviously mean "no run is parked" — that part is unchanged
   and is still worth a fix.
9. **The release archive unpacks one directory deep.** It extracts to
   `dist/keepshipping-<version>/keepshipping`, beside the `LICENSE` and `README.md` that travel
   with it, so `./dist/keepshipping` — what the install section said to run — does not exist.
   The install section now globs for the binary instead of hardcoding a path or a version
   string. The example CI workflow got this right already: it extracted into `dist` and put
   `dist/keepshipping-<version>` — the **directory** — on `$GITHUB_PATH`, which is what that
   variable takes. Putting the *binary's* path there would have been the bug; the comments
   around the line now say so, because the directory/executable mix-up reads as a bug until you
   have checked it. Both the install block and the workflow's install step were run verbatim
   against an archive with the real layout.

Three things the agent's own instructions turned out to be wrong about, recorded so the next
person does not repeat them: the KS0101 in the example is at **line 24, column 13**, not line 22;
no command in the walkthrough emits a `CI`-related warning, so the `env -u CI` prefix some
capture instructions used was unnecessary — with `CI=true` set, every output was byte-identical;
and the `runs pending` row format is `{run}  {step:<12}  {where_to}` (`approve.rs`), which puts
**eight** spaces after a six-character step name like `review`. The row an earlier draft showed
had eight, which was right, but it was presented as a captured line from a run that was never
parked — so it has been replaced by the format itself, which is the only honest form available.

## What a real first-timer should be asked

For [#155](https://github.com/Keep-Shipping/harness/issues/155) — *time it with early-access
users*. None of this is answerable without a person:

- How long from opening the guide to the first `✓ ship.ks`, and where did they stop?
- When they hit `✗ build \`oci.image\` steps are not built in yet`, what did they think the
  project *is*? Did the sentence "no step kind is executable yet" land as a plan, or as a
  broken promise?
- Did they read the KS0101 diagnostic as "the type of the value was wrong, here is where, here is
  what to do instead" — or did they read the hint and skip the subject and the span?
- Did the `deps` and `gate` columns in `graph` mean anything without being told? They are the
  difference between a list of steps and a plan.
- Where did they go looking for `--help`, and what did they conclude when they found a usage
  block instead?
- Could they write their own CI workflow from Step 6 without copying the example verbatim? That
  is the real test of whether the section earns its place.
- Which of the nine stuck points above did they hit, and how long did each cost?
- Did anything in the guide read as a hedge — a "coming soon" where a fact was wanted?

## See also

- [GETTING_STARTED.md](GETTING_STARTED.md) — the walkthrough this note records
- [CLI.md](CLI.md) — exit codes, parking and resuming
- [#140](https://github.com/Keep-Shipping/harness/issues/140) — the guide, and this criterion
- [#155](https://github.com/Keep-Shipping/harness/issues/155) — timing it with real users