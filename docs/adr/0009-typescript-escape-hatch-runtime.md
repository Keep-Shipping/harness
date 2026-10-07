# ADR 0009: TypeScript escape-hatch runtime

Status: accepted, 2026-10-06

## Context
Steps that need a loop, a library or a one-off API call are TypeScript
scripts a repository ships beside its `ship.ks`
([ADR 0003](0003-workflow-syntax.md)). Issue
[#10](https://github.com/Keep-Shipping/harness/issues/10) asks what runs them,
under constraints the earlier decisions have already set: such steps run in a
separate runtime behind the `ScriptHost` port, not in-process, so
`keepshipping` stays one static binary
([ADR 0013](0013-rust-workspace.md)); the runtime is one adapter crate under
`adapters/`, not a core dependency
([ADR 0002](0002-ports-and-adapters.md)); `check` is budgeted at cold 1 s and
warm p95 100 ms and CI fails a blown budget (`crates/cli/benches/check.rs`);
and CI runs `keepshipping check` under `unshare --net`
(`.github/workflows/ci.yml`), so checking a workflow cannot need the network.

The port is already written and tested:
`crates/core/src/ports/script_host.rs` defines `schema(&ScriptRef)` returning a
`Result<StepSchema, ScriptHostError>` without running the script, which is what
`check` inspects, and `run(&ScriptRef, &Values, &SecretBundle)` returning a
`Result<Values, ScriptHostError>` — both async, with secrets travelling on a
dedicated file descriptor and never in argv, the environment or stdio.
`ks-testing` ships the fake and the conformance kit
(`crates/testing/src/script_host.rs`) and the adapter has to pass it.
`StepSchema` has no secret kind: a gap this ADR records, not one it closes.

### Spike
Deno 2.9.7 (V8 15.0.245.2), measured 2026-10-06 on 6 vCPU AMD EPYC, Linux
x86_64, 10 reps, median/p90. The extractor loads `npm:typescript@5.9.3`
through the compiler API, builds a program for the step file and reads types
only — `inputs` off the default export's `step({...})` type, `outputs` off
`run`'s return type with `Promise` unwrapped. It never executes the step and
never sees a secret.

| | median | p90 |
| --- | --- | --- |
| cold first run (empty `DENO_DIR`, npm download) | 1656 ms | |
| **warm extraction, fresh process per call** | **127.5 ms** | **137.1 ms** |
| same, full TypeScript lib instead of the minimal one | 338.7 ms | 354.8 ms |
| `deno compile`d extractor (128 MB binary) | 101.5 ms | 107.1 ms |
| run side (import step, stdin, fd secret, JSON lines) | 17.7 ms | |
| process floor (`deno run` of an empty script) | 12.5 ms | |
| long-lived daemon holding the program | 0.37 ms unchanged file, ~8 ms after an edit | |

The budget this decision needed was under 200 ms warm; 127.5 ms meets it, and
the dominant win was the minimal `noLib` declaration file, not a compiled
binary. Full diagnostics cost about 12 ms more.

The spike also settled three things the decision depends on. Extraction is
type-directed: the site example yields
`{"inputs":{"db":{"kind":"secret"}},"outputs":{"applied":{"type":"number"}}}`,
widening the return to `{applied: 3, skipped: 0}` adds `skipped: number`, and
returning `"3"` yields `string`. A step with a type error still extracts, but
the poisoned field degrades to `any`, so diagnostics must be collected and an
errored schema treated as untrusted. Permissions are the reason Deno wins: the
host runs with `--allow-read` for the workspace and `/proc/self/fd/3`, no env
and no net, and under it `Deno.env.get` and `fetch` throw `NotCapable`; the
extractor additionally needs read and the `TSC_*` variables TypeScript reads
itself. And the secret descriptor does not work the obvious way: Deno 2.x
cannot read an inherited descriptor at all — no `Deno.readSync`,
`Deno.FsFile` refuses the rid, `node:fs.readSync(3)` returns `EBADF` — so the
route is to reopen `/proc/self/fd/3`, which means the parent must `dup2` a
pipe onto that fixed descriptor in `pre_exec`, since Deno does not renumber
inherited descriptors and uses 3, 4, 5 itself. A regular file behind fd 3 is
refused, so it has to be a pipe. That is Linux-only; macOS (`/dev/fd/N`) and
Windows (no Unix descriptor inheritance) are unverified. The spike code is
not committed.

## Decision
Deno, pinned, as a subprocess behind `ScriptHost`, in a new adapter crate
`adapters/deno-script-host`. This ratifies the adapter
[README.md](../../README.md) and [docs/ARCHITECTURE.md](../../docs/ARCHITECTURE.md)
already name as a "deno script host".

- The alternatives and why they lost:
  - **Node.** Type stripping is on by default since v23.6.0 (backported to
    v22.18.0) and only stable since v25.2.0, and it covers *erasable* syntax
    only — no enums,
    no parameter properties, no import aliases, `tsconfig.json` ignored — so
    full TypeScript still means shipping a loader (`tsx` or esbuild) into the
    adapter. Its permission model is the same problem in a worse place:
    `--permission` is stable since v22.13.0 and grants `--allow-fs-read`,
    `--allow-fs-write`, `--allow-child-process` and `--allow-worker`, but the
    Node documentation says plainly that it "does not provide security
    guarantees in the presence of malicious code", that symlinks are followed
    out of granted paths, and that OS-level isolation is needed for untrusted
    code. Deno's sandbox is a boundary; Node's is a seat belt. Node is also not
    pinnable the way Deno is — a Node version is chosen per machine, not by us.
  - **Bun.** It has no permission or sandboxing system at all: an open feature
    request for one (oven-sh/bun#26637) records that Bun "currently has no
    filesystem permission or sandboxing system". A step holding a database
    secret would also get the whole filesystem, the network and the
    environment.
  - **Embedded (`deno_core`, or V8 in-process).** It puts a runtime in every
    `keepshipping` binary, the opposite of the one static binary ADR 0013
    chose; Node-compatibility shims would be ours to maintain; and a crash in
    a step would take the engine with it.
- The Deno version and the per-platform SHA-256 of its release archive are
  compiled into the `keepshipping` binary — for Deno 2.9.7 on linux-x86_64,
  `c6527f24f4b16031d3ae4fa9f658d5f11534c8d84ce7dc8502420280919c3490` over
  `deno-x86_64-unknown-linux-gnu.zip`. That is how "same locally and in
  CI" holds: one `keepshipping` version means one Deno, with no lockfile to
  invent — the issue recommended pinning in a lockfile, and this repository has
  none to pin in. On the first TypeScript step the binary downloads that exact
  archive into a
  per-user cache (`$XDG_CACHE_HOME/keepshipping/deno/<version>/`) and verifies
  it against the compiled-in hash before executing it; a mismatch is a hard
  error, not a warning. That download is from Deno's own release host, not from
  us, so ADR 0005's "no network call to us" is untouched; an air-gapped install
  pre-seeds the cache directory instead and never fetches.
- The pinned TypeScript and the extractor and host scripts ship inside
  `keepshipping` and are installed into a private `DENO_DIR` the same way. The
  runtime runs cached-only, so `check` fetches nothing at all and `run` fetches
  nothing beyond the step's own declared dependencies. npm dependencies of user
  steps are out of scope here and are
  [#57](https://github.com/Keep-Shipping/harness/issues/57).
- The protocol is JSON lines. stdin gets one object of inputs. stdout gets any
  number of `{"log":{"level":..,"msg":..}}` lines and exactly one
  `{"output":{..}}`. The stderr tail becomes `ScriptFailed`, through the run's
  `Redactor` ([ADR 0004](0004-secrets.md)). Secrets go on a pipe `dup2`'d onto
  fd 3 with length-prefixed name/value frames — never argv, never the
  environment, never stdio. Inputs and outputs are validated with the shared
  `StepSchema` checks in `crates/core/src/ports/script_host.rs`, so `check`
  and the adapter enforce one contract.
- The sandbox is deny by default: read the workspace, no environment, no
  network, no writes, no subprocesses. A step widens it only by declaring
  grants in its `step({...})` call, which schema extraction reads so `check`
  can show them. The exact grant shape is #57's.
- `ks-core` stays pure and receives schemas as data. The CLI fills them from a
  cache under `<root>/.ks/cache/script-schemas/<key>.json`, keyed by SHA-256
  over the step file, its local imports, the SDK version, the extractor version
  and the Deno version. A cache hit spawns no process; a miss with the runtime
  installed costs one ~130 ms Deno process and no network; a miss with no
  runtime installed never triggers a download — `check` reports a warning
  finding and types the script's outputs `any`, as an unknown kind's already
  are. A schema extracted alongside type errors is reported, not trusted.
- `StepSchema` gains a way to mark which inputs are secret, matching the
  `{"kind":"secret"}` the extractor already produces. That is a #57 change, not
  this ADR's. ADR 0003's rule that a script's outputs are read as
  `<step>.out.<name>` and typed `any` with the name unverified at check time is
  unchanged; tightening `<step>.out.<name>` once schemas are known is left to
  #57.
- No daemon yet. The warm process meets the budget. A long-lived extractor
  (sub-millisecond against a held program) is the option if the LSP wants one.

## Consequences
- `keepshipping` stays one binary. The cost is a first-use download of about
  40 MB and a Deno a user may already have pinned differently — we ignore any
  Deno on the machine and use our own.
- `check` stops being free for a repository with TypeScript steps: ~130 ms per
  uncached step, paid once and cached by content hash. A cold cache of many
  steps is the case to watch against the 1 s cold budget.
- `check` stays honest offline, at the price of a degraded mode: no runtime
  means `any` and a warning, not a failure. A wrong type in a script can be
  missed on a laptop that has never run it, and a schema is only as
  trustworthy as the extraction — an errored field degrades to `any` rather
  than failing the check.
- The sandbox is a boundary Deno enforces, not one we enforce, and it covers
  the workspace only. A step with net access declared and granted can still do
  what it says, and the grant mechanism deserves its own scrutiny when #57
  defines it.
- fd 3 and `/proc/self/fd/3` are Linux. macOS and Windows need their own
  verified mechanism before the adapter can claim support for them, and until
  then it is Linux-only.
- Pinning Deno inside the binary means a Deno security fix reaches users only
  with a `keepshipping` release. That delay is accepted for reproducibility,
  and it is the strongest argument for revisiting the choice later.
- npm dependencies in user steps are undecided: a step that imports a package
  has no offline story yet, and #57 has to answer it.