# ADR 0014: Release and contract versioning

Status: accepted, 2026-10-07

## Context
Keep Shipping has three contracts that people other than us bind to.
The first is the `ship.ks` file format: a workflow someone wrote last
month has to load in a binary released this week. The second is the
`StepKind` trait plus the port traits a third-party step or adapter is
written against ([ADR 0002](0002-ports-and-adapters.md),
[ADR 0100](0100-step-contract-and-composition-checks.md)) — a step
compiled against one harness must refuse to run against a harness whose
ports moved. The third is the TypeScript script-host protocol: an escape
hatch step written in TypeScript talks to the host over a JSON contract
([ADR 0013](0013-rust-workspace.md)). None of the three was versioned as
a public surface, so nothing told a step author which one they had
written against and nothing stopped us changing one silently.

Cratefield — the harness Keep Shipping is modelled on
([ADR 0200](0200-hosted-venture-on-the-cratefield-harness.md)) — versions
its module contract as a constant and generates a compatibility table
from it. That is the model here.

`STEP_API` was not the gap: it already exists at
`crates/core/src/step.rs`, and `HarnessBuilder::build` already refuses a
step whose `step_api()` differs. What was missing is the other two
constants, a written record of which port trait version is which, and
any enforcement that a change to a port trait comes with a `STEP_API`
bump. The pull-request template and [CONTRIBUTING.md](../../CONTRIBUTING.md)
have both asked for "port contract changes have a changelog entry" since
early on, with nothing behind the ask: the changelog had nowhere to live
and no test would fail if it were skipped.

The release side has the same shape. There is no tag-triggered build, so
"install Keep Shipping" means "build it from a commit", and there is no
artifact whose origin a user can check.

## Decision
- `ks-core` exports three constants from `crates/core/src/version.rs`:
  `FORMAT_VERSION` (the `ship.ks` format), `STEP_API` (the `StepKind`
  and port contract) and `SCRIPT_PROTOCOL` (the TypeScript script-host
  protocol). `STEP_API` moves out of `crates/core/src/step.rs` but is
  still re-exported there, so `ks_core::step::STEP_API` keeps working.
- A step runs only under a harness speaking the same `STEP_API`;
  `HarnessBuilder::build` already refuses a mismatch. Additive changes
  bump the minor, breaking changes bump the major.
- The port contract is fingerprinted from the `pub trait` declarations
  in `crates/core/src/ports/`, and the fingerprint is pinned next to the
  `STEP_API` it belongs to in `crates/testing/tests/compatibility.rs`.
  Changing a port trait without bumping `STEP_API` fails CI.
  Reformatting and comment edits are normalised away before hashing, so
  only signature changes trip it.
- `docs/COMPATIBILITY.md` is generated from the workspace and
  drift-checked. It lists the three contracts and the port-contract
  digest, and names the command that regenerates it.
- `docs/PORTS.md` carries the hand-written port changelog: one
  `## STEP_API <n>` heading per contract version.
- A tag matching `v*` triggers a release: `keepshipping` built for
  macOS arm64 and x86_64 and Linux x86_64 and arm64, one archive per
  target plus a single SHA-256 checksum file, the checksums signed with
  cosign keyless, and a GitHub Release whose body GitHub's own
  release-notes generator writes from the conventional commits.
  Windows comes later; its SBOM and signing story is
  [#116](https://github.com/Keep-Shipping/harness/issues/116).
- **Crates are not published to crates.io.** `publish = false` is
  already set workspace-wide in the root `Cargo.toml` and stays set
  until the licensing decision lands (ADR-0006 — not written yet; the
  number is reserved, so cite it as prose, not as a link). Releases
  are binaries. The issue left this open; this is the answer.
- release-plz is adopted for the changelog, and deliberately not
  wired to `cargo publish`. Its action is pinned at
  `release-plz/action@v0.5.139`; the action publishes `v0.5.x` tags
  only, with no `v0` floating tag, so there is no `v1`-style major tag
  to pin the way `actions/checkout@v4` is. While `publish = false`
  stands, every package is excluded from release and
  `release-plz release` finds nothing to release: the step is present
  and pinned, and currently inert.

## Consequences
- A step author pins `ks-core` and checks the table in
  `docs/COMPATIBILITY.md`. Upgrading `ks-core` across a `STEP_API` bump
  is a deliberate act: the harness refuses the step otherwise, rather
  than failing later in a way that is harder to read.
- Breaking a port trait now costs a `STEP_API` bump, a
  `## STEP_API <n>` entry in `docs/PORTS.md`, a regenerated
  `docs/COMPATIBILITY.md` and an updated pin in the compatibility test —
  four edits in one PR, which is the point.
- The fingerprint has honest limits. It is a source digest of the `pub
  trait` declarations in `crates/core/src/ports/`, normalised to one
  block per trait, so it catches more than a changed signature: a changed
  default-method body is a changed line inside the block, and so is a
  renamed trait, a removed trait, a trait's visibility, or a deleted file
  (its blocks stop entering the hash). What it cannot see is a behaviour
  change that touches neither a signature nor a port module at all — a
  step's own logic, a non-port helper. And a new port wired without
  touching an existing trait is caught only because its file moved the
  digest, not because the fingerprint understands what it is looking at.
  The `Port` enum and `define_ports!` order check covers that case; the
  digest is the backstop, not the argument. Zero extracted blocks is an
  error rather than the hash of the empty string, so a broken extractor
  cannot pin a plausible-looking constant.
- The release pipeline is the one workflow with `contents: write`; every
  other gate is `contents: read`. The signing job additionally needs
  `id-token: write`, which is what actually lets `cosign sign-blob` mint
  the OIDC identity a keyless signature is built on; the permission is
  granted on that job alone. Without it the release fails at the sign
  step and nothing is published.
- A user verifies a release by checking `SHA256SUMS` against the
  cosign signature, not by trusting the download host.
- Windows is still missing from the matrix;
  [#116](https://github.com/Keep-Shipping/harness/issues/116) tracks it.
