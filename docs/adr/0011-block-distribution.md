# ADR 0011: Block distribution

Status: accepted, 2026-10-06

## Context
The site says: package steps as a typed, versioned block; each repo pins a
version and upgrades on its own schedule. The example is
`acme/web-service@v3`, defined in `acme/blocks`, and it appears in a
workflow file in the step-kind position, the same place a built-in kind like
`oci.image` appears. That surface is already fixed — it is a golden fixture,
`crates/lang/tests/fixtures/site-block.ks`, and [ADR
0003](0003-workflow-syntax.md) makes the site's examples the syntax's
tests.

What is not fixed is where a block's bytes come from and what a workflow
file pins. Two requirements pull against each other. A block is reused
across repositories, so it has to be fetchable from somewhere a repository
we have never seen can reach. And `check` must type-check a use of a block
**offline and in under a second** — the cold 1 s / warm p95 100 ms budget
pinned in `crates/cli/benches/check.rs`, and the `offline` CI job that runs
`check` in a network namespace with no interfaces, which says in so many
words to keep `check` free of network access and store reads. Nothing the
checker needs may depend on a round trip.

Three options:

- **A. Git refs.** `acme/blocks` at `web-service/v3.1.0`. For: no
  infrastructure at all, and private repos work with the credentials the
  machine already has. Against: a tag is mutable, so two repos pinned to it
  can run different bytes; resolving `@v3` to a version means listing tags;
  and the first use in a repository clones a repo, which is seconds, not
  milliseconds.
- **B. OCI artifacts.** `ghcr.io/acme/blocks/web-service:3.1.0`, pinned by
  digest. For: a digest is the content, so a pin is exact and a mismatch is
  detectable by hashing; the `Registry` and `Signer` ports
  ([#50](https://github.com/Keep-Shipping/harness/issues/50)) are already
  the shape this needs, the `ArtifactUpload` `Registry::push_artifact` takes
  already carries a `subject` so `referrers` can find it, and every company
  already has a registry. The publishing story is unchanged for anyone who
  ships images today. Against:
  publishing needs a registry login, and registries are less familiar
  territory for people who have never pushed an image.
- **C. A hosted index, ours.** For: discovery and search. Against: a
  dependency on us in the path of every build, a trust ask, and no help at
  all for a private block.

## Decision
Option B for distribution, A as the authoring source, C only ever as
metadata. Git stays where git is good — history, review, branching a block —
and the OCI artifact is what a workflow file consumes.

- **A reference in `ship.ks` is a name and a version**, spelled the way the
  site spells it: `acme/web-service@v3`, or `@3.1.0` for an exact one. (The
  partial `@3.1` is not a spelling this ADR settles; the settled set and its
  meaning are in [`docs/LOCKFILE.md`](../LOCKFILE.md).) A block with no `@` at
  all is the one failure we refuse rather than default — there is no `latest`
  for a block, because the whole pitch is that a repository pins.
- **The name resolves to a repository through configured mappings**, not by
  guessing: `acme/web-service` becomes
  `ghcr.io/acme/blocks/web-service` under the default mapping of "the
  owner's namespace on the owner's default registry". A file overrides it
  under `blocks:` — one line per mapping — and the CLI grows a flag and an
  environment variable for it, beside the existing `--index` flag and its
  environment variable (which name the hosted index, not a mapping).
  Settling where the mapping is configured is the follow-up work this
  decision unblocks,
  [#79](https://github.com/Keep-Shipping/harness/issues/79); the decision
  here is that the mapping is configuration, and configuration is local,
  never a call to us.
- **`ship.lock` is the pin, and it is written by a command, not by
  `check`.** It records, per block, the reference as written, the version
  that reference resolved to, the repository and the manifest digest. `check`
  and `run` read the digest and never resolve a version; `keepshipping
  blocks update` (alias `lock`) is the online command that writes it. A
  workflow that changes without `ship.lock` changing is a `check`
  diagnostic, not a silent re-resolve — the same discipline as a
  `Cargo.lock`, and for the same reason.
- **The artifact is an OCI 1.1 artifact with its own `artifactType`** — a
  keepshipping block media type, not an image media type. OCI 1.1 added
  `artifactType` for exactly this case (a manifest whose `config.mediaType`
  is empty) and requires an implementation to ignore a type it does not
  recognise rather than fail, so a future block format does not break an old
  client. Two layers: a small one carrying the block's typed interface (its
  `inputs` and `outputs`, the typed `check` reads) and a larger one
  carrying the implementation. `check` needs only the small layer, and
  because the manifest lists each layer by digest and size it knows which
  one is small without reading the other.
- **The local cache is content-addressed, keyed by digest.** A cached entry
  is verified by hashing, which is the same rule the `Registry` port
  already states: pulled bytes must hash to the digest they were requested
  under or the call fails with `DigestMismatch`
  (`crates/core/src/ports/supply_chain.rs`). A digest key means a poisoned
  cache entry cannot be substituted for another block. This cache is the
  local side of the `BlockSource` port
  [ADR 0005](0005-local-first-core-with-optional-hosted-services.md) named
  and left unwritten.
- **`check` is offline by construction, not by convention.** A missing cache
  entry is a diagnostic that names the digest and tells the user to run the
  fetch command — `keepshipping blocks fetch`, or `blocks update` — and it
  names no network host. The existing `offline` CI job is what proves the
  rule holds; this ADR adds a second case to it, a fixture that uses a
  block.
- **Publishing goes through the same ports as images.**
  `keepshipping blocks publish` reads a block definition at a git tag or
  commit, builds the layout, and pushes it with `Registry::push_layout`,
  using the registry credentials the machine already has; it never asks for
  a password of its own. The manifest records where it came from as
  annotations — `org.opencontainers.image.source` for the repository and
  `org.opencontainers.image.revision` for the commit, both defined
  annotations — so a block's provenance is the artifact's own metadata, not
  a side table. Signing is the `Signer` port and a `sign` flag, the shape
  `oci.image` already declares (`crates/core/src/catalog.rs`; no adapter
  is wired yet, and none is claimed here). The signature is a referrer
  attached to the
  block's digest, found through `Registry::referrers`, and `check` reads
  the signature status out of the cache, never from the registry.
- **A hosted index holds metadata and nothing else.**
  `BlocksIndex` (`crates/core/src/ports/blocks.rs`) is already written to
  that contract: name, versions, each version's digest, publisher identity,
  signature status, README — never block content. This ADR does not change
  it, and does not build it; the hosted index is
  [#149](https://github.com/Keep-Shipping/harness/issues/149), optional
  per [ADR 0005](0005-local-first-core-with-optional-hosted-services.md),
  and `keepshipping blocks search` is the only command that reads it today
  (`crates/cli/src/blocks.rs`).

### Why not the other two

- **Not A alone.** A tag is mutable policy; a digest is the content — the
  rule `crates/core/src/ports/supply_chain.rs` already states for images,
  applied to blocks. `@v3` resolved against a tag
  list is a network call in the checker's path, and it is a call whose
  answer can change between two checks of an unchanged file — the worst
  possible property for the command that has to tell you whether the file is
  sound. Git's advantage is real but it is an *authoring* advantage, and
  authoring is not what a workflow file consumes.
- **Not C.** It is the trust ask [ADR
  0005](0005-local-first-core-with-optional-hosted-services.md) rules out
  for every other feature: a build would stop working when we are down.
  It also does nothing for a private block, and private blocks are where
  reuse is most valuable. Discovery is real, which is why the index exists
  at all — as something to *search*, never as something to resolve
  against.
- **A's no-infrastructure advantage is partly given up, and that is the
  price.** A company that publishes blocks needs a registry, and a publisher
  needs a login. The mitigation is that the registry need not be ours or a
  vendor's: an OCI Image Layout directory (`oci-layout`, `index.json`,
  `blobs/<alg>/<encoded>`) is the same content-addressed shape on a
  filesystem, which covers an air-gapped publisher and lets the whole
  publish-fetch-verify path be tested without a network. Which is also how
  the cache is testable.

## Consequences
- Two artifacts, two tools: blocks are authored in git and reviewed in
  git, and consumed as an OCI artifact. `publish` is the bridge, and it is
  a command anyone can run in CI.
- `ship.lock` is a new file in every repository that uses a block, and it
  is reviewed like one. It is also what makes "this repo runs the same bytes
  as last month" a claim that can be checked rather than hoped for.
- Upgrades are explicit: change `@v3` to `@v4` in `ship.ks`, run
  `keepshipping blocks update`, review the lock diff, commit. Each repo
  moves on its own schedule, which is the pitch.
- Publishing carries a registry login, and a private registry means the
  fetch side needs credentials too — an identity question this ADR does not
  settle, because ADR 0004 settled where secrets come from and the answer
  there (per-environment resolvers, `env` and GitHub Actions first) applies
  unchanged.
- The block interface is now a published wire format. `check` reads it, so
  a change to it is a change to a contract other repos depend on, and it
  gets the ADR 0100 treatment: declared, versioned, checked.
- Verification is offline but not silent. A block with no signature, or one
  signed by an identity policy does not accept, is a `check` finding — the
  same fail-closed reading as secrets and as `ci-only` in
  [ADR 0004](0004-secrets.md). Reading a signature status from the cache is
  only as good as the cache's integrity, which is why the cache is keyed by
  digest.
- Mirroring is a consequence rather than a feature: an org can mirror its
  blocks into its own registry and repoint the mapping, and nothing about a
  block's identity changes with it.
- Out of scope here, deliberately: the hosted index's storage and search
  ([#149](https://github.com/Keep-Shipping/harness/issues/149)), the exact
  spelling of the `blocks:` configuration section, and the precise semantics
  of version constraints — whether `@v3` means the highest 3.x or a
  prerelease-aware range. Those semantics are now settled, in
  [`docs/LOCKFILE.md`](../LOCKFILE.md): `@v3` is the highest release of that
  major and never a prerelease, `@3.1.2` is exact, and `@sha256:…` pins the
  content; the format that records them is `lock = 1`. Where a block lives is
  still open, and stays the follow-up work this ADR unblocks,
  [#79](https://github.com/Keep-Shipping/harness/issues/79), to be settled
  against what publishers actually tag. A reference that resolves to no
  published version is a `check` error naming what it looked for.
- Not decided, and not blocking #79: whether a block may itself use another
  block. When it can, the same rule applies — the dependency is a reference
  in a file, it is locked, and `check` reads it from the same cache.