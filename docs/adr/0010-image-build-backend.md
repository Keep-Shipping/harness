# ADR 0010: Image build backend

Status: proposed, 2026-10-06

## Context
The `oci.image` step has to build from your Dockerfile, push to any OCI
registry, and hand back a digest, and it has to do those three things the
same way on a laptop — Docker Desktop, OrbStack, Colima, Podman — and in
CI, where GitHub's hosted Linux runners ship Docker and little else. The
port already exists; what is missing is its first adapter, and the choice
is worth an ADR because every later image step inherits it.

`oci.image` (`crates/core/src/catalog.rs`) takes `from`, `push` and
`sign`, and returns `digest`, `tag` and `signed`. Its port is
`ImageBuilder` (`crates/core/src/ports/supply_chain.rs`), whose single
`build` takes a `BuildRequest` — context, dockerfile, args, platforms,
target, push_to — and returns a `BuildOutput`: an `OciLayout` with a path
and a manifest descriptor, or a `PushedImage` with a repository and a
digest. Two rules in that module constrain the adapter before a line of
it is written: a digest is parsed, never computed, and always comes from
the response of whatever holds the bytes; builders and registries return
descriptors, never tags.

[ADR 0002](0002-ports-and-adapters.md) puts this code in a crate under
`adapters/` — `adapters/buildkit`, the name [README.md](../../README.md)
and [docs/ARCHITECTURE.md](../../docs/ARCHITECTURE.md) already carry. What
is decided here is which builder sits behind it, and how it is pinned.

Three options were considered:

- **A. BuildKit, driven through `docker buildx`.** The reference Dockerfile
  frontend, with cache import and export, SBOM and provenance
  attestations, and the reproducibility knobs `SOURCE_DATE_EPOCH`
  (BuildKit v0.11) and the exporter option `rewrite-timestamp=true`
  (v0.13).
- **B. Shell out to `docker build`.** Since Engine 23.0 this *is* BuildKit
  through buildx's `docker` driver, so it inherits that driver's limits.
  `--iidfile` records an image ID, which on the classic image store is the
  config digest, not the manifest digest a registry serves — the wrong
  digest under the port's own rule. Parsing stdout to recover it is
  brittle, and it does not work with Podman at all.
- **C. Daemonless: kaniko or buildah.** `GoogleContainerTools/kaniko` was
  archived on 2025-06-03, and its forks (`chainguard-dev`,
  `osscontainertools`) carry no SBOM or attestation support, which is half
  of what this step is for. Buildah is Podman's builder, not BuildKit's,
  and handles Dockerfile edge cases differently.

Four findings shaped the choice.

- The buildx `docker` driver — Docker's embedded BuildKit — gates cache
  export (registry or local), multi-platform output and provenance on the
  containerd image store, and that store is the default only for *fresh*
  installs of Engine 29.0. GitHub's `ubuntu-24.04` image ships Docker
  28.0.4 with Buildx 0.37.1, so the embedded builder on a hosted runner
  cannot export cache or build multi-platform. Its BuildKit version also
  follows whatever Engine a given machine happens to have.
- OrbStack, Colima and Docker Desktop all run an unmodified Docker
  Engine. Docker Desktop and OrbStack ship buildx; on Colima it is a
  separate install. None guarantees a particular BuildKit version.
- Podman's Docker-compatible API has no BuildKit session endpoints, so the
  buildx `docker` driver cannot be pointed at `podman.sock`
  ([podman#17836](https://github.com/containers/podman/issues/17836)).
  There is no `podman` buildx driver either.
- macOS GitHub runners have no Docker at all, and the arm64 macOS runners
  do not support nested virtualization. Windows runners have no
  Linux-container Docker.

A fifth ruled out the Rust-native alternative. bollard's BuildKit gRPC
client has no attestation support, and the `buildkit-rs` crates were
archived in 2023; shelling out to `docker buildx build` is what Rust
projects actually do. This is the case
[ADR 0013](0013-rust-workspace.md) already legislated — where Go is the
only mature implementation, the adapter drives the upstream binary or API
over a port instead of linking Go
([#11](https://github.com/Keep-Shipping/harness/issues/11)).

## Decision
Option A, behind the existing `ImageBuilder` port, as an
`adapters/buildkit` crate that drives the `docker buildx` CLI. It does not
link Go, and it does not reimplement the BuildKit session protocol in
Rust.

**One pinned builder everywhere.** The adapter does not use the engine's
embedded builder. On first use it creates — and afterwards reuses — a
buildx builder on the `docker-container` driver, running a `moby/buildkit`
image pinned by digest. That digest is compiled into `keepshipping`, and
the builder's name carries the BuildKit version, so an upgrade creates a
fresh builder rather than mutating one in place. Every laptop and runner
with a Docker Engine therefore runs the same BuildKit, with cache export,
multi-platform and attestations available regardless of image store or
Engine version. The only configurable alternative is a `remote` builder
address — a `buildkitd` the user runs themselves, rootless, in
Kubernetes, or next to Podman. That is how Podman users and daemonless CI
reach the same adapter.

**Push and digest.** When `push` is set, BuildKit pushes itself
(`--output type=image,push=true`), which keeps blob mounts and skips
layers the registry already has. The adapter passes `--metadata-file` and
reads `containerimage.digest` out of that JSON file — a documented output
contract, not log text. It then confirms that digest through the
`Registry` port, resolving `repository@digest` with OCI manifest and index
Accept headers. The step's `digest` output is the registry-confirmed
digest, not the one buildx reported; an absent or mismatched digest fails
the step. Tagging stays a `Registry` concern (`Registry::tag`). BuildKit's
build log text is streamed to the user and never parsed.

**No push.** The build exports an OCI layout (`--output type=oci`) and the
port returns `BuildOutput::OciLayout`. Any later push goes through
`Registry::push_layout`, which must transfer the layout's manifest and
index bytes unchanged. The spike found why that wording matters:
re-wrapping or unwrapping a single-manifest index — `crane push` without
`--index`, for instance — produces a different digest for the same
content.

**Reproducible by default.** The adapter always sets
`SOURCE_DATE_EPOCH` — to the commit time of the source revision where
there is one, otherwise 0 — and always passes `rewrite-timestamp=true`.
Together they make byte-identical rebuilds possible. A Dockerfile that
fetches from the network can still break that.

**Attestations.** Provenance is on by default at `mode=min`. `mode=max`
is opt-in, because it records build arguments and that is a disclosure
decision the workflow author has to make. SBOM is opt-in. With any
attestation attached, the pushed digest is an image index rather than a
manifest — and that index digest is what `sign` signs and what a deploy
pins.

**Credentials.** Registry credentials named in the workflow are
`SecretRef`s resolved through the Secrets port at the step boundary
([ADR 0004](0004-secrets.md)), never strings in the file. The adapter
writes them into a per-run temporary `DOCKER_CONFIG` directory and deletes
it afterwards, never touching `~/.docker`. With no credential named, the
ambient Docker login is used — the behaviour `docker push` has today.

**Not supported, with a diagnostic rather than a fallback.** A host with
neither a Docker Engine nor a configured `remote` builder: macOS and
Windows GitHub runners, and Podman without a buildkitd beside it. The
step fails with a message naming what to install or point at. A buildah
adapter is a later decision if early-access users need it; kaniko is
rejected.

### Before acceptance
The spike did not run on the target hosts. A Linux microVM spike
(BuildKit v0.33.1, distribution registry 3.1.2, crane 0.20.6, oras 1.3.0)
confirmed the registry side of the contract: the client-reported digest
equals `Docker-Content-Digest`; normalised timestamps give identical
digests where wall-clock timestamps differ; an attestation manifest turns
the push into an index; OCI-layout push via oras, and `crane` with
`--index`, preserves the digest while `crane` without `--index` changes
it; and a HEAD with only a Docker-schema Accept header 404s for an OCI
manifest. BuildKit itself could not run there — no `CAP_SYS_ADMIN`.

This ADR becomes accepted once the pinned `docker-container` builder has
run on Docker Desktop and OrbStack on macOS, and on an `ubuntu-24.04`
GitHub runner, confirming:

1. `containerimage.digest` equals the registry's digest.
2. Two `--no-cache` builds of one context give the same digest.
3. Multi-platform output and registry cache export both work.

## Consequences
- The adapter requires a Docker Engine with buildx, or a `remote`
  buildkitd. First use pulls the pinned BuildKit image and starts a
  container. Builds do not land in `docker images` — nothing needs them
  there; the output is a push or an OCI layout. The builder's cache lives
  in its container volume, so it survives between runs.
- Multi-platform builds on Linux runners need binfmt/QEMU installed, for
  example `tonistiigi/binfmt`. Docker Desktop and OrbStack already have
  it.
- Upgrading BuildKit becomes a `keepshipping` release rather than a
  machine setting. That is the point: the builder version is a property
  of the tool, not of whoever installed Docker last.
- The port changes under
  [#59](https://github.com/Keep-Shipping/harness/issues/59), which this
  ADR blocks. `BuildRequest` needs fields for cache import and export,
  build secrets (through the Secrets port, never as build args) and
  attestation options. `OciLayoutContents` holds a whole layout in
  memory, which will not scale to multi-GB images, so the layout push
  path should stream from disk instead.
- The `Registry` adapter must send OCI index and manifest Accept headers,
  alongside the Docker ones, on HEAD and GET — a registry that only
  understands the Docker schema 404s on an OCI manifest. Because the OCI
  spec does not require `Docker-Content-Digest` on a manifest PUT, the
  digest is confirmed by HEAD rather than read off the PUT response;
  `oci-client`'s `push_manifest` returns a Location URL, not a digest.
- The honest cost is a container per machine and a dependency on the
  docker CLI. Podman-only laptops need a buildkitd until a buildah
  adapter exists, and macOS and Windows runners get a diagnostic, not a
  build.