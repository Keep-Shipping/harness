# Reproducibility: what "the same digest" means

The site shows one `sha256:…` digest on the laptop and the same one on the CI
runner. This page says exactly what that claim rests on today, and what is
still to be built.

## What the claim means

Within a run it is already true and it is enforced by types. `oci.image`
declares a `digest` output typed `oci.Digest` ([ADR 0010](adr/0010-image-build-backend.md)),
and the catalog gives that type its reason: *so prod runs exactly the image you
built*. A deploy step takes `image: build.digest`, never a tag, so prod cannot
drift to a tag someone moved. The type exists so that the digest a deploy uses
is the digest the build step returned.

Across machines it is a different claim, and the difference matters. The
harness never computes a digest: `Digest::parse` validates hex an adapter
already hashed, and the digest always comes from the response of whatever holds
the bytes — the registry ([ADR 0002](adr/0002-ports-and-adapters.md)). So the
digest CI reports is the digest CI's registry holds. Two things then have to be
true for the laptop and the runner to show one digest:

- CI **reuses** the digest that was built and pushed. A run that pushes in one
  job and deploys from that digest in the next shows the same digest by
  construction — it is promotion, not reproduction.
- CI **rebuilds** the same commit and gets the same digest. That holds only if
  the build is reproducible, which is a property of the Dockerfile and the
  builder, not of the harness.

The second is the claim that needs checking, and it is the one the site should
be read as making.

## What a reproducible build needs

- **Digest-pinned base images.** `FROM debian:bookworm` names a moving tag;
  `FROM debian@sha256:…` names content. `scratch` and an earlier stage alias
  name nothing external and are fine unpinned.
- **Fixed timestamps.** BuildKit reads `SOURCE_DATE_EPOCH` as a build argument
  and the image exporter's `rewrite-timestamp=true` clamps the layer and config
  timestamps to it ([ADR 0010](adr/0010-image-build-backend.md); the build-arg
  support landed in BuildKit v0.11, the exporter option in v0.13). Take the
  value from the commit time, so it is the same on every machine.
- **No floating network fetches.** `apt-get update` against a live mirror,
  `ADD https://…` without `--checksum=`, or a package manager resolving a
  semver range will return different bytes tomorrow and change the digest even
  with everything else pinned. Pin the apt sources to
  `snapshot.debian.org` / `snapshot.ubuntu.com`, checksum every remote `ADD`,
  and commit the lockfiles for whatever language the image builds.
- **The same builder.** Different BuildKit or buildx versions mean different
  output. [ADR 0010](adr/0010-image-build-backend.md) makes that a property of
  the tool rather than of the machine: a `docker-container` builder running a
  `moby/buildkit` image pinned by digest, compiled into `keepshipping`, with the
  BuildKit version in the builder's name.
- **The same platform list.** An arm64 Mac and an amd64 runner do not produce
  the same manifest; each builds the host platform unless told otherwise. Both
  must pass the same `--platform` list. When that list has more than one entry,
  and when any attestation is attached, the digest that gets pushed and signed
  is an **index** digest over those per-platform manifests — a third value,
  different again from either platform's manifest digest.

Which is roughly:

```sh
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --build-arg SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)" \
  --no-cache \
  --output type=image,name=acme/api,push=true,rewrite-timestamp=true \
  --metadata-file metadata.json .
```

The flags only cover the parts BuildKit can fix for you. A Dockerfile that
fetches from the network still breaks the digest, and `--no-cache` is only
there because comparing two cached builds proves nothing.

## Status today

The attestation layout exists, and is not yet on the wire from a
production build. An in-toto v1 statement, a SLSA v1 provenance predicate and a
DSSE envelope are built, signed and pushed against the image digest in
`ks_engine::attestation` (#63): the envelope is an OCI artifact whose
`subject` is the image, so `referrers` will list provenance and SBOM side
by side. The run log has the transition for it —
`RunEvent::AttestationAttached` and `Journal::attestation_attached` — though
nothing emits it yet. What `oci.image` does today
([#114](https://github.com/Keep-Shipping/harness/issues/114)) is attach, after
signing a digest: it pushes a SLSA v1 provenance statement naming the output, the
ref and the commit that produced it as a DSSE envelope beside the image, and
reports the envelope's digest as its `provenance` output. The attach itself is
not journalled; the step log line is the only record of it.
[PROVENANCE.md](PROVENANCE.md) has the field-by-field contents and the
[SLSA v1.0 Build](https://slsa.dev/spec/v1.0/levels) assessment — **no Build
level is claimed**, for reasons that are the same reasons below. Still missing
is the BuildKit `ImageBuilder` adapter
([#59](https://github.com/Keep-Shipping/harness/issues/59),
[ADR 0010](adr/0010-image-build-backend.md)), which also carries the `sbom`
input the catalog now declares. Until the real `Signer` and `ImageBuilder`
adapters exist, `cosign verify-attestation` is **not** verified against
anything here: the tests sign with `ks-testing`'s deterministic fake, which
is honest about not being cryptography.

| Claim | Status |
|---|---|
| `oci.image` sets these knobs by default (`SOURCE_DATE_EPOCH` from the commit time, `rewrite-timestamp=true`, one pinned builder) | Planned — lands with the builder adapter and [ADR 0010](adr/0010-image-build-backend.md). `oci.image` is a built-in step, but no real `ImageBuilder` adapter exists yet — `builtin_steps()` registers the step kind and every build in the tree goes through `ks-testing`'s `FakeImageBuilder` ([STEPS.md](STEPS.md)). |
| `reproducible: strict` — fail the run when a CI rebuild of the same commit yields a different digest | Planned, off by default. Needs the adapter before it can mean anything. |
| The run log records whether a digest was rebuilt or reused | Planned — depends on the run log ([#46](https://github.com/Keep-Shipping/harness/issues/46)) |
| The pushed image carries a provenance statement | Partly — `oci.image` builds a SLSA v1 statement and attaches it beside the digest ([PROVENANCE.md](PROVENANCE.md)). No SLSA Build level is claimed; the tests reach it only through `ks-testing`'s fakes. |
| Cross-OS CI comparison of digests from one commit | Planned — needs a builder on both hosts, which [ADR 0010](adr/0010-image-build-backend.md) is still waiting to be accepted |

## Checking a Dockerfile today

Available now: **`keepshipping check --repro`**
([DIAGNOSTICS.md](DIAGNOSTICS.md#--repro)). It walks from each `oci.image`
step to the Dockerfile its `from:` names — a path, resolved beside the site
file — and warns, code **KS0801**
([ERRORS.md](ERRORS.md#ks0801-image-build-is-not-reproducible)), about the three
inputs above: a `FROM` with no `@sha256:` digest (`scratch` and earlier-stage
aliases excepted; a `FROM ${ARG}` is warned too, since the value only exists at
build time), an `apt-get update` / `apt update` with no snapshot, and an
`ADD http(s)://…` with no `--checksum=`. An `apt` index counts as pinned when
the instruction, or any other instruction in the same file, names
`snapshot.debian.org`, `snapshot.ubuntu.com` or a `--snapshot` option — an
earlier `RUN` may have pointed `sources.list` at a snapshot. A comment naming a
snapshot pins nothing. Findings are reported against the Dockerfile, with its
own path and source, in whichever format was chosen.

A `from:` that is not a path is already a type error from the checker, and
`--repro` skips it rather than guessing. A `from:` naming a file that cannot be
opened is a warning in its own right, against the `from:` itself: an image
nobody can scan is not one to call reproducible. The flag reads those files and
starts nothing — no network, no builder — and KS0801 is a warning, so it leaves
the exit code alone unless you pass `--warnings-as-errors`.

## Bottom line

Until the knobs land and a cross-OS comparison passes, the accurate claim is
**same file, same steps, same order — and CI deploys the digest that was
built**, not "two independent builds give the same digest".