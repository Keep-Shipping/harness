# Provenance: what a pushed image can say about itself

An image digest says what came out of the build. Provenance says *what built
it*. The `oci.image` step attaches a statement to the digest it just signed
([#114](https://github.com/Keep-Shipping/harness/issues/114),
[ADR 0010](adr/0010-image-build-backend.md)): what is in it, where it ends up, and
how far it goes against [SLSA v1.0](https://slsa.dev/spec/v1.0/levels).
**No SLSA Build level is claimed today.**

## What a statement contains

`ks_engine::attestation::provenance` builds an in-toto v1 Statement
(`https://in-toto.io/Statement/v1`) whose predicate type is
`https://slsa.dev/provenance/v1`. Every field is a fact the run already had or a
value the step already resolved — nothing inferred, nothing fetched.

| Field | Where it comes from |
| --- | --- |
| `subject[0]` | the image digest just signed, under the reference it was pushed as |
| `predicateType` | always `https://slsa.dev/provenance/v1` |
| `buildDefinition.buildType` | `https://github.com/Keep-Shipping/harness/buildtypes/oci-image/v1` — the build type is `oci.image`, on a domain this project owns |
| `externalParameters.step` | always `oci.image`: the step *kind*, not the instance's name |
| `externalParameters.shipFile.sha256` | sha256 of the `ship.ks` the run was checked from |
| `externalParameters.source.gitRef` | the ref the run context reported |
| `externalParameters.inputs` | the build's parameters, resolved: `from`, `context` (the *resolved* one — the Dockerfile's directory when `context` is omitted), `args`, `platforms`, `target`, `push`, `cache`, `sbom` (a bool), `secrets` |
| `externalParameters.inputs.secrets` | the mounted secrets' **names**, sorted; the values never appear |
| `externalParameters.inputs.args` | the build args, each recorded whole **unless** the run's redactor finds a secret in its value — such an arg keeps its name and is recorded as `null` |
| `resolvedDependencies[0]` | `uri: "git+<ref>"` with `digest: {"gitCommit": <commit>}` |
| `runDetails.builder.id` | `issuer#subject` when the run context established a CI OIDC identity — the same `issuer#subject` a keyless signature is filed under — otherwise the one fixed `urn:keepshipping:builder:local` |
| `runDetails.builder.version` | `{"keepshipping": <version>}`, from the crate's own version at build time |
| `runDetails.metadata.invocationId` | the run's ULID |

Every key in `inputs` is always present: an optional input the build did not get
is recorded as JSON `null`, so a verifier reads one shape either way. The
statement is signed over the DSSE pre-authentication encoding of its own
canonical bytes. Left out on purpose: secret **values**. A value in a predicate
is a value baked into the artifact for good.

**What is guaranteed for `args`.** Nothing upstream proves an arg value is
secret-free: the checker does not yet walk the entries of a map input such as
`args`, and no production path builds a step's `Inputs` from a `ship.ks` at all.
So this is defence in depth, and the only evidence available is the run's
redactor — the same one every log line goes through, which
`ks_engine::secrets::resolve_step_secrets` registers each resolved secret with
before a step is called. An arg value that redaction *changes* is recorded as
its name with a `null` value; one redaction leaves alone is recorded whole. The
guarantee is therefore "no value the redactor knows is published", fail-closed:
an arg a verifier cannot read costs less than a signed, world-readable referrer
carrying a token. A secret that reached an arg without being registered would not
be caught this way, so the predicate's confidentiality is exactly the
redactor's.

## Where it is attached, and when it is not

The signed envelope is pushed as an OCI referrer whose `subject` is the image
digest, media type `application/vnd.dsse.envelope.v1+json` as both artifact type
and layer media type — OCI 1.1 allows one artifact type per push, so the type
cannot name the predicate — and the annotation `in-toto.io/predicate-type`
recording which predicate it is. A `referrers` listing filters provenance from an
SBOM side by side; the `Registry` port's referrers behaviour is in
[REGISTRIES.md](REGISTRIES.md). The step's `provenance` output is the envelope's
digest, or the empty string when none was attached. A signing or attach failure is
a step failure, not a warning.

A fact is never invented: an attestation naming a commit nobody checked out is
worse than none, because a verifier will believe it. So the attach is skipped,
with the step log naming which one was missing, when the step has no run facts,
no `RunContext` port, no commit, or no git ref — an empty ref would attest to
`uri: "git+"`. An unsigned build never reaches the attach at all. Two limits
follow, both real today:

- **A cache hit produces no new attestation.** A cached step is not run, it is
  restored from its entry, so `oci.image` never reaches the attach.
- **Only the journaled engine path carries the run facts.** The run id and the
  `ship.ks` hash travel through the step's context; a step driven outside a known
  run has none, so it skips. `keepshipping run` drives script steps only and does
  not reach `oci.image` at all yet.

## Against SLSA v1.0 Build

Ids and titles are from the normative
[`requirements.md`](https://github.com/slsa-framework/slsa/blob/v1.0.0/docs/spec/v1.0/requirements.md).
"Follow a consistent build process" and "Distribute provenance" are *unranked*
producer duties: they apply at every Build level rather than distinguishing one.

| Requirement | Level | Status | Why |
| --- | --- | --- | --- |
| Provenance Exists (`provenance-exists`) | L1 | Partly | The engine builds a SLSA v1 statement naming the output by digest and pushes it beside the image. But only against test fakes: the only `Signer` in the tree is `ks-testing`'s `FakeSigner`, which is not cryptography, and the only `ImageBuilder` is `FakeImageBuilder`. No production image carries one. |
| Follow a consistent build process (`follow-a-consistent-build-process`) | unranked | Partly | One build type, one statement shape, one step — as repeatable as the code allows. But there is no builder behind it, so the property has never been observed on a real build. |
| Distribute provenance (`distribute-provenance`) | unranked | Partly | The envelope is discoverable through `referrers` on the registries in [REGISTRIES.md](REGISTRIES.md). It is *not* discoverable by `cosign` — see below. |
| Hosted (`hosted`) | L2 | Not met | A build would run on the runner or laptop that invoked the harness. There is no hosted build platform this project operates. |
| Provenance is Authentic (`provenance-authentic`) | L2 | Not met | The statement is generated in the tenant's own process, not by a platform control plane, and no consumer can verify it: the envelope carries a keyid and signature bytes, with no key and no certificate. |
| Provenance is Unforgeable (`provenance-unforgeable`) | L3 | Not met | Signing material would live in the same CI job as user-defined script steps. Anything the signer can reach, a user step can reach too. |
| Isolated (`isolated`) | L3 | Not met | Same job, same credentials. Secret exposure, cross-build influence and cache poisoning are unaddressed — and with no builder adapter, unassessed rather than merely unimplemented. |

**No SLSA Build level is claimed.** **L1** needs a real `Signer`, the BuildKit
`ImageBuilder` ([#59](https://github.com/Keep-Shipping/harness/issues/59),
[ADR 0010](adr/0010-image-build-backend.md)), `keepshipping run` wired to the
engine with a run context, and one CI-built image whose provenance has been
fetched and read. **L2** needs L1, plus builds on infrastructure this project
controls and provenance from that platform's control plane, verifiable with a key
or a Fulcio certificate. **L3** needs L2, plus signing material a user-defined
build step cannot reach and genuine per-build isolation: fresh environment, no
shared writable cache, no cross-run influence.

## What cosign can and cannot verify today

`cosign verify-attestation` does not pass against anything this project produces,
for three reasons that each suffice alone.

**The type flag.** `--type slsaprovenance` means SLSA **v0.2**
(`https://slsa.dev/provenance/v0.2`), not v1 — cosign's
[`predicate.go`](https://github.com/sigstore/cosign/blob/main/cmd/cosign/cli/options/predicate.go)
maps `PredicateSLSA` and `PredicateSLSA02` to the v0.2 constant in
[in-toto-golang](https://github.com/in-toto/in-toto-golang). SLSA v1 is
`--type slsaprovenance1`, or the full URI verbatim. cosign re-checks the type on
verify and *silently skips* a non-matching attestation, so the wrong flag reports
that none matched rather than that the type was wrong.

**cosign would not find the envelope.** It has two discovery paths: the legacy one
reads a single tag derived from the image digest, `sha256-<hex>.att`, whose layers
are DSSE envelopes; the current one reads referrers and accepts only layers whose
media type starts with `application/vnd.dev.sigstore.bundle` at bundle v0.3 or
later, skipping anything else without comment. That path is the default since
cosign v3.1.1, and v3.1.x falls back to the `.att` tag when it finds no bundles.
What this project writes is a bare DSSE envelope as a referrer — media type
`application/vnd.dsse.envelope.v1+json`, annotation `in-toto.io/predicate-type` —
which is neither, so cosign reports `no valid bundles exist in registry`. It never
reads that annotation; it keys on `predicateType` and `dev.sigstore.bundle.predicateType`.

**There is nothing to verify against.** cosign requires a verification key, or a
Fulcio certificate and its Rekor entry for keyless verification, with
`--certificate-identity{,-regexp}` *and* `--certificate-oidc-issuer{,-regexp}` both
mandatory. Our envelope carries a keyid and a signature and nothing else: no key,
no certificate, no transparency-log entry.

So the command below is what this project *would* have to pass. It is **not yet
passing** — the regexp/issuer pairing is written out here rather than copied from
cosign's own examples, which use the non-regexp form:

```sh
cosign verify-attestation \
  --type slsaprovenance1 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/<org>/<repo>/' \
  <image>@sha256:...
```

## What's next

- A sigstore `Signer` adapter — Fulcio certificate plus a Rekor entry — writing
  an attestation in a cosign-discoverable wire format.
- The BuildKit `ImageBuilder` adapter ([#59](https://github.com/Keep-Shipping/harness/issues/59)),
  blocked on [ADR 0010](adr/0010-image-build-backend.md) being accepted.
- `keepshipping run` driving engine steps such as `oci.image` with ports and a run
  context; the GitHub Actions run context adapter is not wired into it. (Follow-up
  issue.)
- A CI job running `cosign verify-attestation --type slsaprovenance1` against a
  CI-built image, so the claim above is a test result. (Follow-up issue.)