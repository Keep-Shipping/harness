# Deploy verification

A deploy ships an image. The question this harness asks about that image is
never "is it the right one" — the type system already pins that to a digest —
but **"is it signed by somebody we said it would be signed by"**. A workflow
names the identity in a `verify:` input, an environment can insist that every
deploy reaching it does so, and the step refuses to apply an image whose
signature does not match
([#113](https://github.com/Keep-Shipping/harness/issues/113)).

## What a `verify:` says

`k8s.rollout` and `vm.deploy` both take `verify`, a string, defaulting to the
empty string — which means "no verification asked for", not "verification
succeeded".

```
envs:
  dev:
  prod:
    require-verified: true
steps:
  build: oci.image
    from: ./Dockerfile
    push: ghcr.io/acme/api
    sign: true
  deploy: k8s.rollout
    image: build.digest
    verify: "signed-by key:release-key"
```

The value is an identity matcher with a small grammar, the same one
`ks_engine::signing::SignedBy` parses:

- `key:<key-id>` — a named key. The key id must not be empty.
- `<subject> from <issuer>` — a keyless identity: cosign's
  `--certificate-identity` and `--certificate-oidc-issuer`. Both halves are
  required. Half an identity is not an identity, and matching a subject from
  *any* issuer is how a signature gets accepted from somewhere it should not be
  trusted.
- an optional `signed-by ` prefix, so `verify: "signed-by key:release-key"` and
  `verify: "key:release-key"` mean the same thing.

Anything else is refused by the step before it touches anything, naming the
field: a `verify:` the harness cannot satisfy is a failed run, never a skipped
check.

## When the check runs

Before, not after. The deploy verifies the digests it has *resolved but not yet
applied*, so a refusal costs a registry read and changes nothing. This is not
an optimisation — a check that ran after the first apply could only report the
bad deployment, not prevent it.

The images checked are the digest-pinned references the deploy resolved, so
what is verified is exactly what is about to be applied rather than whatever
the file spelled. A tag is refused: verification needs a digest, because a tag
can be repointed between the check and the pull.

`oci.verify` is the same check as a standalone step — it reads one named image
and changes nothing. Use it to inspect an image in a run; use `verify:` on the
deploy to guard one.

## What `require-verified:` adds

`require-verified: true` on an environment turns verification from something a
deploy opts into into something the environment insists on. Every deploy that
can reach that environment and does not declare a usable `verify:` is an error
(`KS0304`) naming both the environment and the step. An empty `verify: ""` does
not count: it is what a deploy that verifies nothing spells.

A step's `when: env is <name>` is what puts it in an environment. **A deploy
with no such gate is in scope for every environment.** The gate is a
declaration of scope; its absence is not an exemption. A deploy that belongs in
`dev` says `when: env is dev`, and that is visible in the file — where
deleting a line to make the check go quiet would not be.

## What this does not do

**It is a client-side pre-flight check, not a control.** `keepshipping check`
and the step's own verification both run on the machine holding the workflow's
credentials. Anyone with a `kubectl` context, a CI token or a deploy script of
their own can roll out an unsigned image without ever going near this harness,
and neither `verify:` nor `require-verified:` will see it. Treat the two as
layers of one defence: this one catches *your* workflows going wrong, including
the workflow an attacker changed without noticing.

Two smaller limits worth being precise about:

- Verification reads the signature from the registry next to the image. It does
  not validate the registry's own transparency log or certificate chain beyond
  what the configured `Signer` port does, and it trusts whatever trust root the
  composition was built with.
- `verify:` covers the images the step knows about. A manifest the step applies
  from disk can name images the step never resolved, and those are outside the
  check.

**This repository has no cluster-side integration.** Nothing here configures
Kyverno, Sigstore policy-controller, or any admission controller, and no
adapter in this workspace talks to one. The manifests below are something you
would write and apply to your own clusters; nothing here keeps them in sync
with your `verify:` values, and a `verify:` change does not update them.

## Mirroring the rule cluster-side

The point of doing it in both places is that the harness check and the
admission check are written twice, so they should be written from the same two
facts: **the digest** the deploy is pinned to, and **the identity matcher** the
workflow names. If those two match what the cluster enforces, a deployment
admitted by somebody else is held to the same rule as one this harness made.

### With Kyverno

`verifyImages` matches on the digest and the identity together. Given
`verify: "signed-by key:release-key"`:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-release-signature
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: signed-by-release-key
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [prod]
      verifyImages:
        - imageReferences: ["ghcr.io/acme/*"]
          # The digest is what gets verified; a tag is not enough, and
          # Kyverno resolves the reference against the registry first.
          attestors:
            - entries:
                - keys:
                    publicKeys: |-
                      -----BEGIN PUBLIC KEY-----
                      ...
                      -----END PUBLIC KEY-----
                    signatureAlgorithm: sha256
```

For a keyless identity, `verifyImages` takes a `certificate` attestor instead of
`publicKeys` — the same subject and issuer the harness matcher names:

```yaml
      verifyImages:
        - imageReferences: ["ghcr.io/acme/*"]
          attestors:
            - entries:
                - keys:
                    subject: "https://github.com/Keep-Shipping/harness/.github/workflows/release.yml@refs/tags/v*"
                    issuer: "https://token.actions.githubusercontent.com"
```

Apply it to every namespace the `prod` environment reaches, and leave staging
out — the harness's scoping decision (`when: env is dev` puts a deploy out of
scope for `prod`) has a direct counterpart in which namespaces carry the
policy.

### With Sigstore policy-controller

policy-controller enforces, in each namespace you label `policy.sigstore.dev/
verify: true`, that images in `ClusterImagePolicy` objects match what their
signatures say. A `ClusterImagePolicy` for the same rule:

```yaml
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: release-signature
spec:
  images:
    - glob: "ghcr.io/acme/**"
  authorities:
    - keyless:
        identities:
          - issuer: https://token.actions.githubusercontent.com
            subject: https://github.com/Keep-Shipping/harness/.github/workflows/release.yml@refs/tags/v*
```

The subject/issuer pair is copied from `verify: "<subject> from <issuer>"`. The
public-key form is a `ctlog`/`key` authority with `key: {}` in place of
`keyless: {}`.

Note what policy-controller does that a pre-flight check cannot: it admits *or
refuses* the admission request, so a `kubectl apply` from a laptop is held to
the same rule as a harness deploy.

### Keeping the two in step

Nothing generates one from the other. The practical arrangement is a single
reviewable place where the identity is written once and both consumers read it —
a values file in the platform repo that renders the Kyverno policy and is
asserted against the `verify:` lines in `ship.ks`. If you want that assertion
in CI, it is a small check of your own: for each environment with
`require-verified: true`, collect the `verify:` values of the deploys that
reach it and compare the set against the identities the cluster policy names.
Until such a check exists, treat a change to `verify:` as a change to the
cluster policy too, and put both in the same pull request.

## Refusals, in the order they happen

| Where | What | Code |
| --- | --- | --- |
| `check` | environment property is not `true`/`false` | `KS0304` |
| `check` | a deploy reaching `require-verified` environment declares no usable `verify:` | `KS0304` |
| `check` | `verify` is not an input of the step kind, or its type is wrong | `KS0101` / unknown input |
| run | `verify` does not parse as an identity matcher | step error, field `verify` |
| run | no registry or no signer port in the composition | step error, port `Registry` / `Signer` |
| run | the image is a tag, not a digest reference | step error, field `verify` |
| run | the signature does not match the named identity | step error, before anything is applied |

The last one is the only one that can be reached by an image the file spelled
correctly and the signer still disagreed about; it fails the run and nothing is
applied.