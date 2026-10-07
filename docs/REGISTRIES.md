# Registries

Which OCI registries the `Registry` adapter
([#60](https://github.com/Keep-Shipping/harness/issues/60)) has actually been
run against, and what each one exercised.

The rule underneath this file: **an untested registry is an untested
registry.** The rows below marked *not tested* are not slow, not planned and
not "should work" — nothing in this repository has pushed a byte to them. If
your registry is not in a *tested* row, the adapter is a reasonable bet, not a
promise.

## What "tested" means

Tested means the `registry_conformance` kit from `ks-testing` ran, unchanged,
against a real registry through the real adapter and passed
(`adapters/oci-distribution/tests/conformance.rs`). The kit pushes a small but
genuinely valid OCI layout — an image manifest over the empty config `{}` and
one layer, real registry schema validation or it would answer 400 — and then
checks:

- the pushed layout comes back **byte-for-byte** under the digest of its exact
  manifest bytes;
- an artifact pushed against that layout as a `subject` pulls back with a
  descriptor digest equal to SHA-256 of the pulled bytes, computed
  independently of the adapter, and a matching `size`;
- `exists` agrees right after a push, and a digest nothing pushed is
  `NotFound` — not an error, not a guess;
- `referrers` lists the artifact under its subject, and nothing under an unused
  digest;
- a tagged reference resolves to the tagged digest, and an unknown tag is
  `NotFound`.

A row marked *tested* is a row where all of that passed on that registry at that
version, over plain HTTP, anonymously. It says nothing about TLS termination,
rate limits, or anything the kit does not exercise.

## The matrix

| Registry | Version | Auth tested | Referrers path | Where tested | Status |
| --- | --- | --- | --- | --- | --- |
| [zot](https://github.com/project-zot/zot) | v2.1.22 | anonymous | native `/v2/<name>/referrers` | CI (`registry-conformance` job) and local | tested |
| [distribution](https://github.com/distribution/distribution) | 2.8.3 | anonymous in CI; Basic via Docker `auths` in a local probe | fallback: `sha256-<hex>` tag schema (`/v2/<name>/referrers` 404s) | CI (`registry-conformance` job) and local | tested |
| GHCR (`ghcr.io`) | — | — | — | — | not tested — needs a maintainer with an account |
| Docker Hub (`registry-1.docker.io`) | — | — | — | — | not tested — needs a maintainer with an account |
| Amazon ECR | — | — | — | — | not tested — needs AWS credentials |
| Google Artifact Registry | — | — | — | — | not tested — needs GCP credentials |
| Azure Container Registry | — | — | — | — | not tested — needs Azure credentials |
| Harbor | — | — | — | — | not tested — needs a running instance |

The two distribution-spec registries differ in exactly the way that matters
here, which is why both are in CI. zot serves the referrers API the OCI
distribution spec defines. distribution 2.8.3 answers `404`, and the adapter
falls back to the conventional `sha256-<hex>` fallback tag; both paths are
therefore covered by the CI run.

## Authentication

Supported:

- **Anonymous.** No credentials; what a local registry usually wants.
- **Basic challenges.** A `401` carrying `WWW-Authenticate: Basic realm="…"` is
  answered with the stored username and password on one retry.
- **Bearer challenges.** The distribution-spec token dance: the realm, service
  and scope are parsed out of `WWW-Authenticate: Bearer …`, a token is fetched
  from the realm, and the request is retried with it. Tokens are cached per
  host and scope.
- **Docker `config.json` `auths`.** `CredentialStore::from_config_json` reads the
  same `auths` block `docker login` writes, including the base64 `auth` form.

Not supported yet:

- **Credential helpers.** `credHelpers` and `credsStore` shell out to another
  program. A host served by one is an **error**, not an anonymous push — a
  silent anonymous write would be worse than a clear failure. Use a plain
  `auths` entry, or set the credentials explicitly.
- **OIDC → registry-token exchange.** GHCR, ECR and GAR all hand out short-lived
  tokens in exchange for a workload identity; none of that is implemented. This
  is what the four untested cloud rows above are waiting on.
- **Cross-repository blob mount.** Blobs are uploaded into the repository they
  belong to, always. Mounting a blob from another repository would need the
  mount header and the permissions to read the source.
- **The bearer flow has not been run against a registry that issues tokens.**
  It is covered by unit and adapter tests against a fake token server, not by
  the CI job above.

## Running it yourself

The test is skipped when `KS_OCI_CONFORMANCE_REGISTRIES` is unset, which is the
case in `cargo test --workspace` — an ordinary test run stays service-free. To
run it, point it at any registries you have:

```sh
KS_OCI_CONFORMANCE_REGISTRIES=localhost:5001,localhost:5002 \
  cargo test -p ks-oci-distribution --test conformance -- --nocapture
```

Each entry is a `host:port`, comma-separated, spoken to over **plain HTTP**
(the test names the hosts insecure, which is what makes the adapter use `http:`
rather than `https:`). Each registry gets its own repository,
`<host>/conformance/app`, so the run is self-contained and repeatable.

The CI job starts both registries as service containers, which is the quickest
way to get them:

```sh
docker run --rm -p 5001:5000 ghcr.io/project-zot/zot-linux-amd64:v2.1.22
docker run --rm -p 5002:5000 registry:2.8.3
```

## Adding a registry to the matrix

1. Run the kit against it and make it pass, as above.
2. Add a row: registry, version, auth, referrers path, where, status. If the
   referrers API 404s, say so — the fallback is a feature, not a workaround to
   hide.
3. If it is a service container, add it to the `registry-conformance` job in
   `.github/workflows/ci.yml` (pinned by tag **and** digest) with its own mapped
   port, and add it to `KS_OCI_CONFORMANCE_REGISTRIES`.
4. If it needs an account, the row stays *not tested* with the reason. Say what
   it would take — that is the useful part for the next person.

The claim this project makes is exactly the tested rows. Everything else is
listed so the gap is visible, not so it looks closed.