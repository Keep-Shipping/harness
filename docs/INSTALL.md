# Installing `keepshipping`

A release is four archives, a CycloneDX SBOM beside each of them, one signed
checksum file and the signature on that.
[`install.sh`](../install.sh) does the whole thing — download, verify, install —
and it verifies before it installs, with no flag to make it skip that.

**There is no release yet.** Nothing has been tagged, so the script has nothing
to download: [the README](../README.md) says the same thing about the code. What
is in place is the path a tag takes — [`.github/workflows/release.yml`](../.github/workflows/release.yml)
builds, signs and publishes, and the script and this page are written against
what it publishes. To run Keep Shipping today, build it from source
(`cargo build -p ks-cli --bin keepshipping`).

## What a release contains

| Asset | What it is |
| --- | --- |
| `keepshipping-<version>-<target>.tar.xz` (Linux) or `.tar.gz` (macOS) | The binary, plus `LICENSE` and `README.md`. One directory inside: `keepshipping-<version>/` |
| `keepshipping-<version>-<target>.cdx.json` | A CycloneDX SBOM per target, same basename as the archive it describes |
| `SHA256SUMS` | One `sha256` line per archive *and* per SBOM — eight — sorted by filename, bare filenames, so `sha256sum -c` works from the download directory |
| `SHA256SUMS.bundle` | The cosign signature on `SHA256SUMS`, with the certificate and the transparency-log proof |

That is the whole asset list: ten files. The workflow also writes
`SHA256SUMS.sig` and `SHA256SUMS.pem` — the classic signature pair, for older
`cosign` versions that cannot read a bundle — but they are **not** attached to the
release, so there is nothing to download for them and nothing to verify with them.
The bundle is what ships, and it is what every command below uses.

The four targets are `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
`x86_64-apple-darwin` and `aarch64-apple-darwin`.

## Install with the script

```sh
curl -fsSL https://raw.githubusercontent.com/Keep-Shipping/harness/main/install.sh | sh
```

Piping a download straight into `sh` is the shortest path and the one with the
least review, which is worth weighing against a harness that runs deploys. The
safer form is to read it first — the script is about a hundred and fifty lines of
POSIX sh with no secrets and no writes outside the install directory:

```sh
curl -fsSL -o install.sh https://raw.githubusercontent.com/Keep-Shipping/harness/main/install.sh
less install.sh
sh install.sh
```

Two environment variables:

- `KEEPSHIPPING_VERSION` — a tag (`v0.1.0`) or a version (`0.1.0`). Without it
  the script takes `releases/latest`, which is a redirect, not the API: no token,
  no `jq`.
- `KEEPSHIPPING_INSTALL_DIR` — where the binary goes. `$HOME/.local/bin` by
  default.

The script stops rather than continuing when it cannot check something. There is
no `--skip-verify`: if `cosign` is not on `PATH`, it says so and stops, because
a binary this harness cannot vouch for is not one it should install.

## Verifying by hand

Download the archive, `SHA256SUMS` and `SHA256SUMS.bundle` for your platform, in
one directory:

```sh
TAG=v0.1.0
BASE=https://github.com/Keep-Shipping/harness/releases/download/$TAG
curl -fsSLO "$BASE/keepshipping-0.1.0-x86_64-unknown-linux-gnu.tar.xz"
curl -fsSLO "$BASE/SHA256SUMS"
curl -fsSLO "$BASE/SHA256SUMS.bundle"
```

**1. The signature on `SHA256SUMS`.** [cosign](https://docs.sigstore.dev/cosign/installation/):

```sh
cosign verify-blob \
  --bundle SHA256SUMS.bundle \
  --certificate-identity https://github.com/Keep-Shipping/harness/.github/workflows/release.yml@refs/tags/v0.1.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```

Both flags matter, and together they are the whole of what "this release is
ours" means. `--certificate-identity` is an exact match, not a pattern: it pins
**the repository**, **the workflow file that signed** and **the tag**, so a
signature from another repository, another workflow, or another tag is refused.
`--certificate-oidc-issuer` pins the OIDC issuer to GitHub Actions, which is
what a keyless signature is minted against.

**2. The archive's digest**, against the `SHA256SUMS` you just verified:

```sh
sha256sum --ignore-missing -c SHA256SUMS
```

On macOS: `shasum -a 256 --ignore-missing -c SHA256SUMS`. `--ignore-missing` skips
the lines for platforms you did not download; without it `shasum` fails on the
seven entries you have no file for. GNU `sha256sum` accepts the same flag.

**3. Where the bytes came from** — SLSA build provenance, published by
`actions/attest-build-provenance`. The attestation's subjects are every file named
in `SHA256SUMS`, so the archive and its SBOM are each covered by one statement
about the release:

```sh
gh attestation verify keepshipping-0.1.0-x86_64-unknown-linux-gnu.tar.xz --repo Keep-Shipping/harness
```

The SBOM for the same archive is next to it on the release page,
`keepshipping-0.1.0-x86_64-unknown-linux-gnu.cdx.json` — CycloneDX, readable with
any SBOM viewer.

## Windows

There is no Windows build. The script says so and stops rather than guessing a
target that was never published; use WSL, or build from source.