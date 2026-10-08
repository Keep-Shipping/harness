#!/usr/bin/env bash
# Install one pinned keepshipping release: fetch, verify, then install, in that
# order. Nothing reaches the install directory unless every check passed, and
# every refusal is a non-zero exit with a message naming the fix.
#
# Inputs arrive through the environment, never as arguments: the composite action
# passes workflow inputs as `env:`, which keeps a `version` of `1.2.3; rm -rf /` a
# value rather than code.
#
#   KS_VERSION          required. An exact version: 1.2.3 or 1.2.3-rc.1.
#   KS_BASE_URL         optional. Defaults to the release download URL for the tag
#                       v<version>; `file://` works, which is how the test drives it.
#   KS_INSTALL_DIR      optional. Defaults to $RUNNER_TOOL_CACHE/keepshipping, else
#                       $HOME/.keepshipping/bin.
#   KS_VERIFY_SIGNATURE optional, default "true". Verify SHA256SUMS with cosign.
#   GH_TOKEN            optional. Bearer token, sent only to github.com URLs.
#
# docs/GITHUB_ACTIONS.md says what this verifies and what it does not.
set -euo pipefail

# The repository whose release workflow is the only identity trusted here. Not an
# input: a variable naming it would name what gets trusted too.
readonly REPO="Keep-Shipping/harness"
readonly ISSUER="https://token.actions.githubusercontent.com"

die() {
  echo "error: $*" >&2
  exit 1
}

# An exact version, or nothing. `latest` is refused by name: a CI job that installs
# "whatever is newest" is not reproducible, and the lockfile has no pin to read.
case "${KS_VERSION:-}" in
  '' | latest | Latest | LATEST)
    die "KS_VERSION must be an exact version (1.2.3, or 1.2.3-rc.1), not empty and not 'latest'."
    ;;
esac
[[ "$KS_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+(\.[0-9A-Za-z-]+)*)?$ ]] \
  || die "KS_VERSION='$KS_VERSION' is not an exact version. Fix: pass 1.2.3 or 1.2.3-rc.1."
readonly VERSION="$KS_VERSION"
readonly TAG="v$VERSION"

# The release triple, as release.yml spells it. A name the release matrix does
# not build is refused here rather than 404'd on download.
detect_target() {
  case "$(uname -s):$(uname -m)" in
    Darwin:arm64 | Darwin:aarch64) echo "aarch64-apple-darwin" ;;
    Darwin:x86_64 | Darwin:amd64) echo "x86_64-apple-darwin" ;;
    Linux:aarch64 | Linux:arm64) echo "aarch64-unknown-linux-gnu" ;;
    Linux:x86_64 | Linux:amd64) echo "x86_64-unknown-linux-gnu" ;;
    *) echo "" ;;
  esac
}

TARGET="$(detect_target)"
readonly TARGET
[ -n "$TARGET" ] \
  || die "no keepshipping release is built for $(uname -s)/$(uname -m). Fix: run this on macOS or Linux."

# release.yml picks the archive format per runner: tar.gz on macOS, tar.xz on Linux.
case "$TARGET" in
  *-apple-darwin) readonly EXT="tar.gz" ;;
  *-linux-gnu) readonly EXT="tar.xz" ;;
  *) die "unknown target '$TARGET': expected one of the four triples release.yml builds." ;;
esac
readonly ARCHIVE="keepshipping-$VERSION-$TARGET.$EXT"
# The archive's top directory, as release.yml stages it. Not a glob.
readonly UNPACK_DIR="keepshipping-$VERSION"

BASE_URL="${KS_BASE_URL:-https://github.com/$REPO/releases/download/$TAG}"
# A trailing slash would make every join produce a double slash.
readonly BASE_URL="${BASE_URL%/}"

if [ -n "${RUNNER_TOOL_CACHE:-}" ]; then
  INSTALL_DIR="${KS_INSTALL_DIR:-$RUNNER_TOOL_CACHE/keepshipping}"
else
  INSTALL_DIR="${KS_INSTALL_DIR:-${HOME:-/tmp}/.keepshipping/bin}"
fi
readonly INSTALL_DIR

verify="${KS_VERIFY_SIGNATURE:-true}"
case "$verify" in
  true | True | TRUE | 1) readonly VERIFY=true ;;
  false | False | FALSE | 0) readonly VERIFY=false ;;
  *) die "KS_VERIFY_SIGNATURE='$verify' is neither true nor false." ;;
esac

WORK="$(mktemp -d "${TMPDIR:-/tmp}/keepshipping-install.XXXXXX")"
STAGED=""
cleanup() {
  if [ -n "$STAGED" ]; then rm -f "$STAGED"; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# `curl` with retries: a runner's network blips. `file://` goes through curl too,
# so the test exercises this function rather than a second code path.
download() {
  local url="$1" dest="$2"
  local -a header=()
  # A private release needs a token. `-L` without `--location-trusted` already drops
  # the header on a redirect; the case below refuses to attach it anywhere else.
  if [ -n "${GH_TOKEN:-}" ]; then
    case "$url" in
      https://github.com/*) header=(-H "Authorization: Bearer $GH_TOKEN") ;;
    esac
  fi
  curl -fsSL --retry 3 --retry-delay 1 --retry-connrefused "${header[@]}" \
    -o "$dest" "$url" \
    || die "could not download $url. Fix: check the version and that the release $TAG is published."
}

echo "keepshipping $VERSION for $TARGET ($EXT)"

download "$BASE_URL/$ARCHIVE" "$WORK/$ARCHIVE"
download "$BASE_URL/SHA256SUMS" "$WORK/SHA256SUMS"

# The digest of exactly this filename, matched on the whole name: a grep for
# `keepshipping-1.2.3` matches all four archives in the file. Two lines for one name
# is a release that disagrees with itself, so it is refused, not guessed at.
sums="$(awk -v want="$ARCHIVE" '$2 == want || $2 == "*" want { print $1 }' "$WORK/SHA256SUMS")"
matches="$(printf '%s\n' "$sums" | awk 'NF { n++ } END { print n + 0 }')"
[ "$matches" -gt 0 ] \
  || die "SHA256SUMS from $BASE_URL names no '$ARCHIVE'. Fix: check the release has an archive for $TARGET."
[ "$matches" -eq 1 ] \
  || die "SHA256SUMS from $BASE_URL names '$ARCHIVE' $matches times. Fix: a release publishes one archive per target; do not guess which line is meant."
want="$sums"

have="$(
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$WORK/$ARCHIVE" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$WORK/$ARCHIVE" | cut -d' ' -f1
  else
    die "neither sha256sum nor shasum is on PATH. Fix: install coreutils (or perl, which ships shasum) on this runner."
  fi
)"
[ "$have" = "$want" ] \
  || die "checksum mismatch for $ARCHIVE: SHA256SUMS says $want, the download is $have. Fix: nothing was installed; re-run, and if it repeats treat the download as tampered."
echo "checksum: $have (matches SHA256SUMS)"

# The signature covers SHA256SUMS, not the archive, so it is verified once the
# checksums file is in hand and before anything is unpacked.
if [ "$VERIFY" = true ]; then
  command -v cosign >/dev/null 2>&1 \
    || die "KS_VERIFY_SIGNATURE=true but cosign is not on PATH. Fix: add the sigstore/cosign-installer step before this one, or set KS_VERIFY_SIGNATURE=false knowing nothing then proves the release came from this project."
  download "$BASE_URL/SHA256SUMS.bundle" "$WORK/SHA256SUMS.bundle"
  # Keyless: the identity is the release workflow at the tag this version came from.
  # Any other identity — a fork, another tag, a hand-run — is a failure, which is the
  # point.
  cosign verify-blob \
    --bundle "$WORK/SHA256SUMS.bundle" \
    --certificate-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$TAG" \
    --certificate-oidc-issuer "$ISSUER" \
    "$WORK/SHA256SUMS" \
    || die "cosign could not verify SHA256SUMS as signed by $REPO's release workflow at refs/tags/$TAG. Fix: nothing was installed; check the tag was cut by that workflow."
  echo "signature: cosign keyless, $REPO/.github/workflows/release.yml@refs/tags/$TAG"
else
  echo "signature: NOT verified (KS_VERIFY_SIGNATURE=false). No authenticity check ran: SHA256SUMS came from the same place as the archive, so it catches corruption, not substitution."
fi

# Unpack into the work directory first, so an archive that does not hold the
# expected layout never reaches the install path.
mkdir -p "$WORK/unpack"
tar -xf "$WORK/$ARCHIVE" -C "$WORK/unpack" --no-same-owner \
  || die "could not unpack $ARCHIVE. Fix: the download may be truncated; nothing was installed."
member="$WORK/unpack/$UNPACK_DIR/keepshipping"
[ -f "$member" ] \
  || die "$ARCHIVE holds no $UNPACK_DIR/keepshipping. Fix: check the archive layout in release.yml; nothing was installed."
# A symlink here would make the install a write to wherever it points, which
# the checksum says nothing about.
if [ -L "$member" ]; then
  die "$UNPACK_DIR/keepshipping in $ARCHIVE is a symlink. Fix: nothing was installed; treat the archive as not the one this release published."
fi

mkdir -p "$INSTALL_DIR"
# Stage under a fresh name and rename into place: `cp` over an existing
# `keepshipping` symlink writes through it, and a rename does not.
staged="$INSTALL_DIR/.keepshipping.install.$$"
STAGED="$staged"
cp "$member" "$staged"
chmod +x "$staged"
mv -f "$staged" "$INSTALL_DIR/keepshipping"

echo "installed: $INSTALL_DIR/keepshipping"
# keepshipping has no --version yet, so nothing reads the version back off the
# installed file; what is proven is the checksum and, when asked, the signature.
echo "not checked: the binary's own version — keepshipping has no --version yet."

# Put the install directory on PATH for the rest of the job: a runner only reads
# this file between steps, which is what a composite action needs.
if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$INSTALL_DIR" >>"$GITHUB_PATH"
  echo "path: $INSTALL_DIR (added to GITHUB_PATH)"
fi