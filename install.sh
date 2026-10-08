#!/bin/sh
# install.sh — install a released `keepshipping`, verified before it is installed.
#
# A release signs exactly one file, SHA256SUMS, with cosign keyless, and every
# archive is named in it. So the order here is fixed: prove the signature on
# SHA256SUMS first, then prove the archive matches its line in that file, and
# only then unpack anything. There is no --skip-verify and no "cosign is not
# installed, carry on" path: a binary whose origin cannot be checked is not
# installed, because a harness that runs other people's deploys should not
# start by trusting an unverified download of itself.
#
#   curl -fsSL https://raw.githubusercontent.com/Keep-Shipping/harness/main/install.sh | sh
#   KEEPSHIPPING_VERSION=v0.1.0 sh install.sh
#
# KEEPSHIPPING_VERSION    a tag (`v0.1.0`) or version (`0.1.0`); default: latest
# KEEPSHIPPING_INSTALL_DIR  where the binary goes; default: $HOME/.local/bin
#
# docs/INSTALL.md spells the same steps out by hand for people who would rather
# read a download than pipe one.

set -eu

REPO='Keep-Shipping/harness'
ISSUER='https://token.actions.githubusercontent.com'
RELEASES="https://github.com/$REPO/releases"
WORKFLOW='.github/workflows/release.yml'

die() {
    printf 'install.sh: %s\n' "$*" >&2
    exit 1
}

# --- what are we installing on? ------------------------------------------------
# The four targets release.yml builds, and nothing else. Windows is not built
# yet, and saying so plainly beats a target triple that 404s later.
uname_s=$(uname -s)
uname_m=$(uname -m)
case "$uname_m" in
    x86_64 | amd64) arch=x86_64 ;;
    aarch64 | arm64) arch=aarch64 ;;
    *) die "unsupported architecture '$uname_m'. Keep Shipping ships x86_64 and aarch64; see docs/INSTALL.md." ;;
esac
case "$uname_s" in
    Linux) target="$arch-unknown-linux-gnu"; archive_ext=tar.xz ;;
    Darwin) target="$arch-apple-darwin"; archive_ext=tar.gz ;;
    MINGW* | MSYS* | CYGWIN* | Windows_NT)
        die "Windows is not built yet. Keep Shipping releases macOS and Linux binaries; see docs/INSTALL.md."
        ;;
    *) die "unsupported operating system '$uname_s'. Keep Shipping ships macOS and Linux binaries; see docs/INSTALL.md." ;;
esac

# --- which version? -------------------------------------------------------------
# `latest` is the redirect of /releases/latest, not the API: no token, no jq.
wanted=${KEEPSHIPPING_VERSION:-${1:-}}
if [ -z "$wanted" ]; then
    latest_url=$(
        if command -v curl >/dev/null 2>&1; then
            curl --proto '=https' --tlsv1.2 -fsSL -o /dev/null -w '%{url_effective}' "$RELEASES/latest"
        else
            # Without following redirects, wget reports the target as a Location header.
            wget -q -O /dev/null --max-redirect=0 "$RELEASES/latest" 2>&1 |
                sed -n 's/^[Ll]ocation:[[:space:]]*//p' | tr -d '\r\n'
        fi
    ) || die "could not resolve the latest release from $RELEASES/latest"
    wanted=${latest_url%/}
    wanted=${wanted##*/}
fi
case "$wanted" in
    v*) tag=$wanted ;;
    *) tag="v$wanted" ;;
esac
version=${tag#v}
archive="keepshipping-$version-$target.$archive_ext"
# The identity cosign binds the signature to: this repository, this workflow
# file, this tag. Not a regex, not a prefix — the exact string.
identity="https://github.com/$REPO/$WORKFLOW@refs/tags/$tag"

# --- download to a scratch directory -------------------------------------------
tmp=$(mktemp -d "${TMPDIR:-/tmp}/keepshipping-install.XXXXXX") || die 'could not create a temporary directory'
cleanup() { rm -rf "$tmp" || true; }
trap cleanup 0 1 2 15

fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl --proto '=https' --tlsv1.2 -fsSL "$1" -o "$2" || die "could not download $1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q --https-only "$1" -O "$2" || die "could not download $1"
    else
        die 'neither curl nor wget is on PATH; install one and re-run'
    fi
}

printf 'keepshipping %s (%s)\n' "$tag" "$target"
fetch "$RELEASES/download/$tag/$archive" "$tmp/$archive"
fetch "$RELEASES/download/$tag/SHA256SUMS" "$tmp/SHA256SUMS"
fetch "$RELEASES/download/$tag/SHA256SUMS.bundle" "$tmp/SHA256SUMS.bundle"

# --- 1. the signature on SHA256SUMS --------------------------------------------
command -v cosign >/dev/null 2>&1 ||
    die 'cosign is not on PATH, and without it nothing below can be checked.
Install it (https://docs.sigstore.dev/cosign/installation/) and re-run; the
manual steps are in docs/INSTALL.md. There is no way to skip this.'
cosign verify-blob \
    --bundle "$tmp/SHA256SUMS.bundle" \
    --certificate-identity "$identity" \
    --certificate-oidc-issuer "$ISSUER" \
    "$tmp/SHA256SUMS" ||
    die "SHA256SUMS is not signed by $identity.
The release is not this repository's, or the download was tampered with. Stop."

# --- 2. the archive's digest ---------------------------------------------------
if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$tmp/$archive" | cut -d' ' -f1)
elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$tmp/$archive" | cut -d' ' -f1)
else
    die 'neither sha256sum nor shasum is on PATH; the digest cannot be checked'
fi
expected=$(awk -v f="$archive" '{ n = $2; sub(/^\*/, "", n); if (n == f) print $1 }' "$tmp/SHA256SUMS")
[ -n "$expected" ] ||
    die "SHA256SUMS lists no line for $archive; not installing an unlisted file"
[ "$actual" = "$expected" ] ||
    die "checksum mismatch for $archive
expected $expected
actual   $actual
The archive does not match the signed checksum file. Stop."

# --- 3. install ----------------------------------------------------------------
install_dir=${KEEPSHIPPING_INSTALL_DIR:-$HOME/.local/bin}
mkdir -p "$install_dir"
mkdir -p "$tmp/unpack"
tar -xf "$tmp/$archive" -C "$tmp/unpack" || die "could not unpack $archive"
src="$tmp/unpack/keepshipping-$version/keepshipping"
[ -f "$src" ] || die "$archive does not contain keepshipping-$version/keepshipping"
dest="$install_dir/keepshipping"
if command -v install >/dev/null 2>&1; then
    install -m 0755 "$src" "$dest" || die "could not write $dest"
else
    cp "$src" "$dest" || die "could not write $dest"
    chmod 0755 "$dest" || die "could not chmod $dest"
fi

printf 'Installed keepshipping %s to %s\n' "$version" "$dest"
# shellcheck disable=SC2016  # $PATH is text to print, not this script's PATH.
printf 'If that directory is not on your PATH: export PATH="%s:$PATH"\n' "$install_dir"