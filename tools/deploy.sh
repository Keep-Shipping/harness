#!/usr/bin/env bash
#
# Build the docs site from docs/ and, only when told to, publish it to
# Cloudflare Pages (issue #143). A "Factory Zero" site: deployed BY HAND, not
# from CI. A tag cutting a binary is not the same act as putting words on the
# public internet, and the person publishing should be the person who read the
# diff.
#
# There is no credential in this file and there never will be. `wrangler` owns
# authentication; this script decides what to hand it, and hands it nothing
# until the build has passed the same gate CI applies.
#
# The build must stay deterministic (no timestamps, no git sha) so the bytes
# served for a given docs/ tree are the same on every machine. That is what
# makes a deploy reviewable rather than mysterious.

set -euo pipefail

# Resolve the repository root from this script's own location, not from $PWD:
# the operator runs this from wherever they are, and a half-built site is a
# confusing way to learn the wrong docs/ was read. Symlinks are followed
# because a symlinked deploy.sh on PATH is ordinary, and `dirname "$0"` would
# then point at the link's directory and report tools/site.py missing.
script="${BASH_SOURCE[0]}"
while [ -L "$script" ]; do
  dir="$(cd -P "$(dirname "$script")" && pwd)"
  script="$(readlink "$script")"
  case "$script" in /*) ;; *) script="$dir/$script" ;; esac
done
ROOT="$(cd -P "$(dirname "$script")/.." && pwd)"
cd "$ROOT"

readonly PROJECT_DEFAULT="keepshipping-docs"
readonly OUT_DEFAULT="target/docs-site"
readonly DOMAIN="docs.keepshipping.run"

# Files without which the output is not a site. A deploy that ships no
# sitemap.xml is "successful" as far as Pages is concerned, which is exactly
# why this check lives here rather than upstream.
readonly REQUIRED=(index.html llms.txt llms-full.txt sitemap.xml styles.css)

DRY_RUN=1
YES=0
PROJECT="$PROJECT_DEFAULT"
OUT="$OUT_DEFAULT"
BRANCH=""

usage() {
  cat <<EOF
usage: tools/deploy.sh [--dry-run | --deploy [--yes]] [options]

  --dry-run          build and verify only (default; no network, no wrangler)
  --deploy           build, verify, then publish to Cloudflare Pages
  --yes              with --deploy, actually run wrangler instead of printing it
  --project NAME     Cloudflare Pages project (default: $PROJECT_DEFAULT)
  --out DIR          build output (default: $OUT_DEFAULT)
  --branch NAME      Pages branch (default: the current git branch)
  --help             this text

Publishing $DOMAIN is two manual steps no script can do; they are printed
at the end of a real deploy.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --deploy) DRY_RUN=0 ;;
    --yes) YES=1 ;;
    --project) PROJECT="${2:?--project needs a name}"; shift ;;
    --out) OUT="${2:?--out needs a directory}"; shift ;;
    --branch) BRANCH="${2:?--branch needs a name}"; shift ;;
    --help | -h) usage; exit 0 ;;
    *) echo "deploy.sh: unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [ "$BRANCH" = "" ]; then
  BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo main)"
fi

# Build under --check and tell a warning from a crash: the generator exits 1
# for warnings, 2 for usage/IO, and the word "warning:" only appears on the
# former. Anything else is a build that did not happen.
echo "deploy.sh: building $OUT from docs/ (branch $BRANCH)"
LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT
set +e
python3 tools/site.py --docs docs --out "$OUT" --check 2>&1 | tee "$LOG"
STATUS="${PIPESTATUS[0]}"
set -e

if [ "$STATUS" -ne 0 ] && ! grep -q 'warning:' "$LOG"; then
  echo "deploy.sh: the generator failed (exit $STATUS); nothing published" >&2
  exit "$STATUS"
fi
if [ "$STATUS" -ne 0 ]; then
  echo "deploy.sh: docs/ has warnings; fix them before publishing" >&2
  exit 1
fi

# Pages will happily serve a directory that is not a site. Check it is one.
for file in "${REQUIRED[@]}"; do
  [ -s "$OUT/$file" ] || { echo "deploy.sh: $OUT/$file is missing or empty" >&2; exit 1; }
done
PAGES=$(find "$OUT" -name '*.html' ! -name 'index.html' ! -name '404.html' | wc -l | tr -d ' ')
[ "$PAGES" -ge 1 ] || { echo "deploy.sh: $OUT holds no page besides index.html" >&2; exit 1; }
echo "deploy.sh: $PAGES pages, $(find "$OUT" -type f | wc -l | tr -d ' ') files"

if [ "$DRY_RUN" -eq 1 ]; then
  echo "deploy.sh: dry run ok. Nothing was sent anywhere."
  exit 0
fi

command -v wrangler >/dev/null 2>&1 || {
  echo "deploy.sh: wrangler is not on PATH. Install it with 'npm i -g wrangler'." >&2
  exit 1
}

CMD=(wrangler pages deploy "$OUT" "--project-name=$PROJECT" "--branch=$BRANCH")
if [ "$YES" -ne 1 ]; then
  echo "deploy.sh: would run: ${CMD[*]}"
  echo "deploy.sh: re-run with --yes to publish."
  exit 0
fi
"${CMD[@]}"

cat <<EOF

deploy.sh: published. Two steps no script can do:
  1. Attach the $DOMAIN custom domain to the $PROJECT project in the
     Cloudflare dashboard (Workers & Pages -> $PROJECT -> Custom domains).
  2. Once the domain serves content, add the Docs link to the landing site in
     Keep-Shipping/website.
EOF