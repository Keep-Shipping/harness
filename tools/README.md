# tools

Three files behind the documentation site at
[docs.keepshipping.run](https://docs.keepshipping.run).

This is a "Factory Zero" site: it is deployed **by hand**, the same way
`ventures/keepshipping` is. Nothing here runs in CI on a push, and no
credential lives in this repository.

## Build

```sh
python3 tools/site.py --check        # default out: target/docs-site
```

Reads `docs/` and `docs/adr/` and writes a complete static site: `index.html`
(the table of contents), `404.html`, `styles.css`, `sitemap.xml`, `robots.txt`,
`llms.txt`, `llms-full.txt`, and one `.html` per doc. The slug is the
lowercased filename, so `adr/0007-jev.md` is `/adr/0007-jev.html` and a
`README.md` becomes `index.html` in its own directory.

Exit codes are `0` ok, `1` warnings under `--check`, `2` usage or IO. Without
`--check` a warning still prints and the build still exits `0`. Warnings go to
stderr as `site.py: <path>:<line>: warning: ...` and mean: an unclosed code
fence, a local link that resolves to no doc, an unsafe URL scheme (escaped as
text, never emitted as an `href`), or a link to a file that is in neither
`docs/` nor the repository.

`llms.txt` is the index, one line per page. `llms-full.txt` is every page's
markdown concatenated as written, code blocks verbatim. They answer different
questions: what is here, versus all of it in one request.

## Deploy

```sh
tools/deploy.sh --dry-run            # build, gate, verify; no network, no wrangler
tools/deploy.sh --deploy             # the above, then print the wrangler line
tools/deploy.sh --deploy --yes       # actually run wrangler
```

`--branch` defaults to the current git branch, so deploying from a feature
branch is a preview rather than production. `--project` defaults to
`keepshipping-docs`. That Pages project exists on the Factory0 account (production branch
`main`, created as a classic Pages project with
`wrangler pages project create keepshipping-docs --production-branch=main --force`
from an empty directory); `wrangler pages deploy` does not create it.

The output is **deterministic** — no timestamps, no git sha, nothing that
varies between two machines holding the same `docs/`. The site is deployed by
hand and reviewed as a diff; a footer that changes every build turns every
review into noise.

Two steps no script can do, printed at the end of a real deploy: attach the
`docs.keepshipping.run` custom domain to the project in the Cloudflare
dashboard, then — once the domain serves content — add the Docs link to the
landing site in `Keep-Shipping/website`.

## The gate

```sh
cargo test -p ks-testing --test docs_site
```

is what CI runs. It drives `tools/site.py` over the real `docs/` and fails when
the docs drift: a broken cross-link, an unclosed fence, a page missing from
`llms.txt`. Run it before you push a doc change, not only before you deploy.