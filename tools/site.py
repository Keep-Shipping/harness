#!/usr/bin/env python3
"""Build the static documentation site for docs.keepshipping.run.

Reads the markdown under docs/, renders one HTML page per source, and writes
llms.txt / llms-full.txt so an agent can read the docs in one request instead
of following links.

    python3 tools/site.py [--docs DIR] [--out DIR] [--check] [--verbose]

Exit codes: 0 clean; 1 warnings were emitted and --check was on (without
--check the warnings still print and the build still succeeds); 2 usage or IO.

The output is byte-for-byte deterministic: no timestamp, no git sha, no build
date anywhere. The site is deployed by hand and reviewed as a diff, and a
footer that changes every run turns every review into noise. Anything from the
machine rather than from docs/ would break that, so the base URL is the one
host constant here, written down rather than discovered.

Standard library only: this runs on a contributor's laptop with nothing
installed but python3.
"""

from __future__ import annotations

import argparse
import html
import posixpath
import re
import sys
from bisect import bisect_right
from pathlib import Path

BASE_URL = "https://docs.keepshipping.run"
REPO_BLOB = "https://github.com/Keep-Shipping/harness/blob/main"
TITLE, TAGLINE = "Keep Shipping", "documentation"
DESCRIPTION = (
    "How the Keep Shipping harness is put together: the site-file language, the command "
    "line, the ports and adapters, the diagnostics, and the decisions behind them."
)

# Group labels for the directories we know, read as directory prefixes. Not a
# page list: the whole tree is read at run time, so a doc added to docs/ -- or a
# new subdirectory of docs/ -- appears without touching this file. A directory
# not named here becomes its own group, labelled after the directory and listed
# after these, so nothing under docs/ is ever left off the site.
GROUPS = (("Guides", ""), ("Decisions", "adr/"), ("Research", "research/"))


def group_of(rel: str) -> str:
    """The group a doc belongs to: the label of its top-level directory."""
    top = rel.split("/", 1)[0] + "/" if "/" in rel else ""
    for label, prefix in GROUPS:
        if prefix == top:
            return label
    return top.rstrip("/").replace("-", " ").replace("_", " ").capitalize()


def group_order(pages: list[dict]) -> list[str]:
    """Known groups in GROUPS order, then any others alphabetically."""
    known = [label for label, _ in GROUPS]
    extra = sorted({page["group"] for page in pages} - set(known))
    return known + extra

FENCE = re.compile(r"^```(\S*)\s*$")
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
BULLET = re.compile(r"^(\s*)([-*+]|\d+[.)])\s+(.*)$")
HR = re.compile(r"^(?:-{3,}|\*{3,}|_{3,})$")
DELIM_ROW = re.compile(r"^\|?[\s:|-]*-{2,}[\s:|-]*\|?$")
SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
# Inline markdown, in the order a match is tried at each position.
#
# A code span opens on a run of backticks and closes on a run of the same
# length, so ``a ` b`` works: `docs/` uses that to quote a snippet which itself
# contains backticks. A span body is literal -- a backslash inside it is not an
# escape -- so `\`x\`` closes at the first backtick, as CommonMark says it does.
INLINE = re.compile(r"(`+)(.+?)\1|\[([^\]]*)\]\(([^)\s]+)\)|\*\*([^*]+)\*\*|\*([^*]+)\*")

STYLES = """\
/* Matches keepshipping.run: Bricolage Grotesque + DM Mono, the same ink,
   paper and blue, square marks, a dark footer. */
:root { --ink: oklch(0.2 0.02 262); --paper: oklch(0.955 0.004 255);
        --blue: oklch(0.48 0.2 263); --muted: oklch(0.45 0.02 262);
        --rule: oklch(0.86 0.008 262); --code: oklch(0.915 0.006 262);
        --mono: 'DM Mono', ui-monospace, monospace; }
* { box-sizing: border-box; }
html, body { margin: 0; background: var(--paper); color: var(--ink);
             -webkit-font-smoothing: antialiased; }
body { font: 17px/1.6 'Bricolage Grotesque', system-ui, sans-serif;
       min-height: 100vh; display: flex; flex-direction: column; }
a { color: var(--blue); text-underline-offset: 3px; }
a:hover { color: var(--ink); }
::selection { background: var(--blue); color: #fff; }
.skip { position: absolute; left: -9999px; top: 8px; padding: 8px 12px;
        background: var(--ink); color: #fff; z-index: 10; }
.skip:focus { left: 8px; }
.top { max-width: 1240px; width: 100%; margin: 0 auto;
       padding: 20px clamp(20px,5vw,48px); display: flex; align-items: center;
       justify-content: space-between; gap: 16px; flex-wrap: wrap; }
.brand { display: flex; align-items: center; gap: 10px; text-decoration: none;
         color: var(--ink); font-weight: 800; font-size: 19px; letter-spacing: -0.02em; }
.brand:hover { color: var(--ink); }
.brand i { width: 14px; height: 14px; background: var(--blue); display: block; }
.brand span { font: 500 14px var(--mono); color: var(--muted); letter-spacing: 0; }
.top nav { display: flex; align-items: center; gap: 22px; font: 14px var(--mono); }
.top nav a { color: var(--ink); text-decoration: none; }
.top nav a:hover { text-decoration: underline; }
.top nav a.cta { color: #fff; background: var(--ink); padding: 9px 14px; }
.top nav a.cta:hover { background: var(--blue); text-decoration: none; }
.wrap { max-width: 1240px; width: 100%; margin: 0 auto; flex: 1;
        padding: clamp(16px,3vw,32px) clamp(20px,5vw,48px) clamp(56px,8vw,112px);
        display: grid; grid-template-columns: 250px minmax(0,1fr); gap: clamp(28px,4vw,64px); }
.side { font: 13.5px/1.45 var(--mono); position: sticky; top: 20px; align-self: start;
        max-height: calc(100vh - 40px); overflow-y: auto; padding-right: 8px; }
.back { display: none; font: 14px var(--mono); margin: 0 0 20px; }
.side h2 { font: 500 12px var(--mono); text-transform: uppercase; letter-spacing: .08em;
           color: var(--muted); margin: 22px 0 8px; }
.side h2:first-of-type { margin-top: 0; }
.side ul { list-style: none; margin: 0; padding: 0; }
.side li { margin: 0; }
.side a { display: block; padding: 4px 0 4px 10px; border-left: 2px solid transparent;
          color: var(--ink); text-decoration: none; }
.side a:hover { border-left-color: var(--rule); }
.side a[aria-current="page"] { border-left-color: var(--blue); color: var(--blue); }
main { min-width: 0; max-width: 46rem; }
h1, h2, h3, h4 { line-height: 1.15; letter-spacing: -0.02em; margin: 2.2rem 0 .7rem; }
h1 { margin-top: 0; font-weight: 800; font-size: clamp(36px,5vw,56px); letter-spacing: -0.045em; line-height: 1; }
h2 { font-weight: 700; font-size: 28px; } h3 { font-size: 21px; } h4 { font-size: 18px; }
li { margin: .25rem 0; }
code { font: .86em var(--mono); background: var(--code); padding: .1em .35em; }
pre { background: var(--ink); color: oklch(0.93 0.005 262); padding: 16px 18px;
      overflow-x: auto; font-size: 14px; line-height: 1.7; }
pre code { background: none; padding: 0; color: inherit; font-size: inherit; }
table { border-collapse: collapse; width: 100%; margin: 1.2rem 0; font-size: 15px;
        display: block; overflow-x: auto; }
th, td { border-bottom: 1px solid var(--rule); padding: .5rem .7rem .5rem 0;
         text-align: left; vertical-align: top; }
th { font: 500 13px var(--mono); text-transform: uppercase; letter-spacing: .05em;
     color: var(--muted); border-bottom: 2px solid var(--ink); }
blockquote { margin: 1.2rem 0; padding: .2rem 1.1rem; border-left: 4px solid var(--blue);
             background: #fff; }
hr { border: 0; border-top: 1px solid var(--rule); margin: 2.4rem 0; }
.foot { background: var(--ink); color: oklch(0.85 0.006 262); }
.foot div { max-width: 1240px; margin: 0 auto; padding: 28px clamp(20px,5vw,48px);
            display: flex; flex-wrap: wrap; justify-content: space-between;
            align-items: center; gap: 16px; font: 14px var(--mono); }
.foot code { background: none; color: #fff; padding: 0; }
.foot a { color: oklch(0.85 0.006 262); } .foot a:hover { color: #fff; }
.foot nav { display: flex; gap: 24px; flex-wrap: wrap; }
.foot .mark { display: flex; align-items: center; gap: 10px; color: #fff; }
.foot .mark i { width: 10px; height: 10px; background: oklch(0.62 0.17 263); display: block; }
@media (max-width: 900px) {
  .wrap { grid-template-columns: minmax(0,1fr); }
  .side { display: none; }
  .back { display: block; }
}
"""


INTERNAL = re.compile(r"^>\s*\*\*Internal\.\*\*")


def is_internal(text: str) -> bool:
    """A doc that opens with a `> **Internal.**` callout (within its first 20
    lines) is the team's runbook, not user documentation: it stays in the repo
    and is left off the public site. Links to it point at GitHub instead."""
    return any(INTERNAL.match(line) for line in text.split("\n")[:20])


def esc(text: str) -> str:
    """Escape for HTML. `quote=False`; call sites putting text into an
    attribute escape again with quotes on."""
    return html.escape(text, quote=False)


def plain(text: str) -> str:
    """Markdown source -> readable plain text, for titles and descriptions."""
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"\[([^\]]*)\]\([^)\s]*\)", r"\1", text)
    return " ".join(re.sub(r"\*+([^*]+)\*+", r"\1", text).split())


class Build:
    """One run over one docs/ tree: the page table and the warnings."""

    def __init__(self, docs: Path, repo_root: Path, verbose: bool = False) -> None:
        self.docs, self.repo_root, self.verbose = docs.resolve(), repo_root.resolve(), verbose
        self.warnings: list[tuple[str, int, str]] = []
        self.by_rel: dict[str, str] = {}  # rel path in docs/ -> page url
        self.internal: set[str] = set()  # docs/ paths marked Internal: not published
        self.pages: list[dict] = []

    def warn(self, rel: str, line: int, message: str) -> None:
        self.warnings.append((rel, line, message))

    # -- discovery ---------------------------------------------------------

    def url_for(self, rel: str) -> str:
        """Slug rule: the lowercased filename without `.md`, `.html`, and a
        README becoming `index.html` in its own directory. That is why
        `adr/README.md` lands at `/adr/index.html` instead of colliding with
        the site's own root index, and why `adr/0007-jev.md` keeps its number."""
        head, _, name = rel.rpartition("/")
        stem = name[:-3].lower()
        out = "index.html" if stem == "readme" else f"{stem}.html"
        return f"/{head}/{out}" if head else f"/{out}"

    def discover(self) -> None:
        for path in sorted(self.docs.rglob("*.md")):
            rel = path.relative_to(self.docs).as_posix()
            if not path.is_file() or any(part.startswith(".") for part in rel.split("/")):
                continue
            if is_internal(path.read_text(encoding="utf-8")):
                self.internal.add(rel)
                continue
            self.by_rel[rel] = self.url_for(rel)
            self.pages.append({"group": group_of(rel), "rel": rel, "path": path, "url": self.by_rel[rel]})
        self.pages.sort(key=lambda page: page["rel"])

    def load(self) -> None:
        for page in self.pages:
            page["text"] = text = page["path"].read_text(encoding="utf-8")
            page["title"] = self.title_of(text, page["rel"])
            page["description"] = self.description_of(text)
            page["body"] = "".join(self.blocks(text.split("\n"), 0, page, 0)[0])

    @staticmethod
    def title_of(text: str, rel: str) -> str:
        for line in text.split("\n"):
            if match := HEADING.match(line.strip()):
                return plain(match.group(2))
        return rel.rpartition("/")[2][:-3].replace("-", " ").replace("_", " ")

    @staticmethod
    def description_of(text: str) -> str:
        """The first real paragraph: the one-line description in the index and
        in llms.txt. Generated files open with an HTML comment, which is
        skipped along with the heading above it."""
        out: list[str] = []
        inside = False
        for line in text.split("\n"):
            stripped = line.strip()
            if stripped.startswith("<!--"):
                inside = True
            if inside:
                inside = "-->" not in stripped
                continue
            if stripped and not (
                HEADING.match(stripped)
                or stripped.startswith("```")
                or BULLET.match(line)
                or stripped.startswith(("|", ">", "-"))
            ):
                out.append(stripped)
            elif out:
                break
        return plain(" ".join(out))[:200]

    # -- links -------------------------------------------------------------

    def href(self, target: str, page: dict, line: int) -> str | None:
        """A safe href, or None when the link must be escaped as plain text:
        an unsafe scheme, or a local target that resolves to nothing."""
        url = target.strip()
        if url.startswith(("#", "/")) or re.match(r"^(https?:|mailto:)", url, re.I):
            return html.escape(url, quote=True)
        if SCHEME.match(url):
            self.warn(page["rel"], line, f"unsafe URL scheme in link {url!r}; escaped as text")
            return None

        path, _, fragment = url.partition("#")
        suffix = f"#{fragment}" if fragment else ""
        here = posixpath.dirname(page["rel"])
        resolved = posixpath.normpath(posixpath.join(here, path))
        if not resolved.startswith(".."):
            if resolved in self.by_rel:
                return self.by_rel[resolved] + suffix
            if resolved in self.internal:
                return f"{REPO_BLOB}/docs/{resolved}{suffix}"
            self.warn(page["rel"], line, f"link target {url!r} does not resolve to a doc (docs/{resolved}.md)")
            return None

        # The docs also link to the repository as a whole (README, LICENCE, a
        # venture directory). Those are real files in git but not part of this
        # site, so they point at GitHub rather than 404. Only a target in
        # neither tree is a warning.
        repo_rel = posixpath.normpath(posixpath.join("docs", here, path))
        if not repo_rel.startswith("..") and (self.repo_root / repo_rel).exists():
            return f"{REPO_BLOB}/{repo_rel}{suffix}"
        self.warn(page["rel"], line, f"link target {url!r} is outside docs/ and outside the repository")
        return None

    # -- markdown ----------------------------------------------------------

    def inline(self, text: str, page: dict, line: int, anchors: list[tuple[int, int]] = ()) -> str:
        """Inline markdown. `anchors` maps character offsets back to source
        lines so a warning names the line the link is on, not the line the
        paragraph started on."""
        def at(offset: int) -> int:
            if not anchors:
                return line
            return anchors[min(bisect_right(anchors, (offset, 1 << 30)) - 1, len(anchors) - 1)][1]

        out: list[str] = []
        pos = 0
        for match in INLINE.finditer(text):
            out.append(esc(text[pos : match.start()]))
            pos = match.end()
            number = at(match.start())
            if match.group(2) is not None:
                out.append(f"<code>{esc(match.group(2))}</code>")
            elif match.group(3) is not None:
                href = self.href(match.group(4), page, number)
                label = self.inline(match.group(3), page, number)
                out.append(f'<a href="{href}">{label}</a>' if href else label)
            elif match.group(5) is not None:
                out.append(f"<strong>{self.inline(match.group(5), page, number)}</strong>")
            else:
                out.append(f"<em>{self.inline(match.group(6), page, number)}</em>")
        out.append(esc(text[pos:]))
        return "".join(out)

    def blocks(self, lines: list[str], i: int, page: dict, base: int | None) -> tuple[list[str], int]:
        """Block markdown from `lines[i:]`.

        `base` is the indent of a list whose tail is being rendered, so a
        marker indented past it belongs to that list and stops the scan here.
        `base=None` means there is no enclosing list and every marker is a
        block of its own, which is what a list item's body wants: its nested
        list is content, not the parent list's continuation."""
        out: list[str] = []
        while i < len(lines):
            raw, stripped = lines[i].rstrip(), lines[i].strip()
            marker = BULLET.match(raw)
            if marker and base is not None and len(marker.group(1)) > base:
                break
            if not stripped:
                i += 1
                continue
            if stripped.startswith("<!--"):
                # Comments carry generator instructions; drop the whole block.
                while i < len(lines) and "-->" not in lines[i]:
                    i += 1
                i += 1
                continue
            if match := HEADING.match(stripped):
                level = len(match.group(1))
                out.append(f"<h{level}>{self.inline(match.group(2), page, i + 1)}</h{level}>")
                i += 1
            elif match := FENCE.match(stripped):
                out.append(self.fence(lines, i, match.group(1), page))
                i = self.fence_end(lines, i, page)
            elif HR.match(stripped):
                out.append("<hr>")
                i += 1
            elif stripped.startswith(">"):
                out.append(self.quote(lines, i, page))
                i = self.quote_end(lines, i)
            elif stripped.startswith("|") and DELIM_ROW.match(lines[i + 1].strip() if i + 1 < len(lines) else ""):
                out.append(self.table(lines, i, page))
                i = self.table_end(lines, i)
            elif marker:
                out.append(self.list_block(lines, i, page, len(marker.group(1))))
                i = self.list_end(lines, i, page)
            else:
                out.append(self.paragraph(lines, i, page))
                i = self.paragraph_end(lines, i)
        return out, i

    def fence_end(self, lines: list[str], i: int, page: dict) -> int:
        i += 1
        while i < len(lines) and not FENCE.match(lines[i].strip()):
            i += 1
        if i >= len(lines):
            self.warn(page["rel"], i, "unclosed code fence: EOF reached with the block still open")
        return i + 1

    def fence(self, lines: list[str], i: int, language: str, page: dict) -> str:
        body: list[str] = []
        while (i + 1) < len(lines) and not FENCE.match(lines[i + 1].strip()):
            body.append(lines[i + 1])
            i += 1
        attr = f' class="language-{esc(language)}"' if language else ""
        # Verbatim apart from HTML escaping: these examples are the ones the
        # tests run, so a paraphrase here would be a lie an agent copies.
        return f"<pre><code{attr}>{esc(chr(10).join(body))}</code></pre>"

    def quote_end(self, lines: list[str], i: int) -> int:
        while i < len(lines) and lines[i].strip().startswith(">"):
            i += 1
        return i

    def quote(self, lines: list[str], i: int, page: dict) -> str:
        body = [re.sub(r"^\s*>\s?", "", lines[j]) for j in range(i, self.quote_end(lines, i))]
        inner, _ = self.blocks(body, 0, page, 0)
        return f"<blockquote>{''.join(inner)}</blockquote>"

    def table_end(self, lines: list[str], i: int) -> int:
        i += 2  # header plus the delimiter row, which is layout not content
        while i < len(lines) and lines[i].strip().startswith("|"):
            i += 1
        return i

    def table(self, lines: list[str], i: int, page: dict) -> str:
        def cells(row: str) -> list[str]:
            return [cell.strip() for cell in row.strip().strip("|").split("|")]

        number = i + 1
        out = ["<table><thead><tr>"]
        out += [f"<th>{self.inline(cell, page, number)}</th>" for cell in cells(lines[i])]
        out.append("</tr></thead><tbody>")
        for row in (cells(lines[j]) for j in range(i + 2, self.table_end(lines, i))):
            out.append("<tr>" + "".join(f"<td>{self.inline(c, page, number)}</td>" for c in row))
            out.append("</tr>")
        out.append("</tbody></table>")
        return "".join(out)

    def list_end(self, lines: list[str], i: int, page: dict) -> int:
        """End of the list whose markers sit at exactly `lines[i]`'s indent."""
        indent = len(BULLET.match(lines[i]).group(1))
        while i < len(lines):
            if BULLET.match(lines[i]) and len(BULLET.match(lines[i]).group(1)) == indent:
                i += 1
            elif self.item_line(lines, i, indent):
                i += 1  # a wrapped line, or one level of nesting
            elif not lines[i].strip() and self.item_line(lines, i, indent, skip_blank=True):
                i += 1
            else:
                return i
        return i

    @staticmethod
    def item_line(lines: list[str], i: int, indent: int, skip_blank: bool = False) -> bool:
        """Does the line belong to the item that started above it?

        An item owns its wrapped lines and one level of nesting, which are the
        lines indented past the marker. A blank line is part of the item only
        when something indented follows it -- otherwise the list has ended and
        the paragraph below it belongs to the document, not to the item."""
        if skip_blank:
            while i < len(lines) and not lines[i].strip():
                i += 1
        raw = lines[i] if i < len(lines) else ""
        if not raw.strip() or not raw[:1].isspace():
            return False
        marker = BULLET.match(raw)
        return not marker or len(marker.group(1)) > indent

    def list_block(self, lines: list[str], i: int, page: dict, indent: int) -> str:
        """One `<ul>`/`<ol>` at exactly `indent`. Every line of an item goes
        back through `blocks`, so a wrapped item and a one-level nested list
        are the same work."""
        end = self.list_end(lines, i, page)
        tag = "ol" if BULLET.match(lines[i]).group(2)[0].isdigit() else "ul"
        out = [f"<{tag}>"]
        while i < end:
            if not lines[i].strip():
                i += 1
                continue
            body = [BULLET.match(lines[i]).group(3)] if BULLET.match(lines[i]) else []
            i += 1
            while i < end and (not lines[i].strip() or self.item_line(lines, i, indent)):
                # Blank lines are kept: an item whose text is split by one is
                # two paragraphs inside one `<li>`, not one run-on paragraph.
                body.append(lines[i].rstrip())
                i += 1
            inner, _ = self.blocks(body, 0, page, None)
            out.append(f"<li>{''.join(inner)}</li>")
        out.append(f"</{tag}>")
        return "".join(out)

    def paragraph_end(self, lines: list[str], i: int) -> int:
        while i < len(lines):
            stripped = lines[i].strip()
            if not stripped or stripped.startswith(("|", ">", "<!--")):
                break
            if HEADING.match(stripped) or FENCE.match(stripped) or HR.match(stripped) or BULLET.match(lines[i]):
                break
            i += 1
        return i

    def paragraph(self, lines: list[str], i: int, page: dict) -> str:
        """Source lines joined with spaces, with an offset -> line map so a
        link's warning names the line the link is on, not the line the
        paragraph started on."""
        body, anchors, offset = [], [], 0
        for j in range(i, self.paragraph_end(lines, i)):
            anchors.append((offset, j + 1))
            offset += len(lines[j].strip()) + 1
            body.append(lines[j].strip())
        return f"<p>{self.inline(' '.join(body), page, i + 1, anchors)}</p>"


# -- output ---------------------------------------------------------------


def nav_html(pages: list[dict], current: str = "") -> str:
    """Every page, grouped, with the current one marked. Wide screens only: a
    phone gets a single "All docs" link to the index (the full table of
    contents) instead of every page listed above the text."""
    out = ['<nav class="side" aria-label="All docs">']
    for group in group_order(pages):
        members = [page for page in pages if page["group"] == group]
        if members:
            out.append(f'<h2>{esc(group)}</h2><ul>')
            for page in members:
                mark = ' aria-current="page"' if page["url"] == current else ""
                out.append(f'<li><a href="{page["url"]}"{mark}>{esc(page["title"])}</a></li>')
            out.append("</ul>")
    out.append("</nav>")
    return "".join(out)


def page_html(title: str, body: str, pages: list[dict], current: str = "") -> str:
    """The one HTML shell. No build date, no version, nothing that varies."""
    return (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{esc(title)} — {esc(TITLE)}</title>\n"
        f'<meta name="description" content="{html.escape(DESCRIPTION, quote=True)}">\n'
        '<link rel="icon" href="https://keepshipping.run/assets/favicon.svg" type="image/svg+xml">\n'
        '<link rel="preconnect" href="https://fonts.googleapis.com">\n'
        '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>\n'
        '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:'
        'opsz,wght@12..96,400;12..96,500;12..96,700;12..96,800&family=DM+Mono:wght@400;500&display=swap">\n'
        '<link rel="stylesheet" href="/styles.css">\n</head>\n<body>\n'
        '<a class="skip" href="#main">Skip to content</a>\n'
        '<header class="top"><a class="brand" href="/" aria-label="Keep Shipping documentation home">'
        f"<i aria-hidden=\"true\"></i>{esc(TITLE)} <span>{esc(TAGLINE)}</span></a>"
        '<nav aria-label="Site"><a href="https://keepshipping.run/">keepshipping.run</a>'
        '<a href="https://github.com/Keep-Shipping">GitHub</a>'
        '<a class="cta" href="https://keepshipping.run/#early-access">Early access</a></nav></header>\n'
        f'<div class="wrap">{nav_html(pages, current)}\n<main id="main">\n'
        f'{"<p class=back><a href=/>← All docs</a></p>" if current else ""}\n{body}\n</main></div>\n'
        '<footer class="foot"><div><span class="mark"><i aria-hidden="true"></i>docs.keepshipping.run</span>'
        '<span>© 2026 <a href="https://factory0.ventures/">Factory Zero Pte. Ltd.</a> · built from <code>docs/</code></span>'
        '<nav aria-label="Footer"><a href="https://keepshipping.run/">Home</a>'
        '<a href="https://keepshipping.run/privacy">Privacy</a><a href="/llms.txt">llms.txt</a></nav></div></footer>\n'
        "</body>\n</html>\n"
    )


def index_html(pages: list[dict]) -> str:
    out = [f"<h1>{esc(TITLE)} {esc(TAGLINE)}</h1>", f"<p>{esc(DESCRIPTION)}</p>"]
    for group in group_order(pages):
        members = [page for page in pages if page["group"] == group]
        if members:
            out.append(f"<h2>{esc(group)}</h2>\n<ul>")
            out += [
                f'<li><a href="{page["url"]}">{esc(page["title"])}</a> — {esc(page["description"])}</li>'
                for page in members
            ]
            out.append("</ul>")
    return page_html(f"{TITLE} {TAGLINE}", "\n".join(out), pages)


def llms_txt(pages: list[dict]) -> str:
    """The index: one line per page with its URL and what it is for."""
    out = [
        f"# {TITLE} {TAGLINE}",
        "",
        f"> {DESCRIPTION}",
        "",
        "One line per page. Read this to choose a page, then fetch it — or read",
        "llms-full.txt for everything at once.",
        "",
    ]
    for group in group_order(pages):
        members = [page for page in pages if page["group"] == group]
        if members:
            out += [f"## {group}", ""]
            out += [f"- [{p['title']}]({BASE_URL}{p['url']}): {p['description']}" for p in members]
            out.append("")
    return "\n".join(out)


def llms_full_txt(pages: list[dict]) -> str:
    """Every page's source, verbatim, in nav order.

    Code blocks are reproduced exactly as written in docs/ because these
    examples are the tested ones, and an agent copying a mangled snippet copies
    a bug. That is also why llms.txt exists beside it: one file to find the
    page, one to read it without following links."""
    out = [
        f"# {TITLE} {TAGLINE} — full text",
        "",
        "Every page, in navigation order, as markdown.",
        "",
        f"- {BASE_URL}/ is the human-readable site.",
        "- llms.txt is the index: one line per page. Read that to choose a page.",
        "- This file is the whole corpus in one request: no link following, no HTML.",
        "",
        "Code blocks are reproduced exactly as written in docs/.",
        "",
    ]
    for page in pages:
        out += ["---", "", f'<!-- url: {page["url"]} -->', f'<!-- source: docs/{page["rel"]} -->', ""]
        out += [page["text"].rstrip("\n"), ""]
    return "\n".join(out)


def sitemap_xml(pages: list[dict]) -> str:
    urls = [f"<url><loc>{BASE_URL}/</loc></url>"] + [
        f"<url><loc>{BASE_URL}{page['url']}</loc></url>" for page in pages
    ]
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "\n".join(urls)
        + "\n</urlset>\n"
    )


def build(docs: Path, out: Path, check: bool, verbose: bool) -> int:
    builder = Build(docs, Path(__file__).resolve().parent.parent, verbose)
    builder.discover()
    if not builder.pages:
        print(f"site.py: no markdown found under {docs}", file=sys.stderr)
        return 2
    builder.load()

    out.mkdir(parents=True, exist_ok=True)
    for page in builder.pages:
        if page["url"] == "/index.html":
            # A root docs/README.md would want the slug the generated table of
            # contents owns. Say so rather than silently dropping a doc.
            builder.warn(page["rel"], 1, "root README.md collides with the generated index; not rendered")
            continue
        target = out / page["url"].lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(page_html(page["title"], page["body"], builder.pages, page["url"]), encoding="utf-8")
        if verbose:
            print(f"site.py: {page['rel']} -> {page['url']}")
    for name, text in (
        ("index.html", index_html(builder.pages)),
        ("404.html", page_html("Not found", "<h1>404</h1>\n<p>No such page.</p>", builder.pages)),
        ("styles.css", STYLES),
        ("sitemap.xml", sitemap_xml(builder.pages)),
        ("robots.txt", f"User-agent: *\nAllow: /\n\nSitemap: {BASE_URL}/sitemap.xml\n"),
        ("llms.txt", llms_txt(builder.pages)),
        ("llms-full.txt", llms_full_txt(builder.pages)),
    ):
        (out / name).write_text(text, encoding="utf-8")

    for rel, number, message in builder.warnings:
        print(f"site.py: {rel}:{number}: warning: {message}", file=sys.stderr)
    return 1 if check and builder.warnings else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Build the docs.keepshipping.run static site.")
    parser.add_argument("--docs", default="docs", help="markdown source tree (default: docs)")
    parser.add_argument("--out", default="target/docs-site", help="output directory")
    parser.add_argument("--check", action="store_true", help="exit 1 if any warning was emitted")
    parser.add_argument("--verbose", action="store_true", help="print each page written")
    args = parser.parse_args(argv)
    try:
        return build(Path(args.docs), Path(args.out), args.check, args.verbose)
    except OSError as error:
        print(f"site.py: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))