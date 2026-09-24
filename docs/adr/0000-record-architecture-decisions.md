# ADR 0000: Record architecture decisions

Status: accepted, 2026-09-25

## Context
Keep Shipping is built as a harness in the style of the Cratefield harness: a
small core, ports and adapters, with work done in parallel by people and by
coding agents. Decisions about the language, the core, the ports and the
hosted parts have to be written down where the code is, so that a change of
direction is a visible act and not a quiet drift.

## Decision
- Every architectural decision is an ADR in `docs/adr/`, numbered
  `NNNN-short-title.md`, with `Status`, `Context`, `Decision` and
  `Consequences`.
- An ADR starts as a GitHub issue labelled `adr` (and `decision` while open)
  that lists the options, trade-offs and a recommendation. When it's decided,
  the accepted text is committed here and the issue is closed with a link.
- An accepted ADR is **never edited**. A change of mind is a new ADR that
  supersedes the old one. The old one keeps its text, and its status line
  says which ADR superseded it.
- Numbers are taken from blocks so parallel work can't collide:
  0000–0099 the harness (core, language, engine, CLI);
  0100–0199 steps and adapters;
  0200–0299 the hosted venture.
  An index, `docs/adr/README.md` (added with the workspace scaffold), will
  list every ADR once, and a CI test will check that numbers and index
  entries are unique.

## Consequences
- The first ADR issues are Keep-Shipping/harness #2 to #13 (ADR-0001 to
  ADR-0012).
- Reviews of changes to ports, policy or the file format ask "which ADR
  covers this?"
