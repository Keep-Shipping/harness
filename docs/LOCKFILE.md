# `ship.lock`

How a repository pins a block, what the lock records, and what `check` and `run` read
([#81](https://github.com/Keep-Shipping/harness/issues/81), decided by
[ADR 0011](adr/0011-block-distribution.md)).

The rule underneath everything: **a reference is a request; the lock is the answer, and the
answer is written once.** `ship.ks` says what a repository wants, `ship.lock` says what it got,
and nothing re-derives the second from the first — which is what makes "this repo runs the same
bytes as last month" a claim you can check.

## Writing a reference

A reference is an `owner/name` and a pin, `acme/web-service@v3`. Three spellings, three meanings:

| Spelling | Means | Moves when |
| --- | --- | --- |
| `@v3` (or `@3`) | the highest published **release** of major 3 | you run `keepshipping blocks update` |
| `@3.1.2` | exactly `3.1.2` | never — it is already the answer |
| `@sha256:<hex>` | exactly those bytes; the version is a label | never |

- **`@v3` never selects a prerelease.** Given `3.4.1`, `3.5.0-rc.1` and `3.5.0` it picks
  `3.5.0`; given only the first two, `3.4.1`. Opting into a candidate means writing it out
  (`@3.5.0-rc.1`), or a pin would make "upgrade on your own schedule" mean "whenever the
  publisher next cut a candidate".
- **Versions compare by semver precedence, not as text.** `3.10.0` is newer than `3.9.0`,
  `3.5.0` newer than `3.5.0-rc.1`. A string comparison gets both wrong.
- **A version is semver, exactly.** Core parts are digits, prerelease identifiers are
  `[0-9A-Za-z-]`, and neither may carry a leading zero. A published version outside that —
  a tag like `2024-10-01`, or one carrying a newline — is not lockable at all, **including
  under a digest pin**. The digest is the pin, but a pin the format cannot record is not a
  pin, and the `version` field beside it is text a run will print.
- **No `@latest`, and no partial `@3.1`.** A reference with no `@` is refused rather than
  defaulted, and `@3.1` is refused *by name*: three spellings are settled, and accepting a
  fourth with an unstated meaning would leave it to be decided by whoever read the code first.

## The file

Written by `keepshipping blocks update`, committed, reviewed like any lock file. A strict subset
of TOML — `lock`, then one `[[block]]` per reference, one field per line:

```toml
# ship.lock: written by `keepshipping blocks update`. Commit it; do not edit by hand.
lock = 1

[[block]]
name    = "acme/web-service"
request = "v3"
version = "3.4.1"
digest  = "sha256:9f2c1b…"
```

- `lock = 1` — the format version, first non-comment line. A build that does not understand the
  number refuses the file and says which version it wanted.
- `name` — the block's `owner/name`, validated to the same grammar a reference uses, so a lookup
  cannot miss on a spelling one side accepted and the other did not.
- `request` — the pin **as the file spells it**, without the `@`. Not normalized: a lock that
  rewrote `@3` as `@v3` would report a change nobody made.
- `version` — what the request resolved to, as the source names it.
- `digest` — the manifest digest the content is addressed by. **This is the pin.** Everything
  else is there so a reviewer can see *why* the digest moved. `sha256` (64 hex digits) and
  `sha512` (128) are both accepted and both round-trip; a `digest` that disagrees with a
  digest-pinning `request` is refused.
- `source` — optional: the repository the block resolved from. Where a block lives is not settled
  ([#79](https://github.com/Keep-Shipping/harness/issues/79)), so it may be absent.

Entries are keyed by **name and request together** and sorted by them, so two majors of one block
are two entries and the file's order never depends on the order things were resolved in. One
reference is one entry: listing `acme/web-service@v3` twice in `ship.ks` writes one entry, and
two different resolutions of one reference are an error rather than two entries.

### What the parser refuses

A lock file is read by people, so every refusal carries a line number:

```
ship.lock:8: unknown field `repository`: a block is name, request, version, digest and optionally source
```

Refused: an unknown `lock` version, an unknown table, an unknown or repeated field, a missing
field, a duplicate `(name, request)`, a malformed version or digest, an unquoted or escaped value
(this format has no escapes — no field can hold one), a value holding a `"`, a `\` or a control
character, and an entry that **contradicts its own request**: a `request = "3.1.2"` whose
`version` is `3.1.3`, a digest-pinning `request` whose `digest` differs, or a `request = "v3"`
whose `version` is not a release of major 3. A `v3` request does not name a version, but it
does constrain one — `version = "not-a-version"` answers nothing. That last one matters most — `check`
reads this file, and an entry that disagrees with itself is a lock that will not mean what it
says.

Comments are whole lines (a leading `#`), never trailing; a canonical file parses and re-renders
byte-identically.

## Stability

`lock = 1` is a promise, not a counter. Within a version: fields keep their meaning, a new field
may only be optional and ignorable, the canonical layout does not change, and entries stay
sorted. What bumps it: a field becoming required or changing meaning, a field being removed or
renamed, or the layout changing. A build meeting an unknown version refuses the file rather than
guessing — a misinterpreted lock is worse than a rejected one.

## What an upgrade looks like

```diff
 # ship.lock: written by `keepshipping blocks update`. Commit it; do not edit by hand.
 lock = 1

 [[block]]
 name    = "acme/web-service"
 request = "v3"
-version = "3.4.1"
-digest  = "sha256:9f2c1b…"
+version = "3.5.0"
+digest  = "sha256:4d81af…"
```

Two lines — the goal of the layout. Nothing re-ordered, nothing reformatted, and a lock with
twenty entries does not reprint its other nineteen.

## Two repositories, two majors

Repositories move on their own schedules, so one block can be pinned differently by two repos at
once — repo A on `@v3` (`3.4.1`), repo B on `@v4` (`4.0.0`). Both work, and neither can be served
the other's bytes: B's `4.0.0` fails against A's digest. One repository *can* hold both entries
(a monorepo, or one mid-migration), and each step resolves through its own.

## How `check` and `run` use it

Both read the **digest** and neither ever resolves a version. That is what keeps `check` inside
its cold-1s/warm-100ms budget and the `offline` CI job passing: no round trip, no store read, no
answer that can change between two checks of an unchanged file.

- **`check`** reads the lock and the block's typed interface **out of the local cache by the
  locked digest**, offline by construction rather than by convention. A cache entry missing for
  that digest is a diagnostic naming the digest and telling you to run `keepshipping blocks fetch`
  (or `blocks update`) — it names no network host. A reference with no lock entry is a *stale
  lock*, and the answer is to update the lock, not to resolve the version now.
- **`run`** fetches by the locked digest and **verifies before use**: the bytes must hash to the
  locked digest, and the content must carry a verified signature. Unsigned content is refused,
  fail-closed, the same reading ADR 0011 takes for secrets and `ci-only`.

The cache is content-addressed by digest, so a poisoned entry cannot be substituted for another
block, and a cached entry is verified by hashing on the way in.

### What is not built yet

A lock file documenting a command that does not exist is worse than no documentation, so:

- **The commands are specified here; the library is what exists.** `ks_core::lock` (format,
  syntax, selection) and `ks_engine::blocks::{update, verify}` are written and tested. The
  `blocks update` / `blocks fetch` commands, the `BlockSource` adapter they would drive, and the
  `check`/`run` wiring are **not** part of this change — there is no source adapter to resolve
  against yet.
- **Signature identity policy** is [#84](https://github.com/Keep-Shipping/harness/issues/84):
  `verify` currently requires a verified signature, full stop.
- **Where a block lives** — the `blocks:` name-to-repository mapping — is
  [#79](https://github.com/Keep-Shipping/harness/issues/79), which is why `source` is optional.

## Reference

| Thing | Where |
| --- | --- |
| format, syntax, `select` | `crates/core/src/lock.rs` (`ks_core::lock`) |
| resolution and verification | `crates/engine/src/blocks.rs` (`ks_engine::blocks`) |
| the `BlockSource` port | `crates/core/src/ports/block_source.rs` |
| the decision | [ADR 0011](adr/0011-block-distribution.md) |