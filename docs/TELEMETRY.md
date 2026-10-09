# Telemetry

Keep Shipping ships no telemetry. There is no command that turns it on, no
config key that enables it, and no outbound call that is not already in
[ADR 0005](adr/0005-local-first-core-with-optional-hosted-services.md)'s
exhaustive list of what leaves the runner. This document exists anyway,
because the useful moment to decide what a payload may contain is before
anyone writes a sender. It is a contract written against a day that has not
arrived: if a telemetry module is ever built, the payload below is what it
sends, the consent model below is what turns it on, and a sender that does
not match this document field for field is a bug. The decisions behind it
are in [ADR 0015](adr/0015-telemetry-policy.md).

## The decision
- **No telemetry, and the absence is the decision.** It is not a missing
  feature waiting on a flag. Adding an outbound call that is not in ADR
  0005's *What leaves the runner* list is a change of architecture, and
  changes of architecture get a new ADR.
- **If** it is ever built, it is opt-in and never on by default:
  `keepshipping telemetry on` is an explicit act, persisted per
  installation, revoked with `keepshipping telemetry off` in one command,
  and `DO_NOT_TRACK` overrides everything.
- **Counts only.** Not a fingerprint, not a sample, not an error message,
  not an identifier that hashes to an identifier. What makes a payload safe
  here is that it has nothing in it that could become one.
- **The payload is specified before the code.** This document is the
  contract. A future sender is written against it and checked by
  `crates/testing/tests/telemetry_policy.rs`, which fails if the two drift.
- It would ride on Cratefield's `module-telemetry` — aggregate counts,
  consent-first — the module the hosted venture already runs
  ([ADR 0200](adr/0200-hosted-venture-on-the-cratefield-harness.md)).

## What is never collected
Not "not by default". Never. Each of these is excluded for a reason, and
the reason is why the payload above is short.

- **File paths and file contents.** A path is a directory layout; a
  `ship.ks` body is the customer's infrastructure. Neither is ever read for
  a payload, because there is no code path that reads them.
- **Repository names and URLs.** `owner/name` is a direct identifier and it
  is also the join key for every public dataset we would ever want to check
  ourselves against.
- **Hostnames and IP addresses.** These name the customer's internal
  network, and a hostname plus a version is often enough to name the
  company.
- **Branch names and commit SHAs.** A SHA is a stable handle. Counting
  runs per SHA is how a build becomes a log.
- **Environment variable names and values.** ADR 0005 already permits a
  variable *name* to leave as an `Establishment` marker for an approval
  request. That is a different request with a different recipient, and it
  does not carry over here.
- **Argument strings other than the top-level command word.** `keepshipping
  run ship.ks --env prod` becomes `run`, not the rest of the line. The
  arguments are where the interesting data is: the file name, the
  environment, the flags. The command word is sent *instead of* the
  arguments for exactly that reason — the first token is what answers
  "which commands matter", and everything after it is a description of
  someone's setup.
- **Step names.** A step name is chosen by the customer and routinely says
  more than the step does — `prod-eu-west-1` is not a step name, it is a
  location.
- **Plan addresses.** `aws_s3_bucket.payments` is infrastructure. Counts
  by action kind say what the tool did; addresses say whose.
- **Error message text.** An error is the richest thing a program emits.
  Paths, hosts and sometimes values arrive inside messages for free. Codes
  are the closed, intentional alternative.
- **Anything a user typed.** Including prompts, annotations and answers to
  the questions a run asks.
- **Timestamps finer than the interval boundary.** A send is stamped with
  the interval it covers, not the instant it happened. Instant timestamps
  turn independent installs into a correlation problem.
- **Any stable or rotating install identifier.** No installation UUID, no
  hashed UUID, no derived-from-machine-value pseudonym. A rotating ID is
  still an ID: it links one installation's sends to each other, which is
  all it takes to turn a count into a history.
- **Durations, raw.** `duration` is bucketed *because* a raw duration is a
  fingerprint. A run that takes 3.147 seconds every time is a
  fingerprint of a machine, a network and a repository. Rounded to
  `1024ms`, the same run is a magnitude.
- **OS, architecture and locale.** No "anonymous" hardware profile: every
  field that narrows the population narrows the anonymity with it.

## The payload, if it is ever sent
One request, one interval, one command. Every value is either a fixed
literal, a value drawn from a closed vocabulary the harness already owns,
a count, or a bucket. `type` below is drawn from exactly this set and
nothing else: `const`, `semver`, `enum(cli)`, `enum(action)`, `enum(code)`,
`count`, `bucket`. A field whose type is not in that set does not belong in
the payload, and the leak test fails on it.

```json
{
  "schema": "keepshipping.telemetry.v1",
  "cli_version": "0.4.1",
  "command": "run",
  "count": 3,
  "failures": 1,
  "duration": "1024ms",
  "actions": 2,
  "action_counts": {
    "plan": 1,
    "apply": 1
  }
}
```

| field | type | example | note |
| --- | --- | --- | --- |
| `schema` | `const` | `keepshipping.telemetry.v1` | bumped if the fields change; a receiver refuses a version it does not know |
| `cli_version` | `semver` | `0.4.1` | the binary that sent it, never the version of a plan or image |
| `command` | `enum(cli)` | `run` | the top-level word, never its arguments |
| `count` | `count` | `3` | invocations of `command` in the interval |
| `failures` | `count` | `1` | invocations that exited non-zero |
| `duration` | `bucket` | `1024ms` | power-of-two bucket, so a duration is a magnitude and not a measurement |
| `actions` | `count` | `2` | steps that finished in the interval, whatever their kind |
| `action_counts` | `count` | `{"plan": 1, "apply": 1}` | one entry per kind that occurred, keyed by the kind; every key is an `enum(action)` member and every value is a count |

The closed vocabularies are named here rather than left to the receiver, so
that a new kind cannot become a free-form field:

- `enum(cli)` is the top-level word `dispatch()` matches in
  `crates/cli/src/main.rs`, seventeen of them: `--version`, `about`, `approve`, `blocks`,
  `check`, `decide`, `decisions`, `deny`, `fmt`, `graph`, `import`,
  `log`, `lsp`, `policy`, `resume`, `run`, `runs`.
- `enum(action)` is `ActionKind::NAMES` in `crates/core/src/step.rs`:
  `apply`, `build`, `deploy`, `destroy`, `other`, `plan`, `read-secrets`.
- `enum(code)` is `Code::ALL` in `crates/lang/src/diagnostic.rs`, the
  33 codes `KS0001`–`KS0005`, `KS0101`–`KS0102`, `KS0201`–`KS0206`,
  `KS0301`–`KS0306`, `KS0401`–`KS0405`, `KS0501`–`KS0502`,
  `KS0601`–`KS0603`, `KS0610`–`KS0611`, `KS0701`–`KS0702`, `KS0801`.
  No field uses it today; it exists in the type set for the one payload
  that would want it, a diagnostic-code-keyed count map of the same shape
  as `action_counts`, and adding that field is a schema bump.

`action_counts` is the only nesting in the payload, and its shape is
fixed: an object whose keys are members of `enum(action)` and whose values
are counts. A kind that happens not to occur is simply absent; nothing else
appears at any level, and there is no free-form string anywhere in the
request.

Note that *step kinds* are not in the payload. Step kinds — the dotted
names like `oci.image` or `tofu.plan`, registered in
`Catalog::builtin()` and open-ended, since a custom kind can be added at
runtime — are not the same thing as action kinds. A step kind is counted by
the closed `enum(action)` its name maps to, and a kind that maps to nothing
is counted under `other`, a fixed bucket that is already in the vocabulary.
An unrecognised kind is therefore counted, never named, and never sent as a
string that could carry whatever a runtime-registered kind happened to be
called.

## What the numbers mean
- `command` and `count` answer one question: which top-level words are used,
  and how often. They cannot tell you why, on what, or for whom.
- `failures` answers whether a command tends to end non-zero. It cannot
  tell you which failure, on which input, or for which reason — error
  text is not collected. A `failures` of 1 out of 3 is a signal to look at
  issues people file, not a diagnosis.
- `duration` is an order of magnitude. `1024ms` covers roughly half a
  second to a second. Slower than expected and faster than expected are
  both coarse on purpose.
- `actions` and `action_counts` say what the harness did: how many steps
  finished, split by what kind of work they were. `plan` and `apply`
  counts together say a workflow ran to completion. They say nothing about
  what was planned or applied.
- **Counts cannot be joined to a person.** There is no installation id to
  join on, by design, so two installs are two rows and never a history. A
  count of 40 is not 40 people; it is 40 things that happened, some
  possibly from one person and some from one CI job.
- **`other` is not an error bucket.** It is where step kinds land that the
  catalog did not recognise, which is the expected case for any custom
  kind. Its size is a fact about the catalog, not about failures.
- **A low count is not evidence of absence.** Users who opt in are the
  users who felt comfortable opting in. Numbers here describe that
  population and nothing wider, and must never be quoted as adoption.

## Consent
None of the commands below exist today. They are the proposed interface,
recorded so that whoever builds this cannot invent a worse one.

```
keepshipping telemetry on
keepshipping telemetry off
keepshipping telemetry status
```

- **Default off**, and off means no sender is constructed at all, not that
  a sender runs and discards.
- `on` persists a single flag in the installation's own state directory —
  per installation, never synced, never account-scoped, never fetched.
- `off` clears it and takes effect immediately. Revocation is one command
  and needs no uninstall, no reinstall and no support ticket.
- `status` prints whether sending is on and what the last interval
  covered, so consent is inspectable and not a hidden state.
- `DO_NOT_TRACK=1` in the environment wins over `on`. There is no way to
  override it from the CLI, and a future `telemetry on` must refuse while
  it is set rather than set a flag that will never be honoured.
- Sends are batched on a timer, off the critical path. A send never blocks
  a run, never fails a run, and never retries in a way that a user would
  wait on. A user who turns it on and loses their network has lost nothing
  they can act on.

## How this is tested
`crates/testing/tests/telemetry_policy.rs` is the leak test. It reads this
document and checks it, so the contract is enforced rather than described:

- Every `type` in the field table above is a member of the closed set
  (`const`, `semver`, `enum(cli)`, `enum(action)`, `enum(code)`, `count`,
  `bucket`). A new type is a new ADR, not a new row.
- No field name contains an identity-ish word — user, host, id, name,
  path, url, repo, token, key, email, org — so a field cannot be added
  under a name that describes a person.
- Every key in the JSON example, at every nesting level, is either a
  declared field name or a member of a declared closed enum. Anything else
  in the payload fails.
- The CLI words, action kinds and diagnostic codes quoted above are the
  ones in the code: `ActionKind::NAMES`, the `dispatch()` arms and
  `Code::ALL`. If the code gains a word, the document has to name it or the
  test fails, and the reverse holds too. This document cannot drift from
  the vocabularies it names.

The test does not, and cannot, prove that a future sender is honest; it
proves the shape of what this project has agreed is allowed to leave a
machine. That is the part worth testing, because it is the part that is
easy to erode one plausible-looking field at a time.

## See also
- [ADR 0015](adr/0015-telemetry-policy.md) — the decision: no telemetry
- [ADR 0005](adr/0005-local-first-core-with-optional-hosted-services.md) — what does leave the runner, and what never does
- [ADR 0200](adr/0200-hosted-venture-on-the-cratefield-harness.md) — the Cratefield hosted venture, and where `module-telemetry` would live
- [SECURITY.md](SECURITY.md) — the threat model this payload has to survive