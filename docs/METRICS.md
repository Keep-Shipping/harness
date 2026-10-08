# Measuring the plan, without watching you

The plan is in the issues, starting with the master plan,
[#1](https://github.com/Keep-Shipping/harness/issues/1). It has success metrics in it. This page
says how each one gets measured, and — because the acceptance criterion is that **no metric is
published on the site without data behind it** — it says which ones currently have data and which
ones are still empty.

It does not add telemetry. There is no metrics client in the CLI, no counters, no analytics. Every
number below comes from a stopwatch held by a person, from a log that already exists for another
reason, or from a benchmark that runs in our own CI. If a number cannot be produced without the tool
phoning home, it is not a metric we collect; it is a metric we ask for.

## The rule

One rule decides whether a metric may be published, and it is not a judgement call:

| A metric may be published when | It may not be published when |
|---|---|
| A collection method above has produced at least one recorded reading | The method exists but has never been run |
| The reading carries what it was measured on — version, corpus, hardware | The number is a budget, a target or an estimate |
| Someone can re-run the method and get a comparable number | Only our own CI produced it and nobody else could check it |

A budget is not a measurement. `docs/adr/0013-rust-workspace.md` pins the `check` budget at cold 1 s
and warm p95 100 ms; that is a ceiling the CI job enforces, not evidence that anyone hit it. The
distinction is the same one [CALIBRATION.md](CALIBRATION.md) makes between a confidence that has a
report behind it and one that is only an example.

## The four metrics

| Metric | What counts | How it is measured | Data today |
|---|---|---|---|
| **Time to first ship** | Wall-clock from the first command to the first successful deploy, per onboarding session | Stopwatch, written down by the person being onboarded | **None** — no sessions run yet |
| **Repos shipping** | Distinct repos with a `ship.ks` that completed a deploy | Counted by the hosted services where a repo uses them; otherwise self-reported | **None** |
| **`check` speed and local/CI parity** | Wall-clock of `keepshipping check`; whether the same file behaves the same on a laptop and in CI | `cargo bench` in our own CI; parity read off run logs a person compares | **Speed: yes. Parity: none** |
| **Product telemetry** | Nothing, until someone asks for it | Opt-in and anonymous ([#156](https://github.com/Keep-Shipping/harness/issues/156)) | **Does not exist** |

Three of the four are empty. That is the honest state of the project, and it is recorded here rather
than left implied by silence.

## Time to first ship

A stopwatch, not a log. The measurement is taken by the person being onboarded, written down by
hand at the end of the session, and reported as one number with the two timestamps: **when they
started** (first command run, before they had installed anything) and **when the first deploy
succeeded**. Sessions that never reached a deploy are recorded as `did not finish` with the step
they stopped at, because a time to first ship that only counts the successes hides exactly the
number worth knowing.

The report is one line per session. There is no session identifier, no account, and nothing sent to
us unless the person sends it: the person being onboarded is the measurement instrument, and an
instrument that reports to the vendor is a different instrument.

**There is no data, and the reason is worth stating plainly: there is no onboarding path yet.**
[CLI.md](CLI.md) says that two of the three subcommands are implemented end to end and `run` is
not, so there is no documented path from nothing to a first deploy to put a stopwatch around. The
metric is defined and ready; the measurement starts when a session can be run. Publishing a number
before then would mean publishing ours, not a user's.

## Repos shipping through Keep Shipping

A repo counts when a `ship.ks` in it completes a deploy — not when it is created, not when it is
checked, not when it is imported. Two ways to count it, and they are not interchangeable:

- **Where the hosted services are in use**, count from them. A repo that used hosted approvals or the
  hosted control plane leaves a record we already hold for another reason, so counting it is reading
  a log, not collecting a new one.
- **Everywhere else, self-reported.** Nobody's local runs are visible to us, and making them visible
  is the thing this project refuses to do. A repo counts when its owner says so.

The two are reported as separate counts and are never added into one headline number. A total across
them would imply a coverage we do not have: the self-reported count is a floor, not a sample, and
the gap between the two is itself the honest answer to "how many repos ship through this".

**There is no data.** The hosted surface in this repository is the early-access waitlist, which
counts people who signed up, not repos that deployed. There is no repo-counting endpoint, and adding
one purely to produce this metric would be the surveillance this page rules out — so it stays
self-reported until a control plane that already knows the answer exists.

## `check` speed and local/CI parity

Speed is the one metric with data behind it, and it is measured by a benchmark that already gates
the build.

```
$ cargo bench -p ks-cli --bench check
cold:  6.008ms (budget 1s)
warm p95 of 50: 6.172ms (budget 100ms)
script cold:  89.070ms (budget 500ms)
script warm p95 of 50: 4.928ms (budget 50ms)
```

Measured 2026-10-08 on 3 vCPU AMD EPYC, Linux x86_64, against the CLI test fixtures
(`crates/cli/tests/fixtures/site`). The budgets are the ones in `crates/cli/benches/check.rs` and
the ones `.github/workflows/ci.yml` fails the build on, so this number and the gate move together:
when the budget is blown, CI says so and the number here is stale. Re-run the command above to
refresh it. One caveat on that gate: the bench job runs on `ubuntu-latest` only, so it does not
cover the macOS leg of the `gates` matrix.

Parsing is measured the same way, and reported here with its caveat:

```
$ cargo bench -p ks-lang
parsing a 522-line, 11 KiB source
median over 100 runs: 206 us
```

This one has a ceiling as well, enforced in `crates/lang/benches/parse.rs`: the run fails when the
median exceeds 5 ms, and the nightly job — `.github/workflows/nightly.yml`, `bench (500-line parse
under 5 ms)` — fails the build when that happens. 206 us against a 5 ms budget is about 24x of
headroom. The two gates are not the same shape, though. The `check` bench runs on every push; the
parse bench runs nightly. A parse regression is therefore caught a day late rather than
immediately, which is a real difference between the two numbers above and worth keeping in mind
before quoting either as "fast".

**Local/CI parity has no data**, and the gap is a wiring gap rather than a measurement gap. Parity
here means what [CI.md](CI.md) means by it — a run on Buildkite and the same run on a laptop are the
same run, per `docs/adr/0005-local-first-core-with-optional-hosted-services.md`. The run-context
modules for GitHub Actions and GitLab CI are built and tested, but the command dispatch still has no
run context to hand them (`crates/cli/src/main.rs`), so the two have not been compared on a real
deploy. When they are, the reading is a pair of logs from the same `ship.ks`, compared by a person —
which is the same self-reported shape as the repo count, and is counted the same way.

## Product telemetry

There is no product telemetry, and this section exists to say what adding one would owe.

If it is ever added ([#156](https://github.com/Keep-Shipping/harness/issues/156)), it is **opt-in
and anonymous**: off by default, carrying no identifier, no repo name, no file contents and no
machine identity, and documented here **before** it ships rather than after. A metric that arrives
in this file after the code that collects it has landed has already been collected without
anyone's consent, which makes the consent meaningless.

The test a proposed metric has to pass is the one this page has been applying all along: **could the
same number be produced without the tool watching the person?** If yes, that is how it is produced.
If no, it is a privacy decision for the person who owns the tool, made in the open, and the default
stays off.

## What this does not measure

- **Anything about a person.** No session length distribution, no feature usage, no retention. The
  stopwatch in *Time to first ship* is one number a person chose to give us, not a duration captured
  for them.
- **Which repos exist.** The self-reported count is a floor. Any statement about how many repos ship
  through Keep Shipping is a statement about the floor.
- **Whether the tool is fast on your machine.** The `check` numbers are from one machine, on one
  corpus, on one day. They bound the budgets CI enforces; they are not a claim about anyone's laptop.
- **Anything about the hosted control plane or the site.** Those live outside this repository
  ([README.md](../README.md)) and this page does not describe what they count.
- **Product success.** Nothing here is evidence that anyone shipped faster *because* of Keep
  Shipping. A time to first ship is a stopwatch, not a control group.

## Where to read more

| For | Read |
|---|---|
| The plan and the metrics it commits to | [#1](https://github.com/Keep-Shipping/harness/issues/1) |
| What `check` and the CLI actually do | [CLI.md](CLI.md) |
| What parity means, and what `--ci` reports | [CI.md](CI.md) |
| Why a budget is not a measurement | [CALIBRATION.md](CALIBRATION.md) |
| Why the local path exists at all | [adr/0005](adr/0005-local-first-core-with-optional-hosted-services.md) |
| Moving to Keep Shipping without a migration project | [COEXISTENCE.md](COEXISTENCE.md) |
