# Calibrating the decision models

A confidence is a claim about how often an answer is right. Nothing in the language, the engine or
the CLI takes that claim on trust yet, and this is the document that says so out loud: **no
threshold is recommended as safe until a calibration report for the pinned model version exists.**
A `≥ 0.95` in an example is an example.

## What every `decide` logs

Each answer becomes a `decide.answered` entry in the run's log
([`crates/core/src/ports/run_log.rs`](../crates/core/src/ports/run_log.rs)): `model` and the
`version` pinned in its `ModelProfile` (confidence is only comparable against other decisions *that*
version made); `question_hash` and `state_hash`, the sha256 of the canonical question and of the
redacted state actually sent, so a decision can be matched to its inputs without the log storing
either; `answer`, `probabilities` and `confidence`; and `threshold` and `outcome` — what the run
compares against, and what it did (`auto`, or an escalation). Nothing beyond the hashes is stored
and no secret reaches the log: every event is scrubbed through the run's `Redactor` first.

## How a human's disagreement is recorded

Two ways, and the report shows both. A `decision.overridden` names the decision it corrects by
`(decision_run, step)` — an override usually lands in a *later* run, the rollback, which is why the
decision's run is a field and not an assumption. An approval of the same step *after* an escalated
decision in the same run also counts: a person looked at what the model proposed and said yes,
which is evidence about the number even though nobody wrote a sentence about it. A recorded
`decision.overridden` wins where both apply: it is a person saying so in words.

## The loop

```sh
keepshipping decisions report                        # 1. what the models said
keepshipping decisions export > decisions.jsonl      # 2. one JSON line per decision
# 3. a human adds the answer that turned out to be right to each line: "label": "allow"
python3 scripts/calibrate.py decisions.jsonl         # 4. the report
```

`calibrate.py` (Python 3, standard library only) skips and counts unlabelled lines, groups by
`model@version`, and prints per band — ten by default, `--bands N` to change it — the count, the mean
confidence and the accuracy, plus each model's overall accuracy and **expected calibration error**:
the count-weighted mean gap between stated confidence and observed accuracy. An ECE near zero means
the confidence can be read as a probability; above roughly 0.1 the high bands overstate themselves,
and any threshold set above them is a guess. A log whose hash chain does not verify is named on
stderr, excluded from the numbers, and makes the command exit 1 — a calibration built on an edited
audit trail is worse than none. The other logs still report.

## Rules for the eval set

- **Re-run the calibration when the pinned model version changes.** A different version is a
  different model; its confidences are not the ones the last report measured, so it starts its own.
- **The eval set is synthetic plans plus early-access plans only, and only with permission.** No
  customer plan enters a calibration set without an explicit yes.
- **A first report for the pinned Jev version is pending.** It needs an API key to run the model and
  a labelled set of decisions to score it against; neither exists yet. Until it does, the threshold
  examples in [LANGUAGE.md](LANGUAGE.md) are illustrative and nothing more.