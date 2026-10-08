#!/usr/bin/env python3
"""Calibration for the decision models: does a high confidence mean a correct answer?

Usage: `python3 scripts/calibrate.py [--bands N] PATH`

PATH is the JSONL `keepshipping decisions export` wrote, once a human has added a `"label"` field to
each line holding the answer that turned out to be right:

    keepshipping decisions export > /tmp/decisions.jsonl
    # a human adds  "label": "allow"  to each line, then:
    python3 scripts/calibrate.py /tmp/decisions.jsonl

Lines with no label are counted and skipped — a report built only from labelled decisions is the
whole point, and folding an unlabelled one in would bias the accuracy upwards. Lines are grouped by
`model@version`, because a confidence is only comparable with other decisions the same pinned
version made: a new version is a new calibration, not an extra row.

Prints a Markdown report and nothing else: per confidence band the count, the mean confidence and
the accuracy (the fraction whose answer matched the label), plus each model's overall accuracy and
the expected calibration error — the count-weighted mean gap between mean confidence and accuracy.
An ECE near zero means the numbers can be read as probabilities; above ~0.1 the high bands
overstate themselves and no threshold set on them is safe. The report writes no file: what to trust
is a human's to read, not a number's to be applied.

Python 3.8+, standard library only, so it runs anywhere the CLI does.
"""

import argparse
import json
import sys

DEFAULT_BANDS = 10


def confidence_of(decision):
    """The confidence clamped to 0..=1, or 0.0 when the log carried none. Clamping once keeps the
    band and the mean agreeing: folding a broken value in raw means a band averaging over 1.0,
    which is not a confidence. NaN fails every comparison, so it lands here too."""
    try:
        value = float(decision.get("confidence", 0.0))
    except (TypeError, ValueError):
        return 0.0
    if not value >= 0.0:  # below the floor, or NaN, which fails every comparison
        return 0.0
    return min(value, 1.0)


def read_labelled(path):
    """The decisions carrying a `label`, plus counts of what did not make it in: lines with no
    label, and lines that are not JSON at all."""
    labelled, unlabelled, unreadable = [], 0, 0
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                decision = json.loads(line)
            except ValueError:
                unreadable += 1
                continue
            if isinstance(decision, dict) and "label" in decision:
                labelled.append(decision)
            else:
                unlabelled += 1
    return labelled, unlabelled, unreadable


def summarise(decisions, bands):
    """Per band: count, mean confidence, and how often the answer matched the label."""
    rows = {}
    for decision in decisions:
        confidence = confidence_of(decision)
        index = min(int(confidence * bands), bands - 1)
        row = rows.setdefault(index, {"count": 0, "confidence": 0.0, "correct": 0})
        row["count"] += 1
        row["confidence"] += confidence
        if decision.get("answer") == decision["label"]:
            row["correct"] += 1
    return [
        {
            "band": "%.1f-%.1f" % (index / bands, (index + 1) / bands),
            "count": row["count"],
            "mean_confidence": row["confidence"] / row["count"],
            "accuracy": row["correct"] / row["count"],
        }
        for index, row in sorted(rows.items())
    ]


def expected_calibration_error(summary):
    """The count-weighted mean gap between stated confidence and observed accuracy."""
    total = sum(row["count"] for row in summary)
    if not total:
        return 0.0
    return sum(
        row["count"] * abs(row["mean_confidence"] - row["accuracy"]) for row in summary
    ) / total


def report(decisions, bands):
    """The Markdown report: one table per model version, then the overall calibration error."""
    groups = {}
    for decision in decisions:
        key = "%s@%s" % (decision.get("model", "?"), decision.get("version", "-"))
        groups.setdefault(key, []).append(decision)

    out = [
        "# Decision calibration",
        "",
        "%d labelled decisions, %d model versions, %d bands."
        % (len(decisions), len(groups), bands),
        "",
    ]
    errors = []
    for key in sorted(groups):
        group = groups[key]
        summary = summarise(group, bands)
        error = expected_calibration_error(summary)
        errors.append(error)
        correct = sum(1 for d in group if d.get("answer") == d["label"])
        out += [
            "## %s" % key,
            "",
            "%d decisions, accuracy %.2f, expected calibration error %.3f"
            % (len(group), correct / len(group), error),
            "",
            "| band | count | mean confidence | accuracy |",
            "| --- | ---: | ---: | ---: |",
        ]
        out += [
            "| %s | %d | %.2f | %.2f |"
            % (row["band"], row["count"], row["mean_confidence"], row["accuracy"])
            for row in summary
        ]
        out.append("")

    out += [
        "Overall expected calibration error: %.3f across %d model versions."
        % (sum(errors) / len(errors) if errors else 0.0, len(errors)),
        "",
    ]
    if not decisions:
        out.append("Nothing labelled: add a `label` to each exported line and run this again.")
    return "\n".join(out)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Calibrate the decision models.")
    parser.add_argument("path", help="the labelled JSONL `keepshipping decisions export` wrote")
    parser.add_argument(
        "--bands", type=int, default=DEFAULT_BANDS,
        help="how many confidence bands to split into (default %d)" % DEFAULT_BANDS)
    args = parser.parse_args(argv)
    if args.bands < 1:
        parser.error("--bands must be at least 1")

    try:
        labelled, unlabelled, unreadable = read_labelled(args.path)
    except OSError as error:
        print("error: cannot read %s (%s)" % (args.path, error), file=sys.stderr)
        return 2

    if unlabelled or unreadable:
        print(
            "%d line(s) without a `label` and %d unreadable line(s) left out of the report"
            % (unlabelled, unreadable),
            file=sys.stderr,
        )
    print(report(labelled, args.bands))
    return 0


if __name__ == "__main__":
    sys.exit(main())