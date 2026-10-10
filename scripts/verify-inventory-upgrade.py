"""Retain a reviewable corpus/finding diff; exit nonzero for any change."""

import argparse
from pathlib import Path
from inventory_upgrade import corpus_diff, finding_diff, load, render


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--baseline-findings", type=Path)
    parser.add_argument("--candidate-findings", type=Path)
    parser.add_argument("--baseline-snapshot")
    parser.add_argument("--candidate-snapshot")
    args = parser.parse_args()
    report = {"schema_version": "m046.inventory-upgrade-diff/1", "status": "failed"}
    try:
        baseline, before_sha = load(args.baseline)
        candidate, after_sha = load(args.candidate)
        report.update(baseline_sha256=before_sha, candidate_sha256=after_sha,
                      corpus=corpus_diff(baseline, candidate))
        finding_inputs = (args.baseline_findings, args.candidate_findings, args.baseline_snapshot, args.candidate_snapshot)
        if any(finding_inputs):
            if not all(finding_inputs):
                raise ValueError("upgrade-complete-finding-pair-required")
            before, before_sha = load(args.baseline_findings)
            after, after_sha = load(args.candidate_findings)
            report["findings"] = {**finding_diff(before, after, baseline_snapshot=args.baseline_snapshot,
                                               candidate_snapshot=args.candidate_snapshot),
                                  "baseline_sha256": before_sha, "candidate_sha256": after_sha,
                                  "advisory_snapshot_sha256": args.baseline_snapshot}
        else:
            report["findings"] = {"status": "not-compared", "reason": "separate-real-Grype-native-gate-required"}
        report["status"] = report["corpus"]["status"]
        if report["findings"]["status"] == "review-required":
            report["status"] = "review-required"
    except (ValueError, KeyError, TypeError, OSError) as error:
        report["reason"] = type(error).__name__
    with args.output.open("xb") as stream:
        raw = render(report)
        if len(raw) > 64 * 1024**2:
            raise ValueError("upgrade-diff-output-limit")
        stream.write(raw)
    print(report["status"])
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
