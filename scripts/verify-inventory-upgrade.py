"""Retain a corpus/finding diff; require exact reviewed approval for changes."""

import argparse
from pathlib import Path
import json
from inventory_upgrade import (
    ACCEPTED_UPGRADES, CURRENT_ORACLE, accepted_upgrades, corpus_diff, finding_diff,
    load, matching_approval, render, transition,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--accepted-upgrades", type=Path, default=ACCEPTED_UPGRADES)
    parser.add_argument("--candidate-oracle", type=Path, default=CURRENT_ORACLE)
    parser.add_argument("--baseline-findings", type=Path)
    parser.add_argument("--candidate-findings", type=Path)
    parser.add_argument("--baseline-snapshot")
    parser.add_argument("--candidate-snapshot")
    args = parser.parse_args()
    report = {"schema_version": "m046.inventory-upgrade-diff/1", "status": "failed"}
    try:
        entries = accepted_upgrades(args.accepted_upgrades)
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
        if report["status"] == "review-required":
            oracle, oracle_sha = load(args.candidate_oracle)
            if candidate.get("expectations_sha256") != oracle_sha:
                raise ValueError("upgrade-candidate-oracle-digest-mismatch")
            if corpus_diff(oracle, candidate)["status"] != "passed":
                raise ValueError("upgrade-candidate-does-not-match-current-oracle")
            report["candidate_oracle_sha256"] = oracle_sha
            identity = transition(report, oracle_sha)
            approval = matching_approval(entries, identity)
            if approval:
                report.update(status="passed", approval=approval)
            else:
                report["proposed_approval"] = {**identity, "reason": "", "pull_request": None}
    except (ValueError, KeyError, TypeError, OSError) as error:
        report.update(status="failed", reason=str(error))
    with args.output.open("xb") as stream:
        raw = render(report)
        if len(raw) > 64 * 1024**2:
            raise ValueError("upgrade-diff-output-limit")
        stream.write(raw)
    print(report["status"])
    if report.get("proposed_approval"):
        corpus = report["corpus"]
        print(f"{len(corpus['changes'])} changed cases; {len(corpus['missing_cases'])} missing; "
              f"{len(corpus['added_cases'])} added. Inspect the full retained diff: {args.output}")
        print("To approve this exact transition, add the following entry to "
              "evaluation/m046/accepted-upgrades.json in a reviewed pull request. "
              "Fill in the reason and pull_request number:")
        print(json.dumps(report["proposed_approval"], indent=2, sort_keys=True))
        print("Approval stops applying if either oracle or any observed difference changes.")
    elif report.get("reason"):
        print(report["reason"])
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
