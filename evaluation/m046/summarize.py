"""Side-by-side exact-identity/edge comparison, without coverage success claims."""

import argparse
import hashlib
import json
from pathlib import Path
import statistics


def summarize(report):
    records = report["records"]
    fixtures = {}
    for record in records:
        fixtures.setdefault(record["fixture"], []).append(record)
    rows = {}
    for name, runs in fixtures.items():
        first = runs[0]
        comparison = first.get("comparison")
        row = {
            "expected": first["expected"],
            "observed": first.get("observed"),
            "comparison": comparison,
            "runs": len(runs),
            "all_outputs_valid": all(
                "observed" in run and run["metrics"]["exit_code"] == 0 and not run["metrics"]["timed_out"]
                for run in runs
            ),
            "source_unchanged": all(run["source_unchanged"] for run in runs),
            "repeat_equal": (
                all(run.get("observed") == first.get("observed") for run in runs)
                if len(runs) > 1 and all("observed" in run for run in runs)
                else None
            ),
            "raw_sha256": [run.get("raw_sha256") for run in runs],
            "trace_sha256": [run.get("trace_sha256") for run in runs],
        }
        row["exact_package_edge_agreement"] = row["all_outputs_valid"] and all(
            run.get("comparison") is not None
            and not any(
                run["comparison"][key] for key in ("missing_packages", "extra_packages", "missing_edges", "extra_edges")
            )
            for run in runs
        )
        row["full_contract_agreement"] = row["all_outputs_valid"] and all(
            run.get("comparison", {}).get("full_contract_agreement") is True for run in runs
        )
        rows[name] = row
    metrics = [run["metrics"] for run in records]
    return {
        "engine": report["engine"],
        "binary_sha256": report["binary_sha256"],
        "runner_sha256": report.get("runner_sha256"),
        "corpus_sha256": report["corpus_sha256"],
        "oracle_sha256": report.get("oracle_sha256"),
        "corpus_data_sha256": report.get("corpus_data_sha256"),
        "entrypoint_sha256": report.get("entrypoint_sha256"),
        "entrypoint_tree_sha256": report.get("entrypoint_tree_sha256"),
        "prepared_tree_unchanged": report.get("prepared_tree_unchanged"),
        "architecture": report["architecture"],
        "runs": len(records),
        "fixtures": rows,
        "exact_package_edge_agreements": sum(row["exact_package_edge_agreement"] for row in rows.values()),
        "full_contract_agreements": sum(row["full_contract_agreement"] for row in rows.values()),
        "valid_output_runs": sum("observed" in run and run["metrics"]["exit_code"] == 0 for run in records),
        "median_traced_wall_seconds": statistics.median(metric["wall_seconds"] for metric in metrics),
        "max_traced_wall_seconds": max(metric["wall_seconds"] for metric in metrics),
        "max_child_rss_kib": max(metric["max_child_rss_kib"] for metric in metrics),
        "coverage_assessment": "pending",
        "process_network_write_audit": "manual-review-required",
    }


def render(summaries):
    engines = [summary["engine"] for summary in summaries]
    fixtures = sorted(set().union(*(summary["fixtures"] for summary in summaries)))
    lines = ["| Fixture | " + " | ".join(engines) + " |", "|---|" + "---|" * len(engines)]
    for fixture in fixtures:
        cells = []
        for summary in summaries:
            row = summary["fixtures"].get(fixture)
            if not row:
                cells.append("not run")
            elif not row["all_outputs_valid"]:
                cells.append("execution/output error")
            elif row["exact_package_edge_agreement"]:
                cells.append("agree")
            else:
                counts = row["comparison"]
                cells.append(
                    ", ".join(
                        f"{len(counts[key])} {label}"
                        for key, label in (
                            ("missing_packages", "missing"),
                            ("extra_packages", "extra"),
                            ("missing_edges", "missing edge"),
                            ("extra_edges", "extra edge"),
                        )
                        if counts[key]
                    )
                )
        lines.append("| " + fixture + " | " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", type=Path, nargs="+")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    documents = [json.loads(path.read_text()) for path in args.reports]
    if (
        len(
            {
                (document["corpus_sha256"], document.get("oracle_sha256"), document.get("corpus_data_sha256"))
                for document in documents
            }
        )
        != 1
    ):
        raise ValueError("cannot compare different corpus revisions")
    if len({document["engine"] for document in documents}) != len(documents):
        raise ValueError("duplicate engine reports")
    summaries = [summarize(document) for document in documents]
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "measurements.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "status": "preliminary-unreviewed",
                "report_sha256": {
                    document["engine"]: hashlib.sha256(path.read_bytes()).hexdigest()
                    for path, document in zip(args.reports, documents)
                },
                "engines": summaries,
            },
            indent=2,
        )
        + "\n"
    )
    (args.output / "table.md").write_text(render(summaries))
    print(render(summaries))


if __name__ == "__main__":
    main()
