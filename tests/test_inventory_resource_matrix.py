"""The native resource-proof matrix runner.

Concurrency here is only acceptable if it preserves what the matrix measures:
repeats must stay independent samples, arms must not oversubscribe the runner
against a frozen wall-clock ceiling, and a failure must stop the matrix rather
than be averaged away by a later repeat.
"""

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "scripts/run-inventory-resource-matrix.py"

#: Stands in for the proof driver. Records when each invocation started and
#: finished so the test can reconstruct what actually overlapped.
STUB = '''#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
args = sys.argv[1:]
output = Path(args[args.index("--output") + 1])
output.mkdir(parents=True, exist_ok=False)
arm = args[args.index("--arm") + 1] if "--arm" in args else "corpus"
start = time.monotonic()
time.sleep(0.25)
record = {"arm": arm, "start": start, "end": time.monotonic(), "pid": os.getpid()}
(output / "trace.json").write_text(json.dumps(record))
print(json.dumps({"arm": arm}))
fail = os.environ.get("STUB_FAIL_ARM")
sys.exit(1 if fail and fail == arm else 0)
'''


@pytest.fixture
def harness(tmp_path, monkeypatch):
    """A matrix runner whose proof driver is the recording stub."""
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "run-inventory-resource-proof.py").write_text(STUB)
    runner = scripts / "run-inventory-resource-matrix.py"
    runner.write_text(MATRIX.read_text())
    return runner, tmp_path


def run(runner, root, *, repeats=2, concurrency=3, env=None):
    return subprocess.run(
        [sys.executable, str(runner), "--image", "img", "--checkout", str(root),
         "--output-root", str(root / "out"), "--repeats", str(repeats),
         "--concurrency", str(concurrency)],
        capture_output=True, text=True, env={**__import__("os").environ, **(env or {})},
    )


def traces(root, repeat):
    found = {}
    for path in sorted((root / "out").glob(f"*-{repeat}/trace.json")):
        record = json.loads(path.read_text())
        found[record["arm"]] = record
    return found


def test_all_seven_workloads_run_in_every_repeat(harness):
    runner, root = harness

    result = run(runner, root, repeats=2)

    assert result.returncode == 0, result.stderr
    for repeat in (1, 2):
        assert set(traces(root, repeat)) == {
            "corpus", "flat-1000", "flat-10000", "flat-100000",
            "flat-100001", "graph", "expansion",
        }


def test_arms_within_a_repeat_actually_overlap(harness):
    """Otherwise this is a rewrite with no benefit."""
    runner, root = harness

    assert run(runner, root, repeats=1, concurrency=3).returncode == 0
    records = list(traces(root, 1).values())
    spans = sorted((r["start"], r["end"]) for r in records)
    overlaps = sum(1 for i in range(1, len(spans)) if spans[i][0] < spans[i - 1][1])

    assert overlaps >= 2, f"expected concurrent arms, got spans {spans}"


def test_repeats_stay_sequential_so_each_is_an_independent_sample(harness):
    """Three repeats under identical contention are not three samples."""
    runner, root = harness

    assert run(runner, root, repeats=2, concurrency=3).returncode == 0
    first, second = traces(root, 1), traces(root, 2)
    last_of_first = max(r["end"] for r in first.values())
    first_of_second = min(r["start"] for r in second.values())

    assert first_of_second >= last_of_first, "a later repeat overlapped an earlier one"


def test_concurrency_is_bounded_so_the_runner_is_not_oversubscribed(harness):
    """Each arm uses about one core and is judged against a frozen wall-clock
    ceiling, so unbounded fan-out would make a resource proof flaky."""
    runner, root = harness

    assert run(runner, root, repeats=1, concurrency=2).returncode == 0
    spans = sorted((r["start"], r["end"]) for r in traces(root, 1).values())
    peak = max(
        sum(1 for start, end in spans if start <= point < end)
        for point in [s for s, _ in spans]
    )

    assert peak <= 2, f"ran {peak} arms at once against a limit of 2"


def test_a_failing_arm_fails_the_matrix_and_stops_it(harness):
    """A later repeat must not average away an exceeded ceiling."""
    runner, root = harness

    result = run(runner, root, repeats=3, env={"STUB_FAIL_ARM": "graph"})

    assert result.returncode == 1
    assert "graph" in result.stderr
    assert not (root / "out" / "inventory-resources-graph-2").exists(), "matrix continued past a failure"


def test_invalid_bounds_are_refused(harness):
    runner, root = harness

    assert run(runner, root, repeats=0).returncode != 0
    assert run(runner, root, concurrency=0).returncode != 0
