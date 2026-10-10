"""Run the native resource-proof matrix with bounded concurrency.

Every arm is single-threaded -- measured at roughly 1.0x CPU against its 2-CPU
ceiling -- so running the whole matrix one arm at a time leaves most of a
runner idle. Arms within a repeat are independent: each proof creates its own
container and its own cgroup and shares nothing but the Docker daemon.

Repeats stay sequential on purpose. `repeats_per_native_architecture` exists to
sample variance, and three repeats executed under identical contention are not
three independent samples.

Concurrency is bounded rather than unlimited because each proof is measured
against a frozen wall-clock ceiling. Oversubscribing the runner inflates wall
time and would turn a resource proof into a flaky one, which is worse than a
slow one: it undermines the measurement the proof exists to make.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import subprocess
import sys
from pathlib import Path

#: Corpus first: it exercises the production adapter path, so a failure there
#: is more informative than a synthetic arm's. Order is otherwise fixed so a
#: reviewer reads the same sequence every run.
ARMS = ("flat-1000", "flat-10000", "flat-100000", "flat-100001", "graph", "expansion")
PROOF = Path(__file__).with_name("run-inventory-resource-proof.py")


def plan(output_root, repeat):
    """Every workload in one repeat, as (name, arguments, needs_provider)."""
    jobs = [("corpus", ["--workload", "corpus"], True)]
    jobs += [(arm, ["--workload", "stress", "--arm", arm], False) for arm in ARMS]
    return [
        (name, extra, provider, output_root / f"inventory-resources-{name}-{repeat}")
        for name, extra, provider in jobs
    ]


def execute(image, checkout, provider, name, extra, needs_provider, output):
    command = [
        sys.executable, str(PROOF), "--image", image, "--checkout", str(checkout),
        "--output", str(output), *extra,
    ]
    # Stated by the plan rather than inferred from the arguments, so an arm
    # named like a workload cannot silently change what it is handed.
    if needs_provider and provider is not None:
        command += ["--provider", str(provider)]
    completed = subprocess.run(command, capture_output=True, text=True)
    return name, completed.returncode, completed.stdout, completed.stderr


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--checkout", required=True, type=Path)
    parser.add_argument("--provider", type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument(
        "--concurrency",
        type=int,
        default=3,
        help="Arms in flight within one repeat. Each uses about one core.",
    )
    args = parser.parse_args()
    if args.repeats < 1 or args.concurrency < 1:
        raise SystemExit("resource-matrix-bounds-invalid")

    failures = []
    for repeat in range(1, args.repeats + 1):
        jobs = plan(args.output_root, repeat)
        with ThreadPoolExecutor(max_workers=min(args.concurrency, len(jobs))) as pool:
            results = list(pool.map(
                lambda job: execute(args.image, args.checkout, args.provider, *job),
                jobs,
            ))
        # Reported in plan order regardless of completion order, so the log of a
        # concurrent run reads the same as a serial one.
        for name, code, out, err in results:
            print(f"::group::repeat {repeat} {name} exit={code}")
            if out.strip():
                print(out.strip())
            if err.strip():
                print(err.strip(), file=sys.stderr)
            print("::endgroup::")
            if code != 0:
                failures.append(f"repeat {repeat} {name} exit {code}")
        # A failed repeat stops the matrix: later repeats cannot rehabilitate a
        # ceiling that was already exceeded, and the retained evidence for the
        # failure is what a reviewer needs.
        if failures:
            break

    if failures:
        print("resource matrix failed: " + "; ".join(failures), file=sys.stderr)
        return 1
    print(f"resource matrix passed: {args.repeats} repeats x {len(ARMS) + 1} workloads")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
