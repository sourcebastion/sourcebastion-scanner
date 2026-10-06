"""Run pinned candidates sequentially on the synthetic corpus, never select one."""

import argparse
import json
from pathlib import Path
import subprocess
import sys

from .run import digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--strace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeat", type=int, default=2, choices=range(1, 4))
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "tool-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    reports = []
    for engine in ("syft", "cdxgen", "scalibr", "syft-projection"):
        tool = manifest["tools"]["syft" if engine == "syft-projection" else engine]
        output = args.output / engine
        command = [
            sys.executable,
            "-m",
            "evaluation.m046.run",
            "--engine",
            engine,
            "--binary",
            tool["binary"],
            "--sha256",
            tool["sha256"],
            "--strace",
            str(args.strace),
            "--output",
            str(output),
            "--repeat",
            str(args.repeat),
        ]
        if engine == "cdxgen":
            for flag in ("entrypoint", "entrypoint_sha256", "entrypoint_tree_sha256"):
                command += ["--" + flag.replace("_", "-"), tool[flag]]
        subprocess.run(command, check=True)
        reports.append(str(output / "report.json"))
    subprocess.run(
        [sys.executable, "-m", "evaluation.m046.summarize", *reports, "--output", str(args.output / "comparison")],
        check=True,
    )
    (args.output / "SHA256SUMS").write_text(
        "".join(
            f"{digest(path)}  {path.relative_to(args.output)}\n"
            for path in sorted(args.output.rglob("*"))
            if path.is_file()
        )
    )


if __name__ == "__main__":
    main()
