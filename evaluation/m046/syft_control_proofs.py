"""Real Docker probes of the trusted control launcher, never inventory acceptance."""

import argparse
import json
import os
from pathlib import Path
import subprocess

from . import benchmark
from .run import digest

PROGRAM = r"""
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    char mode[32] = {0};
    FILE *input = fopen("/source/mode", "r");
    if (!input || !fgets(mode, sizeof mode, input)) return 2;
    fclose(input);
    if (strncmp(mode, "overflow", 8) == 0) {
        char block[4096];
        memset(block, 'x', sizeof block);
        for (int i=0; i<=16384; i++) {
            if (fwrite(block, 1, sizeof block, stdout) != sizeof block) return 3;
        }
        return fflush(stdout) == 0 ? 0 : 3;
    }
    printf("{\"uid\":%lu,\"gid\":%lu,\"argv\":[", (unsigned long)getuid(), (unsigned long)getgid());
    for (int i=1; i<argc; i++) printf("%s\"%s\"", i==1 ? "" : ",", argv[i]);
    puts("]}");
    return 0;
}
"""


def run(output):
    if not __debug__:
        raise RuntimeError("proofs require assertions enabled")
    output.mkdir(parents=True, exist_ok=False)
    source_code, binary = output / "probe.c", output / "probe"
    source_code.write_text(PROGRAM)
    with (output / "compile.stdout").open("wb") as stdout, (output / "compile.stderr").open("wb") as stderr:
        subprocess.run(
            ["cc", "-O2", "-o", str(binary), str(source_code)], stdout=stdout, stderr=stderr, timeout=60, check=True
        )
    benchmark.native_elf(binary)
    tool = {"binary": str(binary), "sha256": digest(binary)}
    records = []
    for mode, engine in (
        ("small", "syft-control-cpe-on"),
        ("small", "syft-control-cpe-off"),
        ("overflow", "syft-control-cpe-off"),
    ):
        name = mode + "-" + engine
        source = output / (name + "-source")
        source.mkdir()
        (source / "mode").write_text(mode)
        previous_umask = os.umask(0o077)
        try:
            measurement = benchmark.measure(engine, tool, source, output / name, "python")
        finally:
            os.umask(previous_umask)
        raw = output / name / "controller/raw.json"
        if mode == "small":
            result = json.loads(raw.read_text())
            assert result["uid"] == 65534 and result["gid"] == 65534
            assert result["argv"] == [
                "--mode",
                "control",
                "--root",
                "/source",
                "--generate-cpes=" + str(engine.endswith("on")).lower(),
                "--timeout",
                "150s",
            ]
            assert measurement["resource_sample_valid"] and measurement["source_unchanged"]
        else:
            assert not measurement["resource_sample_valid"] and measurement["exit_code"] != 0
            assert raw.stat().st_size == 64 * 1024 * 1024
            assert measurement["captured_raw_bytes"] == raw.stat().st_size
            assert measurement["source_unchanged"]
        records.append({"mode": mode, "engine": engine, "measurement": measurement})
        report = {
            "status": "launcher-path-proofs-only",
            "runtime_image": benchmark.IMAGE,
            "program_sha256": digest(source_code),
            "binary_sha256": tool["sha256"],
            "launcher_sha256": digest(Path(__file__).with_name("syft_control_job.py")),
            "controller_sha256": digest(Path(__file__).with_name("container_job.py")),
            "records": records,
        }
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    run(parser.parse_args().output.resolve())
