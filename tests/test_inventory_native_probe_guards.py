"""Native evidence cannot report success after Python strips assertions."""

import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize(
    "name",
    [
        "verify-inventory-discovery.py",
        "verify-inventory-foundation.py",
        "verify-inventory-composition.py",
        "verify-go-source.py",
        "verify-inventory-cyclonedx.py",
        "validate-inventory-cyclonedx.py",
        "verify-inventory-matching.py",
    ],
)
@pytest.mark.parametrize("mode", ["flag", "environment"])
def test_optimized_interpreter_refuses_probe_receipt(name, mode, tmp_path):
    root = Path(__file__).resolve().parents[1]
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(root) + os.pathsep + environment.get("PYTHONPATH", "")
    command = [sys.executable]
    if mode == "flag":
        command.append("-O")
    else:
        environment["PYTHONOPTIMIZE"] = "1"
    command.append(str(root / "scripts" / name))
    result = subprocess.run(command, cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=15)
    assert result.returncode != 0
    assert "optimized-probe-runtime-refused" in result.stderr
    assert '"reason": "RuntimeError"' in result.stdout
    expected = "offline-official-cyclonedx-validation-failed" if name.startswith("validate-") else "native-"
    assert expected in result.stdout
    assert "-passed" not in result.stdout
