import json
from pathlib import Path
import subprocess
from unittest.mock import patch

import pytest

from sourcebastion.external_scanners import GrypeScanner, ScannerExecutionError, SemgrepScanner
from sourcebastion.grype_database import refresh


def test_offline_dependency_scan_never_installs_or_updates(tmp_path, monkeypatch):
    monkeypatch.setenv("SOURCEBASTION_SCAN_OFFLINE", "1")
    (tmp_path / "requirements.txt").write_text("requests==2.19.1\n")
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        assert command[0] == "grype", "offline scan invoked a package installer"
        assert kwargs.get("env", {}).get("GRYPE_DB_AUTO_UPDATE") == "false"
        if "--file" in command:
            Path(command[command.index("--file") + 1]).write_text(json.dumps({"matches": []}))
        return subprocess.CompletedProcess(command, 0)

    scanner = GrypeScanner()
    scanner.is_installed = lambda: True
    with patch("sourcebastion.external_scanners.subprocess.run", side_effect=run):
        _, raw = scanner.scan_with_raw_output(str(tmp_path))
    Path(raw).unlink()
    assert commands == [["grype", "db", "status"], commands[1]]
    assert not (tmp_path / ".grype-deps").exists()


def test_offline_invalid_database_fails_without_network_update(tmp_path, monkeypatch):
    monkeypatch.setenv("SOURCEBASTION_SCAN_OFFLINE", "1")
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 1)

    scanner = GrypeScanner()
    scanner.is_installed = lambda: True
    with patch("sourcebastion.external_scanners.subprocess.run", side_effect=run):
        with pytest.raises(ScannerExecutionError) as caught:
            scanner.scan(str(tmp_path))
    assert caught.value.code == "execution_failed"
    assert commands == [["grype", "db", "status"]]


def test_semgrep_probe_disables_network_background_tasks():
    with patch("sourcebastion.external_scanners.subprocess.run") as run:
        assert SemgrepScanner().is_installed()
    command = run.call_args.args[0]
    assert "--metrics=off" in command and "--disable-version-check" in command


def test_failed_refresh_keeps_previous_snapshot(tmp_path):
    root = tmp_path / "advisories"

    def success(command, **kwargs):
        directory = Path(kwargs["env"]["GRYPE_DB_CACHE_DIR"])
        (directory / "data").write_text("verified")
        return subprocess.CompletedProcess(command, 0, json.dumps({"valid": True}))

    first = refresh(root, runner=success)
    assert (root / "current").resolve() == first

    def failure(command, **kwargs):
        return subprocess.CompletedProcess(command, 1, "", "untrusted diagnostic")

    with pytest.raises(RuntimeError, match="validation failed"):
        refresh(root, runner=failure)
    assert (root / "current").resolve() == first
    assert list(root.glob("snapshot-*")) == [first]


def test_refresh_switches_generation_without_editing_running_snapshot(tmp_path):
    root = tmp_path / "advisories"
    counter = 0

    def success(command, **kwargs):
        nonlocal counter
        directory = Path(kwargs["env"]["GRYPE_DB_CACHE_DIR"])
        if command[-1] == "update":
            counter += 1
            (directory / "data").write_text(str(counter))
        return subprocess.CompletedProcess(command, 0, json.dumps({"valid": True}))

    first = refresh(root, runner=success)
    second = refresh(root, runner=success)
    assert (root / "current").resolve() == second
    assert first != second and (first / "data").read_text() == "1"
    assert (second / "data").read_text() == "2"
