"""Per-scanner budgets, resolved at run time rather than baked into an image."""

import json
import subprocess
import time
from pathlib import Path

import pytest

from sourcebastion.config import Config, ScannerSettings, MAX_SCANNER_TIMEOUT_SECONDS
from sourcebastion.external_scanners import (
    DEFAULT_COMPONENT_TIMEOUTS,
    ExternalScannerManager,
    GrypeScanner,
    KicsScanner,
    ScannerExecutionError,
)


class TestDefaults:
    def test_kics_defaults_to_ten_minutes(self):
        """120 stopped being enough on an ordinary repository.

        `kics scan -p .` runs with no path exclusions, so its cost tracks
        repository size. Raising the default is a stopgap -- bounding the work
        is the real fix -- but a stopgap that needs no image build.
        """
        assert DEFAULT_COMPONENT_TIMEOUTS["kics"]["scan"] == 600
        assert KicsScanner()._budget("scan") == 600

    def test_setup_and_scan_are_separate_budgets(self):
        """A database refresh is not analysis, and one number cannot bound both.

        grype's refresh cost tracks network throughput and database size; its
        scan cost tracks the repository.
        """
        grype = GrypeScanner()
        assert grype._budget("setup") == DEFAULT_COMPONENT_TIMEOUTS["grype"]["setup"]
        assert grype._budget("scan") == DEFAULT_COMPONENT_TIMEOUTS["grype"]["scan"]


class TestPrecedence:
    def test_repository_configuration_overrides_the_default(self):
        scanner = KicsScanner()
        scanner.configure_timeouts(ScannerSettings(timeout=900))
        assert scanner._budget("scan") == 900

    def test_environment_retunes_without_building_an_image(self, monkeypatch):
        """The point of the change: a hosted deployment can retune in place."""
        monkeypatch.setenv("SOURCEBASTION_SETUP_TIMEOUT_GRYPE", "450")
        assert GrypeScanner()._budget("setup") == 450

    def test_repository_configuration_wins_over_the_environment(self, monkeypatch):
        monkeypatch.setenv("SOURCEBASTION_SCAN_TIMEOUT_KICS", "200")
        scanner = KicsScanner()
        scanner.configure_timeouts(ScannerSettings(timeout=700))
        assert scanner._budget("scan") == 700

    def test_the_execution_deadline_still_wins(self):
        """Configuration tunes a component; it cannot extend the contract.

        `_timeout` returns min(ceiling, remaining deadline), and a configured
        budget must not change that -- otherwise a repository could opt out of
        the M036 deadline its caller set.
        """
        scanner = KicsScanner()
        scanner.configure_timeouts(ScannerSettings(timeout=MAX_SCANNER_TIMEOUT_SECONDS))
        scanner.set_execution_deadline(time.monotonic() + 30)
        assert scanner._budget("scan") <= 30


class TestInvalidValuesAreRefused:
    @pytest.mark.parametrize("value", ["0", "-1", "abc", "", "99999", "12.5"])
    def test_a_malformed_environment_value_is_refused_not_ignored(
        self, monkeypatch, value
    ):
        """An operator who set this believes it took effect.

        Silently falling back to the default is the failure mode that let a
        stale scanner pin run for weeks elsewhere in this product.
        """
        monkeypatch.setenv("SOURCEBASTION_SCAN_TIMEOUT_KICS", value)
        with pytest.raises(ValueError):
            KicsScanner()._budget("scan")

    @pytest.mark.parametrize("value", [0, -5, MAX_SCANNER_TIMEOUT_SECONDS + 1])
    def test_configuration_is_bounded(self, value):
        """An unbounded timeout on a shared runner is a denial-of-service knob."""
        with pytest.raises(Exception):
            ScannerSettings(timeout=value)

    def test_a_malformed_scanners_block_is_an_error(self, tmp_path):
        config_file = tmp_path / ".sourcebastion.yaml"
        config_file.write_text("scanners: [kics]\n")
        with pytest.raises(ValueError):
            Config.from_file(str(config_file))


class TestWiring:
    def test_configuration_reaches_the_named_scanner_only(self):
        manager = ExternalScannerManager(
            scanner_settings={"kics": ScannerSettings(timeout=750)}
        )
        assert manager.scanners["kics"]._budget("scan") == 750
        assert manager.scanners["grype"]._budget("scan") == (
            DEFAULT_COMPONENT_TIMEOUTS["grype"]["scan"]
        )

    def test_settings_for_an_unknown_scanner_are_ignored_not_fatal(self):
        """A config naming a scanner this build does not have must not crash."""
        manager = ExternalScannerManager(
            scanner_settings={"nosuchscanner": ScannerSettings(timeout=90)}
        )
        assert "nosuchscanner" not in manager.scanners

    def test_the_config_file_round_trips(self, tmp_path):
        config_file = tmp_path / ".sourcebastion.yaml"
        config_file.write_text(
            "scanners:\n  kics:\n    timeout: 800\n  grype:\n    setup_timeout: 400\n"
        )
        config = Config.from_file(str(config_file))
        assert config.scanners["kics"].timeout == 800
        assert config.scanners["grype"].setup_timeout == 400


class TestGrypeDatabaseValidationBudget:
    @pytest.fixture
    def boundary(self, monkeypatch, tmp_path):
        clock = [100.0]
        calls = []
        monkeypatch.delenv("SOURCEBASTION_SETUP_TIMEOUT_GRYPE", raising=False)
        monkeypatch.delenv("SOURCEBASTION_SCAN_TIMEOUT_GRYPE", raising=False)
        monkeypatch.setenv("SOURCEBASTION_SCAN_OFFLINE", "1")
        monkeypatch.setattr("sourcebastion.external_scanners.time.monotonic", lambda: clock[0])
        monkeypatch.setattr("sourcebastion.external_scanners.tempfile.tempdir", str(tmp_path))

        def run(command, **kwargs):
            calls.append((command, kwargs))
            if command == ["grype", "--version"]:
                clock[0] += 5
            elif command == ["grype", "db", "status"]:
                env = kwargs["env"]
                assert env["GRYPE_DB_AUTO_UPDATE"] == "false"
                assert env["GRYPE_CHECK_FOR_APP_UPDATE"] == "false"
                assert env["GRYPE_DB_VALIDATE_AGE"] == "true"
                assert env["GRYPE_DB_VALIDATE_BY_HASH_ON_START"] == "true"
                clock[0] += 2
            else:
                assert command[:2] == ["grype", "dir:/fixture"]
                Path(command[command.index("--file") + 1]).write_text(json.dumps({"matches": []}))
            return subprocess.CompletedProcess(command, 0)

        monkeypatch.setattr("sourcebastion.external_scanners.subprocess.run", run)
        return calls, clock

    @pytest.mark.parametrize(
        "environment,configured,deadline,status_budget,scan_budget",
        [
            (None, None, None, 300, 300),
            (90, None, None, 90, 300),
            (90, 120, None, 120, 300),
            (90, 120, 140, 35, 33),
        ],
    )
    def test_setup_budget_reaches_database_status_after_version_probe(
        self, monkeypatch, boundary, environment, configured, deadline, status_budget, scan_budget
    ):
        calls, _clock = boundary
        if environment is not None:
            monkeypatch.setenv("SOURCEBASTION_SETUP_TIMEOUT_GRYPE", str(environment))
        scanner = GrypeScanner()
        scanner.configure_timeouts(ScannerSettings(setup_timeout=configured))
        if deadline is not None:
            scanner.set_execution_deadline(deadline)
        findings, raw_path = scanner.scan_with_raw_output("/fixture")
        try:
            assert findings == []
            assert [call[0] for call in calls[:2]] == [["grype", "--version"], ["grype", "db", "status"]]
            assert calls[0][1]["timeout"] == 30
            assert calls[1][1]["timeout"] == status_budget
            assert calls[2][1]["timeout"] == scan_budget
        finally:
            Path(raw_path).unlink()

    def test_deadline_exhausted_by_probe_prevents_database_work(self, boundary, tmp_path):
        calls, _clock = boundary
        scanner = GrypeScanner()
        scanner.configure_timeouts(ScannerSettings(setup_timeout=450))
        scanner.set_execution_deadline(105)
        with pytest.raises(ScannerExecutionError) as failure:
            scanner.scan_with_raw_output("/fixture")
        assert failure.value.scanner == "grype" and failure.value.code == "timeout"
        assert [call[0] for call in calls] == [["grype", "--version"]]
        assert not list(tmp_path.glob("*.json"))
