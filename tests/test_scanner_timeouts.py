"""Per-scanner budgets, resolved at run time rather than baked into an image."""

import time

import pytest

from ez_appsec.config import Config, ScannerSettings, MAX_SCANNER_TIMEOUT_SECONDS
from ez_appsec.external_scanners import (
    DEFAULT_COMPONENT_TIMEOUTS,
    ExternalScannerManager,
    GrypeScanner,
    KicsScanner,
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
        config_file = tmp_path / ".ez-appsec.yaml"
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
        config_file = tmp_path / ".ez-appsec.yaml"
        config_file.write_text(
            "scanners:\n  kics:\n    timeout: 800\n  grype:\n    setup_timeout: 400\n"
        )
        config = Config.from_file(str(config_file))
        assert config.scanners["kics"].timeout == 800
        assert config.scanners["grype"].setup_timeout == 400
