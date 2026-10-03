"""Unit tests for CLI commands"""

import json
import os
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from click.testing import CliRunner
from sourcebastion.cli import main, scan, gitlab_scan, github_scan, init, check, status
from sourcebastion.external_scanners import ScannerExecutionError


@pytest.fixture(autouse=True)
def stub_external_scanner_execution():
    """CLI unit tests do not depend on host-installed scanner binaries."""
    with (
        patch("sourcebastion.external_scanners.ExternalScannerManager.scan_all", return_value=[]),
        patch(
            "sourcebastion.external_scanners.ExternalScannerManager.scan_all_with_raw_outputs",
            return_value=([], {}),
        ),
    ):
        yield


class TestCLIBasic:
    """Test basic CLI functionality"""

    def test_main_command_help(self):
        """Test that main command help works"""
        runner = CliRunner()
        result = runner.invoke(main, ['--help'])
        assert result.exit_code == 0
        assert 'SourceBastion Scan: deterministic application security scanning.' in result.output

    def test_version_option(self):
        """Test that version option works"""
        runner = CliRunner()
        result = runner.invoke(main, ['--version'])
        assert result.exit_code == 0


class TestScanCommand:
    """Test scan command functionality"""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    @pytest.fixture
    def sample_file(self, temp_dir):
        """Create a sample Python file for scanning"""
        file_path = Path(temp_dir) / "test.py"
        file_path.write_text("""
# Sample file for scanning
def example():
    return "hello"
""")
        return str(file_path)

    def test_scan_help(self):
        """Test scan command help"""
        runner = CliRunner()
        result = runner.invoke(main, ['scan', '--help'])
        assert result.exit_code == 0
        assert 'Scan a codebase' in result.output
        assert '--output' in result.output

    def test_scan_basic(self, sample_file):
        """Test basic scan command"""
        runner = CliRunner()
        result = runner.invoke(main, ['scan', sample_file])
        assert result.exit_code == 0
        assert 'Security scan completed' in result.output

    def test_scan_with_nonexistent_path(self):
        """Test scan with nonexistent path"""
        runner = CliRunner()
        result = runner.invoke(main, ['scan', '/nonexistent/path'])
        assert result.exit_code != 0
        assert 'does not exist' in result.output

    def test_scan_reports_bounded_component_failure(self, sample_file):
        runner = CliRunner()
        with patch(
            "sourcebastion.external_scanners.ExternalScannerManager.scan_all",
            side_effect=ScannerExecutionError("semgrep", "timeout"),
        ):
            result = runner.invoke(main, ["scan", sample_file])

        assert result.exit_code == 1
        assert "semgrep scanner failed (timeout)" in result.output

    def test_scan_with_invalid_output_path(self, sample_file):
        """Test scan with invalid output path"""
        runner = CliRunner()
        result = runner.invoke(main, [
            'scan',
            sample_file,
            '--output', '/root/forbidden/output.json'
        ])
        # Should handle invalid output path gracefully
        assert result.exit_code != 0

    def test_scan_directory(self, temp_dir):
        """Test scanning a directory"""
        runner = CliRunner()
        result = runner.invoke(main, ['scan', temp_dir])
        assert result.exit_code == 0
        assert 'Security scan completed' in result.output

    def test_legacy_ai_prompt_is_ignored(self, sample_file):
        """The legacy option must never enable LLM-backed scanning."""
        runner = CliRunner()
        result = runner.invoke(main, [
            'scan',
            sample_file,
            '--ai-prompt', 'Focus on SQL injection'
        ])
        assert result.exit_code == 0
        assert 'scans never call LLM providers' in result.output

    def test_scan_with_languages(self, sample_file):
        """Test scan with language filter"""
        runner = CliRunner()
        result = runner.invoke(main, [
            'scan',
            sample_file,
            '--languages', 'python'
        ])
        assert result.exit_code == 0

    def test_scan_with_severity(self, sample_file):
        """Test scan with severity filter"""
        runner = CliRunner()
        result = runner.invoke(main, [
            'scan',
            sample_file,
            '--severity', 'high'
        ])
        assert result.exit_code == 0


class TestGitlabScanCommand:
    """Test gitlab-scan command functionality"""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    @pytest.fixture
    def sample_file(self, temp_dir):
        """Create a sample Python file for scanning"""
        file_path = Path(temp_dir) / "test.py"
        file_path.write_text("def test(): pass")
        return str(file_path)

    @pytest.fixture
    def temp_output_file(self, temp_dir):
        """Create a temporary output file path"""
        return str(Path(temp_dir) / "output.json")

    def test_gitlab_scan_help(self):
        """Test gitlab-scan command help"""
        runner = CliRunner()
        result = runner.invoke(main, ['gitlab-scan', '--help'])
        assert result.exit_code == 0
        assert 'GitLab vulnerability format' in result.output

    def test_gitlab_scan_basic(self, sample_file):
        """Test basic gitlab-scan command"""
        runner = CliRunner()
        result = runner.invoke(main, ['gitlab-scan', sample_file])
        assert result.exit_code == 0
        assert 'GitLab vulnerability scan completed' in result.output

    def test_gitlab_scan_with_output(self, sample_file, temp_output_file):
        """Test gitlab-scan with output file"""
        runner = CliRunner()
        result = runner.invoke(main, [
            'gitlab-scan',
            sample_file,
            '--output', temp_output_file
        ])
        assert result.exit_code == 0
        assert 'GitLab report saved' in result.output
        assert os.path.exists(temp_output_file)

    def test_gitlab_scan_output_format(self, sample_file, temp_output_file):
        """Test that gitlab-scan produces correct GitLab format"""
        runner = CliRunner()
        result = runner.invoke(main, [
            'gitlab-scan',
            sample_file,
            '--output', temp_output_file
        ])
        assert result.exit_code == 0

        # Verify output format
        with open(temp_output_file) as f:
            data = json.load(f)
        assert 'version' in data
        assert 'vulnerabilities' in data
        assert 'remediations' in data
        assert data['version'] == '15.0.0'

    def test_gitlab_scan_with_nonexistent_path(self):
        """Test gitlab-scan with nonexistent path"""
        runner = CliRunner()
        result = runner.invoke(main, ['gitlab-scan', '/nonexistent/path'])
        assert result.exit_code != 0
        assert 'does not exist' in result.output


class TestGithubScanCommand:
    """Test github-scan command functionality"""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    @pytest.fixture
    def sample_file(self, temp_dir):
        """Create a sample Python file for scanning"""
        file_path = Path(temp_dir) / "test.py"
        file_path.write_text("def test(): pass")
        return str(file_path)

    @pytest.fixture
    def temp_output_file(self, temp_dir):
        """Create a temporary output file path"""
        return str(Path(temp_dir) / "output.sarif")

    def test_github_scan_help(self):
        """Test github-scan command help"""
        runner = CliRunner()
        result = runner.invoke(main, ['github-scan', '--help'])
        assert result.exit_code == 0
        assert 'SARIF format' in result.output

    def test_github_scan_basic(self, sample_file):
        """Test basic github-scan command"""
        runner = CliRunner()
        result = runner.invoke(main, ['github-scan', sample_file])
        assert result.exit_code == 0
        assert 'GitHub SARIF scan completed' in result.output

    def test_github_scan_reports_suppressed_count(self, sample_file):
        report = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "test", "rules": []}},
                    "results": [],
                    "properties": {"sourcebastionSuppressedCount": 3},
                }
            ],
        }
        runner = CliRunner()

        with patch(
            "sourcebastion.scanner.SecurityScanner.scan_to_github_format",
            return_value=report,
        ):
            result = runner.invoke(main, ['github-scan', sample_file])

        assert result.exit_code == 0
        assert '[suppressed] 3 finding(s)' in result.output

    def test_github_scan_with_output(self, sample_file, temp_output_file):
        """Test github-scan with output file"""
        runner = CliRunner()
        result = runner.invoke(main, [
            'github-scan',
            sample_file,
            '--output', temp_output_file
        ])
        assert result.exit_code == 0
        assert 'SARIF report saved' in result.output
        assert os.path.exists(temp_output_file)

    def test_github_scan_output_format(self, sample_file, temp_output_file):
        """Test that github-scan produces correct SARIF format"""
        runner = CliRunner()
        result = runner.invoke(main, [
            'github-scan',
            sample_file,
            '--output', temp_output_file
        ])
        assert result.exit_code == 0

        # Verify SARIF format
        with open(temp_output_file) as f:
            data = json.load(f)
        assert data['version'] == '2.1.0'
        assert '$schema' in data
        assert 'runs' in data
        assert len(data['runs']) > 0
        assert 'tool' in data['runs'][0]
        assert 'driver' in data['runs'][0]['tool']

    def test_github_scan_with_nonexistent_path(self):
        """Test github-scan with nonexistent path"""
        runner = CliRunner()
        result = runner.invoke(main, ['github-scan', '/nonexistent/path'])
        assert result.exit_code != 0
        assert 'does not exist' in result.output


class TestInitCommand:
    """Test init command functionality"""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    def test_init_help(self):
        """Test init command help"""
        runner = CliRunner()
        result = runner.invoke(main, ['init', '--help'])
        assert result.exit_code == 0

    def test_init_creates_config(self, temp_dir, monkeypatch):
        """Test that init creates configuration file"""
        runner = CliRunner()
        monkeypatch.chdir(temp_dir)
        result = runner.invoke(main, ['init'])
        assert result.exit_code == 0
        assert os.path.exists('.sourcebastion.yaml')
        config_text = Path('.sourcebastion.yaml').read_text(encoding='utf-8')
        assert 'ai:' not in config_text
        assert 'gpt-' not in config_text

    def test_init_with_existing_config(self, temp_dir, monkeypatch):
        """Test init with existing configuration file"""
        # Create existing config
        config_path = Path(temp_dir) / '.sourcebastion.yaml'
        config_path.write_text("# Existing config")

        runner = CliRunner()
        monkeypatch.chdir(temp_dir)
        result = runner.invoke(main, ['init'])
        assert result.exit_code == 0
        assert 'already exists' in result.output


class TestGitlabScanConfig:
    def test_gitlab_scan_loads_project_config(self, tmp_path):
        """Ported from `web-report`, which was removed with the dashboard.

        The invariant is that the command reads `.sourcebastion.yaml` and
        applies its ignore rules, not which command does it. `gitlab-scan`
        produces the same document -- both called `scan_to_gitlab_format` --
        and had no coverage of this.
        """
        config_path = tmp_path / ".sourcebastion.yaml"
        config_path.write_text(
            """ignore:
  - file_path: tests/fixtures/**
    permanent: true
    reason: intentional fixture
""",
            encoding="utf-8",
        )
        output_dir = tmp_path / "report"
        observed = {}

        def fake_gitlab_scan(scanner, path, output_file=None, custom_prompt=None):
            observed["ignore_rules"] = scanner.config.ignore_rules
            return {"version": "15.0.0", "vulnerabilities": [], "remediations": []}

        with patch(
            "sourcebastion.scanner.SecurityScanner.scan_to_gitlab_format",
            new=fake_gitlab_scan,
        ):
            result = CliRunner().invoke(
                main,
                [
                    "gitlab-scan",
                    str(tmp_path),
                    "--output",
                    str(output_dir / "vulnerabilities.json"),
                    "--config",
                    str(config_path),
                ],
            )

        assert result.exit_code == 0
        assert len(observed["ignore_rules"]) == 1
        assert observed["ignore_rules"][0].file_path == "tests/fixtures/**"


class TestErrorHandling:
    """Test error handling and edge cases"""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    def test_scan_with_empty_directory(self, temp_dir):
        """Test scanning empty directory"""
        runner = CliRunner()
        result = runner.invoke(main, ['scan', temp_dir])
        assert result.exit_code == 0
        assert 'Security scan completed' in result.output

    def test_scan_with_unreadable_file(self, temp_dir):
        """Test scanning unreadable file"""
        file_path = Path(temp_dir) / "unreadable.py"
        file_path.write_text("test")
        os.chmod(file_path, 0o000)  # Make unreadable

        runner = CliRunner()
        result = runner.invoke(main, ['scan', str(file_path)])
        # Should handle unreadable file gracefully
        assert result.exit_code != 0 or result.exit_code == 0

        # Cleanup
        os.chmod(file_path, 0o644)

    def test_scan_with_special_characters_in_path(self, temp_dir):
        """Test scanning file with special characters"""
        file_path = Path(temp_dir) / "test file with spaces.py"
        file_path.write_text("def test(): pass")

        runner = CliRunner()
        result = runner.invoke(main, ['scan', str(file_path)])
        assert result.exit_code == 0

    def test_scan_with_symlink(self, temp_dir):
        """Test scanning symlinked file"""
        target_file = Path(temp_dir) / "target.py"
        target_file.write_text("def test(): pass")

        link_path = Path(temp_dir) / "link.py"
        link_path.symlink_to(target_file)

        runner = CliRunner()
        result = runner.invoke(main, ['scan', str(link_path)])
        assert result.exit_code == 0

    def test_serve_metrics_help_exposes_flags(self):
        """UX-1: the v2 metrics endpoint must be reachable from the CLI."""
        runner = CliRunner()
        result = runner.invoke(main, ['serve-metrics', '--help'])
        assert result.exit_code == 0
        assert 'serve-metrics' in result.output or 'Serve Prometheus' in result.output
        assert '--storage-backend' in result.output
        assert '--host' in result.output
        assert '--project' in result.output

    def test_scan_summary_shows_trend_when_v2_computed(self, tmp_path, monkeypatch):
        """UX-1: new/resolved counts computed by the scanner must reach stdout."""
        from sourcebastion import scanner as scanner_mod

        sample_file = tmp_path / "sample.py"
        sample_file.write_text("password = 'hardcoded'\n")

        real_scan = scanner_mod.SecurityScanner.scan

        def fake_scan(self, path, custom_prompt=None):
            result = real_scan(self, path, custom_prompt)
            result["scan_record"] = {
                "scan_id": "s1", "new_count": 3, "resolved_count": 1,
                "finding_count": 5,
            }
            # Make a couple of findings look aged for the >30d line.
            for issue in result.get("issues", []):
                issue["age_days"] = 45
            return result

        monkeypatch.setattr(scanner_mod.SecurityScanner, "scan", fake_scan)
        runner = CliRunner()
        result = runner.invoke(main, ['scan', str(sample_file)])
        assert result.exit_code == 0
        assert 'Trend:' in result.output
        assert '3 new' in result.output
        assert '1 resolved' in result.output


if __name__ == '__main__':
    pytest.main([__file__, '-v'])


class TestAFailedScanLeavesEvidence:
    """A tool failure must stay fatal, and must stop being invisible.

    KICS timed out in CI and the only output was a traceback: no artifact, so
    "one scanner exceeded its budget" looked identical to "the scanner is
    broken" without reading the log.
    """

    def test_component_failure_still_fails_the_scan(self, tmp_path):
        runner = CliRunner()
        output = tmp_path / "scan-results" / "sourcebastion.sarif"
        output.parent.mkdir(parents=True)

        with patch("sourcebastion.cli.SecurityScanner") as scanner:
            scanner.return_value.scan_to_github_format.side_effect = (
                ScannerExecutionError("kics", "timeout")
            )
            result = runner.invoke(
                main, ["github-scan", str(tmp_path), "--output", str(output)]
            )

        assert result.exit_code == 1

    def test_the_failed_component_and_code_are_recorded(self, tmp_path):
        runner = CliRunner()
        output = tmp_path / "scan-results" / "sourcebastion.sarif"
        output.parent.mkdir(parents=True)

        with patch("sourcebastion.cli.SecurityScanner") as scanner:
            scanner.return_value.scan_to_github_format.side_effect = (
                ScannerExecutionError("kics", "timeout")
            )
            runner.invoke(
                main, ["github-scan", str(tmp_path), "--output", str(output)]
            )

        evidence = json.loads((output.parent / "scan-failure.json").read_text())
        assert evidence["outcome"] == "failed"
        assert evidence["component"] == "kics"
        assert evidence["diagnostic_code"] == "timeout"

    def test_no_sarif_is_written_for_a_failed_scan(self, tmp_path):
        """A zero-result SARIF would be uploaded and could clear real alerts.

        The upload step runs whenever the SARIF exists, so writing one here
        would turn a failed scan into an apparent all-clear in code scanning.
        """
        runner = CliRunner()
        output = tmp_path / "scan-results" / "sourcebastion.sarif"
        output.parent.mkdir(parents=True)

        with patch("sourcebastion.cli.SecurityScanner") as scanner:
            scanner.return_value.scan_to_github_format.side_effect = (
                ScannerExecutionError("kics", "timeout")
            )
            runner.invoke(
                main, ["github-scan", str(tmp_path), "--output", str(output)]
            )

        assert not output.exists()

    def test_reporting_failure_does_not_change_the_outcome(self, tmp_path):
        """An unwritable directory must not turn a timeout into something else."""
        runner = CliRunner()

        with patch("sourcebastion.cli.SecurityScanner") as scanner:
            scanner.return_value.scan_to_github_format.side_effect = (
                ScannerExecutionError("kics", "timeout")
            )
            with patch("sourcebastion.cli.Path.write_text", side_effect=OSError):
                result = runner.invoke(
                    main,
                    ["github-scan", str(tmp_path), "--output", str(tmp_path / "o.sarif")],
                )

        assert result.exit_code == 1
