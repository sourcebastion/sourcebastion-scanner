"""Failure-contract tests for enabled external scanner components."""

import json
import csv
import os
import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from sourcebastion.external_scanners import (
    ExternalScannerManager,
    GitleaksScanner,
    GrypeScanner,
    KicsScanner,
    PHPVulnScanner,
    ScannerExecutionError,
    SemgrepScanner,
)
from sourcebastion.converters import VulnerabilityConverters
from sourcebastion.scanner import SecurityScanner


def test_repository_grype_exclusion_uses_supported_path_prefix():
    config = (Path(__file__).parents[1] / ".grype.yaml").read_text()

    assert '- "./tests/live/**"' in config


@pytest.mark.parametrize(
    ("scanner", "name"),
    [
        (GitleaksScanner(), "gitleaks"),
        (SemgrepScanner(), "semgrep"),
        (KicsScanner(), "kics"),
        (GrypeScanner(), "grype"),
    ],
)
def test_enabled_missing_component_is_not_empty_success(scanner, name):
    with patch.object(scanner, "is_installed", return_value=False):
        with pytest.raises(ScannerExecutionError) as raised:
            scanner.scan(".")

    assert raised.value.scanner == name
    assert raised.value.code == "not_installed"
    assert str(raised.value) == f"{name} scanner failed (not_installed)"


def test_timeout_is_a_bounded_failure(tmp_path):
    scanner = GitleaksScanner()
    with (
        patch.object(scanner, "is_installed", return_value=True),
        patch(
            "sourcebastion.external_scanners.subprocess.run",
            side_effect=subprocess.TimeoutExpired("gitleaks", 60),
        ),
    ):
        with pytest.raises(ScannerExecutionError) as raised:
            scanner.scan(str(tmp_path))

    assert raised.value.scanner == "gitleaks"
    assert raised.value.code == "scan_timeout"
    assert "gitleaks" in str(raised.value)
    assert str(tmp_path) not in str(raised.value)


def test_contract_deadline_caps_external_scanner_timeout(monkeypatch):
    scanner = GitleaksScanner()
    scanner.set_execution_deadline(101.5)
    monkeypatch.setattr("sourcebastion.external_scanners.time.monotonic", lambda: 100.0)

    assert scanner._timeout(60) == 1.5


def test_expired_contract_deadline_fails_before_starting_tool(monkeypatch):
    scanner = GitleaksScanner()
    scanner.set_execution_deadline(100.0)
    monkeypatch.setattr("sourcebastion.external_scanners.time.monotonic", lambda: 100.0)

    with pytest.raises(ScannerExecutionError) as raised:
        scanner.is_installed()

    assert raised.value.code == "timeout"


def test_invalid_json_is_not_empty_success(tmp_path):
    scanner = SemgrepScanner()
    completed = subprocess.CompletedProcess([], 0, "", "")
    with (
        patch.object(scanner, "is_installed", return_value=True),
        patch("sourcebastion.external_scanners.subprocess.run", return_value=completed),
    ):
        with pytest.raises(ScannerExecutionError) as raised:
            scanner.scan(str(tmp_path))

    assert raised.value.scanner == "semgrep"
    assert raised.value.code == "invalid_output"


def test_tool_specific_finding_exit_codes_are_complete(tmp_path):
    scanner = GitleaksScanner()

    def write_empty_report(command, **_kwargs):
        report_path = Path(command[command.index("--report-path") + 1])
        report_path.write_text("[]")
        return subprocess.CompletedProcess(command, 1, "", "")

    with (
        patch.object(scanner, "is_installed", return_value=True),
        patch("sourcebastion.external_scanners.subprocess.run", side_effect=write_empty_report),
    ):
        issues, raw_path = scanner.scan_with_raw_output(str(tmp_path))

    try:
        assert issues == []
        assert Path(raw_path).read_text() == "[]"
    finally:
        os.unlink(raw_path)


def test_gitleaks_success_with_empty_report_is_complete(tmp_path):
    scanner = GitleaksScanner()
    completed = subprocess.CompletedProcess([], 0, "", "")
    with (
        patch.object(scanner, "is_installed", return_value=True),
        patch("sourcebastion.external_scanners.subprocess.run", return_value=completed),
    ):
        issues, raw_path = scanner.scan_with_raw_output(str(tmp_path))

    try:
        assert issues == []
        assert Path(raw_path).read_text() == ""
    finally:
        os.unlink(raw_path)


def test_gitleaks_finding_exit_with_empty_report_fails_closed(tmp_path):
    scanner = GitleaksScanner()
    completed = subprocess.CompletedProcess([], 1, "", "")
    with (
        patch.object(scanner, "is_installed", return_value=True),
        patch("sourcebastion.external_scanners.subprocess.run", return_value=completed),
    ):
        with pytest.raises(ScannerExecutionError) as raised:
            scanner.scan_with_raw_output(str(tmp_path))

    assert raised.value.code == "invalid_output"


def test_semgrep_finding_exit_code_is_complete(tmp_path):
    scanner = SemgrepScanner()

    def write_empty_report(command, **_kwargs):
        report_path = Path(command[command.index("--output") + 1])
        report_path.write_text('{"results": [], "errors": []}')
        return subprocess.CompletedProcess(command, 1, "", "")

    with (
        patch.object(scanner, "is_installed", return_value=True),
        patch("sourcebastion.external_scanners.subprocess.run", side_effect=write_empty_report),
    ):
        issues, raw_path = scanner.scan_with_raw_output(str(tmp_path))

    try:
        assert issues == []
    finally:
        os.unlink(raw_path)



def test_kics_uses_exact_profile_exclusions_without_narrowing_platforms(tmp_path):
    scanner = KicsScanner()
    source = tmp_path / "source,fixture"
    names = ("infra/app.yaml", "infra/Vendor/nested/unused.yaml", "infra/GEN/unused.yaml",
             "infra/zz_generated_test.yaml", "infra/tests/test_app.yaml")
    for name in names:
        file = source / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text("apiVersion: v1\nkind: ConfigMap\n")

    def write_empty_report(command, **kwargs):
        exclusions, = csv.reader([command[command.index("--exclude-paths") + 1]])
        assert set(exclusions) == {
            str(source / "infra/Vendor"),
            str(source / "infra/GEN"),
            str(source / "infra/zz_generated_test.yaml"),
        }
        assert "--type" not in command
        output_dir = Path(command[command.index("-o") + 1])
        (output_dir / "results.json").write_text('{"queries": []}')
        return subprocess.CompletedProcess(command, 0, "", "")

    with (
        patch.object(scanner, "is_installed", return_value=True),
        patch.object(scanner, "_find_assets_path", return_value=tmp_path),
        patch("sourcebastion.external_scanners.subprocess.run", side_effect=write_empty_report),
    ):
        scanner.scan(str(source))
        assert scanner.scan_coverage == {"profile_excluded_paths": 3}
        with pytest.raises(ScannerExecutionError) as raised:
            scanner.scan_units(str(source), ["infra"])
        assert raised.value.code == "scope_unresolved"
        assert scanner.scan_coverage is None


def test_kics_keeps_large_exclusion_lists_in_bounded_arguments(tmp_path):
    scanner = KicsScanner()
    source = tmp_path / "source"
    source.mkdir()
    paths = {str(source / f"zz_generated_{index:04}_{'x' * 150}.yaml") for index in range(400)}
    for path in paths:
        Path(path).touch()

    def write_empty_report(command, **kwargs):
        chunks = [command[index + 1] for index, flag in enumerate(command) if flag == "--exclude-paths"]
        assert len(chunks) > 1 and all(len(os.fsencode(chunk)) <= 64 * 1024 for chunk in chunks)
        assert {path for chunk in chunks for path in next(csv.reader([chunk]))} == paths
        (Path(command[command.index("-o") + 1]) / "results.json").write_text('{"queries": []}')
        return subprocess.CompletedProcess(command, 0, "", "")

    with (
        patch.object(scanner, "is_installed", return_value=True),
        patch.object(scanner, "_find_assets_path", return_value=tmp_path),
        patch("sourcebastion.external_scanners.subprocess.run", side_effect=write_empty_report),
    ):
        scanner.scan(str(source))
    assert scanner.scan_coverage == {"profile_excluded_paths": 400}


def test_kics_engine_exit_is_a_failure(tmp_path):
    scanner = KicsScanner()
    completed = subprocess.CompletedProcess([], 126, "", "engine failed")
    with (
        patch.object(scanner, "is_installed", return_value=True),
        patch.object(scanner, "_find_assets_path", return_value=tmp_path),
        patch("sourcebastion.external_scanners.subprocess.run", return_value=completed),
    ):
        with pytest.raises(ScannerExecutionError) as raised:
            scanner.scan(str(tmp_path))

    assert raised.value.scanner == "kics"
    assert raised.value.code == "execution_failed"
    assert "engine failed" not in str(raised.value)


def test_kics_requires_binary_and_query_assets(tmp_path, monkeypatch):
    scanner = KicsScanner()
    binary_dir = tmp_path / "bin"
    assets = binary_dir / "assets"
    (assets / "queries").mkdir(parents=True)
    (assets / "libraries").mkdir()
    binary = binary_dir / "kics"
    binary.touch()
    monkeypatch.setattr(shutil, "which", lambda _name: str(binary))

    with patch(
        "sourcebastion.external_scanners.subprocess.run",
        return_value=subprocess.CompletedProcess([], 0, "", ""),
    ):
        assert scanner.is_installed()

    (assets / "queries").rmdir()
    with patch(
        "sourcebastion.external_scanners.subprocess.run",
        return_value=subprocess.CompletedProcess([], 0, "", ""),
    ):
        assert not scanner.is_installed()


def test_kics_passes_matching_query_and_library_paths(tmp_path):
    scanner = KicsScanner()
    assets = tmp_path / "assets"
    (assets / "queries").mkdir(parents=True)
    (assets / "libraries").mkdir()

    def write_empty_report(command, **_kwargs):
        assert command[command.index("-q") + 1] == str(assets / "queries")
        assert command[command.index("-b") + 1] == str(assets / "libraries")
        output_dir = Path(command[command.index("-o") + 1])
        (output_dir / "results.json").write_text('{"queries": []}')
        return subprocess.CompletedProcess(command, 0, "", "")

    with (
        patch.object(scanner, "is_installed", return_value=True),
        patch.object(scanner, "_find_assets_path", return_value=assets),
        patch("sourcebastion.external_scanners.subprocess.run", side_effect=write_empty_report),
    ):
        issues, raw_path = scanner.scan_with_raw_output(str(tmp_path))

    try:
        assert issues == []
    finally:
        os.unlink(raw_path)


def test_grype_dependency_preparation_failure_is_explicit(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    scanner = GrypeScanner()
    db_ready = subprocess.CompletedProcess([], 0, "", "")
    with (
        patch.object(scanner, "is_installed", return_value=True),
        patch(
            "sourcebastion.external_scanners.subprocess.run",
            side_effect=[db_ready, FileNotFoundError("npm")],
        ),
    ):
        with pytest.raises(ScannerExecutionError) as raised:
            scanner.scan(str(tmp_path))

    assert raised.value.scanner == "grype"
    assert raised.value.code == "not_installed"
    assert "npm" not in str(raised.value)


def test_php_failure_is_not_empty_success(tmp_path):
    scanner = PHPVulnScanner()
    with patch(
        "sourcebastion.php_vuln_scanner_simple.run_php_scanners",
        side_effect=RuntimeError("source fragment must stay private"),
    ):
        with pytest.raises(ScannerExecutionError) as raised:
            scanner.scan(str(tmp_path))

    assert raised.value.scanner == "php-vuln"
    assert raised.value.code == "execution_failed"
    assert "source fragment" not in str(raised.value)


def test_manager_propagates_failure_and_discards_prior_raw_output(tmp_path):
    completed_path = tmp_path / "completed.json"
    completed_path.write_text("{}")
    complete = Mock(enabled=True)
    complete.scan_with_raw_output.return_value = ([], str(completed_path))
    failed = Mock(enabled=True)
    failed.scan_with_raw_output.side_effect = ScannerExecutionError("semgrep", "timeout")

    manager = ExternalScannerManager(enabled_scanners=[])
    manager.scanners = {"gitleaks": complete, "semgrep": failed}

    with pytest.raises(ScannerExecutionError) as raised:
        manager.scan_all_with_raw_outputs(str(tmp_path))

    assert raised.value.scanner == "semgrep"
    assert raised.value.code == "timeout"
    assert not completed_path.exists()


def test_manager_normalizes_unexpected_component_exception():
    failed = Mock(enabled=True)
    failed.scan.side_effect = RuntimeError("unbounded implementation detail")
    manager = ExternalScannerManager(enabled_scanners=[])
    manager.scanners = {"gitleaks": failed}

    with pytest.raises(ScannerExecutionError) as raised:
        manager.scan_all(".")

    assert raised.value.scanner == "gitleaks"
    assert raised.value.code == "execution_failed"
    assert "implementation detail" not in str(raised.value)


def test_quick_check_does_not_suppress_component_failure(tmp_path):
    gitleaks = Mock(enabled=True)
    gitleaks.scan.side_effect = ScannerExecutionError("gitleaks", "timeout")
    scanner = SecurityScanner.__new__(SecurityScanner)
    scanner.use_external = True
    scanner.external = Mock(scanners={"gitleaks": gitleaks})

    with pytest.raises(ScannerExecutionError) as raised:
        scanner.quick_check(str(tmp_path))

    assert raised.value.scanner == "gitleaks"
    assert raised.value.code == "timeout"


@pytest.mark.parametrize(
    ("method_name", "converter"),
    [
        ("scan_to_gitlab_format", "convert_scanner_output"),
        ("scan_to_github_format", "convert_to_github_format"),
    ],
)
def test_output_conversion_failure_discards_all_outputs(tmp_path, method_name, converter):
    first = tmp_path / "gitleaks.json"
    second = tmp_path / "semgrep.json"
    first.write_text("[]")
    second.write_text("{}")
    scanner = SecurityScanner.__new__(SecurityScanner)
    scanner.use_external = True
    scanner.external = Mock()
    scanner.external.scan_all_with_raw_outputs.return_value = (
        [],
        {"gitleaks": str(first), "semgrep": str(second)},
    )

    with patch.object(VulnerabilityConverters, converter, side_effect=ValueError("raw source must stay private")):
        with pytest.raises(ScannerExecutionError) as raised:
            getattr(scanner, method_name)(str(tmp_path))

    assert raised.value.scanner == "gitleaks"
    assert raised.value.code == "invalid_output"
    assert "raw source" not in str(raised.value)
    assert not first.exists()
    assert not second.exists()


def _semgrep_report(tmp_path, payload):
    """Run SemgrepScanner against a canned semgrep report."""
    scanner = SemgrepScanner()

    def write_report(command, **_kwargs):
        report_path = Path(command[command.index("--output") + 1])
        report_path.write_text(json.dumps(payload))
        return subprocess.CompletedProcess(command, 0, "", "")

    with (
        patch.object(scanner, "is_installed", return_value=True),
        patch("sourcebastion.external_scanners.subprocess.run", side_effect=write_report),
    ):
        return scanner.scan_with_raw_output(str(tmp_path))


def test_semgrep_security_finding_with_list_technology_survives_parsing(tmp_path):
    # A real WebGoat result uses this metadata shape. Technology is optional
    # descriptive metadata, not a signal for dropping a security finding.
    issues, raw_path = _semgrep_report(tmp_path, {
        "results": [{
            "check_id": "java.inject.command-injection",
            "path": "src/CommandInjection.java",
            "start": {"line": 10, "col": 1},
            "end": {"line": 10, "col": 20},
            "extra": {
                "message": "Potential command injection",
                "severity": "ERROR",
                "metadata": {"category": "security", "technology": ["java", "spring"],
                             "cwe": ["CWE-78: OS Command Injection"]},
            },
        }], "errors": [],
    })
    try:
        assert len(issues) == 1
        assert issues[0]["scanner"] == "semgrep"
        assert issues[0]["file"] == "src/CommandInjection.java"
    finally:
        os.unlink(raw_path)


# The exact shape semgrep emits for a file it cannot fully parse, captured from
# the pinned scanner image. Note semgrep's own exit code is 0: it does not
# consider this a failed scan, and neither may we.
PARTIAL_PARSING_ERROR = {
    "level": "warn",
    "type": ["PartialParsing", [{"path": "/src/vendor.min.js"}]],
    "message": "Syntax error at line /src/vendor.min.js:1:",
}


def test_semgrep_partial_parsing_does_not_discard_the_scan(tmp_path):
    """One unparseable file must not fail a repository's whole scan.

    This was a live outage: every hosted gate on a repository containing a
    vendored or minified file reported "the scan produced no report", because
    a non-fatal `errors` entry was read as a fatal one.
    """
    issues, raw_path = _semgrep_report(
        tmp_path,
        {
            "results": [],
            "errors": [PARTIAL_PARSING_ERROR],
        },
    )
    try:
        assert issues == []
    finally:
        os.unlink(raw_path)


def test_semgrep_fatal_error_still_fails(tmp_path):
    with pytest.raises(ScannerExecutionError) as raised:
        _semgrep_report(
            tmp_path,
            {
                "results": [],
                "errors": [{"level": "error", "type": "SemgrepFatalError", "message": "boom"}],
            },
        )
    assert raised.value.code == "execution_failed"


def test_semgrep_error_without_a_level_fails_closed(tmp_path):
    """An entry whose shape we do not recognise is treated as fatal."""
    with pytest.raises(ScannerExecutionError) as raised:
        _semgrep_report(tmp_path, {"results": [], "errors": [{"message": "unknown shape"}]})
    assert raised.value.code == "execution_failed"


def test_semgrep_keeps_findings_alongside_a_partial_parse(tmp_path):
    """The findings from the files semgrep *could* read must survive."""
    issues, raw_path = _semgrep_report(
        tmp_path,
        {
            "results": [
                {
                    "check_id": "python.lang.security.audit.dangerous-exec",
                    "path": "app.py",
                    "start": {"line": 3},
                    "end": {"line": 3},
                    "extra": {
                        "severity": "ERROR",
                        "message": "exec with user input",
                        # Real security metadata: a finding with none is
                        # classified as code quality and filtered, which would
                        # make this test pass for the wrong reason.
                        "metadata": {"cwe": ["CWE-94"], "category": "security"},
                    },
                }
            ],
            "errors": [PARTIAL_PARSING_ERROR],
        },
    )
    try:
        assert len(issues) == 1
    finally:
        os.unlink(raw_path)


@pytest.mark.parametrize("level", [None, "", "fatal", "unknown", 0, []])
def test_semgrep_unrecognized_error_level_fails_closed(tmp_path, level):
    with pytest.raises(ScannerExecutionError):
        _semgrep_report(tmp_path, {"results": [], "errors": [{"level": level}]})


@pytest.mark.parametrize("level", ["warn", "info"])
def test_semgrep_recognized_nonfatal_levels_preserve_full_scan(tmp_path, level):
    issues, raw_path = _semgrep_report(tmp_path, {"results": [], "errors": [{"level": level}]})
    try:
        assert issues == []
    finally:
        os.unlink(raw_path)


@pytest.mark.parametrize("errors", [None, {}, "", [None], ["not-an-error"]])
def test_semgrep_malformed_errors_collection_fails_closed(tmp_path, errors):
    with pytest.raises(ScannerExecutionError) as raised:
        _semgrep_report(tmp_path, {"results": [], "errors": errors})
    assert raised.value.code == "invalid_output"


def test_grype_dependency_install_uses_the_running_interpreter(tmp_path):
    """requirements.txt materialisation must not depend on a `pip` binary.

    The scanner images provision pip through `python3 -m ensurepip`, which
    installs no unversioned `pip`. Bare `pip` here raised FileNotFoundError,
    which `_install_dependencies` maps to `not_installed` -- reported against
    grype, which was present and working the whole time.
    """
    from sourcebastion.external_scanners import GrypeScanner

    (tmp_path / "requirements.txt").write_text("six==1.17.0\n")
    scanner = GrypeScanner()
    seen = {}

    def record(cmd, **kwargs):
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, "", "")

    with patch("sourcebastion.external_scanners.subprocess.run", side_effect=record):
        scanner._install_dependencies(str(tmp_path))

    assert seen["cmd"][:3] == [sys.executable, "-m", "pip"], seen["cmd"]
    assert "pip" != seen["cmd"][0]


def test_semgrep_subprocesses_ignore_inherited_online_settings(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SOURCEBASTION_SCAN_OFFLINE", "1")
    monkeypatch.setenv("SEMGREP_APP_TOKEN", "private-token")
    monkeypatch.setenv("SEMGREP_RULES", "https://example.invalid/rules")
    monkeypatch.setenv("SEMGREP_SEND_METRICS", "on")
    monkeypatch.setenv("SEMGREP_ENABLE_VERSION_CHECK", "1")
    monkeypatch.setenv("SEMGREP_OTEL_ENDPOINT", "https://example.invalid/traces")
    original_isdir = os.path.isdir
    monkeypatch.setattr(os.path, "isdir", lambda path:
        path == "/usr/local/share/sast-rules/go"
        if str(path).startswith("/usr/local/share/sast-rules") else original_isdir(path))
    seen = []

    def run(command, **kwargs):
        seen.append(command)
        env = kwargs["env"]
        assert {k: v for k, v in env.items() if k.startswith("SEMGREP_")} == {
            "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0",
            "SEMGREP_SETTINGS_FILE": env["SEMGREP_SETTINGS_FILE"],
            "SEMGREP_LOG_FILE": env["SEMGREP_LOG_FILE"]}
        settings_root = Path(env["SEMGREP_SETTINGS_FILE"]).parent
        assert settings_root.name.startswith("sourcebastion-semgrep-")
        assert settings_root.is_dir() and settings_root.stat().st_mode & 0o077 == 0
        assert Path(env["SEMGREP_LOG_FILE"]).parent == settings_root
        if "--version" not in command:
            assert command[:3] == ["semgrep", "scan", "--oss-only"]
            assert "--config=/usr/local/share/sast-rules/go" in command
            assert "--max-target-bytes=1000000" in command
            assert any(flag.startswith("--jobs=") for flag in command)
            assert any(flag.startswith("--max-memory=") for flag in command)
            Path(command[command.index("--output") + 1]).write_text('{"results": [], "errors": []}')
        assert "--metrics=off" in command and "--disable-version-check" in command
        return subprocess.CompletedProcess(command, 0, "", "private source fragment")

    with patch("sourcebastion.external_scanners.subprocess.run", side_effect=run):
        issues, raw_path = SemgrepScanner().scan_with_raw_output(str(tmp_path))
    try:
        assert issues == [] and len(seen) == 2
        err = capsys.readouterr().err
        assert "scan started" in err and "process exited code=0" in err
        assert "private" not in err
    finally:
        os.unlink(raw_path)


@pytest.mark.parametrize(("memory", "cpu_quota", "expected_jobs", "expected_memory"), [
    (1024, "100000 100000", 1, 256),
    (7168, "400000 100000", 1, 512),
    (8192, "400000 100000", 2, 512),
    (8192, "100000 100000", 1, 512),
])
def test_semgrep_limits_follow_the_container(memory, cpu_quota, expected_jobs, expected_memory, monkeypatch):
    from sourcebastion.external_scanners import _semgrep_resource_flags

    def cgroup_value(path, **kwargs):
        values = {
            "/sys/fs/cgroup/memory.max": str(memory * 1024**2),
            "/sys/fs/cgroup/cpu.max": cpu_quota,
        }
        try:
            return values[str(path)]
        except KeyError:
            raise FileNotFoundError(path) from None

    monkeypatch.setattr(Path, "read_text", cgroup_value)
    monkeypatch.setattr(os, "cpu_count", lambda: 16)
    monkeypatch.setattr(os, "sched_getaffinity", lambda pid: set(range(16)), raising=False)
    monkeypatch.setattr(os, "sysconf", lambda key: {"SC_PHYS_PAGES": 16 * 1024**3 // 4096,
                                                   "SC_PAGE_SIZE": 4096}[key])
    assert _semgrep_resource_flags() == [
        f"--jobs={expected_jobs}", f"--max-memory={expected_memory}", "--max-target-bytes=1000000",
    ]


def test_semgrep_offline_missing_packs_never_uses_registry(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SOURCEBASTION_SCAN_OFFLINE", "1")
    monkeypatch.setattr(os.path, "isdir", lambda path: False)
    monkeypatch.setattr(os.path, "isfile", lambda path: False)
    scanner = SemgrepScanner()
    with patch.object(scanner, "is_installed", return_value=True), patch(
        "sourcebastion.external_scanners.subprocess.run") as run:
        with pytest.raises(ScannerExecutionError):
            scanner.scan_with_raw_output(str(tmp_path))
    run.assert_not_called()
    assert "error code=execution_failed" in capsys.readouterr().err


@pytest.mark.parametrize("returncode,stderr,expected", [
    (2, "out of memory: secret source", "diagnostic=memory_exhaustion"),
    (2, "SIGKILL: secret source", "diagnostic=engine_killed"),
    (-11, "secret source", "process exited code=-11"),
])
def test_semgrep_exit_diagnostic_never_echoes_raw_stderr(tmp_path, capsys, returncode, stderr, expected):
    scanner = SemgrepScanner()
    with patch.object(scanner, "is_installed", return_value=True), patch(
        "sourcebastion.external_scanners.subprocess.run",
        return_value=subprocess.CompletedProcess([], returncode, "", stderr)):
        with pytest.raises(ScannerExecutionError):
            scanner.scan_with_raw_output(str(tmp_path))
    err = capsys.readouterr().err
    assert expected in err and "error code=execution_failed" in err
    assert "secret source" not in err


def test_semgrep_timeout_reports_to_stderr_without_exception_output(tmp_path, capsys):
    scanner = SemgrepScanner()
    with patch.object(scanner, "is_installed", return_value=True), patch(
        "sourcebastion.external_scanners.subprocess.run",
        side_effect=subprocess.TimeoutExpired("semgrep", 300, stderr="secret source")):
        with pytest.raises(ScannerExecutionError):
            scanner.scan_with_raw_output(str(tmp_path))
    err = capsys.readouterr().err
    assert "error code=scan_timeout" in err and "secret source" not in err


def test_semgrep_error_types_are_counted_without_messages_or_paths(tmp_path, capsys):
    issues, raw_path = _semgrep_report(tmp_path, {"results": [], "errors": [
        PARTIAL_PARSING_ERROR,
        {"level": "warn", "type": ["Timeout", "private source"], "message": "secret"},
        {"level": "info", "type": "untrusted customer text", "message": "secret"},
    ]})
    try:
        err = capsys.readouterr().err
        assert 'error_counts={"PartialParsing": 1, "Timeout": 1, "other": 1}' in err
        assert all(value not in err for value in ("vendor.min.js", "private source", "secret", "untrusted customer"))
    finally:
        os.unlink(raw_path)


def _gitleaks_command(path):
    """Run GitleaksScanner.scan against a fake gitleaks and return its argv."""
    scanner = GitleaksScanner()
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        report = command[command.index("--report-path") + 1]
        Path(report).write_text("[]")
        return subprocess.CompletedProcess(command, 0, "", "")

    with (
        patch.object(scanner, "is_installed", return_value=True),
        patch("sourcebastion.external_scanners.subprocess.run", side_effect=fake_run),
    ):
        scanner.scan(str(path))
    return calls[-1]


def test_tree_without_git_is_scanned_as_current_tree_not_history(tmp_path):
    """No .git means history mode would silently find nothing (platform #478)."""
    command = _gitleaks_command(tmp_path)
    assert command[:3] == ["gitleaks", "dir", str(tmp_path)]
    assert "detect" not in command


def test_tree_without_git_honours_repository_gitleaks_files(tmp_path):
    (tmp_path / ".gitleaks.toml").write_text("")
    (tmp_path / ".gitleaksignore").write_text("")
    command = _gitleaks_command(tmp_path)
    assert command[command.index("--config") + 1] == str(tmp_path / ".gitleaks.toml")
    assert command[command.index("--gitleaks-ignore-path") + 1] == str(tmp_path / ".gitleaksignore")


def test_git_repository_keeps_history_mode(tmp_path):
    (tmp_path / ".git").mkdir()
    command = _gitleaks_command(tmp_path)
    assert command[:2] == ["gitleaks", "detect"]


def test_a_probe_timeout_is_distinct_from_a_scan_timeout(tmp_path):
    """M066 D11: a slow `--version` under contention is not a slow scan."""
    scanner = GitleaksScanner()
    with patch(
        "sourcebastion.external_scanners.subprocess.run",
        side_effect=subprocess.TimeoutExpired("gitleaks", 30),
    ):
        with pytest.raises(ScannerExecutionError) as raised:
            scanner.scan(str(tmp_path))
    assert (raised.value.scanner, raised.value.code) == ("gitleaks", "probe_timeout")


@pytest.mark.parametrize("value, expected", [(None, 30), ("1", 1), ("30", 30)])
def test_probe_timeout_setting_only_lowers_the_ceiling(monkeypatch, value, expected):
    from sourcebastion.external_scanners import probe_timeout_seconds

    if value is None:
        monkeypatch.delenv("SOURCEBASTION_PROBE_TIMEOUT_SECONDS", raising=False)
    else:
        monkeypatch.setenv("SOURCEBASTION_PROBE_TIMEOUT_SECONDS", value)
    assert probe_timeout_seconds() == expected


@pytest.mark.parametrize("value", ["0", "31", "5s", "-1", ""])
def test_probe_timeout_setting_refuses_out_of_range_values(monkeypatch, value):
    from sourcebastion.external_scanners import probe_timeout_seconds

    monkeypatch.setenv("SOURCEBASTION_PROBE_TIMEOUT_SECONDS", value)
    with pytest.raises(ValueError, match="SOURCEBASTION_PROBE_TIMEOUT_SECONDS"):
        probe_timeout_seconds()


def test_the_probe_timeout_reaches_the_version_check(monkeypatch):
    monkeypatch.setenv("SOURCEBASTION_PROBE_TIMEOUT_SECONDS", "2")
    seen = []

    def run(argv, **kwargs):
        seen.append(kwargs["timeout"])
        return subprocess.CompletedProcess(argv, 0, b"", b"")
    with patch("sourcebastion.external_scanners.subprocess.run", side_effect=run):
        assert GitleaksScanner().is_installed()
    assert seen == [2]


def test_each_enabled_tool_is_probed_once_before_any_scan(tmp_path):
    from sourcebastion.external_scanners import ExternalScannerManager

    manager = ExternalScannerManager()
    order = []
    for name, scanner in manager.scanners.items():
        scanner.enabled = name in {"gitleaks", "kics"}
        scanner.is_installed = (lambda n: (lambda: order.append(("probe", n)) or True))(name)
        scanner.scan_with_raw_output = (lambda n: (lambda path: order.append(("scan", n)) or ([], None)))(name)
    manager.scan_all_with_raw_outputs(str(tmp_path))
    probes = [entry for entry in order if entry[0] == "probe"]
    assert sorted(probes) == [("probe", "gitleaks"), ("probe", "kics")]
    first_scan = min(i for i, entry in enumerate(order) if entry[0] == "scan")
    assert all(order.index(probe) < first_scan for probe in probes)
    # A later check inside a scan reuses the probe's answer.
    assert manager.scanners["gitleaks"].installed() and len([e for e in order if e[0] == "probe"]) == 2


@pytest.mark.parametrize("workers", [1, 2])
def test_an_unexpected_probe_error_maps_to_a_stable_code(tmp_path, workers):
    """The up-front probe keeps the scan loops' contract: no raw exception."""
    from sourcebastion.external_scanners import ExternalScannerManager

    manager = ExternalScannerManager(enabled_scanners=["gitleaks"], max_workers=workers)
    with patch("sourcebastion.external_scanners.subprocess.run", side_effect=PermissionError("denied")):
        with pytest.raises(ScannerExecutionError) as raised:
            manager.scan_all_with_raw_outputs(str(tmp_path))
    assert (raised.value.scanner, raised.value.code) == ("gitleaks", "execution_failed")
    assert "denied" not in str(raised.value)


def test_a_bad_probe_ceiling_is_refused_when_the_manager_is_built(monkeypatch):
    from sourcebastion.external_scanners import ExternalScannerManager

    monkeypatch.setenv("SOURCEBASTION_PROBE_TIMEOUT_SECONDS", "99")
    with pytest.raises(ValueError, match="SOURCEBASTION_PROBE_TIMEOUT_SECONDS"):
        ExternalScannerManager()
