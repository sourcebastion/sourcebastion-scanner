"""Failure dispositions for finite proof helpers; no synthetic SCA acceptance."""

import importlib.util
import json
import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace

import pytest


@pytest.fixture
def probe():
    path = Path(__file__).resolve().parents[1] / "scripts/verify-inventory-real-grype.py"
    spec = importlib.util.spec_from_file_location("real_grype_probe", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_child(probe, tmp_path, program, seconds=5):
    return probe.capture(
        [sys.executable, "-c", program],
        environment={"PATH": os.environ.get("PATH", "")},
        cwd=tmp_path,
        stdout=tmp_path / "stdout",
        stderr=tmp_path / "stderr",
        deadline=time.monotonic() + seconds,
        check=lambda: None,
    )


def test_original_child_bytes_retained(probe, tmp_path):
    original = b'{ "x": 1.25 }\n'
    diagnostic = b"diagnostic\n"
    value = run_child(probe, tmp_path, f"import os;os.write(1,{original!r});os.write(2,{diagnostic!r})")
    assert value["exit_code"] == 0
    assert (tmp_path / "stdout").read_bytes() == b'{ "x": 1.25 }\n'
    assert (tmp_path / "stderr").read_bytes() == b"diagnostic\n"


@pytest.mark.parametrize("channel,fd", [("stdout", 1), ("stderr", 2)])
def test_overflow_stops_child_and_bounds_retained_evidence(probe, tmp_path, monkeypatch, channel, fd):
    monkeypatch.setattr(probe, channel.upper() + "_BYTES", 4096)
    with pytest.raises(RuntimeError, match=channel + "-budget-exceeded"):
        run_child(probe, tmp_path, f"import os;os.write({fd},b'x'*1000000)")
    assert (tmp_path / channel).stat().st_size == 4096


def test_nonzero_exit_retains_diagnostics_and_refuses_success(probe, tmp_path):
    with pytest.raises(RuntimeError, match="nonzero-exit"):
        run_child(probe, tmp_path, "import os;os.write(2,b'failed');raise SystemExit(4)")
    assert (tmp_path / "stderr").read_bytes() == b"failed"


def test_deadline_kills_sleeping_process_group(probe, tmp_path):
    start = time.monotonic()
    with pytest.raises(RuntimeError, match="deadline-exceeded"):
        run_child(probe, tmp_path, "import time;time.sleep(30)", seconds=0.1)
    assert time.monotonic() - start < 3


def test_expired_budget_does_not_spawn(probe, tmp_path):
    with pytest.raises(RuntimeError, match="deadline-exceeded"):
        run_child(probe, tmp_path, "raise SystemExit('must not run')", seconds=-1)
    assert not (tmp_path / "stdout").exists()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo"])
def test_untrusted_file_representation_refused_without_read(probe, tmp_path, kind):
    original = tmp_path / "original"
    original.write_bytes(b"bound")
    target = tmp_path / "target"
    if kind == "symlink":
        target.symlink_to(original)
    elif kind == "hardlink":
        os.link(original, target)
    else:
        os.mkfifo(target)
    with pytest.raises(ValueError, match="unsafe-file"):
        probe.file_binding(target, maximum=20, deadline=time.monotonic() + 1)


def test_advisory_symlink_and_excess_entries_refused(probe, tmp_path):
    (tmp_path / "snapshot.json").write_text("{}")
    (tmp_path / "6").mkdir()
    (tmp_path / "6/vulnerability.db").write_bytes(b"database")
    before = probe.advisory_binding(tmp_path, time.monotonic() + 5)
    assert set(before["files"]) == {"snapshot.json", "6/vulnerability.db"}
    link = tmp_path / "foreign"
    link.symlink_to(tmp_path / "6", target_is_directory=True)
    with pytest.raises(ValueError, match="unsafe-file"):
        probe.advisory_binding(tmp_path, time.monotonic() + 5)
    link.unlink()
    for index in range(31):
        (tmp_path / ("extra-" + str(index))).write_bytes(b"x")
    with pytest.raises(ValueError, match="entry-budget-exceeded"):
        probe.advisory_binding(tmp_path, time.monotonic() + 5)


def advisory_fixture():
    groups = [[{"id": f"GHSA-required-{number}", "namespace": "github:language:python"}] for number in range(4)]
    matches = [{"vulnerability": dict(group[0])} for group in groups]
    bindings = [SimpleNamespace(ordinal=number, occurrence_id="occurrence:first") for number in range(4)]
    return groups, matches, bindings


def test_all_four_groups_required_on_each_distinct_source_id(probe):
    groups, matches, bindings = advisory_fixture()
    expected = {"occurrence:first": groups, "occurrence:second": groups}
    # Four matches on one equal-purl source cannot satisfy the other source.
    with pytest.raises(ValueError, match="missing-required-advisory"):
        probe.required_advisories(bindings, matches, expected)
    second = [SimpleNamespace(ordinal=number + 4, occurrence_id="occurrence:second") for number in range(4)]
    evidence = probe.required_advisories(bindings + second, matches + matches, expected)
    assert [row["match_ordinals"] for row in evidence["occurrence:first"]] == [[0], [1], [2], [3]]
    assert [row["match_ordinals"] for row in evidence["occurrence:second"]] == [[4], [5], [6], [7]]


@pytest.mark.parametrize("missing", range(4))
def test_three_of_four_advisories_refused(probe, missing):
    groups, matches, bindings = advisory_fixture()
    with pytest.raises(ValueError, match="missing-required-advisory"):
        probe.required_advisories([row for row in bindings if row.ordinal != missing], matches, {"occurrence:first": groups})


@pytest.mark.parametrize("expected", [{}, {"occurrence:first": []}, {"occurrence:first": [[]]}])
def test_empty_advisory_policy_never_reports_success(probe, expected):
    with pytest.raises(ValueError, match="missing-required-advisory"):
        probe.required_advisories([], [], expected)


def test_missing_advisory_files_refused(probe, tmp_path):
    with pytest.raises(ValueError, match="missing-advisory-files"):
        probe.advisory_binding(tmp_path, time.monotonic() + 1)


def test_advisory_alias_requires_exact_structured_id_and_namespace(probe):
    aliases = {("GHSA-x84v-xcm2-53pg", "github:language:python"), ("CVE-2018-18074", "nvd:cpe")}
    match = {"vulnerability": {"id": "GHSA-x84v-xcm2-53pg", "namespace": "github:language:python"}}
    assert probe.known_advisory(match, aliases)
    match["vulnerability"]["namespace"] = "untrusted"
    assert not probe.known_advisory(match, aliases)
    match["relatedVulnerabilities"] = [{"id": "CVE-2018-18074", "namespace": "nvd:cpe"}]
    assert probe.known_advisory(match, aliases)
    match["relatedVulnerabilities"][0]["id"] += "-substring"
    assert not probe.known_advisory(match, aliases)
    match["vulnerability"]["description"] = json.dumps(sorted(aliases))
    assert not probe.known_advisory(match, aliases)


def test_advisory_aggregate_byte_ceiling(probe, tmp_path, monkeypatch):
    (tmp_path / "snapshot.json").write_bytes(b"{}")
    (tmp_path / "6").mkdir()
    (tmp_path / "6/vulnerability.db").write_bytes(b"database")
    monkeypatch.setattr(probe, "ADVISORY_BYTES", 10)
    assert sum(row["bytes"] for row in probe.advisory_binding(tmp_path, time.monotonic() + 5)["files"].values()) == 10
    (tmp_path / "extra").write_bytes(b"x")
    with pytest.raises(ValueError, match="unsafe-file"):
        probe.advisory_binding(tmp_path, time.monotonic() + 5)
