"""Independent checks for evaluator boundaries, semantics and measurement."""

import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tarfile
import time

import pytest

from evaluation.m046.corpus import CORPUS
from evaluation.m046.cgroup_metrics import counters, mount_relative
from evaluation.m046.oracle import DIMENSIONS
from evaluation.m046.pack_evidence import pack
from evaluation.m046.performance_corpus import generate
from evaluation.m046.prepare import assert_module_files_unchanged, build_environment
from evaluation.m046.run import compare, execute, identity, materialize, normalize, projection, snapshot, validate_case
from evaluation.m046.summarize import summarize


def test_oracle_has_required_ecosystems_and_unique_cases():
    assert len(CORPUS) >= 40
    assert len({fixture["id"] for fixture in CORPUS}) == len(CORPUS)
    assert {fixture["ecosystem"] for fixture in CORPUS} >= {
        "python",
        "node",
        "go",
        "rust",
        "java",
        "dotnet",
        "ruby",
        "php",
    }
    assert {fixture["expected"]["disposition"] for fixture in CORPUS} >= {
        "parsed",
        "declaration-only",
        "unsupported",
        "malformed",
        "unsafe",
        "ignored",
    }
    for fixture in CORPUS:
        validate_case(fixture)


@pytest.mark.parametrize("path", ["../escape.txt", "/tmp/escape.txt", "a/../../escape.txt"])
def test_materializer_refuses_path_escape(tmp_path, path):
    fixture = copy.deepcopy(CORPUS[0])
    fixture["files"] = {path: "requests==2.32.3\n"}
    with pytest.raises(ValueError, match="unsafe fixture path"):
        materialize(fixture, tmp_path / "source")
    assert not (tmp_path / "source").exists()


def test_materializer_refuses_arbitrary_symlink_target(tmp_path):
    fixture = copy.deepcopy(next(fixture for fixture in CORPUS if fixture["id"] == "symlink-escape"))
    fixture["symlinks"] = {"requirements.txt": "/etc/passwd"}
    with pytest.raises(ValueError, match="unapproved synthetic symlink"):
        materialize(fixture, tmp_path / "source")


def test_projected_hash_lock_retains_original_provenance(tmp_path):
    fixture = next(fixture for fixture in CORPUS if fixture["id"] == "python-custom-hashed-lock")
    root = tmp_path / "source"
    materialize(fixture, root)
    original = (root / "dependencies-prod.txt").read_bytes()
    mappings = projection(root)
    assert len(mappings) == 1
    assert mappings[0]["original"] == "dependencies-prod.txt"
    assert (root / mappings[0]["projected"]).read_text() == "requests==2.32.3\n"
    assert (root / "dependencies-prod.txt").read_bytes() == original


@pytest.mark.parametrize(
    "content",
    [
        "-c constraints.txt\n",
        "-r base.txt\n",
        "requests>=2\n",
        'requests==2.32.3; os_name=="posix"\n',
        "Please discuss requests==2.32.3.\n",
    ],
)
def test_projection_refuses_unsupported_semantics_and_prose(tmp_path, content):
    root = tmp_path / "source"
    root.mkdir()
    (root / "custom.in").write_text(content)
    assert projection(root) == []


def test_projection_does_not_follow_escape_or_cycle(tmp_path):
    root = tmp_path / "source"
    materialize(next(fixture for fixture in CORPUS if fixture["id"] == "symlink-escape"), root)
    before = snapshot(root)
    assert projection(root) == []
    assert snapshot(root) == before


def test_projection_does_not_turn_constraint_target_into_installed_package(tmp_path):
    fixture = next(fixture for fixture in CORPUS if fixture["id"] == "python-constraint-only")
    root = tmp_path / "source"
    materialize(fixture, root)
    assert projection(root) == []


def test_pep503_normalization_keeps_ecosystem_namespace_and_version():
    assert identity("pkg:pypi/Typing_Extensions@4.12.2") == "pypi:typing-extensions@4.12.2"
    assert identity("pkg:npm/%40scope/lib@1.2.3?arch=x86_64") == "npm:@scope/lib@1.2.3"
    assert identity("pkg:golang/golang.org/x/text@v0.18.0") == "golang:golang.org/x/text@v0.18.0"
    assert identity("pkg:pypi/requests") is None


def test_syft_dependency_of_direction_excludes_file_ownership():
    document = {
        "artifacts": [{"id": "ms", "purl": "pkg:npm/ms@2.1.3"}, {"id": "debug", "purl": "pkg:npm/debug@4.3.7"}],
        "artifactRelationships": [
            {"parent": "ms", "child": "debug", "type": "dependency-of"},
            {"parent": "debug", "child": "file", "type": "contains"},
        ],
    }
    assert normalize(document, "syft")["edges"] == [["npm:debug@4.3.7", "npm:ms@2.1.3"]]


def test_cyclonedx_edges_require_evidenced_package_endpoints():
    document = {
        "components": [
            {"bom-ref": "debug", "purl": "pkg:npm/debug@4.3.7"},
            {"bom-ref": "ms", "purl": "pkg:npm/ms@2.1.3"},
        ],
        "dependencies": [{"ref": "debug", "dependsOn": ["ms", "missing"]}, {"ref": "root", "dependsOn": ["debug"]}],
    }
    assert normalize(document, "cdxgen")["edges"] == [["npm:debug@4.3.7", "npm:ms@2.1.3"]]


def test_empty_output_cannot_claim_coverage_or_declaration_success():
    expected = next(fixture["expected"] for fixture in CORPUS if fixture["id"] == "python-constraint-only")
    result = compare(expected, {"packages": [], "edges": []})
    assert result["missing_packages"] == []
    assert result["coverage"] == "unassessed"
    assert result["declarations"] == "unassessed"


def test_non_object_json_output_is_rejected():
    with pytest.raises(ValueError, match="JSON object"):
        normalize([], "syft")


def test_application_components_have_same_role_in_metadata_and_top_level():
    component = {"bom-ref": "fixture", "purl": "pkg:npm/fixture@1.0.0", "type": "application"}
    for document in ({"metadata": {"component": component}}, {"components": [component]}):
        result = normalize(document, "cdxgen")
        assert result["packages"] == []
        assert result["application_identities"] == ["npm:fixture@1.0.0"]


def test_flat_stock_output_cannot_pass_full_contract_even_for_empty_negative_case():
    expected = next(fixture["expected"] for fixture in CORPUS if fixture["id"] == "python-constraint-only")
    result = compare(expected, normalize({"components": []}, "cdxgen"))
    assert result["missing_packages"] == []
    assert not result["full_contract_agreement"]
    assert all(record["status"] == "unreported" for record in result["semantic_dimensions"].values())


@pytest.mark.parametrize("lost_semantics", ["root", "scope", "marker", "extras", "selection", "locator"])
def test_semantic_comparison_detects_identity_preserving_occurrence_loss(lost_semantics):
    expected = next(fixture["expected"] for fixture in CORPUS if fixture["id"] == "python-identical-multiple-roots")
    observed = {
        "packages": expected["packages"],
        "edges": expected["edges"],
        "application_identities": [],
        "semantic_dimensions": {dimension: copy.deepcopy(expected[dimension]) for dimension in DIMENSIONS},
    }
    assert compare(expected, observed)["full_contract_agreement"]
    observed["semantic_dimensions"]["occurrences"][1][lost_semantics] = "changed"
    result = compare(expected, observed)
    assert result["missing_packages"] == []
    assert not result["full_contract_agreement"]
    assert not result["semantic_dimensions"]["occurrences"]["agreement"]


def test_semantic_comparison_preserves_duplicate_occurrence_count_and_input_reason():
    expected = next(fixture["expected"] for fixture in CORPUS if fixture["id"] == "python-identical-multiple-roots")
    observed = {
        "packages": expected["packages"],
        "edges": expected["edges"],
        "application_identities": [],
        "semantic_dimensions": {dimension: copy.deepcopy(expected[dimension]) for dimension in DIMENSIONS},
    }
    observed["semantic_dimensions"]["occurrences"].pop()
    observed["semantic_dimensions"]["inputs"][1]["reason"] = "silently-skipped"
    result = compare(expected, observed)
    assert not result["semantic_dimensions"]["occurrences"]["agreement"]
    assert not result["semantic_dimensions"]["inputs"]["agreement"]


def test_summary_does_not_count_a_partial_failed_repeat_as_agreement():
    record = {
        "fixture": "sample",
        "expected": {"packages": []},
        "observed": {"packages": [], "edges": []},
        "comparison": {"missing_packages": [], "extra_packages": [], "missing_edges": [], "extra_edges": []},
        "metrics": {"exit_code": 0, "timed_out": False, "wall_seconds": 1, "max_child_rss_kib": 100},
        "source_unchanged": True,
    }
    failed = copy.deepcopy(record)
    failed["metrics"]["exit_code"] = 1
    failed.pop("observed")
    report = {
        "records": [record, failed],
        "engine": "sample",
        "binary_sha256": "binary",
        "corpus_sha256": "corpus",
        "architecture": "test",
    }
    result = summarize(report)
    assert result["exact_package_edge_agreements"] == 0
    assert result["fixtures"]["sample"]["repeat_equal"] is None
    assert result["coverage_assessment"] == "pending"


def test_summary_scores_every_valid_repeat_against_oracle():
    good = {
        "fixture": "sample",
        "expected": {"packages": []},
        "observed": {"packages": [], "edges": []},
        "comparison": {"missing_packages": [], "extra_packages": [], "missing_edges": [], "extra_edges": []},
        "metrics": {"exit_code": 0, "timed_out": False, "wall_seconds": 1, "max_child_rss_kib": 100},
        "source_unchanged": True,
    }
    different = copy.deepcopy(good)
    different["observed"]["packages"] = ["pypi:unexpected@1.0.0"]
    different["comparison"]["extra_packages"] = ["pypi:unexpected@1.0.0"]
    report = {
        "records": [good, different],
        "engine": "sample",
        "binary_sha256": "binary",
        "corpus_sha256": "corpus",
        "architecture": "test",
    }
    result = summarize(report)
    assert result["fixtures"]["sample"]["repeat_equal"] is False
    assert result["exact_package_edge_agreements"] == 0


@pytest.mark.integration
def test_native_sandbox_denies_network_source_writes_and_inherited_secrets(tmp_path, monkeypatch):
    tracer = os.environ.get("M046_STRACE")
    if not tracer:
        pytest.skip("opt-in native namespace proof requires M046_STRACE")
    source, scratch = tmp_path / "source", tmp_path / "run"
    source.mkdir()
    scratch.mkdir()
    monkeypatch.setenv("M046_PRIVATE_SENTINEL", "must-not-inherit")
    code = """import json, os, socket
result={"secret": "M046_PRIVATE_SENTINEL" in os.environ}
try:
    open("MUTATED", "w").write("bad")
    result["write"]="accepted"
except OSError as error:
    result["write"]=error.errno
try:
    socket.create_connection(("1.1.1.1", 443), timeout=1)
    result["network"]="accepted"
except OSError as error:
    result["network"]=error.errno
print(json.dumps(result))
"""
    result = execute(source, scratch, Path(tracer), [sys.executable, "-c", code], 10)
    assert result["exit_code"] == 0, (scratch / "stderr.log").read_text()
    observed = json.loads((scratch / "stdout.log").read_text())
    assert observed == {"secret": False, "write": 30, "network": 101}
    assert not (source / "MUTATED").exists()


@pytest.mark.integration
def test_native_sandbox_deadline_stops_process_tree(tmp_path):
    tracer = os.environ.get("M046_STRACE")
    if not tracer:
        pytest.skip("opt-in native namespace proof requires M046_STRACE")
    source, scratch = tmp_path / "source", tmp_path / "run"
    source.mkdir()
    scratch.mkdir()
    child_pid_file = scratch / "child-host-pid"
    # A new session evades a parent-only process-group kill. PID namespace
    # teardown must still kill it, and this proof checks its host /proc entry.
    code = f"""import os, time
from pathlib import Path
if os.fork() == 0:
    os.setsid()
    status = Path("/proc/self/status").read_text()
    host_pid = next(line.split()[1] for line in status.splitlines() if line.startswith("NSpid:"))
    Path({str(child_pid_file)!r}).write_text(host_pid)
time.sleep(60)
"""
    result = execute(source, scratch, Path(tracer), [sys.executable, "-c", code], 1)
    assert result["timed_out"]
    assert result["exit_code"] == -9
    assert result["wall_seconds"] < 5
    child = Path("/proc") / child_pid_file.read_text()
    deadline = time.monotonic() + 2
    while child.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not child.exists(), "descendant survived namespace teardown"


@pytest.mark.integration
@pytest.mark.parametrize(
    "termination,blocked", [(signal.SIGTERM, False), (signal.SIGKILL, False), (signal.SIGKILL, True)]
)
def test_native_supervisor_death_stops_session_escaping_descendant(tmp_path, termination, blocked):
    tracer = os.environ.get("M046_STRACE")
    if not tracer:
        pytest.skip("opt-in native namespace proof requires M046_STRACE")
    source, scratch = tmp_path / "source", tmp_path / "run"
    source.mkdir()
    scratch.mkdir()
    child_pid_file = scratch / "child-host-pid"
    child_code = f"""import os, time
from pathlib import Path
if os.fork() == 0:
    os.setsid()
    status = Path("/proc/self/status").read_text()
    host_pid = next(line.split()[1] for line in status.splitlines() if line.startswith("NSpid:"))
    Path({str(child_pid_file)!r}).write_text(host_pid)
time.sleep(60)
"""
    supervisor_code = f"""from pathlib import Path
import sys
import signal
from evaluation.m046.run import execute
if {blocked!r}:
    signal.pthread_sigmask(signal.SIG_BLOCK, {{signal.SIGTERM, signal.SIGINT, signal.SIGHUP}})
execute(Path({str(source)!r}), Path({str(scratch)!r}), Path({tracer!r}), [sys.executable, "-c", {child_code!r}], 60)
"""
    supervisor = subprocess.Popen([sys.executable, "-c", supervisor_code])
    try:
        deadline = time.monotonic() + 10
        while (
            (not child_pid_file.exists() or not child_pid_file.read_text().isdigit())
            and time.monotonic() < deadline
            and supervisor.poll() is None
        ):
            time.sleep(0.05)
        assert child_pid_file.exists(), (scratch / "stderr.log").read_text()
        child = Path("/proc") / child_pid_file.read_text()
        assert child.exists()
        supervisor.send_signal(termination)
        assert supervisor.wait(timeout=5) == -termination
        deadline = time.monotonic() + 3
        while child.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not child.exists(), "descendant survived evaluator cancellation"
    finally:
        if supervisor.poll() is None:
            supervisor.kill()
            supervisor.wait(timeout=5)
        # Even a failing proof must clean up its controlled probe.
        if child_pid_file.exists():
            child_pid = int(child_pid_file.read_text())
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


@pytest.mark.integration
def test_guard_refuses_to_launch_when_supervisor_already_disappeared(tmp_path):
    marker = tmp_path / "unexpected-launch"
    script = Path(__file__).resolve().parents[1] / "evaluation/m046/run.py"
    child = subprocess.run(
        [sys.executable, str(script), "_guard", "0", sys.executable, "-c", f"open({str(marker)!r}, 'w').close()"],
        start_new_session=True,
        timeout=5,
    )
    assert child.returncode == -signal.SIGKILL
    assert not marker.exists()


def test_performance_counts_and_digests_are_independent_and_deterministic(tmp_path):
    spec = {"id": "test-pins", "kind": "pins", "count": 1001, "roots": 10}
    first = generate(spec, tmp_path / "one")
    second = generate(spec, tmp_path / "two")
    assert first == second
    assert first["expected"]["identities"] == 1001
    assert first["expected"]["occurrences"] == 1001
    assert first["expected"]["source_files"] == 10
    assert first["expected"]["traversal_entries"] == 20
    assert not (tmp_path / "one" / "one.oracle.json").exists()


@pytest.mark.parametrize("count", [2 * 1024 * 1024, 2 * 1024 * 1024 + 1])
def test_performance_file_boundary_is_exact(tmp_path, count):
    result = generate({"id": "bytes", "kind": "bytes", "count": count}, tmp_path / "source")
    assert (tmp_path / "source/requirements.txt").stat().st_size == count
    assert result["expected"]["max_file_bytes"] == count


def test_performance_graph_has_requested_distinct_root_aware_edges(tmp_path):
    spec = {"id": "edges", "kind": "edges", "count": 501, "roots": 2}
    manifest = generate(spec, tmp_path / "source")
    edges = set()
    for path in (tmp_path / "source").rglob("package-lock.json"):
        data = json.loads(path.read_text())
        for parent, package in data["packages"].items():
            if not parent:
                continue
            for child in package.get("dependencies", {}):
                assert "node_modules/" + child in data["packages"]
                edges.add((path.parent.name, parent, child))
    assert len(edges) == manifest["expected"]["dependency_edges"] == 499
    assert manifest["expected"]["edges"] == 501
    assert manifest["expected"]["application_edges"] == 2
    assert manifest["expected"]["identities"] == 202


def test_go_build_environment_rejects_ambient_code_and_checksum_overrides(tmp_path, monkeypatch):
    for name in ("GOFLAGS", "GOWORK", "GOENV", "GONOSUMDB", "GOPRIVATE", "GOPROXY", "GOARCH"):
        monkeypatch.setenv(name, "attacker-override")
    env = build_environment(tmp_path, "arm64")
    assert "attacker-override" not in env.values()
    assert env["GOFLAGS"] == "-mod=readonly"
    assert env["GOWORK"] == env["GOENV"] == "off"
    assert env["GOSUMDB"] == "sum.golang.org"
    assert env["GOARCH"] == "arm64"
    assert env["GONOSUMDB"] == env["GOPRIVATE"] == ""


def test_module_preparation_cannot_change_pinned_manifest_bytes(tmp_path):
    from evaluation.m046.run import digest

    (tmp_path / "go.mod").write_text("module example.test/fixture\n")
    (tmp_path / "go.sum").write_text("synthetic checksum\n")
    expected = {name: digest(tmp_path / name) for name in ("go.mod", "go.sum")}
    assert_module_files_unchanged(tmp_path, expected)
    (tmp_path / "go.mod").write_text("module example.test/changed\n")
    with pytest.raises(ValueError, match="module files changed"):
        assert_module_files_unchanged(tmp_path, expected)


@pytest.mark.integration
@pytest.mark.parametrize("termination", [signal.SIGTERM, signal.SIGKILL])
def test_native_orchestrator_death_stops_nested_evaluator_and_candidate(tmp_path, termination):
    tracer = os.environ.get("M046_STRACE")
    if not tracer:
        pytest.skip("opt-in native namespace proof requires M046_STRACE")
    from evaluation.m046.run import digest

    child_pid_file = tmp_path / "candidate-host-pid"
    shim = tmp_path / "synthetic-candidate"
    shim.write_text(f"""#!{sys.executable}
import os, time
from pathlib import Path
if os.fork() == 0:
    os.setsid()
    status = Path("/proc/self/status").read_text()
    host_pid = next(line.split()[1] for line in status.splitlines() if line.startswith("NSpid:"))
    Path({str(child_pid_file)!r}).write_text(host_pid)
time.sleep(60)
""")
    shim.chmod(0o755)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"tools": {"syft": {"binary": str(shim), "sha256": digest(shim)}}}))
    supervisor = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "evaluation.m046.native",
            "--manifest",
            str(manifest),
            "--strace",
            tracer,
            "--output",
            str(tmp_path / "evidence"),
            "--repeat",
            "1",
        ]
    )
    try:
        deadline = time.monotonic() + 10
        while (
            (not child_pid_file.exists() or not child_pid_file.read_text().isdigit())
            and time.monotonic() < deadline
            and supervisor.poll() is None
        ):
            time.sleep(0.05)
        assert child_pid_file.exists(), "nested candidate did not start"
        child = Path("/proc") / child_pid_file.read_text()
        assert child.exists()
        supervisor.send_signal(termination)
        assert supervisor.wait(timeout=5) == -termination
        deadline = time.monotonic() + 3
        while child.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not child.exists(), "candidate survived top-level orchestration cancellation"
    finally:
        if supervisor.poll() is None:
            supervisor.kill()
            supervisor.wait(timeout=5)
        if child_pid_file.exists() and child_pid_file.read_text().isdigit():
            try:
                os.kill(int(child_pid_file.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_cgroup_namespace_mount_root_is_resolved_without_path_escape():
    assert mount_relative("/lxc/113/docker/job", "/lxc/113", "/sys/fs/cgroup") == Path("/sys/fs/cgroup/docker/job")
    for membership in ("/../../docker/job", "/other/job", "relative/job"):
        with pytest.raises(ValueError):
            mount_relative(membership, "/lxc/113", "/sys/fs/cgroup")


def test_cgroup_cpu_and_memory_are_kernel_aggregate_counters(tmp_path):
    (tmp_path / "cpu.stat").write_text("usage_usec 1234567\nuser_usec 1000000\nsystem_usec 234567\n")
    (tmp_path / "memory.peak").write_text("20971520\n")
    (tmp_path / "memory.events").write_text("low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n")
    observed = counters({"version": 2, "unified": tmp_path})
    assert observed["cpu_seconds"] == 1.234567
    assert observed["peak_charged_memory_bytes"] == 20 * 1024 * 1024
    (tmp_path / "memory.peak").unlink()
    with pytest.raises(FileNotFoundError):
        counters({"version": 2, "unified": tmp_path})


def test_evidence_archive_preserves_cycle_escape_as_data_and_never_reads_target(tmp_path):
    root = tmp_path / "raw"
    root.mkdir()
    (root / "output.json").write_text('{"packages":[]}\n')
    (root / "a").symlink_to("b")
    (root / "b").symlink_to("a")
    (root / "outside").symlink_to("../outside-secret")
    (tmp_path / "outside-secret").write_text("must-not-archive\n")
    archive = tmp_path / "evidence.tar.gz"
    result = pack({"raw": root}, archive)
    assert result["regular_files"] == 1
    assert result["links_as_data"] == 3
    with tarfile.open(archive) as handle:
        assert all(member.isfile() for member in handle.getmembers())
        links = json.load(handle.extractfile("SYMLINKS.json"))
        assert links == {"raw/a": "b", "raw/b": "a", "raw/outside": "../outside-secret"}
        assert "outside-secret" not in handle.getnames()
        for line in handle.extractfile("SHA256SUMS").read().decode().splitlines():
            expected, name = line.split("  ", 1)
            assert hashlib.sha256(handle.extractfile(name).read()).hexdigest() == expected
    other = tmp_path / "repeat.tar.gz"
    assert pack({"raw": root}, other)["archive_sha256"] == result["archive_sha256"]


def test_evidence_archive_refuses_resource_overflow_and_special_files(tmp_path):
    root = tmp_path / "raw"
    root.mkdir()
    (root / "large").write_text("12345")
    with pytest.raises(ValueError, match="byte budget"):
        pack({"raw": root}, tmp_path / "too-large.tar.gz", max_bytes=4)
    (root / "large").unlink()
    os.mkfifo(root / "fifo")
    with pytest.raises(ValueError, match="non-regular"):
        pack({"raw": root}, tmp_path / "fifo.tar.gz")


@pytest.mark.parametrize("kind", ["fifo", "symlink", "dangling-symlink"])
def test_evidence_archive_refuses_special_or_symlink_roots(tmp_path, kind):
    root = tmp_path / "root"
    if kind == "fifo":
        os.mkfifo(root)
    else:
        target = tmp_path / "target"
        if kind == "symlink":
            target.write_text("controlled fixture")
        root.symlink_to(target)
    with pytest.raises(ValueError, match="evidence root"):
        pack({"raw": root}, tmp_path / "evidence.tar.gz")


def test_missing_partial_evidence_is_explicit_in_archive_manifest(tmp_path):
    file = tmp_path / "present"
    file.write_text("controlled fixture")
    archive = tmp_path / "evidence.tar.gz"
    pack({"present": file, "missing": tmp_path / "absent"}, archive)
    with tarfile.open(archive) as handle:
        manifest = json.load(handle.extractfile("ARCHIVE.json"))
    assert manifest["missing_roots"] == ["missing"]


def test_evidence_swap_before_descriptor_open_never_follows_new_link(tmp_path, monkeypatch):
    root = tmp_path / "raw"
    root.mkdir()
    file = root / "result.json"
    file.write_text("INSIDE")
    outside = tmp_path / "outside"
    outside.write_text("PUBLIC")
    real_open = os.open

    def swap(name, flags, *args, **kwargs):
        if name == "result.json":
            file.unlink()
            file.symlink_to(outside)
        return real_open(name, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", swap)
    archive = tmp_path / "evidence.tar.gz"
    with pytest.raises(OSError):
        pack({"raw": root}, archive)
    assert not archive.exists()


def test_evidence_swap_during_snapshot_refuses_changed_binding(tmp_path, monkeypatch):
    root = tmp_path / "raw"
    root.mkdir()
    file = root / "result.json"
    file.write_text("INSIDE")
    outside = tmp_path / "outside"
    outside.write_text("PUBLIC")
    real_read = os.read
    swapped = False

    def swap(descriptor, size):
        nonlocal swapped
        content = real_read(descriptor, size)
        if not swapped:
            swapped = True
            file.unlink()
            file.symlink_to(outside)
        return content

    monkeypatch.setattr(os, "read", swap)
    archive = tmp_path / "evidence.tar.gz"
    with pytest.raises(ValueError, match="changed"):
        pack({"raw": root}, archive)
    assert not archive.exists()
