"""Refuse substituted published identities and altered frozen proof inputs."""

import json
from pathlib import Path
import runpy
import sys
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import m046_published as published
from inventory_upgrade import transition

SOURCE = "a" * 40
CONFIG = "sha256:" + "b" * 64


def test_release_requires_published_exact_tag_source_and_digest():
    release = dict(id=123, tag_name="v1.8.0", draft=False, prerelease=False, published_at="2026-10-10T00:00:00Z")
    value = published.release_identity(release, "v1.8.0", SOURCE, SOURCE, CONFIG)
    assert value["image"] == published.IMAGE + "@" + CONFIG
    for patch in ({"draft": True}, {"published_at": None}, {"tag_name": "v1.7.38"}, {"prerelease": True}):
        with pytest.raises(ValueError, match="published-stable-release-required"):
            published.release_identity({**release, **patch}, "v1.8.0", SOURCE, SOURCE, CONFIG)
    for tag, source, resolved, image in (
        ("latest", SOURCE, SOURCE, CONFIG), ("v1.8.0", SOURCE, "c" * 40, CONFIG),
        ("v1.8.0", SOURCE[:7], SOURCE[:7], CONFIG), ("v1.8.0", SOURCE, SOURCE, "latest"),
    ):
        with pytest.raises(ValueError):
            published.release_identity(release, tag, source, resolved, image)


def manifest_fixture():
    raw = json.dumps({"schemaVersion": 2, "config": {"digest": CONFIG}, "layers": []}).encode()
    descriptor = {"digest": "sha256:" + published.sha(raw), "size": len(raw),
                  "platform": {"os": "linux", "architecture": "amd64"}}
    return raw, descriptor


def test_selects_unique_native_platform_and_keeps_attestations_separate():
    _, descriptor = manifest_fixture()
    unknown = {**descriptor, "platform": {"os": "unknown", "architecture": "unknown"}}
    index = json.dumps({"schemaVersion": 2, "manifests": [descriptor, unknown]}).encode()
    assert published.native_descriptor(index, "sha256:" + published.sha(index), "amd64") == descriptor
    for rows in ([unknown], [descriptor, descriptor]):
        raw = json.dumps({"schemaVersion": 2, "manifests": rows}).encode()
        with pytest.raises(ValueError, match="unique-published-native-manifest-required"):
            published.native_descriptor(raw, "sha256:" + published.sha(raw), "amd64")
    with pytest.raises(ValueError, match="published-index-identity-mismatch"):
        published.native_descriptor(index + b" ", "sha256:" + published.sha(index), "amd64")


@pytest.mark.parametrize("field,value", [("Id", "sha256:" + "c" * 64), ("Architecture", "arm64"), ("Os", "windows")])
def test_pulled_image_must_match_native_manifest_config(field, value):
    raw, descriptor = manifest_fixture()
    observed = {"Id": CONFIG, "Architecture": "amd64", "Os": "linux"}
    assert published.bind_native(raw, descriptor, observed, "amd64")["config_digest"] == CONFIG
    observed[field] = value
    with pytest.raises(ValueError, match="pulled-native-config-mismatch"):
        published.bind_native(raw, descriptor, observed, "amd64")


@pytest.mark.parametrize("change", ["bytes", "digest", "size"])
def test_registry_manifest_bytes_size_and_digest_must_all_match(change):
    raw, descriptor = manifest_fixture()
    if change == "bytes":
        raw += b" "
    elif change == "digest":
        descriptor["digest"] = "sha256:" + "c" * 64
    else:
        descriptor["size"] += 1
    with pytest.raises(ValueError, match="published-native-manifest-mismatch"):
        published.bind_native(raw, descriptor, {"Id": CONFIG}, "amd64")


def generation(tmp_path):
    root = tmp_path / "generation"
    (root / "6").mkdir(parents=True)
    (root / "snapshot.json").write_bytes(b'{"database": {"valid": true}}')
    (root / "6/vulnerability.db").write_bytes(b"authored synthetic advisory bytes")
    manifest = tmp_path / "advisory-files.json"
    manifest.write_bytes(json.dumps(published.advisory_files(root), sort_keys=True, separators=(",", ":")).encode())
    return root, manifest, published.sha(manifest.read_bytes())


@pytest.mark.parametrize("change", ["db", "snapshot", "extra", "manifest", "missing", "symlink", "hardlink"])
def test_both_architectures_must_receive_exact_same_advisory_file_set(tmp_path, change):
    root, manifest, digest = generation(tmp_path)
    assert published.verify_advisories(root, manifest, digest) == published.sha((root / "snapshot.json").read_bytes())
    if change in {"db", "snapshot"}:
        (root / ("6/vulnerability.db" if change == "db" else "snapshot.json")).write_bytes(b"changed")
    elif change == "extra":
        (root / "extra").write_bytes(b"unexpected file")
    elif change == "manifest":
        manifest.write_bytes(manifest.read_bytes() + b" ")
    elif change == "missing":
        (root / "snapshot.json").unlink()
    elif change == "symlink":
        (root / "alias").symlink_to("snapshot.json")
    else:
        import os
        os.link(root / "snapshot.json", root / "alias")
    with pytest.raises(ValueError):
        published.verify_advisories(root, manifest, digest)


def test_s01_zip_is_verified_before_extracting_only_fixed_oci_entry(tmp_path, monkeypatch):
    archive, output = tmp_path / "s01.zip", tmp_path / "baseline.tar"
    payload = b"synthetic OCI archive for admission boundary test"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("runtime.oci.tar", payload)
        bundle.writestr("runtime.oci.tar.sha256", published.sha(payload))
    row = {"architecture": "amd64", "oci_zip_sha256": published.sha(archive.read_bytes()),
           "oci_sha256": published.sha(payload), "image_cost": {"archive_bytes": len(payload)}}
    review = tmp_path / "evaluation/m046/evidence/direct-alpine-independent-verification.json"
    review.parent.mkdir(parents=True)
    review.write_text(json.dumps({"architectures": [row]}))
    monkeypatch.setattr(published, "ROOT", tmp_path)
    published.extract_s01(archive, output, "amd64")
    assert output.read_bytes() == payload
    with pytest.raises(FileExistsError):
        published.extract_s01(archive, output, "amd64")
    archive.write_bytes(archive.read_bytes() + b"changed")
    with pytest.raises(ValueError, match="frozen-s01-zip-digest-mismatch"):
        published.extract_s01(archive, tmp_path / "refused", "amd64")
    assert not (tmp_path / "refused").exists()


def native_pair(tmp_path):
    roots = [tmp_path / arch for arch in ("amd64", "arm64")]
    arms = ("corpus", "flat-1000", "flat-10000", "flat-100000", "flat-100001", "graph", "expansion")
    for root, arch in zip(roots, ("amd64", "arm64")):
        root.mkdir()
        paths = [root / f"inventory-resources-{arm}-{repeat}" for arm in arms for repeat in range(1, 4)]
        paths += [root / f"entrypoint/repeat-{repeat}/entrypoint-resources" for repeat in range(1, 4)]
        for path in paths:
            path.mkdir(parents=True)
            workload = b'{"finite": "synthetic unit-test evidence"}'
            (path / "workload.json").write_bytes(workload)
            (path / "resources.json").write_text(json.dumps({
                "observer": "host-cgroup-v2", "status": "passed", "architecture": arch, "image_id": CONFIG,
                "cpu_usec": 1, "memory_peak": 1, "swap_peak": 0, "pids_peak": 1,
                "wall_seconds": 1, "oom_kill": 0, "exit_code": 0, "removed": True,
                "workload_sha256": published.sha(workload)}))
        (root / "source-expectations.stdout").write_text(json.dumps({"cases": [
            {"case": f"unit-test-{i}", "inventory_sha256": f"{i:064x}", "expectation_disagreement": None} for i in range(64)]}))
        for repeat in range(1, 4):
            path = root / f"inventory-resources-corpus-{repeat}"
            workload = (root / "source-expectations.stdout").read_bytes()
            (path / "workload.json").write_bytes(workload)
            resource = json.loads((path / "resources.json").read_bytes())
            resource["workload_sha256"] = published.sha(workload)
            (path / "resources.json").write_text(json.dumps(resource))
        (root / "frozen-s01-growth.json").write_text(json.dumps({"status": "passed", "candidate_manifest": CONFIG,
            "tested_image_id": CONFIG, "baseline_kind": "frozen-s01-pre-inventory-layer-prefix"}))
        receipt = {"status": "finite-published-native-passed", "architecture": arch, "acceptance": False,
                   "config_digest": CONFIG, "native_manifest": CONFIG, "image": published.IMAGE + "@" + CONFIG,
                   "source_sha": SOURCE, "release_tag": "v1.8.0", "release_id": 123,
                   "shared_advisory_manifest_sha256": "d" * 64, "advisory_snapshot_sha256": "d" * 64,
                   "remaining_acceptance": ["human review"], "retained_files": {}}
        (root / "receipt.json").write_text(json.dumps(receipt))
        rebind(root)
    return roots


def rebind(root):
    path = root / "receipt.json"
    receipt = json.loads(path.read_bytes())
    receipt["retained_files"] = {p.relative_to(root).as_posix(): published.sha(p.read_bytes())
                                 for p in root.rglob("*") if p.is_file() and p != path}
    path.write_text(json.dumps(receipt))


def test_comparison_checks_48_bindings_and_64_cases_without_claiming_acceptance(tmp_path):
    result = published.compare_native(*native_pair(tmp_path))
    assert result["resource_workload_bindings"] == 48 and result["equal_canonical_cases"] == 64
    assert result["acceptance"] is False and result["remaining_acceptance"] == ["human review"]


@pytest.mark.parametrize("change", ["stale-hash", "resource-limit", "missing-resource", "case-digest", "missing-case", "advisory", "growth", "repeated-case"])
def test_cross_native_comparison_refuses_altered_evidence_even_with_rehashed_bundle(tmp_path, change):
    roots = native_pair(tmp_path)
    root = roots[1]
    if change == "stale-hash":
        (root / "source-expectations.stdout").write_bytes(b"substituted")
    elif change == "advisory":
        path = root / "receipt.json"
        receipt = json.loads(path.read_bytes())
        receipt["advisory_snapshot_sha256"] = "e" * 64
        path.write_text(json.dumps(receipt))
    elif change in {"resource-limit", "missing-resource"}:
        path = root / "inventory-resources-corpus-1/resources.json"
        value = json.loads(path.read_bytes())
        if change == "missing-resource":
            path.unlink()
        else:
            value["cpu_usec"] = 120_000_001
            path.write_text(json.dumps(value))
    elif change == "repeated-case":
        path = root / "inventory-resources-corpus-2/workload.json"
        value = json.loads(path.read_bytes())
        value["cases"][0]["inventory_sha256"] = "f" * 64
        path.write_text(json.dumps(value))
        resource_path = path.parent / "resources.json"
        resource = json.loads(resource_path.read_bytes())
        resource["workload_sha256"] = published.sha(path.read_bytes())
        resource_path.write_text(json.dumps(resource))
    elif change in {"case-digest", "missing-case"}:
        path = root / "source-expectations.stdout"
        value = json.loads(path.read_bytes())
        if change == "missing-case":
            value["cases"].pop()
        else:
            value["cases"][0]["inventory_sha256"] = "f" * 64
        path.write_text(json.dumps(value))
    else:
        path = root / "frozen-s01-growth.json"
        value = json.loads(path.read_bytes())
        value["baseline_kind"] = "newer-pr-base"
        path.write_text(json.dumps(value))
    if change != "stale-hash":
        rebind(root)
    with pytest.raises((ValueError, FileNotFoundError)):
        published.compare_native(*roots)


@pytest.mark.parametrize("change", [None, "delta", "baseline", "candidate", "missing-case", "concealed-status", "approval-metadata"])
def test_ci_auditor_recomputes_exact_upgrade_approval_instead_of_trusting_passed(tmp_path, monkeypatch, change):
    functions = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/audit-m046-native-ci.py"))
    verify = functions["verify_corpus_gate"]
    report = {"status": "passed", "baseline_sha256": "a" * 64, "candidate_oracle_sha256": "b" * 64,
              "corpus": {"status": "review-required", "cases_compared": 64, "same_source_corpus": True,
                         "missing_cases": [], "added_cases": [], "changes": [{"case": "synthetic-unit-case", "delta": "original"}]},
              "findings": {"status": "not-compared"}}
    report["approval"] = {**transition(report, report["candidate_oracle_sha256"]),
                          "reason": "Synthetic exact-transition boundary test", "pull_request": 162}
    ledger = tmp_path / "ledger.json"
    ledger.write_text(json.dumps([report["approval"]]))
    monkeypatch.setitem(verify.__globals__, "ACCEPTED_UPGRADES", ledger)
    if change == "delta":
        report["corpus"]["changes"][0]["delta"] = "substituted"
    elif change == "baseline":
        report["baseline_sha256"] = "c" * 64
    elif change == "candidate":
        report["candidate_oracle_sha256"] = "c" * 64
    elif change == "missing-case":
        report["corpus"]["missing_cases"] = ["disappeared"]
    elif change == "concealed-status":
        report["corpus"]["status"] = "passed"
    elif change == "approval-metadata":
        report["approval"]["pull_request"] = 999
    if change is None:
        verify(report)
    else:
        with pytest.raises(ValueError):
            verify(report)
