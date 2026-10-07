"""Source-authored semantic fixtures; no whole-corpus or M046 acceptance."""

from collections import Counter
from copy import deepcopy
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import sys
import tempfile

COLLECTIONS = (
    "roots",
    "analysis_scopes",
    "installed_environments",
    "declarations",
    "input_references",
    "occurrences",
    "relationships",
    "applications",
    "losses",
    "applicability",
    "dependency_selectors",
)
ANCHOR_FIELDS = {
    "roots": ("kind", "path"),
    "analysis_scopes": ("kind",),
    "installed_environments": ("kind",),
    "declarations": ("kind",),
    "input_references": ("kind", "role"),
    "occurrences": ("evidence_kind",),
    "applications": ("ecosystem",),
    "losses": ("dimension", "reason"),
}
ID_FIELDS = frozenset(
    {
        "root_id",
        "analysis_scope_id",
        "installed_environment_id",
        "occurrence_id",
        "relationship_id",
        "parent_id",
        "child_id",
        "selector_id",
    }
)
ID_LIST_FIELDS = frozenset(
    {
        "selection_declaration_ids",
        "root_ids",
        "analysis_scope_ids",
        "installed_environment_ids",
    }
)
EXPECTATIONS = Path("evaluation/m046/canonical-source-expectations-v1.json")
CORPUS = Path("tests/fixtures/inventory/corpus.json")
GO_SOURCE_FILES = frozenset({"go.mod", "go.sum", "main.go", "main_test.go", "toolchain.json", "gomod/main.go", "gomod/main_test.go"})


def render(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def anchor(collection, row):
    # Never bind by equal package name/purl. Ambiguous source anchors refuse;
    # extending to such fixtures requires a separately reviewed binding rule.
    return render({key: row[key] for key in ("source", *ANCHOR_FIELDS.get(collection, ()))})


def normalize(row, aliases):
    result = deepcopy(row)

    def bound(value):
        if value is None:
            return None
        if value not in aliases:
            raise ValueError("expectation-unknown-record-reference")
        return aliases[value]

    if "id" in result:
        result["id"] = bound(result["id"])
    for key in ID_FIELDS & result.keys():
        result[key] = bound(result[key])
    for key in ID_LIST_FIELDS & result.keys():
        # Sorting preserves multiplicity, including duplicate evidence links.
        result[key] = sorted(bound(value) for value in result[key])
    return result


def compare(expected, actual):
    """Compare complete contextual record multisets and coverage/stage fields.

    The caller separately validates the Inventory and controller envelope.
    This finite comparator refuses duplicate source anchors rather than
    guessing which equal-purl occurrence owns a later reference.
    """
    if set(expected["records"]) != set(COLLECTIONS):
        raise ValueError("expectation-collection-contract-mismatch")
    aliases, labels = {}, set()
    for collection in COLLECTIONS:
        wanted, observed = expected["records"][collection], actual[collection]
        if len(wanted) != len(observed):
            raise ValueError("expectation-record-count-mismatch")
        by_anchor = {}
        for row in wanted:
            label, key = row["id"], anchor(collection, row)
            if label in labels or key in by_anchor:
                raise ValueError("expectation-ambiguous-source-anchor")
            labels.add(label)
            by_anchor[key] = label
        seen = set()
        for row in observed:
            key = anchor(collection, row)
            if key not in by_anchor or key in seen or row["id"] in aliases:
                raise ValueError("expectation-unbound-source-anchor")
            seen.add(key)
            aliases[row["id"]] = by_anchor[key]
    expected_aliases = {label: label for label in labels}
    for collection in COLLECTIONS:
        wanted = Counter(render(normalize(row, expected_aliases)) for row in expected["records"][collection])
        observed = Counter(render(normalize(row, aliases)) for row in actual[collection])
        if observed != wanted:
            raise ValueError("expectation-record-fields-mismatch")
    wanted, observed = deepcopy(expected["coverage"]), deepcopy(actual["coverage"])
    wanted_inputs = Counter(render(normalize(row, expected_aliases)) for row in wanted.pop("inputs"))
    observed_inputs = Counter(render(normalize(row, aliases)) for row in observed.pop("inputs"))
    if wanted != observed or wanted_inputs != observed_inputs:
        raise ValueError("expectation-coverage-mismatch")
    if expected["stages"] != actual["stages"]:
        raise ValueError("expectation-stages-mismatch")


def bounded_file(path, maximum, *, retain=False):
    """Finite trusted-preparation evidence; no persistent cross-call custody."""
    def identity(metadata):
        return tuple(getattr(metadata, field) for field in (
            "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink"
        ))

    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        initial = os.fstat(descriptor)
        if not stat.S_ISREG(initial.st_mode) or initial.st_nlink != 1 or not 0 < initial.st_size <= maximum:
            raise ValueError("go-preparation-file-contract-refused")
        digest, total, prefix, chunks = hashlib.sha256(), 0, b"", []
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum or total > initial.st_size:
                raise ValueError("go-preparation-file-budget-exceeded")
            digest.update(chunk)
            prefix = (prefix + chunk[:20])[:20]
            if retain:
                chunks.append(chunk)
        if total != initial.st_size or identity(initial) != identity(os.fstat(descriptor)) or identity(initial) != identity(os.lstat(path)):
            raise ValueError("changed-go-preparation-file")
        return {"sha256": digest.hexdigest(), "bytes": total, "identity": identity(initial)}, b"".join(chunks) if retain else prefix
    finally:
        os.close(descriptor)


def bind_go_runtime(binary, preparation):
    from sourcebastion.inventory.go_sources import Runtime

    if not binary.is_absolute() or not preparation.is_absolute():
        raise ValueError("absolute-go-preparation-paths-required")
    manifest_binding, raw = bounded_file(preparation, 1024 * 1024, retain=True)
    manifest = json.loads(raw)
    assert manifest["schema_version"] == "sourcebastion.provider-preparation/1"
    assert manifest["status"] == "trusted-preparation-only"
    assert set(manifest["source_files"]) == GO_SOURCE_FILES
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
    assert manifest["architecture"] == architecture and manifest["cgo_enabled"] == "0"
    source = Path("cmd/inventory-provider")
    files, bindings, source_raw = {}, {}, {}
    for name in sorted(GO_SOURCE_FILES):
        binding, content = bounded_file(source / name, 2 * 1024 * 1024, retain=True)
        assert binding["sha256"] == manifest["source_files"][name]
        files[name], bindings[name], source_raw[name] = binding["sha256"], binding, content
    pins = json.loads(source_raw["toolchain.json"])
    assert manifest["go_version"] == pins["version"]
    assert manifest["go_archive_sha256"] == pins[f"linux_{architecture}_sha256"]
    binary_binding, elf = bounded_file(binary, 64 * 1024 * 1024)
    assert elf[:6] == b"\x7fELF\x02\x01" and int.from_bytes(elf[18:20], "little") == {"amd64": 62, "arm64": 183}[architecture]
    assert binary_binding["identity"][2] & 0o111
    assert binary_binding["sha256"] == manifest["go_source_binary_sha256"]
    assert binary_binding["bytes"] == manifest["go_source_binary_bytes"]
    runtime = Runtime(binary, binary_binding["sha256"])

    def unchanged():
        assert bounded_file(binary, 64 * 1024 * 1024)[0] == binary_binding
        assert bounded_file(preparation, 1024 * 1024)[0] == manifest_binding
        for name in GO_SOURCE_FILES:
            assert bounded_file(source / name, 2 * 1024 * 1024)[0] == bindings[name]

    receipt = {
        "preparation_sha256": manifest_binding["sha256"],
        "binary_sha256": runtime.sha256,
        "binary_bytes": binary_binding["bytes"],
        "architecture": architecture,
        "go_version": pins["version"],
        "go_archive_sha256": manifest["go_archive_sha256"],
        "cgo_enabled": "0",
        "source_files": files,
        "scope": "Explicit trusted preparation manifest/source/binary binding with pre/post identity checks; no independent build attestation or persistent custody.",
    }
    return runtime, receipt, unchanged


def verify(binary, preparation):
    if sys.flags.optimize:
        raise RuntimeError("optimized-probe-runtime-refused")
    from sourcebastion.inventory import contract
    from sourcebastion.inventory.compose_source import compose_source
    from sourcebastion.inventory.contract import Environment, Inventory, InventoryLimits, Producer, canonical_bytes
    from sourcebastion.inventory.inputs import Source
    from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256

    installed = Path(contract.__file__).resolve().parent
    checkout = Path("sourcebastion/inventory").resolve()
    assert not installed.is_relative_to(Path.cwd().resolve())

    def modules(root):
        return {
            path.relative_to(root).as_posix(): sha(path.read_bytes())
            for path in sorted(root.rglob("*"))
            if path.is_file() and path.suffix in {".py", ".cjs", ".js", ".json", ".mjs"}
        }

    source_modules = modules(checkout)
    assert modules(installed) == source_modules
    go_runtime, go_receipt, go_unchanged = bind_go_runtime(binary, preparation)
    raw = EXPECTATIONS.read_bytes()
    assert len(raw) <= 1024 * 1024
    expectations = json.loads(raw)
    assert expectations["schema_version"] == "m046.canonical-source-expectations/1"
    corpus_raw = CORPUS.read_bytes()
    assert sha(corpus_raw) == expectations["historical_oracle_sha256"]
    historical = {case["id"]: case for case in json.loads(corpus_raw)}
    config = DiscoveryConfig()
    producer = Producer(
        name="native-source-expectations",
        version="1",
        code_sha256=sha(render(source_modules)),
        registry_sha256=REGISTRY_SHA256,
        config_sha256=config.sha256,
    )
    records = []
    names = set()
    for case in expectations["cases"]:
        assert case["case"] not in names
        names.add(case["case"])
        files = {row["path"]: row["utf8"] for row in case["fixture_files"]}
        assert files == historical[case["case"]]["files"]
        assert not historical[case["case"]]["symlinks"]
        source_sha256 = sha(render(files))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for row in case["fixture_files"]:
                path = Path(row["path"])
                assert not path.is_absolute() and ".." not in path.parts
                content = row["utf8"].encode()
                assert sha(content) == row["sha256"]
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
            with Source(root) as source:
                value = compose_source(source, source_sha256=source_sha256, producer=producer, config=config, go_runtime=go_runtime)
                encoded = canonical_bytes(value)
                actual = Inventory.model_validate_json(encoded)
                assert set(json.loads(encoded)) == set(COLLECTIONS) | {
                    "schema_version",
                    "source_sha256",
                    "producer",
                    "limits",
                    "environment",
                    "environment_sha256",
                    "coverage",
                    "stages",
                }
                assert actual.source_sha256 == source_sha256 and actual.producer == producer
                assert actual.schema_version == "sourcebastion.inventory/1"
                assert actual.environment == Environment() and actual.environment_sha256 == Environment().sha256
                assert actual.limits == InventoryLimits()
                compare(case, json.loads(encoded))
                source.validate()
                repeated = compose_source(source, source_sha256=source_sha256, producer=producer, config=config, go_runtime=go_runtime)
                assert canonical_bytes(repeated) == encoded
            records.append({"case": case["case"], "inventory_sha256": sha(encoded)})
    assert modules(installed) == modules(checkout) == source_modules
    assert EXPECTATIONS.read_bytes() == raw and CORPUS.read_bytes() == corpus_raw
    go_unchanged()
    print(
        json.dumps(
            {
                "schema_version": "m046.canonical-source-expectations-proof/1",
                "expectations_sha256": sha(raw),
                "historical_oracle_sha256": sha(corpus_raw),
                "python": platform.python_version(),
                "architecture": platform.machine(),
                "source_modules": source_modules,
                "go_runtime": go_receipt,
                "cases": records,
                "scope": f"{len(records)} reviewed source cases, full record/coverage comparison and repeatability; no full64 corpus, controller custody, real matching, shared kernel resources or S03/M046 acceptance.",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    try:
        if sys.flags.optimize:
            raise RuntimeError("optimized-probe-runtime-refused")
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--go-binary", required=True, type=Path)
        parser.add_argument("--go-preparation", required=True, type=Path)
        arguments = parser.parse_args()
        verify(arguments.go_binary, arguments.go_preparation)
    except Exception as error:
        print(json.dumps({"status": "native-source-expectations-failed", "reason": type(error).__name__}))
        raise
