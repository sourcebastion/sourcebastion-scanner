"""Finite actual installed metadata observations; no interpreter qualification."""

import hashlib
import json
from pathlib import Path
import platform
import sys
import tempfile


def verify():
    if sys.flags.optimize:
        raise RuntimeError("optimized-probe-runtime-refused")
    import packaging
    from sourcebastion.inventory.compose_source import compose_source
    from sourcebastion.inventory.contract import Producer, canonical_bytes
    from sourcebastion.inventory.inputs import InputRefusal, Source
    from sourcebastion.inventory.python_metadata import parse
    from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256

    base = "Metadata-Version: 2.3\nName: observed\nVersion: 1.0\n"
    path = "site-packages/observed-1.0.dist-info/METADATA"
    records = []

    def compose(files, config=None):
        config = config or DiscoveryConfig()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, content in files.items():
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content.encode() if isinstance(content, str) else content)
            with Source(root) as source:
                value = compose_source(
                    source,
                    source_sha256="a" * 64,
                    config=config,
                    producer=Producer(
                        name="native-fixed-controller",
                        version="1",
                        code_sha256="a" * 64,
                        registry_sha256=REGISTRY_SHA256,
                        config_sha256=config.sha256,
                    ),
                )
                source.validate()
        return value

    def record(name, files, config=None):
        one, two = compose(files, config), compose(files, config)
        assert canonical_bytes(one) == canonical_bytes(two)
        records.append(
            {
                "case": name,
                "inventory": json.loads(canonical_bytes(one)),
                "inventory_sha256": hashlib.sha256(canonical_bytes(one)).hexdigest(),
                "repeats": 2,
            }
        )
        return one

    one = record("observed-metadata-unknown-ownership", {path: base + "\n"})
    assert len(one.occurrences) == 1 and one.occurrences[0].evidence_kind == "installed"
    assert one.occurrences[0].root_id is one.occurrences[0].installed_environment_id is None
    assert not one.installed_environments and not one.roots and not one.relationships
    assert one.coverage.graph == "partial" and one.coverage.environment == "unknown"
    one = record(
        "dynamic-concrete-requirement",
        {
            path: base
            + 'Dynamic: Requires-Dist\nRequires-Dist: dep[extra]>=1; python_version < "4"\nRequires-Python: >=3.12\nProvides-Extra: test\n\n'
        },
    )
    assert len(one.occurrences) == len(one.declarations) == len(one.applicability) == 1
    assert one.declarations[0].name == "dep" and one.declarations[0].exact_version is None
    assert one.occurrences[0].activation == "unknown"
    one = record(
        "folded-header-with-body",
        {path: (base + "Requires-Dist: dep\n >=1\n\n" + "body " * 5000).replace("\n", "\r\n")},
    )
    assert len(one.declarations) == 1 and one.declarations[0].name == "dep"
    one = record(
        "same-purl-distinct-metadata-contexts",
        {path: base + "\n", "other/observed-1.0.dist-info/METADATA": base + "\n"},
    )
    assert len(one.occurrences) == len(one.analysis_scopes) == 2
    assert len({row.purl for row in one.occurrences}) == 1 and len({row.id for row in one.occurrences}) == 2
    for name, content in (
        ("structural-header-error", base + "not a header\nRequires-Dist: hidden==1\n\n"),
        ("duplicate-identity", base + "Version: 2.0\n\n"),
        ("contradictory-directory", base.replace("Version: 1.0", "Version: 2.0") + "\n"),
        ("invalid-encoding", b"\xff"),
    ):
        one = record(name + "-preserves-independent-pip", {path: content, "requirements.txt": "pip==26.0.1\n"})
        assert one.stages.inventory == "partial" and [row.name for row in one.occurrences] == ["pip"]
    one = record("egg-info-is-not-installed-evidence", {"observed.egg-info/PKG-INFO": base + "\n"})
    assert not one.occurrences and one.coverage.inputs[0].disposition == "unsupported"
    one = record(
        "redacted-url-declaration-no-child",
        {path: base + "Requires-Dist: dep @ https://user:private@example.test/file.whl?secret=yes\n\n"},
    )
    assert len(one.occurrences) == len(one.declarations) == 1
    assert one.declarations[0].declared_range == "direct-reference" and b"private" not in canonical_bytes(one)
    one = record("external-control-explicit-partial", {path: base + "Requires-External: libssl\n\n"})
    assert one.stages.inventory == "partial" and any(row.reason == "metadata-control-unassessed" for row in one.losses)
    one = record(
        "legal-empty-import-name-is-explicit-unassessed", {path: base.replace("2.3", "2.5") + "Import-Name:\n\n"}
    )
    assert len(one.occurrences) == 1 and one.stages.inventory == "partial"
    assert any(row.reason == "metadata-import-identity-unassessed" for row in one.losses)
    for name, text in (
        ("conflicting-import-names", base.replace("2.3", "2.5") + "Import-Name: x ; private\nImport-Namespace: x\n\n"),
        ("new-extra-spelling", base + "Provides-Extra: Test_Extra\n\n"),
    ):
        one = record(name + "-preserves-independent-pip", {path: text, "requirements.txt": "pip==26.0.1\n"})
        assert one.stages.inventory == "partial" and [row.name for row in one.occurrences] == ["pip"]
    prefix = "Requires-Dist: dep;" + 'os_name=="x" and ' * 127 + 'os_name=="'
    line = prefix + "a" * (16380 - len(prefix) - 1) + '"'
    one = record(
        "normalized-marker-expansion-preserves-independent-pip",
        {path: base + line + "\n\n", "requirements.txt": "pip==26.0.1\n"},
    )
    assert one.stages.inventory == "partial" and [row.name for row in one.occurrences] == ["pip"]
    one = record(
        "shared-budget-refuses-all-authority",
        {path: base + "\n", "requirements.txt": "pip==26.0.1\n"},
        DiscoveryConfig(semantic_checks=1),
    )
    assert one.stages.inventory == "failed" and not one.occurrences

    def refuse():
        raise InputRefusal("changed-native-metadata-source")

    try:
        parse(path, (base + "\n").encode(), check=refuse)
    except InputRefusal as error:
        assert error.reason == "changed-native-metadata-source"
    else:
        raise AssertionError("shared-source-refusal-swallowed")
    records.append({"case": "source-check-refusal-propagated"})
    modules = {}
    checkout = Path.cwd().resolve()
    for name, module in sorted(sys.modules.items()):
        if not name.startswith("sourcebastion.inventory") or not getattr(module, "__file__", None):
            continue
        target = Path(module.__file__).resolve()
        assert not target.is_relative_to(checkout)
        relative = Path(*name.split("."))
        relative = relative / "__init__.py" if target.name == "__init__.py" else relative.with_suffix(".py")
        checksum = hashlib.sha256(target.read_bytes()).hexdigest()
        assert checksum == hashlib.sha256((checkout / relative).read_bytes()).hexdigest()
        modules[str(relative)] = checksum
    print(
        json.dumps(
            {
                "schema_version": "sourcebastion.metadata-native-proof/1",
                "status": "native-installed-metadata-observations-passed",
                "python": platform.python_version(),
                "architecture": platform.machine(),
                "packaging": packaging.__version__,
                "cases": records,
                "source_modules": modules,
                "scope": "Seventeen finite source observations/guards with sixteen repeated fixture compositions; no actual interpreter, shared installation environment, runtime graph, kernel custody or S03 closure.",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    try:
        verify()
    except Exception as error:
        print(json.dumps({"status": "native-installed-metadata-failed", "reason": type(error).__name__}))
        raise
