"""Finite installed provider/protocol probes; not full graph or kernel acceptance."""

import argparse
import hashlib
import importlib
from importlib.metadata import version
import json
from pathlib import Path
import platform
import subprocess
import tempfile
import time

# Import from the installed distribution; never insert the source checkout.
from sourcebastion.inventory.discovery import discover
from sourcebastion.inventory.inputs import InputRefusal, Source
from sourcebastion.inventory.provider import bind_provider


def sha(value):
    return hashlib.sha256(value).hexdigest()


def observations(receipt):
    candidates = {
        row.raw_id: {
            "cataloger": row.cataloger,
            "role": row.role,
            "identity_status": row.identity_status,
            "purl": row.purl,
            "metadata_type": row.metadata_type,
            "bindings": [(binding.path, binding.source_sha256) for binding in row.bindings],
            "canonical_semantics": row.canonical_semantics,
        }
        for row in receipt.candidates
    }
    dependencies = [
        {
            "parent": candidates[row.parent_raw_id],
            "child": candidates[row.child_raw_id],
            "canonical_semantics": row.canonical_semantics,
        }
        for row in receipt.dependencies
    ]
    return {
        "candidates": sorted(candidates.values(), key=lambda value: json.dumps(value, sort_keys=True)),
        "dependencies": sorted(dependencies, key=lambda value: json.dumps(value, sort_keys=True)),
        "coverage": receipt.coverage,
    }


def probe(binary, files):
    with tempfile.TemporaryDirectory(prefix="provider-fixture-") as folder:
        root = Path(folder)
        for name, content in files.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        before = {name: sha((root / name).read_bytes()) for name in files}
        with Source(root) as source:
            found = discover(source)
            checks = found.semantic_checks

            def check():
                nonlocal checks
                checks += 1
                source.check()
                if checks > 5000000:
                    raise InputRefusal("composition-check-budget-exceeded")

            remaining = source.deadline - time.monotonic()
            result = subprocess.run(
                [str(binary), "--root", str(root), "--remaining", f"{remaining:.6f}s"],
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                capture_output=True,
                timeout=remaining,
                check=True,
            )
            receipt = bind_provider(
                result.stdout,
                source,
                found,
                source_sha256="a" * 64,
                provider_binary_sha256=sha(binary.read_bytes()),
                check=check,
            )
            assert before == {name: sha((root / name).read_bytes()) for name in files}
            return observations(receipt), sha(result.stdout), checks


def main(binary, preparation):
    if not __debug__:
        raise RuntimeError("optimized-validation-not-supported")
    manifest = json.loads(preparation.read_text())
    if sha(binary.read_bytes()) != manifest["binary_sha256"]:
        raise ValueError("provider-binary-manifest-mismatch")
    modules = {}
    for name in ("provider", "inputs", "discovery", "contract"):
        module = importlib.import_module("sourcebastion.inventory." + name)
        path = Path(module.__file__).resolve()
        if "site-packages" not in path.parts:
            raise ValueError("installed-inventory-module-required")
        modules[name] = {"path": str(path), "sha256": sha(path.read_bytes())}
    npm = {
        "requirements.txt": "pip==99.99.99\n",
        "package.json": '{"name":"fixture-app","version":"1.0.0","dependencies":{"debug":"^4.3.7"}}',
        "package-lock.json": '{"name":"fixture-app","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"fixture-app","version":"1.0.0","dependencies":{"debug":"^4.3.7"}},"node_modules/debug":{"version":"4.3.7","dependencies":{"ms":"^2.1.3"}},"node_modules/ms":{"version":"2.1.3"}}}',
        "site-packages/pip-26.0.1.dist-info/METADATA": "Metadata-Version: 2.3\nName: pip\nVersion: 26.0.1\n\n",
    }
    cases = {
        "npm-application-lock-installed": npm,
        "versionless-application": {"package.json": '{"name":"fixture-app","dependencies":{"debug":"^4"}}'},
        "go-source-declaration": {
            "go.mod": "module example.com/app\n\ngo 1.24\n\nrequire example.com/dependency v1.2.3\n"
        },
        "cargo-lock-observation": {
            "Cargo.lock": 'version=3\n[[package]]\nname="fixture"\nversion="1.0.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="'
            + "a" * 64
            + '"\n'
        },
    }
    results = []
    for name, files in cases.items():
        first, raw_sha, checks = probe(binary, files)
        second, second_sha, _ = probe(binary, files)
        if first != second:
            raise ValueError("nondeterministic-provider-observations")
        candidates = first["candidates"]
        if name == "npm-application-lock-installed":
            assert len(candidates) == 5 and len(first["dependencies"]) == 2
            assert sum(row["purl"] == "pkg:npm/fixture-app@1.0.0" for row in candidates) == 2
            assert (
                sum(row["role"] == "installed-candidate" and row["purl"] == "pkg:pypi/pip@26.0.1" for row in candidates)
                == 1
            )
            assert all("99.99.99" not in (row["purl"] or "") for row in candidates)
        elif name == "versionless-application":
            assert len(candidates) == 1 and candidates[0]["identity_status"] == "version-unreported"
        elif name == "go-source-declaration":
            assert candidates and all(row["role"] == "declaration-candidate" for row in candidates)
            assert any(row["purl"] == "pkg:golang/example.com/dependency@v1.2.3" for row in candidates)
        else:
            assert len(candidates) == 1 and candidates[0]["role"] == "lock-candidate"
        results.append(
            {
                "case": name,
                "observations": first,
                "observations_sha256": sha(json.dumps(first, sort_keys=True, separators=(",", ":")).encode()),
                "provider_output_sha256": [raw_sha, second_sha],
                "semantic_checks": checks,
            }
        )
    print(
        json.dumps(
            {
                "schema_version": "sourcebastion.provider-native-probe/1",
                "python": platform.python_version(),
                "architecture": platform.machine(),
                "packaging": version("packaging"),
                "pydantic": version("pydantic"),
                "provider_binary_sha256": manifest["binary_sha256"],
                "preparation_sha256": sha(preparation.read_bytes()),
                "modules": modules,
                "cases": results,
                "coverage": "unassessed",
                "canonical_graph": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--preparation", required=True, type=Path)
    arguments = parser.parse_args()
    main(arguments.binary.resolve(), arguments.preparation.resolve())
