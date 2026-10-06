"""Deterministic synthetic stress inputs, with counts independent of tools.

Source generation is installation-free. Large/boundary cases intentionally exceed
proposed budgets; they must produce explicit overflow, not silent success.
"""

import argparse
import hashlib
import json
from pathlib import Path

SPECS = (
    *(
        {"id": f"pins-{count}-{roots}-roots", "kind": "pins", "count": count, "roots": roots}
        for count, roots in ((1000, 1), (10000, 10), (100000, 100), (100001, 100))
    ),
    *({"id": f"traversal-{count}", "kind": "traversal", "count": count} for count in (1000, 10000, 100000, 100001)),
    *({"id": f"include-depth-{count}", "kind": "depth", "count": count} for count in (64, 65)),
    *(
        {"id": f"file-bytes-{count}", "kind": "bytes", "count": count}
        for count in (2 * 1024 * 1024, 2 * 1024 * 1024 + 1)
    ),
    *({"id": f"include-targets-{count}", "kind": "fanout", "count": count} for count in (4096, 4097)),
    {"id": "include-cycle-fanout", "kind": "cycle", "count": 128},
    *({"id": f"edges-{count}", "kind": "edges", "count": count, "roots": 100} for count in (500000, 500001)),
)


def hash_records(records):
    return hashlib.sha256(json.dumps(sorted(records), separators=(",", ":")).encode()).hexdigest()


def generate(spec, destination):
    destination.mkdir(parents=True, exist_ok=False)
    file_hashes = {}
    packages, relationships, application_edges, occurrences = set(), [], [], []

    def write(path, text):
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        file_hashes[path] = {"bytes": len(text.encode()), "sha256": hashlib.sha256(text.encode()).hexdigest()}

    def pin(index, path, root):
        name = f"m046-dep-{index:06d}"
        package = f"pypi:{name}@1.0.0"
        packages.add(package)
        occurrences.append((root, package))
        return f"{name}==1.0.0\n"

    kind, count = spec["kind"], spec["count"]
    if kind == "pins":
        roots = spec["roots"]
        for root in range(roots):
            path = f"root-{root:03d}/requirements.txt"
            write(path, "".join(pin(index, path, f"root-{root:03d}") for index in range(root, count, roots)))
    elif kind == "traversal":
        write("requirements.txt", pin(0, "requirements.txt", "."))
        for index in range(count - 1):
            write(f"ignored-{index:06d}.log", "Synthetic non-dependency text.\n")
    elif kind in {"depth", "fanout", "cycle"}:
        names = [f"input-{index:04d}.pip" for index in range(count)]
        if kind == "depth":
            write("requirements.txt", "-r " + names[0] + "\n")
            for index, name in enumerate(names):
                write(name, "-r " + names[index + 1] + "\n" if index + 1 < count else pin(0, name, "."))
        else:
            write("requirements.txt", "".join("-r " + name + "\n" for name in names))
            for index, name in enumerate(names):
                write(name, "-r requirements.txt\n" if kind == "cycle" else pin(index, name, "."))
    elif kind == "bytes":
        initial = pin(0, "requirements.txt", ".") + "#"
        write("requirements.txt", initial + "x" * (count - len(initial) - 1) + "\n")
    elif kind == "edges":
        # 100 independent npm roots, at most 101 packages per root; spread dense
        # evidenced edges so every source stays below the 2 MiB file budget.
        roots = spec["roots"]
        for root in range(roots):
            # The proposed graph budget includes root->dependency edges.
            graph_count = count // roots + (1 if root < count % roots else 0) - 1
            name = f"m046-root-{root:03d}"
            nodes = {f"node_modules/{name}-p{i:03d}": {"version": "1.0.0", "dependencies": {}} for i in range(101)}
            root_packages = [f"npm:{name}-p{i:03d}@1.0.0" for i in range(101)]
            packages.update(root_packages)
            occurrences.extend((name, package) for package in root_packages)
            for index in range(graph_count):
                parent, offset = divmod(index, 100)
                child = offset if offset < parent else offset + 1
                nodes[f"node_modules/{name}-p{parent:03d}"]["dependencies"][f"{name}-p{child:03d}"] = "1.0.0"
                relationships.append((name, root_packages[parent], root_packages[child]))
            nodes[""] = {"name": name, "version": "1.0.0", "dependencies": {f"{name}-p000": "1.0.0"}}
            application_edges.append((name, f"npm:{name}@1.0.0", root_packages[0]))
            write(
                f"{name}/package.json",
                json.dumps({"name": name, "version": "1.0.0", "dependencies": {f"{name}-p000": "1.0.0"}}),
            )
            write(
                f"{name}/package-lock.json",
                json.dumps(
                    {"name": name, "version": "1.0.0", "lockfileVersion": 3, "requires": True, "packages": nodes}
                ),
            )
    else:
        raise ValueError("unknown synthetic performance fixture")
    manifest = {
        "schema_version": 1,
        "spec": spec,
        "files": file_hashes,
        "expected": {
            "identities": len(packages),
            "occurrences": len(occurrences),
            "edges": len(relationships) + len(application_edges),
            "dependency_edges": len(relationships),
            "application_edges": len(application_edges),
            "identities_sha256": hash_records(packages),
            "occurrences_sha256": hash_records(occurrences),
            "root_aware_edges_sha256": hash_records(relationships),
            "all_edges_sha256": hash_records(relationships + application_edges),
            "source_files": len(file_hashes),
            "traversal_entries": sum(1 for _ in destination.rglob("*")),
            "max_file_bytes": max(record["bytes"] for record in file_hashes.values()),
            "aggregate_file_bytes": sum(record["bytes"] for record in file_hashes.values()),
        },
        "expected_acceptance": "review-required-boundary-probe",
        "source_execution": "forbidden",
    }
    # Keep the oracle outside the source; candidate discovery must not scan it.
    destination.with_suffix(".oracle.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fixture", action="append")
    args = parser.parse_args()
    specs = [spec for spec in SPECS if not args.fixture or spec["id"] in args.fixture]
    if not specs or args.fixture and set(args.fixture) != {spec["id"] for spec in specs}:
        raise ValueError("unknown performance fixture")
    args.output.mkdir(parents=True, exist_ok=False)
    for spec in specs:
        manifest = generate(spec, args.output / spec["id"])
        print(spec["id"], json.dumps(manifest["expected"]), flush=True)


if __name__ == "__main__":
    main()
