"""Loss-explicit restricted Syft facts; never a canonical graph or resolver.

Normalization uses only raw evidence. Independent expected records are consumed
only by the separate comparison function, never by facts().
"""

from pathlib import PurePosixPath
import time

from .run import compare, identity, normalize

CATALOGERS = (
    "javascript-lock-cataloger",
    "javascript-package-cataloger",
    "go-module-file-cataloger",
    "rust-cargo-lock-cataloger",
    "python-installed-package-cataloger",
    "java-gradle-lockfile-cataloger",
    "java-pom-cataloger",
    "dotnet-packages-lock-cataloger",
    "ruby-gemfile-cataloger",
    "php-composer-lock-cataloger",
)
DECLARATION_PROVIDERS = {"go-module-file-cataloger", "java-pom-cataloger"}
UNREPORTED = (
    "per-input-parse-disposition",
    "record-locator",
    "canonical-project-root",
    "scope",
    "environment-activation",
    "declared-range",
    "source-hash",
    "complete-graph",
    "application-role",
)


def bounded_tree(document):
    # Called only in the separately time/address-space limited audit process.
    stack, nodes, seen = [(document, 0)], 0, set()
    deadline = time.monotonic() + 15
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > 2000000 or depth > 32 or time.monotonic() > deadline:
            raise ValueError("provider-input-complexity-exceeded")
        if type(value) in {dict, list}:
            if id(value) in seen:
                raise ValueError("shared-provider-container")
            seen.add(id(value))
            children = list(value.values()) if type(value) is dict else value
            if nodes + len(stack) + len(children) > 2000000:
                raise ValueError("provider-input-complexity-exceeded")
            stack.extend((child, depth + 1) for child in children)
        elif type(value) is str and len(value.encode()) > 2 * 1024 * 1024:
            raise ValueError("provider-string-limit-exceeded")
        elif type(value) not in {str, int, float, bool, type(None)}:
            raise ValueError("invalid-provider-value")


def facts(document):
    bounded_tree(document)
    if document.get("descriptor", {}).get("name") != "m046-restricted-evidence-provider":
        raise ValueError("wrong-provider-profile")
    artifacts = document.get("artifacts")
    relationships = document.get("artifactRelationships")
    if type(artifacts) is not list or type(relationships) is not list:
        raise ValueError("missing-provider-records")
    if len(artifacts) > 100000 or len(relationships) > 500000:
        raise ValueError("provider-record-limit-exceeded")
    identifiers, records = {}, []
    for artifact in artifacts:
        identifier, cataloger = artifact.get("id"), artifact.get("foundBy")
        if type(identifier) is not str or not identifier or identifier in identifiers:
            raise ValueError("duplicate-or-missing-provider-id")
        if cataloger not in CATALOGERS or artifact.get("cpes"):
            raise ValueError("unadmitted-provider-or-cpe")
        package = identity(artifact.get("purl"))
        if package is None:
            raise ValueError("missing-provider-package-identity")
        locations = artifact.get("locations")
        if type(locations) is not list or not locations:
            raise ValueError("missing-provider-location")
        paths = []
        for location in locations:
            path = location.get("path")
            if (
                type(path) is not str
                or not path.startswith("/")
                or path.startswith("//")
                or ".." in path.split("/")
                or "\\" in path
                or "\x00" in path
            ):
                raise ValueError("invalid-provider-location")
            relative = path[1:]
            if str(PurePosixPath(relative)) != relative or relative == ".":
                raise ValueError("noncanonical-provider-location")
            paths.append(relative)
        record = {
            "provider_id": identifier,
            "identity": package,
            "purl": artifact["purl"],
            "raw_name": artifact.get("name"),
            "raw_version": artifact.get("version"),
            "package_type": artifact.get("type"),
            "cataloger": cataloger,
            "evidence_kind": (
                "declared-version-candidate"
                if cataloger in DECLARATION_PROVIDERS
                else (
                    "installed-metadata"
                    if cataloger == "python-installed-package-cataloger"
                    else (
                        "package-metadata-role-unassessed"
                        if cataloger == "javascript-package-cataloger"
                        else "lock-record"
                    )
                )
            ),
            "paths": sorted(set(paths)),
            "metadata_type": artifact.get("metadataType"),
            "raw_metadata": artifact.get("metadata"),
            "canonical_semantics": "unassessed",
        }
        identifiers[identifier] = record
        records.append(record)
    dependencies = []
    for relationship in relationships:
        if relationship.get("type") != "dependency-of":
            continue
        child = identifiers.get(relationship.get("parent"))
        parent = identifiers.get(relationship.get("child"))
        if parent is None or child is None:
            raise ValueError("dangling-provider-dependency")
        common = sorted(set(parent["paths"]) & set(child["paths"]))
        dependencies.append(
            {
                "parent_provider_id": parent["provider_id"],
                "child_provider_id": child["provider_id"],
                "parent": parent["identity"],
                "child": child["identity"],
                "shared_evidence_paths": common,
                "canonical_edge": "unassessed",
            }
        )
    return {
        "schema_version": "m046-restricted-provider-facts-v1",
        "records": sorted(records, key=lambda row: row["provider_id"]),
        "provider_dependencies": sorted(
            dependencies, key=lambda row: (row["parent_provider_id"], row["child_provider_id"])
        ),
        "coverage": "unassessed",
        "unreported_dimensions": list(UNREPORTED),
        "joining_policy": "no name/purl-only occurrence or root joining",
    }


def bind_sources(extracted, source_snapshot):
    """Bind only observed paths; never infer discovery coverage from raw packages."""
    bindings = {}
    for record in extracted["records"]:
        for path in record["paths"]:
            source = source_snapshot.get(path)
            checksum = source.get("sha256") if type(source) is dict else None
            if (
                type(checksum) is not str
                or len(checksum) != 64
                or any(character not in "0123456789abcdef" for character in checksum)
                or "symlink" in source
                or "directory" in source
            ):
                raise ValueError("provider-path-not-bound-to-regular-source")
            bindings[path] = checksum
    return {
        "observed_path_sha256": bindings,
        "coverage": "unassessed",
        "scope": "controller snapshots only; no descriptor custody or per-record locator inferred",
    }


def comparison(expected, document):
    observed = facts(document)
    basic = normalize(document, "syft-provider")
    # go.mod and POM version strings do not establish a selected dependency.
    declarations = {
        row["identity"] for row in observed["records"] if row["evidence_kind"] == "declared-version-candidate"
    }
    selected = {row["identity"] for row in observed["records"] if row["evidence_kind"] != "declared-version-candidate"}
    basic["packages"] = sorted(selected)
    admitted_ids = {
        row["provider_id"] for row in observed["records"] if row["evidence_kind"] != "declared-version-candidate"
    }
    basic["edges"] = sorted(
        {
            (edge["parent"], edge["child"])
            for edge in observed["provider_dependencies"]
            if edge["parent_provider_id"] in admitted_ids and edge["child_provider_id"] in admitted_ids
        }
    )
    return {
        "basic": compare(expected, basic),
        "declared_version_candidates": sorted(declarations),
        "unreported_dimensions": list(UNREPORTED),
        "full_contract_qualified": False,
    }
