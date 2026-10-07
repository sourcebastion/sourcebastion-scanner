"""Finite S01 ownership/identity feasibility spike, not production composition.

Direct Python remains authoritative. Provider facts stay separately typed until
a source-aware adapter proves their canonical semantics. No oracle is imported.
"""

from email.parser import BytesParser
from copy import deepcopy
import hashlib
import json
import math
import posixpath
import time

from .provider_evidence import bind_sources, bounded_tree, facts
from .static_cli import encode
from .static_inputs import InputRefusal, Source
from .static_inventory import evaluate
from packaging.utils import canonicalize_name
from packaging.version import Version
from urllib.parse import quote


def stable_id(kind, value):
    content = json.dumps([kind, value], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return kind + ":" + hashlib.sha256(content).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate-application-json-key")
        result[key] = value
    return result


def refuse_constant(value):
    raise ValueError("nonfinite-application-json")


def finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("nonfinite-application-json")
    return number


def metadata_role(source, record):
    if record["identity"] is None:
        return "unselected-versionless-metadata", False
    if record["evidence_kind"] == "declared-version-candidate":
        return "declaration-candidate", False
    if record["evidence_kind"] == "installed-metadata":
        if record["package_type"] != "python" or record["metadata_type"] != "python-package":
            raise ValueError("unadmitted-installed-metadata-role")
        if type(record["raw_name"]) is not str or type(record["raw_version"]) is not str:
            raise ValueError("invalid-installed-provider-fields")
        raw_name = canonicalize_name(record["raw_name"], validate=True)
        Version(record["raw_version"])
        for path in record["paths"]:
            if not path.endswith(".dist-info/METADATA"):
                return "installed-metadata-unadapted", False
            message = BytesParser().parsebytes(source.read(path).content, headersonly=True)
            names, versions = message.get_all("Name", []), message.get_all("Version", [])
            metadata_versions = message.get_all("Metadata-Version", [])
            if len(names) != 1 or len(versions) != 1 or len(metadata_versions) != 1:
                raise ValueError("ambiguous-installed-identity")
            # Feasibility subset, not a claim to implement all Core Metadata.
            if metadata_versions[0] != "2.1":
                return "installed-metadata-unadapted", False
            name = canonicalize_name(names[0], validate=True)
            Version(versions[0])
            if (
                name != raw_name
                or versions[0] != record["raw_version"]
                or record["identity"] != f"pypi:{name}@{versions[0]}"
                or record["purl"] != f"pkg:pypi/{name}@{quote(versions[0], safe='')}"
            ):
                raise ValueError("installed-source-provider-identity-mismatch")
        return "installed-version-evidence", True
    if record["cataloger"] == "javascript-package-cataloger":
        for path in record["paths"]:
            # This is declared application metadata in an analysis scope, not
            # project identity/custody. Installed node_modules remain unadapted.
            if posixpath.basename(path) != "package.json" or "node_modules" in path.split("/"):
                return "package-role-unassessed", False
            data = json.loads(
                source.read(path).content,
                object_pairs_hook=unique_object,
                parse_constant=refuse_constant,
                parse_float=finite_float,
            )
            bounded_tree(data)
            source.check()
            if (
                type(data) is not dict
                or data.get("name") != record["raw_name"]
                or data.get("version") != record["raw_version"]
            ):
                raise ValueError("application-source-provider-identity-mismatch")
        return "application-metadata", False
    return "lock-evidence-unadapted", False


def compose(source, provider_document):
    if not isinstance(source, Source):
        raise TypeError("controller-bound Source required")
    deadline = min(source.deadline, time.monotonic() + 30)
    bounded_tree(provider_document)
    direct = evaluate(source)
    if direct["inventory_status"] == "failed":
        raise InputRefusal("direct-source-unavailable")
    extracted = facts(provider_document)
    snapshot = {}
    for record in extracted["records"]:
        for path in record["paths"]:
            snapshot[path] = {"sha256": source.read(path).sha256}
    binding = bind_sources(extracted, snapshot)
    canonical, provider, identifiers = [], [], {}
    for occurrence in direct["semantic_dimensions"]["occurrences"]:
        body = {
            "authority": "direct-python-source",
            "occurrence": deepcopy(occurrence),
            "source_sha256": source.read(occurrence["path"]).sha256,
        }
        canonical.append({"id": stable_id("source-occurrence", body), **body})
    for record in extracted["records"]:
        role, eligible = metadata_role(source, record)
        evidence = [
            {"path": path, "sha256": snapshot[path]["sha256"], "analysis_scope": posixpath.dirname(path) or "."}
            for path in record["paths"]
        ]
        body = {
            "authority": "restricted-provider",
            "raw_provider_id": record["provider_id"],
            "role": role,
            "evidence": evidence,
            "record": record,
        }
        identifier = stable_id("provider-evidence", body)
        identifiers[record["provider_id"]] = identifier
        provider.append(
            {
                "id": identifier,
                **body,
                "match_eligible_identity_evidence": eligible,
                "canonical_root": None,
                "installed_environment": None,
                "activation": "unknown",
            }
        )
    relations = []
    for edge in extracted["provider_dependencies"]:
        # Keep raw-ID endpoints before any identity reduction. Shared paths
        # give analysis scopes, never an asserted project or canonical edge.
        relations.append(
            {
                **edge,
                "parent_evidence_id": identifiers[edge["parent_provider_id"]],
                "child_evidence_id": identifiers[edge["child_provider_id"]],
                "analysis_scopes": sorted({posixpath.dirname(path) or "." for path in edge["shared_evidence_paths"]}),
                "matching_edge": False,
            }
        )
    result = {
        "schema_version": "m046-composition-feasibility-v1",
        "inventory_status": "partial",
        "canonical_source_inventory": direct,
        "source_occurrences": canonical,
        "provider_evidence": provider,
        "provider_relations": relations,
        "observed_source_binding": binding,
        "joining_policy": "separate authorities; no identity-only joins or canonical provider-edge promotion",
        "losses": [
            "non-python-lock-and-declaration-adapters-unimplemented",
            "provider-input-coverage-unassessed",
            "installed-environment-unknown",
            "provider-canonical-roots-and-record-locators-unassessed",
            "standard-export-and-matching-not-run",
        ],
        "full_contract_qualified": False,
    }
    bounded_tree(result)
    encode(result, deadline=deadline)  # Entire bounded representation must fit before acceptance.
    source.validate()
    return result
