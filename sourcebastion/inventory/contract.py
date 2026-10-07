"""Versioned canonical inventory: typed authority, coverage and bounded JSON.

Controllers supply the source/producer identities. Schema validation checks
structure and internal consistency; it does not authenticate those assertions.
Adapters must establish identity and ownership from source evidence first.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from typing import Annotated, Literal
from urllib.parse import quote

from packaging.utils import canonicalize_name
from packaging.version import Version
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .inputs import relative_path

SHA256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
Text = Annotated[str, Field(min_length=1, max_length=16384, pattern=r"^[^\x00-\x1f\x7f-\x9f]+$")]
Name = Annotated[str, Field(min_length=1, max_length=512, pattern=r"^[^\x00-\x1f\x7f-\x9f]+$")]
Reason = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,127}$")]
ID = Annotated[str, Field(pattern=r"^[a-z-]+:sha256:[a-f0-9]{64}$", max_length=128)]
Ecosystem = Literal["pypi", "npm", "golang", "cargo", "maven", "nuget", "gem", "composer"]
Fidelity = Literal["complete", "partial", "unknown", "failed"]
Activation = Literal["active", "inactive", "unknown"]
Stage = Literal["not-run", "succeeded", "failed"]


class Record(BaseModel):
    model_config = ConfigDict(
        extra="forbid", strict=True, frozen=True, allow_inf_nan=False, revalidate_instances="always"
    )

    @field_validator("*", mode="after")
    @classmethod
    def no_control_characters(cls, value):
        if isinstance(value, str) and any(ord(c) < 32 or 127 <= ord(c) < 160 for c in value):
            raise ValueError("invalid-control-character")
        return value


def identifier(kind, value):
    """Stable IDs bind full occurrence/context evidence, never only equal purls."""
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return kind + ":sha256:" + hashlib.sha256(data).hexdigest()


def package_purl(ecosystem, name, version=None):
    if ecosystem not in {"pypi", "npm", "golang", "cargo", "maven", "nuget", "gem", "composer"}:
        raise ValueError("unsupported-purl-ecosystem")
    if not isinstance(name, str) or not name or len(name) > 512:
        raise ValueError("invalid-canonical-name")
    if any(ord(c) < 32 for c in name) or any(part in {"", ".", ".."} for part in name.split("/")):
        raise ValueError("invalid-canonical-name")
    if any(c in name for c in ":?#%\\") or any(c.isspace() for c in name):
        raise ValueError("invalid-canonical-name")
    if "@" in name and not (ecosystem == "npm" and name.startswith("@") and name.count("@") == 1):
        raise ValueError("invalid-canonical-name")
    if version is not None and (
        not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.!+_-]{0,511}", version)
    ):
        raise ValueError("invalid-selected-version")
    if ecosystem in {"pypi", "cargo", "nuget", "gem"} and "/" in name:
        raise ValueError("invalid-canonical-name")
    if ecosystem == "pypi":
        if canonicalize_name(name, validate=True) != name:
            raise ValueError("noncanonical-pypi-name")
        if version is not None and str(Version(version)) != version:
            raise ValueError("noncanonical-pypi-version")
    if ecosystem in {"maven", "composer"} and len(name.split("/")) != 2:
        raise ValueError("package-namespace-required")
    if ecosystem in {"nuget", "composer"} and name.lower() != name:
        raise ValueError("noncanonical-case-insensitive-name")
    if version is not None and version.lower() in {"latest", "release", "head", "main", "master", "unknown"}:
        raise ValueError("unresolved-selected-version")
    if ecosystem in {"npm", "cargo", "golang"} and version is not None:
        selected = version[1:] if ecosystem == "golang" and version.startswith("v") else version
        if ecosystem == "golang" and not version.startswith("v"):
            raise ValueError("invalid-selected-version")
        semantic = re.fullmatch(
            r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
            r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
            r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?",
            selected,
        )
        if not semantic or (
            semantic.group(4)
            and any(part.isdigit() and len(part) > 1 and part.startswith("0") for part in semantic.group(4).split("."))
        ):
            raise ValueError("invalid-selected-version")
    if ecosystem == "npm" and (
        (name.startswith("@") and (len(name.split("/")) != 2 or len(name.split("/")[0]) == 1))
        or (not name.startswith("@") and "/" in name)
    ):
        raise ValueError("invalid-npm-namespace")
    encoded = "/".join(quote(part, safe="-._~") for part in name.split("/"))
    return "pkg:" + ecosystem + "/" + encoded + ("@" + quote(version, safe="-._~") if version is not None else "")


class Locator(Record):
    path: Text
    source_sha256: SHA256
    locator: Text
    parser: Name

    @field_validator("path")
    @classmethod
    def path_confined(cls, value):
        if relative_path(value) != value:
            raise ValueError("noncanonical-source-path")
        return value


class ContentHash(Record):
    algorithm: Literal["sha1", "sha256", "sha384", "sha512", "go-h1"]
    digest: Text
    kind: Literal["artifact", "integrity", "module-tree"]

    @model_validator(mode="after")
    def correct_hash_shape(self):
        length = {"sha1": 40, "sha256": 64, "sha384": 96, "sha512": 128, "go-h1": 64}[self.algorithm]
        if len(self.digest) != length or any(c not in "0123456789abcdef" for c in self.digest):
            raise ValueError("invalid-content-hash")
        if (self.algorithm == "go-h1") != (self.kind == "module-tree"):
            raise ValueError("invalid-module-hash-kind")
        return self


def go_module_hash(value):
    """Decode canonical go.sum h1 base64 into an explicitly typed tree digest.

    The internal lowercase hex is reversible; it is not a raw file SHA256.
    See https://go.dev/ref/mod#go-sum-files.
    """
    if not isinstance(value, str) or len(value) != 47 or not value.startswith("h1:"):
        raise ValueError("invalid-go-module-hash")
    try:
        decoded = base64.b64decode(value[3:], validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("invalid-go-module-hash") from error
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value[3:]:
        raise ValueError("invalid-go-module-hash")
    return ContentHash(algorithm="go-h1", digest=decoded.hex(), kind="module-tree")


class Root(Record):
    id: ID
    path: Text
    kind: Literal["project"] = "project"
    source: Locator

    @field_validator("path")
    @classmethod
    def root_path(cls, value):
        if value != "." and relative_path(value) != value:
            raise ValueError("noncanonical-root-path")
        return value


class AnalysisScope(Record):
    id: ID
    kind: Literal["requirements-origin", "lock-input", "provider-directory"]
    source: Locator


class InstalledEnvironment(Record):
    id: ID
    source: Locator
    kind: Literal["installed-metadata"] = "installed-metadata"


class Environment(Record):
    schema_version: Literal["sourcebastion.environment/1"] = "sourcebastion.environment/1"
    policy: Literal["preserve-alternatives", "explicit-target"] = "preserve-alternatives"
    python_implementation: Name | None = None
    python_version: Name | None = None
    platform: Name | None = None
    architecture: Name | None = None
    # Additional named marker inputs are data only. Adapters may evaluate only
    # when every variable used in an expression is explicitly supplied.
    marker_inputs: tuple[tuple[Name, Text], ...] = Field(default=(), max_length=32)

    @model_validator(mode="after")
    def no_implicit_target(self):
        if len({key for key, _value in self.marker_inputs}) != len(self.marker_inputs):
            raise ValueError("duplicate-environment-input")
        if self.policy == "preserve-alternatives" and (
            self.marker_inputs
            or any(
                value is not None
                for value in (self.python_implementation, self.python_version, self.platform, self.architecture)
            )
        ):
            raise ValueError("target-inputs-require-explicit-policy")
        allowed = {
            "implementation_name",
            "implementation_version",
            "os_name",
            "platform_machine",
            "platform_python_implementation",
            "platform_release",
            "platform_system",
            "platform_version",
            "python_full_version",
            "python_version",
            "sys_platform",
        }
        if any(key not in allowed for key, _value in self.marker_inputs):
            raise ValueError("unknown-environment-variable")
        target = self._target_inputs()
        for key, value in self.marker_inputs:
            if key in target and value != target[key]:
                raise ValueError("contradictory-environment-input")
        inputs = {**target, **dict(self.marker_inputs)}
        for key in ("python_version", "python_full_version"):
            if key in inputs:
                parsed = Version(inputs[key])
                minimum = 3 if key == "python_full_version" else 2
                if len(parsed.release) < minimum or str(parsed) != inputs[key]:
                    raise ValueError("noncanonical-python-marker-version")
                if key == "python_version" and len(parsed.release) != 2:
                    raise ValueError("noncanonical-python-marker-version")
        if "python_version" in inputs and "python_full_version" in inputs:
            full = Version(inputs["python_full_version"])
            if inputs["python_version"] != ".".join(str(part) for part in full.release[:2]):
                raise ValueError("contradictory-environment-input")
        return self

    def _target_inputs(self):
        target = {}
        for key, value in (
            ("implementation_name", self.python_implementation),
            ("sys_platform", self.platform),
            ("platform_machine", self.architecture),
        ):
            if value is not None:
                target[key] = value
        if self.python_version is not None:
            parsed = Version(self.python_version)
            if len(parsed.release) < 2:
                raise ValueError("incomplete-python-target-version")
            target["python_version"] = ".".join(str(part) for part in parsed.release[:2])
            if len(parsed.release) >= 3:
                target["python_full_version"] = str(parsed)
        return target

    @property
    def marker_environment(self):
        # No call to default_environment(), os, platform or the worker runtime.
        return {**self._target_inputs(), **dict(self.marker_inputs)}

    @property
    def sha256(self):
        data = self.model_dump()
        data["marker_inputs"] = sorted(data["marker_inputs"])
        return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class ProviderReference(Record):
    # The raw sidecar remains separate and is not customer-facing metadata.
    provider_output_sha256: SHA256
    raw_record_sha256: SHA256


class Occurrence(Record):
    id: ID
    source: Locator
    ecosystem: Ecosystem
    name: Name
    purl: Text | None
    evidence_kind: Literal["declared", "locked", "installed"]
    selected_version: Name | None
    declared_range: Text | None = None
    hashes: tuple[ContentHash, ...] = Field(default=(), max_length=4096)
    provider_references: tuple[ProviderReference, ...] = Field(default=(), max_length=256)
    root_id: ID | None = None
    installed_environment_id: ID | None = None
    analysis_scope_id: ID | None = None
    directness: Literal["direct", "transitive", "unknown"] = "unknown"
    scopes: tuple[Name, ...] = Field(default=(), max_length=256)
    groups: tuple[Name, ...] = Field(default=(), max_length=256)
    marker: Text | None = None
    extras: tuple[Name, ...] = Field(default=(), max_length=256)
    activation: Activation = "unknown"

    @model_validator(mode="after")
    def consistent_identity(self):
        expected = package_purl(self.ecosystem, self.name, self.selected_version)
        if self.purl is not None and self.purl != expected:
            raise ValueError("contradictory-package-identity")
        if self.evidence_kind != "installed" and self.installed_environment_id is not None:
            raise ValueError("source-declaration-is-not-installed")
        if self.evidence_kind == "installed" and self.root_id is not None:
            raise ValueError("installed-evidence-cannot-borrow-source-root")
        return self


class Relationship(Record):
    id: ID
    parent_id: ID
    child_id: ID
    source: Locator
    evidence_status: Literal["evidenced", "unassessed"]
    scopes: tuple[Name, ...] = Field(default=(), max_length=256)
    marker: Text | None = None
    extras: tuple[Name, ...] = Field(default=(), max_length=256)
    activation: Activation = "unknown"


class Application(Record):
    id: ID
    root_id: ID
    source: Locator
    ecosystem: Ecosystem
    name: Name
    version: Name | None


class ProjectionLoss(Record):
    id: ID
    source: Locator
    dimension: Literal["identity", "version", "graph", "environment", "scope"]
    reason: Reason
    occurrence_id: ID | None = None
    relationship_id: ID | None = None


class InputCoverage(Record):
    source_path: Text
    source_sha256: SHA256 | None
    format: Name | None
    parser: Name | None
    disposition: Literal["discovered", "parsed", "ignored", "unsupported", "failed", "bounded-omission", "unresolved"]
    reason: Reason
    # Contexts assert only evidenced ownership/analysis, never completeness of
    # an entire project. Empty contexts preserve unknown ownership.
    root_ids: tuple[ID, ...] = Field(default=(), max_length=4096)
    analysis_scope_ids: tuple[ID, ...] = Field(default=(), max_length=4096)
    installed_environment_ids: tuple[ID, ...] = Field(default=(), max_length=4096)

    @field_validator("source_path")
    @classmethod
    def safe_path(cls, value):
        if relative_path(value) != value:
            raise ValueError("noncanonical-coverage-path")
        return value


class Coverage(Record):
    schema_version: Literal["sourcebastion.inventory-coverage/1"] = "sourcebastion.inventory-coverage/1"
    discovery: Fidelity
    enumeration: Fidelity
    version_resolution: Fidelity
    graph: Fidelity
    environment: Fidelity
    inputs: tuple[InputCoverage, ...] = Field(max_length=100000)
    refusal_codes: tuple[Reason, ...] = Field(default=(), max_length=4096)


class StageStates(Record):
    inventory: Literal["complete", "partial", "failed"]
    export: Stage = "not-run"
    matching: Stage = "not-run"

    @model_validator(mode="after")
    def valid_stage_dependency(self):
        if self.matching == "succeeded" and (self.export != "succeeded" or self.inventory == "failed"):
            raise ValueError("matching-requires-admitted-export")
        if self.export == "succeeded" and self.inventory == "failed":
            raise ValueError("export-requires-admitted-inventory")
        return self


class Producer(Record):
    name: Name
    version: Name
    code_sha256: SHA256
    registry_sha256: SHA256
    config_sha256: SHA256


class InventoryLimits(Record):
    schema_version: Literal["sourcebastion.inventory-limits/1"] = "sourcebastion.inventory-limits/1"
    cpu_quota: Annotated[float, Field(gt=0, le=2)] = 2.0
    gomaxprocs: Annotated[int, Field(ge=1, le=2)] = 2
    cataloger_concurrency: Annotated[int, Field(ge=1, le=2)] = 2
    charged_memory_bytes: Annotated[int, Field(ge=1, le=2 * 1024**3)] = 2 * 1024**3
    swap_bytes: Literal[0] = 0
    aggregate_cpu_seconds: Annotated[float, Field(gt=0, le=120)] = 120.0
    pipeline_wall_seconds: Annotated[float, Field(gt=0, le=150)] = 150.0
    pids: Annotated[int, Field(ge=1, le=256)] = 256
    traversal_entries: Annotated[int, Field(ge=1, le=100000)] = 100000
    traversal_depth: Annotated[int, Field(ge=1, le=64)] = 64
    source_file_bytes: Annotated[int, Field(ge=1, le=2 * 1024**2)] = 2 * 1024**2
    parsed_text_bytes: Annotated[int, Field(ge=1, le=256 * 1024**2)] = 256 * 1024**2
    include_depth: Annotated[int, Field(ge=1, le=64)] = 64
    include_targets_per_origin: Annotated[int, Field(ge=1, le=4096)] = 4096
    occurrences: Annotated[int, Field(ge=1, le=100000)] = 100000
    relationships: Annotated[int, Field(ge=1, le=500000)] = 500000
    semantic_checks: Annotated[int, Field(ge=1, le=5000000)] = 5000000
    inventory_bytes: Annotated[int, Field(ge=1, le=64 * 1024**2)] = 64 * 1024**2
    sbom_bytes: Annotated[int, Field(ge=1, le=64 * 1024**2)] = 64 * 1024**2
    diagnostic_file_bytes: Annotated[int, Field(ge=1, le=64 * 1024**2)] = 64 * 1024**2
    diagnostic_job_bytes: Annotated[int, Field(ge=1, le=256 * 1024**2)] = 256 * 1024**2
    export_nodes: Annotated[int, Field(ge=1, le=2000000)] = 2000000
    export_depth: Annotated[int, Field(ge=1, le=32)] = 32
    export_string_bytes: Annotated[int, Field(ge=1, le=2 * 1024**2)] = 2 * 1024**2
    added_compressed_image_bytes: Annotated[int, Field(ge=1, le=250 * 1024**2)] = 250 * 1024**2

    @field_validator("swap_bytes", mode="before")
    @classmethod
    def numeric_zero_swap(cls, value):
        if type(value) is not int or value != 0:
            raise ValueError("swap-must-be-numeric-zero")
        return value


class Inventory(Record):
    schema_version: Literal["sourcebastion.inventory/1"] = "sourcebastion.inventory/1"
    # This is a controller assertion of its admitted source, not a digest
    # inferred from the subset of inputs a parser happened to recognize.
    source_sha256: SHA256
    producer: Producer
    limits: InventoryLimits = Field(default_factory=InventoryLimits)
    environment: Environment
    environment_sha256: SHA256
    roots: tuple[Root, ...] = Field(default=(), max_length=100000)
    analysis_scopes: tuple[AnalysisScope, ...] = Field(default=(), max_length=100000)
    installed_environments: tuple[InstalledEnvironment, ...] = Field(default=(), max_length=100000)
    occurrences: tuple[Occurrence, ...] = Field(default=(), max_length=100000)
    relationships: tuple[Relationship, ...] = Field(default=(), max_length=500000)
    applications: tuple[Application, ...] = Field(default=(), max_length=100000)
    losses: tuple[ProjectionLoss, ...] = Field(default=(), max_length=100000)
    coverage: Coverage
    stages: StageStates

    @model_validator(mode="after")
    def references_and_authority(self):
        if self.environment_sha256 != self.environment.sha256:
            raise ValueError("environment-digest-mismatch")
        if len(self.occurrences) > self.limits.occurrences or len(self.relationships) > self.limits.relationships:
            raise ValueError("inventory-record-budget-exceeded")
        if len({row.source_path for row in self.coverage.inputs}) != len(self.coverage.inputs):
            raise ValueError("duplicate-input-coverage")
        indexes = {}
        for kind, records in (
            ("root", self.roots),
            ("scope", self.analysis_scopes),
            ("environment", self.installed_environments),
            ("occurrence", self.occurrences),
            ("relationship", self.relationships),
            ("application", self.applications),
            ("loss", self.losses),
        ):
            ids = {row.id for row in records}
            if len(ids) != len(records) or any(not key.startswith(kind + ":sha256:") for key in ids):
                raise ValueError("duplicate-or-mistyped-record-id")
            indexes[kind] = ids
        inputs = {row.source_path: row for row in self.coverage.inputs}
        for row in self.coverage.inputs:
            for kind, keys in (
                ("root", row.root_ids),
                ("scope", row.analysis_scope_ids),
                ("environment", row.installed_environment_ids),
            ):
                if len(set(keys)) != len(keys) or any(key not in indexes[kind] for key in keys):
                    raise ValueError("unbound-or-duplicate-coverage-context")
        for records in (
            self.roots,
            self.analysis_scopes,
            self.installed_environments,
            self.occurrences,
            self.relationships,
            self.applications,
            self.losses,
        ):
            for record in records:
                covered = inputs.get(record.source.path)
                if covered is None or covered.source_sha256 != record.source.source_sha256:
                    raise ValueError("unbound-source-coverage")
        for occurrence in self.occurrences:
            for kind, key in (
                ("root", occurrence.root_id),
                ("scope", occurrence.analysis_scope_id),
                ("environment", occurrence.installed_environment_id),
            ):
                if key is not None and key not in indexes[kind]:
                    raise ValueError("unbound-occurrence-context")
        for relationship in self.relationships:
            if (
                relationship.parent_id not in indexes["occurrence"]
                or relationship.child_id not in indexes["occurrence"]
            ):
                raise ValueError("unbound-relationship-endpoint")
        if any(app.root_id not in indexes["root"] for app in self.applications):
            raise ValueError("unbound-application-root")
        for loss in self.losses:
            if (loss.occurrence_id is not None and loss.occurrence_id not in indexes["occurrence"]) or (
                loss.relationship_id is not None and loss.relationship_id not in indexes["relationship"]
            ):
                raise ValueError("unbound-projection-loss")
        if self.coverage.version_resolution == "complete" and any(
            row.selected_version is None for row in self.occurrences
        ):
            raise ValueError("unresolved-version-cannot-be-complete")
        if self.stages.inventory == "complete" and (
            self.coverage.discovery != "complete"
            or self.coverage.enumeration != "complete"
            or self.coverage.version_resolution != "complete"
            or self.coverage.refusal_codes
            or any(row.purl is None for row in self.occurrences)
            or any(
                row.disposition in {"unsupported", "failed", "bounded-omission", "unresolved", "discovered"}
                for row in self.coverage.inputs
            )
        ):
            raise ValueError("incomplete-coverage-cannot-be-promoted")
        if self.stages.inventory == "failed" and (self.occurrences or self.relationships):
            raise ValueError("failed-inventory-cannot-admit-graph")
        return self


def _record_values(record):
    for name in type(record).model_fields:
        yield getattr(record, name)


def _preflight_structure(value, max_nodes, max_depth, max_string_bytes):
    """Walk existing typed objects lazily before any graph validation/copy.

    Each frame is an iterator, not a list of children. Even a lowered node
    budget therefore refuses dense graphs without materializing their export.
    """
    stack, visited = [(iter((value,)), 0)], 0
    while stack:
        children, depth = stack[-1]
        try:
            item = next(children)
        except StopIteration:
            stack.pop()
            continue
        visited += 1
        if visited > max_nodes or depth > max_depth:
            raise ValueError("inventory-structure-budget-exceeded")
        if isinstance(item, str):
            if len(item) > max_string_bytes or len(item.encode()) > max_string_bytes:
                raise ValueError("inventory-string-budget-exceeded")
        elif isinstance(item, Record):
            child_count = len(type(item).model_fields)
            child_iter = _record_values(item)
            if visited + child_count > max_nodes:
                raise ValueError("inventory-structure-budget-exceeded")
            stack.append((child_iter, depth + 1))
        elif type(item) in (tuple, list, dict):
            if visited + len(item) > max_nodes:
                raise ValueError("inventory-structure-budget-exceeded")
            if type(item) is dict:
                for key in item:
                    if type(key) is not str:
                        raise ValueError("invalid-inventory-object-key")
                    if len(key) > max_string_bytes or len(key.encode()) > max_string_bytes:
                        raise ValueError("inventory-string-budget-exceeded")
                child_iter = iter(item.values())
            else:
                child_iter = iter(item)
            stack.append((child_iter, depth + 1))
        elif item is not None and type(item) not in (bool, int, float):
            raise ValueError("invalid-inventory-value")


def canonical_bytes(inventory, *, max_bytes=64 * 1024 * 1024, max_nodes=2000000):
    """Deterministic bounded export, with refusal instead of truncation."""
    if not isinstance(inventory, Inventory):
        raise TypeError("validated Inventory required")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 1 <= max_bytes <= 64 * 1024 * 1024:
        raise ValueError("invalid-inventory-byte-limit")
    if isinstance(max_nodes, bool) or not isinstance(max_nodes, int) or not 1 <= max_nodes <= 2000000:
        raise ValueError("invalid-inventory-node-limit")
    # The small limits record is revalidated first: trusted model_copy can
    # otherwise replace it with unvalidated data before effective caps apply.
    limits = InventoryLimits.model_validate(inventory.limits)
    max_bytes = min(max_bytes, limits.inventory_bytes)
    max_nodes = min(max_nodes, limits.export_nodes)
    _preflight_structure(inventory, max_nodes, limits.export_depth, limits.export_string_bytes)
    inventory = Inventory.model_validate(inventory)
    data = inventory.model_dump(mode="json")
    data["environment"]["marker_inputs"].sort()
    for field in (
        "roots",
        "analysis_scopes",
        "installed_environments",
        "occurrences",
        "relationships",
        "applications",
        "losses",
    ):
        data[field].sort(key=lambda row: row["id"])
    data["coverage"]["inputs"].sort(key=lambda row: row["source_path"])
    for row in data["coverage"]["inputs"]:
        for key in ("root_ids", "analysis_scope_ids", "installed_environment_ids"):
            row[key].sort()
    data["coverage"]["refusal_codes"].sort()
    encoded, size = [], 0
    encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    for chunk in encoder.iterencode(data):
        part = chunk.encode()
        size += len(part)
        if size > max_bytes:
            raise ValueError("inventory-output-budget-exceeded")
        encoded.append(part)
    return b"".join(encoded)
