"""Bound restricted provider observations to admitted source bytes.

This is an internal evidence receipt, not canonical package/edge authority.
Provider candidates retain unknown roles and graph semantics until a reviewed
source adapter interprets them. Raw metadata and host paths stay in the private
sidecar; public records can refer to its hashes without copying its contents.
The controller supplies the outer isolation boundary and shared work callback.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Literal

from pydantic import Field, ValidationError, model_validator

from .contract import Name, ProviderReference, Record, SHA256, Text, package_purl
from .discovery import Discovery
from .inputs import InputRefusal, Source, relative_path

VERSION = "sourcebastion.provider-receipt/1"
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
FILE_CATALOGERS = (
    "file-content-cataloger",
    "file-digest-cataloger",
    "file-executable-cataloger",
    "file-metadata-cataloger",
)
# Cataloger/type/metadata contracts are deliberately narrower than arbitrary
# Syft JSON. New representations require a reviewed adapter/profile change.
ROLES = {
    "javascript-lock-cataloger": ("npm", "lock-candidate", {"npm-lock", "pnpm-lock", "yarn-lock"}),
    "javascript-package-cataloger": ("npm", "package-metadata", {"npm-manifest"}),
    "go-module-file-cataloger": ("go-module", "declaration-candidate", {"go-mod", "go-sum"}),
    "rust-cargo-lock-cataloger": ("rust-crate", "lock-candidate", {"cargo-lock"}),
    "python-installed-package-cataloger": ("python", "installed-candidate", {"python-installed-metadata"}),
    "java-gradle-lockfile-cataloger": ("java-archive", "lock-candidate", {"gradle-lock"}),
    "java-pom-cataloger": ("java-archive", "declaration-candidate", {"maven-pom"}),
    "dotnet-packages-lock-cataloger": ("dotnet", "lock-candidate", {"nuget-lock"}),
    "ruby-gemfile-cataloger": ("gem", "lock-candidate", {"bundler-lock"}),
    "php-composer-lock-cataloger": ("php-composer", "lock-candidate", {"composer-lock"}),
}
METADATA_TYPES = {
    "javascript-lock-cataloger": {
        "javascript-npm-package-lock-entry",
        "javascript-pnpm-lock-entry",
        "javascript-yarn-lock-entry",
    },
    "javascript-package-cataloger": {"javascript-npm-package"},
    "go-module-file-cataloger": {"go-module-entry"},
    "rust-cargo-lock-cataloger": {"rust-cargo-lock-entry"},
    "python-installed-package-cataloger": {"python-package"},
    "java-gradle-lockfile-cataloger": {"java-archive"},
    "java-pom-cataloger": {"java-archive"},
    "dotnet-packages-lock-cataloger": {"dotnet-packages-lock-entry"},
    "ruby-gemfile-cataloger": {None},
    "php-composer-lock-cataloger": {"php-composer-lock-entry"},
}
ECOSYSTEMS = {
    "npm": "npm",
    "go-module": "golang",
    "rust-crate": "cargo",
    "python": "pypi",
    "java-archive": "maven",
    "dotnet": "nuget",
    "gem": "gem",
    "php-composer": "composer",
}
MAX_OUTPUT = 64 * 1024 * 1024
MAX_NODES = 2000000


class ProviderBinding(Record):
    path: Text
    source_sha256: SHA256
    provider_file_id: Name

    @model_validator(mode="after")
    def safe_path(self):
        if relative_path(self.path) != self.path:
            raise ValueError("noncanonical-provider-path")
        return self


class ProviderCandidate(Record):
    raw_id: Name
    cataloger: Name
    metadata_type: Name | None
    role: Literal["lock-candidate", "declaration-candidate", "package-metadata", "installed-candidate"]
    identity_status: Literal["versioned-observation", "version-unreported", "unassessed"]
    ecosystem: Literal["pypi", "npm", "golang", "cargo", "maven", "nuget", "gem", "composer"] | None = None
    name: Name | None = None
    observed_version: Name | None = None
    purl: Text | None = None
    bindings: tuple[ProviderBinding, ...] = Field(min_length=1, max_length=256)
    reference: ProviderReference
    canonical_semantics: Literal["unassessed"] = "unassessed"

    @model_validator(mode="after")
    def observational_identity(self):
        if self.identity_status == "unassessed":
            if any(value is not None for value in (self.ecosystem, self.name, self.observed_version, self.purl)):
                raise ValueError("unassessed-provider-identity")
        elif (
            self.ecosystem is None
            or self.name is None
            or self.purl != package_purl(self.ecosystem, self.name, self.observed_version)
        ):
            raise ValueError("contradictory-provider-identity")
        elif (self.observed_version is None) != (self.identity_status == "version-unreported"):
            raise ValueError("contradictory-provider-version-status")
        return self


class ProviderDependency(Record):
    # Syft dependency-of stores the dependency in parent and dependent in child.
    parent_raw_id: Name
    child_raw_id: Name
    reference: ProviderReference
    canonical_semantics: Literal["unassessed"] = "unassessed"


class ProviderReceipt(Record):
    schema_version: Literal["sourcebastion.provider-receipt/1"] = VERSION
    source_sha256: SHA256
    provider_binary_sha256: SHA256
    provider_output_sha256: SHA256
    syft_version: Literal["1.54.0"] = "1.54.0"
    candidates: tuple[ProviderCandidate, ...] = Field(max_length=100000)
    dependencies: tuple[ProviderDependency, ...] = Field(max_length=500000)
    uninterpreted_relationship_count: int = Field(ge=0, le=500000)
    coverage: Literal["unassessed"] = "unassessed"
    unreported_dimensions: tuple[str, ...] = (
        "input-parse-disposition",
        "record-locator",
        "canonical-project-root",
        "scope",
        "environment-activation",
        "declared-range",
        "complete-graph",
        "application-role",
    )

    @model_validator(mode="after")
    def bound_observations(self):
        ids, paths, files = set(), {}, {}
        for candidate in self.candidates:
            _raw_id(candidate.raw_id)
            if (
                candidate.raw_id in ids
                or candidate.cataloger not in ROLES
                or candidate.role != ROLES[candidate.cataloger][1]
                or candidate.metadata_type not in METADATA_TYPES[candidate.cataloger]
            ):
                raise ValueError("invalid-provider-candidate-context")
            if candidate.reference.provider_output_sha256 != self.provider_output_sha256:
                raise ValueError("unbound-provider-reference")
            ids.add(candidate.raw_id)
            local = set()
            for binding in candidate.bindings:
                _raw_id(binding.provider_file_id)
                signature = (binding.source_sha256, binding.provider_file_id)
                if binding.path in local or paths.get(binding.path, signature) != signature:
                    raise ValueError("contradictory-provider-binding")
                if files.get(binding.provider_file_id, binding.path) != binding.path:
                    raise ValueError("ambiguous-provider-file-id")
                local.add(binding.path)
                paths[binding.path] = signature
                files[binding.provider_file_id] = binding.path
        if ids & set(files):
            raise ValueError("colliding-provider-id-namespaces")
        for dependency in self.dependencies:
            if dependency.parent_raw_id not in ids or dependency.child_raw_id not in ids:
                raise ValueError("dangling-provider-dependency")
            if dependency.reference.provider_output_sha256 != self.provider_output_sha256:
                raise ValueError("unbound-provider-reference")
        return self


def _refuse(reason):
    raise InputRefusal(reason) from None


def _object(value, reason):
    if type(value) is not dict:
        _refuse(reason)
    return value


def _raw_id(value):
    if type(value) is not str or re.fullmatch(r"[a-f0-9]{16}", value) is None:
        _refuse("invalid-provider-record-id")
    return value


def _path(value):
    if type(value) is not str or not value.startswith("/") or value.startswith("//"):
        _refuse("unsafe-provider-location")
    path = value[1:]
    if relative_path(path) != path:
        _refuse("unsafe-provider-location")
    return path


def _decode(raw, step):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_OUTPUT:
        _refuse("provider-output-budget-exceeded")
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        _refuse("invalid-provider-json")
    # Reserve byte-scanning work; deadline checks recur during lexical depth
    # admission, before JSON's recursive decoder can see deeply nested input.
    depth = 0
    quoted = escaped = False
    for offset, byte in enumerate(raw):
        if offset % 4096 == 0:
            step()
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 32:
                _refuse("provider-input-depth-exceeded")
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                _refuse("invalid-provider-json")

    def pairs(items):
        output = {}
        for key, value in items:
            if key in output:
                _refuse("duplicate-provider-json-key")
            output[key] = value
        return output

    def constant(_value):
        _refuse("nonfinite-provider-json")

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except InputRefusal:
        raise
    except (ValueError, UnicodeError, RecursionError):
        _refuse("invalid-provider-json")
    pending, nodes = [value], 0
    while pending:
        step()
        child = pending.pop()
        nodes += 1
        if nodes > MAX_NODES:
            _refuse("provider-input-node-budget-exceeded")
        if type(child) is dict:
            # Include keys, not only values, in string and node allowances.
            children = list(child.keys()) + list(child.values())
        elif type(child) is list:
            children = child
        elif type(child) is str:
            try:
                size = len(child.encode("utf-8"))
            except UnicodeError:
                _refuse("invalid-provider-json-string")
            if size > 2 * 1024 * 1024:
                _refuse("provider-input-string-budget-exceeded")
            continue
        elif type(child) is float and not math.isfinite(child):
            _refuse("nonfinite-provider-json")
        else:
            continue
        if nodes + len(pending) + len(children) > MAX_NODES:
            _refuse("provider-input-node-budget-exceeded")
        pending.extend(children)
    if type(value) is not dict:
        _refuse("invalid-provider-document")
    return value


def _profile(document):
    try:
        descriptor = document["descriptor"]
        cfg = descriptor["configuration"]
        expected = {
            "syft": "1.54.0",
            "profile": "offline-file-provider-v1",
            "generate_cpes": False,
            "catalogers": list(CATALOGERS),
            "coverage": "unassessed",
        }
        if (
            descriptor["name"] != "sourcebastion-restricted-provider"
            or descriptor["version"] != "1"
            or document["schema"]["version"] != "16.1.11"
            or document["source"]["type"] != "directory"
            or cfg["extra"] != [expected]
            or cfg["data-generation"]["generate-cpes"] is not False
            or cfg["catalogers"]["requested"] != {"default": [*CATALOGERS, "file"]}
            or sorted(cfg["catalogers"]["used"]) != sorted([*CATALOGERS, *FILE_CATALOGERS])
            or cfg["files"]["hashers"] != ["sha-256"]
            or cfg["files"]["selection"] != "owned-by-package"
        ):
            _refuse("unadmitted-provider-profile")
        packages = cfg["packages"]
        for section, keys in {
            "golang": (
                "use-packages-lib",
                "search-remote-licenses",
                "search-local-mod-cache-licenses",
                "search-local-vendor-licenses",
            ),
            "python": ("search-remote-licenses", "guess-unpinned-requirements"),
            "javascript": ("search-remote-licenses",),
            "java-archive": ("use-network", "use-maven-localrepository", "resolve-transitive-dependencies"),
            "cpp": ("vcpkg-allow-git-clone",),
        }.items():
            if any(packages[section][key] is not False for key in keys):
                _refuse("unadmitted-provider-profile")
        if packages["javascript"]["include-dev-dependencies"] is not True:
            _refuse("unadmitted-provider-profile")
    except (KeyError, TypeError, AttributeError):
        _refuse("unadmitted-provider-profile")


def bind_provider(raw, source, discovery, *, source_sha256, provider_binary_sha256, check):
    """Admit a complete private sidecar against one already-used controller Source.

    `check` MUST charge the caller's existing semantic ledger and shared deadline;
    this function creates no new stage allowance. Observed file SHA256s must
    match the same admitted Source bytes. Assertions are structurally verified,
    not authenticated: process custody and snapshot isolation remain controller
    obligations. No path-only/name-only/purl-only joining is performed.
    """
    if not isinstance(source, Source) or not isinstance(discovery, Discovery) or not callable(check):
        raise TypeError("controller-bound provider inputs required")
    for digest in (source_sha256, provider_binary_sha256):
        if type(digest) is not str or re.fullmatch(r"[a-f0-9]{64}", digest) is None:
            raise ValueError("invalid-controller-provider-digest")
    try:
        return _bind_provider(raw, source, discovery, source_sha256, provider_binary_sha256, check)
    except InputRefusal:
        raise
    except ValidationError:
        # Pydantic errors include input_value: never return raw source paths or
        # identity strings through a purported fixed diagnostic interface.
        _refuse("provider-receipt-validation-refused")


def _bind_provider(raw, source, discovery, source_sha256, provider_binary_sha256, check):
    if discovery.status == "failed":
        _refuse("provider-discovery-not-admitted")

    def step():
        source.check()
        check()

    document = _decode(raw, step)
    _profile(document)
    artifacts, files, relationships = (document.get(key) for key in ("artifacts", "files", "artifactRelationships"))
    if any(type(rows) is not list for rows in (artifacts, files, relationships)):
        _refuse("missing-provider-records")
    if len(artifacts) > 100000 or len(files) > source.limits.entries or len(relationships) > 500000:
        _refuse("provider-record-budget-exceeded")
    admitted = {}
    for row in discovery.inputs:
        step()
        if row.sha256 is not None and row.disposition not in {"ignored", "failed", "bounded-omission"}:
            item = source.cache.get(row.path)
            if item is None or item.sha256 != row.sha256:
                _refuse("unbound-provider-input")
            admitted[row.path] = row
    bindings, file_ids = {}, set()
    for row in files:
        step()
        if type(row) is not dict:
            _refuse("invalid-provider-file")
        file_id = _raw_id(row.get("id"))
        path = _path(_object(row.get("location"), "invalid-provider-file-location").get("path"))
        if file_id in file_ids or path in bindings:
            _refuse("duplicate-provider-file")
        item = admitted.get(path)
        if item is None or row.get("digests") != [{"algorithm": "sha256", "value": item.sha256}]:
            _refuse("provider-source-hash-mismatch")
        meta = _object(row.get("metadata"), "invalid-provider-file-metadata")
        if (
            meta.get("type") != "RegularFile"
            or type(meta.get("size")) is not int
            or meta["size"] != len(source.cache[path].content)
        ):
            _refuse("invalid-provider-file-metadata")
        bindings[path] = ProviderBinding(path=path, source_sha256=item.sha256, provider_file_id=file_id)
        file_ids.add(file_id)
    output_sha = hashlib.sha256(raw).hexdigest()

    def reference(row):
        return ProviderReference(
            provider_output_sha256=output_sha,
            raw_record_sha256=hashlib.sha256(
                json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            ).hexdigest(),
        )

    candidates, ids = [], set()
    for artifact in artifacts:
        step()
        if type(artifact) is not dict:
            _refuse("invalid-provider-artifact")
        raw_id = _raw_id(artifact.get("id"))
        cataloger = artifact.get("foundBy")
        if (
            raw_id in ids
            or raw_id in file_ids
            or type(cataloger) is not str
            or cataloger not in ROLES
            or artifact.get("cpes") != []
        ):
            _refuse("unadmitted-provider-artifact")
        package_type, role, formats = ROLES[cataloger]
        metadata_type = artifact.get("metadataType")
        if (
            artifact.get("type") != package_type
            or (metadata_type is not None and type(metadata_type) is not str)
            or metadata_type not in METADATA_TYPES[cataloger]
        ):
            _refuse("unadmitted-provider-representation")
        locations = artifact.get("locations")
        if type(locations) is not list or not 1 <= len(locations) <= 256:
            _refuse("invalid-provider-locations")
        selected_bindings, paths = [], set()
        for location in locations:
            step()
            if type(location) is not dict:
                _refuse("invalid-provider-location")
            path = _path(location.get("path"))
            # Differing accessPath can hide archive/alias traversal semantics.
            if location.get("accessPath", location.get("path")) != location.get("path"):
                _refuse("unsupported-provider-access-path")
            if path in paths or path not in bindings or admitted[path].format not in formats:
                _refuse("unbound-provider-location")
            paths.add(path)
            selected_bindings.append(bindings[path])
        ecosystem = ECOSYSTEMS[package_type]
        name, raw_version = artifact.get("name"), artifact.get("version")
        version = raw_version or None
        identity = {"identity_status": "unassessed"}
        try:
            if type(name) is not str or type(raw_version) is not str:
                raise ValueError("invalid-observed-identity-type")
            if any(
                not 1 <= len(value) <= 512 or any(ord(c) < 32 or 127 <= ord(c) < 160 for c in value)
                for value in (name, version)
                if value is not None
            ):
                raise ValueError("invalid-observed-identity-text")
            purl = package_purl(ecosystem, name, version)
            if purl == artifact.get("purl"):
                identity = dict(
                    identity_status="version-unreported" if version is None else "versioned-observation",
                    ecosystem=ecosystem,
                    name=name,
                    observed_version=version,
                    purl=purl,
                )
        except (ValueError, TypeError):
            pass
        candidates.append(
            ProviderCandidate(
                raw_id=raw_id,
                cataloger=cataloger,
                metadata_type=metadata_type,
                role=role,
                bindings=tuple(sorted(selected_bindings, key=lambda value: value.path)),
                reference=reference(artifact),
                **identity,
            )
        )
        ids.add(raw_id)
    dependencies = []
    uninterpreted = 0
    for row in relationships:
        step()
        if type(row) is not dict:
            _refuse("invalid-provider-relationship")
        kind = row.get("type")
        if type(kind) is not str or re.fullmatch(r"[a-z][a-z-]{0,127}", kind) is None:
            _refuse("invalid-provider-relationship-type")
        if kind == "dependency-of":
            parent, child = _raw_id(row.get("parent")), _raw_id(row.get("child"))
            if parent not in ids or child not in ids:
                _refuse("dangling-provider-dependency")
            dependencies.append(
                ProviderDependency(
                    parent_raw_id=row["child"],
                    child_raw_id=row["parent"],
                    reference=reference(row),
                )
            )
        else:
            uninterpreted += 1
    source.validate()
    step()
    return ProviderReceipt(
        source_sha256=source_sha256,
        provider_binary_sha256=provider_binary_sha256,
        provider_output_sha256=output_sha,
        candidates=tuple(candidates),
        dependencies=tuple(dependencies),
        uninterpreted_relationship_count=uninterpreted,
    )
