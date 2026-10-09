"""Bounded admission of a source- or artifact-bound local build SBOM.

The contract is `docs/inventory-imported-sbom.md`. This module is the gate it
describes: it decides whether a supplied document may be admitted at all, and
records what was admitted. It deliberately stops there.

`admit` is the gate alone and produces no occurrences. `project` is the import
proper: it admits, then builds occurrences carrying `evidence_kind="imported"`
so a reader can always tell a built dependency from a declared one. It never
merges by name or purl into anything discovery found -- a caller holds the
imported occurrences separately and decides what to do with them.

No route invokes this. It performs no network access and runs no tool.
"""

from dataclasses import dataclass
import hashlib
import json
from urllib.parse import unquote

from .contract import (
    AnalysisScope,
    Locator,
    Occurrence,
    identifier,
    package_purl,
)
from .inputs import InputRefusal, relative_path

VERSION = "sourcebastion.imported-sbom/1"
#: The exported profile's pinned specification. An import is held to what this
#: scanner itself emits, so one schema family is reasoned about rather than
#: two, and no version is coerced into another.
FORMAT = "CycloneDX"
SPECIFICATIONS = frozenset({"1.6"})
#: Its own ceiling, separate from the export cap: an imported document is
#: untrusted input, and a build SBOM large enough to exhaust the export budget
#: must not be able to consume it.
MAX_IMPORT_BYTES = 8 * 1024 * 1024
MAX_COMPONENTS = 100000


@dataclass(frozen=True)
class ImportedBom:
    """One admitted document. Facts about bytes, never an inventory."""

    sha256: str
    specification: str
    components: int
    binding: str
    path: str | None = None
    schema_version: str = VERSION

    def __post_init__(self):
        if self.binding not in ("source", "controller"):
            raise ValueError("invalid-import-binding")
        if (self.path is None) != (self.binding == "controller"):
            raise ValueError("invalid-import-binding")


@dataclass(frozen=True)
class ImportedProjection:
    """Imported occurrences, held apart from anything discovery composed.

    `skipped` counts components the canonical model cannot state. `duplicates`
    counts components that restate one already projected; they are two
    separate facts about an incomplete projection and are never summed.
    """

    admitted: "ImportedBom"
    scope: object
    occurrences: tuple
    skipped: int
    duplicates: int = 0


def _decode(raw, limits, check):
    ceiling = min(MAX_IMPORT_BYTES, limits.sbom_bytes)
    if type(raw) is not bytes or not raw or len(raw) > ceiling:
        raise InputRefusal("imported-sbom-byte-budget-exceeded")
    depth, quoted, escaped = 0, False, False
    for offset, byte in enumerate(raw):
        if offset % 4096 == 0:
            check()
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
            if depth > limits.export_depth:
                raise InputRefusal("imported-sbom-depth-budget-exceeded")
        elif byte in (93, 125):
            depth -= 1

    def pairs(rows):
        value = {}
        for key, child in rows:
            if key in value:
                raise ValueError("duplicate-imported-sbom-key")
            value[key] = child
        return value

    def constant(_value):
        raise ValueError("nonfinite-imported-sbom")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except InputRefusal:
        raise
    except (UnicodeError, RecursionError, ValueError):
        raise ValueError("invalid-imported-sbom") from None
    check()
    return value


def admit(raw, *, limits, check, path=None):
    """Validate one document and return what was admitted, nothing more."""
    return _admit(raw, limits=limits, check=check, path=path)[0]


def _admit(raw, *, limits, check, path=None):
    """Validate one document and return what was admitted.

    `path` names the artifact inside the admitted source; its absence means the
    controller supplied the bytes directly and the document is identified by
    digest alone. Nothing here opens a file: a caller that reads from source
    does so through `inputs.Source`, which refuses symlinks against a pinned
    root descriptor, and passes the bytes it read.
    """
    confined = relative_path(path) if path is not None else None
    value = _decode(raw, limits, check)
    if type(value) is not dict:
        raise ValueError("invalid-imported-sbom")
    if value.get("bomFormat") != FORMAT:
        raise ValueError("unsupported-imported-sbom-format")
    specification = value.get("specVersion")
    if specification not in SPECIFICATIONS:
        # No coercion: a 1.5 document is not a 1.6 document with fields
        # missing, and guessing which is which is how an import starts
        # asserting things its bytes do not say.
        raise ValueError("unsupported-imported-sbom-specification")
    components = value.get("components", [])
    if type(components) is not list or len(components) > MAX_COMPONENTS:
        raise ValueError("invalid-imported-sbom-components")
    check()
    return (
        ImportedBom(
            sha256=hashlib.sha256(raw).hexdigest(),
            specification=specification,
            components=len(components),
            binding="source" if confined is not None else "controller",
            path=confined,
        ),
        value,
    )

#: Only what the canonical model can state about a component. CycloneDX
#: carries more, and an import that quietly promoted its extra fields into
#: canonical claims would be asserting what the bytes do not establish.
_ECOSYSTEMS = {
    "pypi": "pypi",
    "npm": "npm",
    "golang": "golang",
    "cargo": "cargo",
    "maven": "maven",
    "nuget": "nuget",
    "gem": "gem",
    "composer": "composer",
}


def _ecosystem(purl):
    if type(purl) is not str or not purl.startswith("pkg:"):
        return None
    return _ECOSYSTEMS.get(purl[4:].split("/", 1)[0].split("@", 1)[0].lower())


def _asserted(purl):
    """What a supplied purl states about identity, and nothing else.

    Qualifiers and the subpath are dropped because the canonical model cannot
    state them, and percent-encoding and the type's case are normalised so the
    same identity written two legal ways compares equal. What survives is only
    the type, namespace, name and version -- the part the derived purl also
    states, so the two can be held against each other.
    """
    bare = purl.split("#", 1)[0].split("?", 1)[0]
    type_name, _, rest = bare[4:].partition("/")
    return "pkg:" + type_name.lower() + "/" + unquote(rest)


def project(raw, *, limits, check, path=None, source_sha256=None):
    """Admit a document and build its occurrences, separately from discovery.

    Returns the admitted facts and the occurrences the document supports. A
    component without a usable purl ecosystem, name or version is skipped
    rather than guessed at: the count of what was skipped is on the result, so
    an incomplete projection is visible instead of silently smaller.

    Nothing here consults or mutates a composed inventory. Equal purls between
    an import and discovery stay separate occurrences, because the built
    artifact and the declared dependency are not established to be the same
    thing.
    """
    admitted, document = _admit(raw, limits=limits, check=check, path=path)
    digest = source_sha256 if source_sha256 is not None else admitted.sha256
    locator = Locator(
        path=admitted.path if admitted.path is not None else "(controller-supplied)",
        source_sha256=digest,
        locator="imported-sbom",
        parser=VERSION,
    )
    scope = AnalysisScope(
        id=identifier("scope", locator.model_dump()),
        kind="imported-sbom-input",
        source=locator,
    )
    occurrences, seen, skipped, duplicates = [], set(), 0, 0
    for component in document.get("components", []):
        check()
        if type(component) is not dict:
            skipped += 1
            continue
        supplied = component.get("purl")
        ecosystem = _ecosystem(supplied)
        name, version = component.get("name"), component.get("version")
        if ecosystem is None or type(name) is not str or type(version) is not str:
            skipped += 1
            continue
        try:
            purl = package_purl(ecosystem, name, version)
            # The document states identity twice. Where the two disagree,
            # neither is adopted: rewriting the purl to agree with the fields
            # would make the import assert a version its bytes contradict.
            if _asserted(supplied) != _asserted(purl):
                skipped += 1
                continue
            values = dict(
                source=locator,
                ecosystem=ecosystem,
                name=name,
                purl=purl,
                evidence_kind="imported",
                selected_version=version,
                analysis_scope_id=scope.id,
                activation="unknown",
            )
            row = Occurrence(
                id=identifier("occurrence", {**values, "source": locator.model_dump()}),
                **values,
            )
        except ValueError:
            skipped += 1
            continue
        if row.id in seen:
            # The same component stated twice is one occurrence, not two. The
            # canonical model refuses duplicate record ids, so emitting both
            # would hand a caller something no Inventory can hold -- and a
            # document is untrusted input that may well repeat itself.
            duplicates += 1
            continue
        seen.add(row.id)
        occurrences.append(row)
    check()
    return ImportedProjection(
        admitted=admitted,
        scope=scope,
        occurrences=tuple(occurrences),
        skipped=skipped,
        duplicates=duplicates,
    )
