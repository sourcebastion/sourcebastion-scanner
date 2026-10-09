"""Bounded admission of a source- or artifact-bound local build SBOM.

The contract is `docs/inventory-imported-sbom.md`. This module is the gate it
describes: it decides whether a supplied document may be admitted at all, and
records what was admitted. It deliberately stops there.

Admission produces no occurrences and touches no inventory. Projecting an
imported component into the canonical model is a separate question with its own
evidence rules -- an import must not merge by name or purl into something
discovery found -- and answering it here would give the gate the one property
the slice forbids. A caller holding an `ImportedBom` has a validated document
and its identity, nothing more.

No route invokes this. It performs no network access and runs no tool.
"""

from dataclasses import dataclass
import hashlib
import json

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
    return ImportedBom(
        sha256=hashlib.sha256(raw).hexdigest(),
        specification=specification,
        components=len(components),
        binding="source" if confined is not None else "controller",
        path=confined,
    )
