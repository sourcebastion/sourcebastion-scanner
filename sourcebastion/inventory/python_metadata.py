"""Bounded observed dist-info metadata; never interpreter or resolver evidence."""

from __future__ import annotations

from dataclasses import dataclass
from email.parser import BytesParser
from email.policy import compat32
from pathlib import PurePosixPath
import re

from packaging import metadata
from packaging.utils import canonicalize_name
from packaging.version import Version
from pydantic import TypeAdapter

from .inputs import InputRefusal
from .requirements import parse_requirement
from .contract import Text, package_purl

VERSION = "sourcebastion.python-metadata/1"
MAX_HEADERS = 100000
MAX_FIELD = 16384
CANONICAL_TEXT = TypeAdapter(Text)


@dataclass(frozen=True)
class Document:
    disposition: str
    reason: str
    name: str | None = None
    version: str | None = None
    requirements: tuple = ()
    requires_python: str | None = None
    losses: tuple = ()


class Refusal(ValueError):
    pass


def _field(value, check):
    check()
    if not isinstance(value, str) or len(value) > MAX_FIELD:
        raise Refusal("metadata-field-budget-exceeded")
    if any((ord(c) < 32 and c not in "\t\r\n") or 127 <= ord(c) < 160 for c in value):
        raise Refusal("invalid-metadata-control")
    # Preflight before eager maintained Version, Requirement, marker and
    # license-expression validation. No parser receives an unbounded expression.
    if re.search(r"\d{129,}", value):
        raise Refusal("metadata-expression-budget-exceeded")
    depth = 0
    for c in value:
        if c == "(":
            depth += 1
            if depth > 32:
                raise Refusal("metadata-expression-budget-exceeded")
        elif c == ")":
            depth -= 1
    if len(re.findall(r"\b(?:and|or|AND|OR)\b", value)) > 128:
        raise Refusal("metadata-expression-budget-exceeded")


def parse(path, content, *, check):
    """Return located observations; Source/shared budget refusals propagate."""
    parent = PurePosixPath(path).parent.name
    if PurePosixPath(path).name != "METADATA" or not parent.endswith(".dist-info"):
        return Document("unsupported", "unassessed-egg-metadata-ownership")
    if not isinstance(content, bytes):
        raise TypeError("exact metadata bytes required")
    if len(content) > 2 * 1024 * 1024:
        raise InputRefusal("input-file-budget-exceeded")
    try:
        text = content.decode("utf-8")
        # Charge and bound headers before either email parser allocates fields.
        lines = text.splitlines(keepends=True)
        header_count = 0
        have_field = False
        field_bytes = 0
        for line_number, line in enumerate(lines):
            check()
            if line_number >= MAX_HEADERS:
                raise Refusal("metadata-record-budget-exceeded")
            line = line.removesuffix("\n").removesuffix("\r")
            if not line:
                break
            if "\r" in line or "\n" in line:
                raise Refusal("invalid-metadata-header")
            if line.startswith((" ", "\t")):
                if not have_field:
                    raise Refusal("invalid-metadata-header")
                field_bytes += len(line)
            else:
                if not re.match(r"^[!-9;-~]+:", line):
                    raise Refusal("invalid-metadata-header")
                have_field = True
                field_bytes = len(line)
                header_count += 1
                if header_count > MAX_HEADERS:
                    raise Refusal("metadata-record-budget-exceeded")
            if field_bytes > MAX_FIELD:
                raise Refusal("metadata-field-budget-exceeded")
        message = BytesParser(policy=compat32).parsebytes(content)
        if message.defects or message.is_multipart():
            raise Refusal("invalid-metadata-header")
        raw, unparsed = metadata.parse_email(content)
        if unparsed:
            raise Refusal("unsupported-or-malformed-metadata-field")

        def unfold(value):
            _field(value, check)
            # RFC822 continuation is retained by parse_email. Unfold before
            # maintained dependency grammars; original source bytes stay bound.
            return re.sub(r"\r?\n[ \t]+", " ", value)

        for field, value in tuple(raw.items()):
            # Body prose is bounded by the source byte ceiling and is neither
            # dependency syntax nor exported arbitrary metadata.
            if field == "description":
                check()
                continue
            if isinstance(value, dict):
                raw[field] = {unfold(key): unfold(member) for key, member in value.items()}
            elif isinstance(value, list):
                raw[field] = [unfold(member) for member in value]
            else:
                raw[field] = unfold(value)
        requirements = []
        for ordinal, value in enumerate(raw.get("requires_dist", [])):
            check()
            try:
                requirement = parse_requirement(ordinal, value)
                exact = str(Version(requirement.exact_version)) if requirement.exact_version is not None else None
                package_purl("pypi", requirement.name, exact)
                if len(requirement.extras) > 256 or any(len(extra) > 512 for extra in requirement.extras):
                    raise Refusal("unsupported-metadata-declaration-identity")
                for normalized in (requirement.specifier, requirement.marker):
                    if normalized:
                        CANONICAL_TEXT.validate_python(normalized, strict=True)
                requirements.append(requirement)
            except InputRefusal as exc:
                raise Refusal(exc.reason) from None
            except ValueError:
                raise Refusal("unsupported-metadata-declaration-identity") from None
        version_id = raw.get("metadata_version")
        if version_id in {"2.3", "2.4", "2.5", "2.6"}:
            for extra in raw.get("provides_extra", []):
                check()
                if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", extra):
                    raise Refusal("invalid-metadata-extra")
        imports = {}
        for field in ("import_names", "import_namespaces"):
            imports[field] = set()
            for value in raw.get(field, []):
                check()
                imports[field].add(value.partition(";")[0].strip())
        if imports["import_names"] & imports["import_namespaces"]:
            raise Refusal("conflicting-metadata-import-identity")
        check()
        try:
            parsed = metadata.Metadata.from_raw(raw, validate=True)
        except (ValueError, metadata.ExceptionGroup, RecursionError):
            raise Refusal("invalid-core-metadata") from None
        check()
        name, version = canonicalize_name(parsed.name), str(parsed.version)
        try:
            package_purl("pypi", name, version)
        except ValueError:
            raise Refusal("unsupported-metadata-distribution-identity") from None
        if parsed.metadata_version == "1.0":
            raise Refusal("unsupported-installed-metadata-version")
        requires_python = str(parsed.requires_python) if parsed.requires_python is not None else None
        if requires_python:
            try:
                CANONICAL_TEXT.validate_python(requires_python, strict=True)
            except ValueError:
                raise Refusal("unsupported-metadata-python-requirement") from None
        # Accept historical case/dot spelling while refusing a contradictory
        # filename. The metadata itself remains the identity authority.
        stem = parent.removesuffix(".dist-info")
        if "-" not in stem:
            raise Refusal("invalid-dist-info-identity")
        directory_name, directory_version = stem.rsplit("-", 1)
        _field(directory_version, check)
        if canonicalize_name(directory_name) != name or Version(directory_version.replace("_", "-")) != parsed.version:
            raise Refusal("conflicting-dist-info-identity")
        losses = []
        for field in (
            "requires",
            "provides",
            "obsoletes",
            "requires_external",
            "provides_dist",
            "obsoletes_dist",
            "platforms",
            "supported_platforms",
        ):
            for ordinal, _value in enumerate(raw.get(field, [])):
                check()
                dimension = "environment" if field in {"platforms", "supported_platforms"} else "graph"
                losses.append((field, ordinal, dimension, "metadata-control-unassessed"))
        for field, reason in (
            ("provides_extra", "metadata-provided-extra-unassessed"),
            ("dynamic", "metadata-dynamic-information-unprojected"),
        ):
            for ordinal, _value in enumerate(raw.get(field, [])):
                check()
                losses.append((field, ordinal, "scope", reason))
        for field in ("import_names", "import_namespaces"):
            # parse_email correctly represents the legal single empty
            # Import-Name header as []. Preserve that located control too.
            values = raw.get(field, [])
            if field == "import_names" and field in raw and not values:
                values = ("",)
            for ordinal, _value in enumerate(values):
                check()
                losses.append((field, ordinal, "identity", "metadata-import-identity-unassessed"))
        unresolved = any(
            r in {"metadata-control-unassessed", "metadata-import-identity-unassessed"} for _, _, _, r in losses
        )
        return Document(
            "unresolved" if unresolved else "parsed",
            ("metadata-control-unassessed" if unresolved else "observed-distribution-metadata"),
            name,
            version,
            tuple(requirements),
            requires_python or None,
            tuple(losses),
        )
    except InputRefusal:
        # Source epoch/deadline/shared accounting failures invalidate the whole
        # operation; they are not ordinary per-input syntax failures.
        raise
    except UnicodeDecodeError:
        return Document("failed", "invalid-input-encoding")
    except Refusal as exc:
        reason = str(exc)
        return Document(
            (
                "bounded-omission"
                if "budget" in reason
                else "unsupported" if reason.startswith("unsupported-") else "failed"
            ),
            reason,
        )
    except (ValueError, RecursionError):
        return Document("failed", "invalid-core-metadata")
