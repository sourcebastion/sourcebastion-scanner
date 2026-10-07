"""Bounded local discovery and pip include/constraint provenance.

This foundation is intentionally not wired to production scan results until
M046 S03/S04 supply canonical semantics and real matching. Discovered formats
without an adapter are unsupported, never an empty complete inventory.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import posixpath
import re

from .inputs import InputRefusal, Source
from .registry import DiscoveryConfig, REGISTRY_SHA256, VERSION, format_for
from .requirements import Document, parse


@dataclass(frozen=True)
class InputRecord:
    path: str
    format: str | None
    sha256: str | None
    disposition: str
    reason: str
    parser: str | None = None


@dataclass(frozen=True)
class ReferenceRecord:
    origin: str
    source: str
    line: int
    kind: str
    target: str | None
    role: str
    disposition: str
    reason: str


@dataclass(frozen=True)
class Discovery:
    registry_version: str
    registry_sha256: str
    config_sha256: str
    status: str
    inputs: tuple
    references: tuple
    contexts: tuple
    documents: tuple
    refusal_codes: tuple
    parsed_input_digest: str
    # Actual visits, including those deduplicated in reference evidence.
    semantic_checks: int

    def to_dict(self):
        return asdict(self)


def _disposition(reason):
    if "budget" in reason or "deadline" in reason:
        return "bounded-omission"
    if reason.startswith("unsupported-"):
        return "unsupported"
    return "failed"


def discover(source, *, config=None):
    """Use a controller-held Source; caller retains it for later adapters.

    Only parsed-input hashes are digested here, not the whole repository.
    Source.validate detects changes; it does not grant persistent custody.
    """
    if not isinstance(source, Source):
        raise TypeError("controller-bound Source required")
    config = config or DiscoveryConfig()
    if not isinstance(config, DiscoveryConfig):
        raise TypeError("validated DiscoveryConfig required")
    records, documents, references, refusals = {}, {}, set(), set()
    contexts = set()
    parsed_records = 0
    partial = False
    failed = False
    checks = 0

    def record(path, fmt, sha, disposition, reason, parser=None):
        nonlocal partial
        records[path] = InputRecord(path, fmt, sha, disposition, reason, parser)
        if disposition in {"unsupported", "failed", "bounded-omission", "unresolved"}:
            partial = True

    def load(path, fmt, explicit=False):
        nonlocal parsed_records
        if path in records and not (
            explicit
            and records[path].disposition == "ignored"
            and records[path].reason in {"ambiguous-bare-declarations", "empty-candidate", "non-dependency-prose"}
        ):
            return documents.get(path)
        if config.ignores(path):
            record(path, fmt, None, "ignored", "configured-or-vcs-ignore")
            return None
        try:
            item = source.read(path)
            if fmt != "pip-requirements":
                record(path, fmt, item.sha256, "unsupported", "unsupported-format-adapter")
                return None
            doc = parse(
                path,
                item.content,
                explicit=explicit,
                deadline=source.deadline,
                max_records=max(0, 100000 - parsed_records),
            )
            parsed_records += len(doc.requirements) + len(doc.references)
            disposition = {"malformed": "failed", "unsafe": "failed", "budget-exceeded": "bounded-omission"}.get(
                doc.disposition, doc.disposition
            )
            record(path, fmt, item.sha256, disposition, doc.reason, doc.parser)
            documents[path] = doc
            return doc
        except InputRefusal as exc:
            # A detected epoch failure invalidates the whole operation, even if
            # this failing read never entered the cache used by validate().
            record(path, fmt, None, _disposition(exc.reason), exc.reason)
            if exc.reason.startswith("changed-") or exc.reason in {"closed-source", "input-deadline-exceeded"}:
                raise
            return None

    try:
        for entry in source.discover(ignored=config.ignored):
            fmt = format_for(entry.path, config)
            if entry.kind == "directory":
                continue
            if entry.kind == "ignored":
                record(entry.path, fmt, None, "ignored", "configured-or-vcs-ignore")
            elif entry.kind == "depth-omission":
                record(entry.path, None, None, "bounded-omission", "input-depth-budget-exceeded")
            elif entry.kind != "file":
                record(entry.path, fmt, None, "unsupported", "unsupported-" + entry.kind)
            elif fmt:
                load(entry.path, fmt, explicit=entry.path in dict(config.mappings))
        # Explicit mappings to absent paths must not disappear from coverage.
        for path, fmt in sorted(config.mappings):
            load(path, fmt, explicit=True)

        seeds = sorted(documents)
        for origin in seeds:
            visited, targets = set(), set()

            def visit(path, role, ancestry):
                nonlocal checks, partial
                source.check()
                if (path, role) in visited:
                    return
                visited.add((path, role))
                contexts.add((origin, path, role))
                doc = documents.get(path)
                if doc is None:
                    return
                for ref in doc.references:
                    checks += 1
                    source.check()
                    if checks > config.semantic_checks:
                        raise InputRefusal("reference-check-budget-exceeded")
                    target_role = "constraint" if role == "constraint" or ref.kind == "constraint" else "requirement"
                    reason = ref.reason
                    disposition = "discovered"
                    if reason:
                        disposition = _disposition(reason)
                    elif ref.target in ancestry + (path,):
                        disposition, reason = "failed", "include-cycle"
                    elif len(ancestry) >= config.include_depth:
                        disposition, reason = "bounded-omission", "include-depth-budget-exceeded"
                    elif ref.target not in targets and len(targets) >= config.include_targets:
                        disposition, reason = "bounded-omission", "include-target-budget-exceeded"
                    elif config.ignores(ref.target):
                        disposition, reason = "ignored", "configured-or-vcs-ignore"
                    elif format_for(ref.target, config) not in {None, "pip-requirements"}:
                        disposition, reason = "failed", "conflicting-reference-format"
                    else:
                        targets.add(ref.target)
                        child = load(ref.target, "pip-requirements", explicit=True)
                        disposition = records[ref.target].disposition
                        reason = records[ref.target].reason
                        if child is not None:
                            visit(ref.target, target_role, ancestry + (path,))
                    references.add(
                        ReferenceRecord(origin, path, ref.line, ref.kind, ref.target, target_role, disposition, reason)
                    )
                    if disposition not in {"parsed", "discovered", "ignored"}:
                        partial = True

            seed_role = (
                "constraint"
                if re.fullmatch(r"constraints(?:[-_.].*)?\.(?:txt|in|pip)", posixpath.basename(origin))
                else "requirement"
            )
            visit(origin, seed_role, ())
    except InputRefusal as exc:
        refusals.add(exc.reason)
        partial = True
        # Content/path changes invalidate all parsed evidence for consumption.
        if exc.reason.startswith(("changed-", "unavailable-")) or exc.reason == "closed-source":
            failed = True
            documents.clear()
    try:
        source.validate()
    except InputRefusal as exc:
        refusals.add(exc.reason)
        failed = True
        documents.clear()
    ordered = tuple(records[key] for key in sorted(records))
    digest = hashlib.sha256(
        json.dumps([(r.path, r.sha256) for r in ordered if r.sha256], separators=(",", ":")).encode()
    ).hexdigest()
    return Discovery(
        VERSION,
        REGISTRY_SHA256,
        config.sha256,
        "failed" if failed else "partial" if partial else "complete",
        ordered,
        tuple(sorted(references, key=lambda r: (r.origin, r.source, r.line, r.role, r.target or ""))),
        tuple(sorted(contexts)),
        tuple(documents[key] for key in sorted(documents)),
        tuple(sorted(refusals)),
        digest,
        checks,
    )
