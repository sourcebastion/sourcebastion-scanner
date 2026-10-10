"""Inactive canonical-to-row materialization; no storage or admission authority."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from .contract import Inventory, canonical_bytes, identifier

VERSION = "sourcebastion.inventory-row-projection/1"
_DOMAIN = VERSION.encode("ascii") + b"\0"
_COLLECTIONS = (
    "roots",
    "analysis_scopes",
    "installed_environments",
    "occurrences",
    "relationships",
    "applications",
    "losses",
    "declarations",
    "input_references",
    "applicability",
    "dependency_selectors",
)
_CONTEXTS = (
    ("roots", "root"),
    ("analysis_scopes", "scope"),
    ("installed_environments", "environment"),
)
_EVIDENCE = (
    ("applications", "application"),
    ("losses", "loss"),
    ("declarations", "declaration"),
    ("input_references", "input-reference"),
    ("applicability", "applicability"),
    ("dependency_selectors", "selector"),
)


class RowProjectionError(ValueError):
    """Fixed diagnostics never include canonical payload or source paths."""


@dataclass(frozen=True)
class ProjectedRow:
    table: str
    key: tuple[str, ...]
    columns: tuple[tuple[str, str | int | None], ...]
    detail: bytes


@dataclass(frozen=True)
class RowProjection:
    """Forgeable pure result, never a validator/server acceptance receipt."""

    projection_version: str
    inventory_sha256: str
    source_sha256: str
    rows: tuple[ProjectedRow, ...]
    projection_sha256: str
    logical_bytes: int


def _encode(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _frame(raw):
    return len(raw).to_bytes(8, "big") + raw


def _bounded_encode(value, remaining, check):
    encoder = json.JSONEncoder(
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    chunks = iter(encoder.iterencode(value))
    parts = []
    while True:
        check()
        try:
            text = next(chunks)
        except StopIteration:
            break
        # ensure_ascii makes character count the exact encoded byte count.
        # Reject before allocating/appending encoded bytes. One encoder string
        # chunk is still bounded by the canonical scalar limit, not this quota.
        if len(text) > remaining:
            raise RowProjectionError("inventory_row_byte_limit")
        remaining -= len(text)
        parts.append(text.encode("ascii"))
    check()
    return b"".join(parts)


def _row_header(row):
    return {"table": row.table, "key": row.key, "columns": row.columns}


def _count_rows(snapshot, max_rows, check):
    count = 1

    def charge(size):
        nonlocal count
        check()
        if size > max_rows - count:
            raise RowProjectionError("inventory_row_count_limit")
        count += size

    for field in _COLLECTIONS:
        charge(len(getattr(snapshot, field)))
    charge(len(snapshot.coverage.inputs))
    for record in snapshot.occurrences:
        for field in ("scopes", "groups", "extras"):
            check()
            charge(len(set(getattr(record, field))))
    for record in snapshot.coverage.inputs:
        for field in ("root_ids", "analysis_scope_ids", "installed_environment_ids"):
            charge(len(getattr(record, field)))
    return count


def _locator(record):
    source = record["source"]
    return tuple(
        (column, source[key])
        for column, key in (
            ("source_path", "path"),
            ("source_sha256", "source_sha256"),
            ("source_locator", "locator"),
            ("source_parser", "parser"),
        )
    )


def project_rows(inventory, *, max_rows, max_bytes, check):
    """Build detached immutable rows from one internally generated snapshot.

    Explicit caller limits are logical admission, not physical SQL/index/WAL
    capacity or approved deployment settings. No numeric defaults are granted.
    The existing canonical contract is the only schema validator. Confinement
    must bound its serialization/validation and Python sorts between callbacks.
    This helper has no caller, SQL, matching, ecosystem-coverage inference or
    execution/authentication authority. It accepts no raw inventory JSON.
    """
    if not callable(check):
        raise TypeError("shared-projection-ledger-required")
    if (
        type(max_rows) is not int
        or type(max_bytes) is not int
        or not 1 <= max_rows <= 2**63 - 1
        or not 1 <= max_bytes <= 2**63 - 1
    ):
        raise RowProjectionError("inventory_row_limits_invalid")
    check()
    if type(inventory) is not Inventory:
        raise RowProjectionError("inventory_row_projection_invalid")
    try:
        raw = canonical_bytes(inventory)
        snapshot = Inventory.model_validate_json(raw)
    except (TypeError, ValueError):
        raise RowProjectionError("inventory_row_projection_invalid") from None
    check()
    expected_rows = _count_rows(snapshot, max_rows, check)
    check()
    value = snapshot.model_dump(mode="json")
    check()
    inventory_sha = hashlib.sha256(raw).hexdigest()
    header = _encode(
        {
            "projection_version": VERSION,
            "inventory_sha256": inventory_sha,
            "source_sha256": snapshot.source_sha256,
        }
    )
    total_bytes = len(_DOMAIN) + len(_frame(header))
    if total_bytes > max_bytes:
        raise RowProjectionError("inventory_row_byte_limit")
    rows = []

    def add(table, key, columns, detail):
        nonlocal total_bytes
        check()
        if len(rows) >= max_rows:
            raise RowProjectionError("inventory_row_count_limit")
        remaining = max_bytes - total_bytes - 16  # two framing lengths
        if remaining < 0:
            raise RowProjectionError("inventory_row_byte_limit")
        header = _bounded_encode(
            {
                "table": table,
                "key": key,
                "columns": columns,
            },
            remaining,
            check,
        )
        encoded = _bounded_encode(detail, remaining - len(header), check)
        charge = len(header) + len(encoded) + 16
        row = ProjectedRow(table, tuple(key), tuple(columns), encoded)
        total_bytes += charge
        rows.append(row)

    # Preserve top-level scalar/evidence records and global coverage exactly.
    # Input records have their own rows so this detail is bounded independently
    # of the full input list; no per-context completeness is manufactured.
    metadata = {key: child for key, child in value.items() if key not in _COLLECTIONS}
    metadata["coverage"] = {key: child for key, child in value["coverage"].items() if key != "inputs"}
    add(
        "snapshot",
        ("snapshot",),
        (
            ("canonical_state", snapshot.stages.inventory),
            ("input_count", len(snapshot.coverage.inputs)),
            ("occurrence_count", len(snapshot.occurrences)),
        ),
        metadata,
    )

    for collection, kind in _CONTEXTS:
        for record in value[collection]:
            add(
                "context",
                (kind, record["id"]),
                (
                    ("kind", kind),
                    ("id", record["id"]),
                    *_locator(record),
                ),
                record,
            )

    check()
    ordered = sorted(
        value["occurrences"],
        key=lambda row: (
            row["name"],
            row["selected_version"] is None,
            row["selected_version"] or "",
            row["id"],
        ),
    )
    check()
    for rank, record in enumerate(ordered):
        columns = (
            tuple(
                (key, record[key])
                for key in (
                    "id",
                    "ecosystem",
                    "name",
                    "purl",
                    "selected_version",
                    "declared_range",
                    "evidence_kind",
                    "directness",
                    "activation",
                    "root_id",
                    "analysis_scope_id",
                    "installed_environment_id",
                )
            )
            + (("name_version_rank", rank),)
            + _locator(record)
        )
        add("occurrence", (record["id"],), columns, record)
        for facet in ("scopes", "groups", "extras"):
            check()
            # DISTINCT facets are query membership, not a lossy rewrite of the
            # original arrays: their exact contents remain in occurrence detail.
            values = sorted(set(record[facet]))
            check()
            for item in values:
                add(
                    "occurrence_facet",
                    (record["id"], facet, item),
                    (
                        ("occurrence_id", record["id"]),
                        ("facet", facet),
                        ("value", item),
                    ),
                    None,
                )

    for record in value["relationships"]:
        add(
            "relationship",
            (record["id"],),
            tuple(
                (key, record[key])
                for key in (
                    "id",
                    "parent_id",
                    "child_id",
                    "selector_id",
                    "evidence_status",
                    "activation",
                )
            )
            + _locator(record),
            record,
        )

    for collection, kind in _EVIDENCE:
        for record in value[collection]:
            add(
                "evidence",
                (kind, record["id"]),
                (
                    ("kind", kind),
                    ("id", record["id"]),
                    *_locator(record),
                ),
                record,
            )

    for ordinal, record in enumerate(value["coverage"]["inputs"]):
        input_id = identifier("input", record["source_path"])
        add(
            "input",
            (str(ordinal),),
            (("ordinal", ordinal), ("canonical_id", input_id))
            + tuple(
                (key, record[key])
                for key in (
                    "source_path",
                    "source_sha256",
                    "format",
                    "parser",
                    "disposition",
                    "reason",
                    "ecosystem",
                    "enumeration",
                    "enumeration_basis",
                )
            ),
            record,
        )
        for field, kind in (
            ("root_ids", "root"),
            ("analysis_scope_ids", "scope"),
            ("installed_environment_ids", "environment"),
        ):
            for context_id in record[field]:
                add(
                    "input_context",
                    (str(ordinal), kind, context_id),
                    (
                        ("input_ordinal", ordinal),
                        ("kind", kind),
                        ("context_id", context_id),
                    ("parent_id", input_id),
                    ("canonical_id", context_id),
                    ("context_kind", kind),
                    ("root_id", context_id if kind == "root" else None),
                    ("ecosystem", record["ecosystem"]),
                    ),
                    None,
                )

    check()
    if len(rows) != expected_rows:
        raise RowProjectionError("inventory_row_projection_invalid")
    rows.sort(key=lambda row: (row.table, row.key))
    check()
    digest = hashlib.sha256(_DOMAIN + _frame(header))
    for row in rows:
        check()
        header = _bounded_encode(_row_header(row), max_bytes, check)
        for part in (header, row.detail):
            check()
            digest.update(len(part).to_bytes(8, "big"))
            digest.update(part)
    check()
    return RowProjection(
        VERSION,
        inventory_sha,
        snapshot.source_sha256,
        tuple(rows),
        digest.hexdigest(),
        total_bytes,
    )
