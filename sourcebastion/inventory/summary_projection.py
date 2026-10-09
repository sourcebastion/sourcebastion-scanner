"""Inactive canonical-derived facts; no upload or execution admission."""

import hashlib

from .contract import Inventory, canonical_bytes

VERSION = "sourcebastion.inventory-summary-projection/1"
FIDELITIES = ("discovery", "enumeration", "version_resolution", "graph", "environment")
DISPOSITIONS = ("discovered", "parsed", "ignored", "unsupported", "failed", "bounded-omission", "unresolved")


class ProjectionError(ValueError):
    """Fixed diagnostics omit source and validation details."""


def project_inventory(inventory, *, check):
    """Return detached facts from one internally generated canonical snapshot.

    Only an exact typed Inventory is accepted. This is not a raw JSON decoder.
    The callback consumes the caller's existing allowance; external confinement
    must bound canonical serialization and strict-model validation between calls.
    No receipt, execution status, export or matching authority is returned.
    """
    if not callable(check):
        raise TypeError("shared-projection-ledger-required")
    check()
    if type(inventory) is not Inventory:
        raise ProjectionError("inventory_projection_invalid")
    try:
        raw = canonical_bytes(inventory)
        # Snapshot before deriving facts: never count the caller's live model
        # after hashing it, nor substitute Python-mode collection semantics.
        snapshot = Inventory.model_validate_json(raw)
    except (TypeError, ValueError):
        raise ProjectionError("inventory_projection_invalid") from None
    check()
    dispositions = dict.fromkeys(DISPOSITIONS, 0)
    recognized = selected = evidenced = 0
    for offset, row in enumerate(snapshot.coverage.inputs):
        if offset % 256 == 0:
            check()
        dispositions[row.disposition] += 1
        recognized += row.format is not None
    for offset, row in enumerate(snapshot.occurrences):
        if offset % 256 == 0:
            check()
        selected += row.selected_version is not None
    for offset, row in enumerate(snapshot.relationships):
        if offset % 256 == 0:
            check()
        evidenced += row.evidence_status == "evidenced"
    result = {
        "projection_version": VERSION,
        "source_sha256": snapshot.source_sha256,
        "inventory": {
            "producer": snapshot.producer.model_dump(mode="json"),
            "environment_sha256": snapshot.environment_sha256,
            "canonical_state": snapshot.stages.inventory,
            "coverage": {key: getattr(snapshot.coverage, key) for key in FIDELITIES},
            "counts": {
                "discovered_inputs": len(snapshot.coverage.inputs),
                "recognized_inputs": recognized,
                "input_dispositions": dispositions,
                "package_occurrences": len(snapshot.occurrences),
                "selected_occurrences": selected,
                "declarations": len(snapshot.declarations),
                "canonical_relationships": len(snapshot.relationships),
                "evidenced_relationships": evidenced,
                "canonical_projection_losses": len(snapshot.losses),
            },
            "artifact": {
                "format": "sourcebastion.inventory/1",
                "sha256": hashlib.sha256(raw).hexdigest(),
                "byte_count": len(raw),
            },
        },
    }
    check()
    return result
