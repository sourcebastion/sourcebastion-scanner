"""License policy over the canonical inventory (M048 S04).

License evidence comes only from the canonical inventory (M048 D1): the values
the inputs an adapter read actually state, composed locally with no network.
Each package occurrence gets one result. ``permitted`` produces no finding,
``denied`` and ``undetermined`` do. Undetermined (no license stated, unparsed
text, an unlisted ``LicenseRef``) is never permitted.

When an occurrence has several observations, the strictest wins: any denied
observation denies it, and any undetermined one keeps it from being permitted.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any, Dict

from sourcebastion.external_scanners import ScannerExecutionError
from sourcebastion.license_expression import (
    DENIED,
    PERMITTED,
    UNDETERMINED,
    LicensePolicy,
    evaluate,
)

logger = logging.getLogger(__name__)

SCANNER = "license-checker"
PRODUCER = "sourcebastion-scanner-license-check"


def compose_licensed_inventory(path: str):
    """Compose a local inventory/2 for *path*; never published or uploaded."""
    from sourcebastion import __version__
    from sourcebastion.inventory.compose_source import compose_source
    from sourcebastion.inventory.contract import Producer
    from sourcebastion.inventory.inputs import Source
    from sourcebastion.inventory.registry import REGISTRY_SHA256, DiscoveryConfig

    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        root = root.parent
    config = DiscoveryConfig()
    identity = f"{PRODUCER}/{__version__}".encode()
    producer = Producer(
        name=PRODUCER,
        version=__version__,
        code_sha256=hashlib.sha256(identity).hexdigest(),
        registry_sha256=REGISTRY_SHA256,
        config_sha256=config.sha256,
    )
    with Source(str(root)) as source:
        return compose_source(
            source,
            # A local check has no controller-admitted source digest; the
            # inventory is evaluated in-process and never leaves it.
            source_sha256=hashlib.sha256(str(root).encode()).hexdigest(),
            producer=producer,
            config=config,
            licenses=True,
        )


def check_licenses(
    path: str,
    policy: LicensePolicy,
    *,
    undetermined_severity: str = "medium",
    inventory=None,
) -> Dict[str, Any]:
    """Evaluate *policy* over the canonical inventory of *path*.

    A failed inventory fails the component, as any scanner failure does: a
    clean license result over nothing would read as compliance.
    """
    if inventory is None:
        try:
            inventory = compose_licensed_inventory(path)
        except (OSError, ValueError) as error:
            logger.error("license inventory composition failed: %s", type(error).__name__)
            raise ScannerExecutionError(SCANNER, "execution_failed") from None
    if inventory.stages.inventory == "failed":
        raise ScannerExecutionError(SCANNER, "scope_unresolved")
    return evaluate_inventory(inventory, policy, undetermined_severity=undetermined_severity)


def evaluate_inventory(inventory, policy: LicensePolicy, *, undetermined_severity: str = "medium"):
    """Findings, per-package rows and a coverage-aware summary."""
    if undetermined_severity not in ("medium", "low"):
        raise ValueError("undetermined severity is medium or low")
    observations: Dict[str, list] = {}
    for row in inventory.licenses:
        observations.setdefault(row.occurrence_id, []).append(row)
    gaps = {row.occurrence_id: row for row in inventory.license_gaps}

    findings, packages = [], []
    counts = {PERMITTED: 0, DENIED: 0, UNDETERMINED: 0}
    for occurrence in sorted(inventory.occurrences, key=lambda row: (row.name, row.selected_version or "", row.id)):
        rows = sorted(observations.get(occurrence.id, ()), key=lambda row: row.id)
        evaluated = [(row, evaluate(row.value_raw, policy)) for row in rows]
        if any(e.result == DENIED for _, e in evaluated):
            result = DENIED
        elif not evaluated or any(e.result == UNDETERMINED for _, e in evaluated):
            result = UNDETERMINED
        else:
            result = PERMITTED
        counts[result] += 1
        stated = [row.expression or row.value_raw for row in rows]
        packages.append({
            "name": occurrence.name,
            "version": occurrence.selected_version,
            "ecosystem": occurrence.ecosystem,
            "licenses": stated,
            "result": result,
            "occurrence_id": occurrence.id,
        })
        if result == PERMITTED:
            continue
        findings.append(_finding(occurrence, result, evaluated, gaps.get(occurrence.id), stated, undetermined_severity))

    return {
        "findings": findings,
        "packages": packages,
        "summary": {
            "total": len(inventory.occurrences),
            "permitted": counts[PERMITTED],
            "denied": counts[DENIED],
            "undetermined": counts[UNDETERMINED],
            # Partial coverage means packages may exist that were never read.
            # "0 denied" over partial coverage is not a compliant result.
            "coverage": inventory.stages.inventory,
            "unassessed_inputs": sorted(
                row.source_path
                for row in inventory.coverage.inputs
                if row.disposition not in ("parsed", "ignored")
            ),
            "license_list_version": inventory.license_list_version,
        },
    }


def _finding(occurrence, result, evaluated, gap, stated, undetermined_severity):
    package = f"{occurrence.name}@{occurrence.selected_version or 'unresolved'}"
    if result == DENIED:
        row, evaluation = next((r, e) for r, e in evaluated if e.result == DENIED)
        terms = ", ".join(str(t) for t in evaluation.denied_terms)
        title = f"Denied license: {row.expression} in {package}"
        description = (
            f"{package} states the license '{row.expression}' ({row.evidence} in {row.source.path}). "
            f"Denied by policy: {terms}."
        )
        solution = (
            f"Replace {occurrence.name} with a package under a permitted license, or add an ignore rule "
            f"(rule_id: license-denied-{row.expression}) with a justification."
        )
        severity, rule_id = "high", f"license-denied-{row.expression}"
        license_value, location = row.expression, row.source
    else:
        undetermined = next((r for r, e in evaluated if e.result == UNDETERMINED), None)
        if undetermined is None:
            title = f"No license stated: {package}"
            description = (
                f"No input that was read states a license for {package} ({gap.reason if gap else 'unassessed'}). "
                "An unstated license is not a permitted one."
            )
            key, license_value, location = "unstated", None, occurrence.source
        elif undetermined.expression is None:
            title = f"Unrecognized license in {package}"
            description = (
                f"{package} states '{undetermined.value_raw}' ({undetermined.evidence} in "
                f"{undetermined.source.path}), which is not an SPDX license expression."
            )
            key, license_value, location = "unparsed", undetermined.value_raw, undetermined.source
        else:
            title = f"License not on the allowed list: {undetermined.expression} in {package}"
            description = (
                f"{package} states '{undetermined.expression}' ({undetermined.evidence} in "
                f"{undetermined.source.path}), which the policy neither allows nor denies."
            )
            key, license_value, location = undetermined.expression, undetermined.expression, undetermined.source
        solution = (
            "Confirm the package's license. If acceptable, add it to allowed_licenses; if not, to "
            f"denied_licenses. To suppress: add an ignore rule (rule_id: license-undetermined-{key})."
        )
        severity, rule_id = undetermined_severity, f"license-undetermined-{key}"
    return {
        "type": "license_compliance",
        "category": "license_compliance",
        "title": title,
        "description": description,
        "solution": solution,
        "file": location.path,
        "line": 0,  # Evidence is located by `license_locator`, not a line.
        "license_locator": location.locator,
        "severity": severity,
        "scanner": SCANNER,
        "rule_id": rule_id,
        "license_result": result,
        "license": license_value,
        "all_licenses": stated,
        "package": occurrence.name,
        "package_version": occurrence.selected_version,
        "package_type": occurrence.ecosystem,
        "occurrence_id": occurrence.id,
    }


__all__ = ["LicensePolicy", "check_licenses", "compose_licensed_inventory", "evaluate_inventory"]
