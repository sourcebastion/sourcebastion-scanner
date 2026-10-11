"""License observations from inputs adapters already read (M048 S03).

Nothing here looks a license up, guesses one from a package name or reaches the
network. An adapter hands over the value a read input states, with its locator;
every occurrence without such a value gets an explicit gap instead.
"""

from __future__ import annotations

import json

from sourcebastion.license_expression import parse_license

from .contract import LicenseGap, LicenseObservation, Locator, identifier

VERSION = "sourcebastion.license-evidence/1"
MAX_RAW = 16384


def stated_value(value):
    """The stated value as bounded control-free text, or None if nothing is stated.

    A string keeps its text with whitespace runs collapsed, because the
    contract refuses control characters and folded metadata headers carry
    newlines. Any other JSON shape (an npm legacy object, a malformed array)
    is kept as compact JSON so it stays visible as an unparsed claim.
    """
    if value is None:
        return None
    if isinstance(value, str):
        text = " ".join(value.split())
    else:
        try:
            text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        except (TypeError, ValueError):
            return None
    if not text or len(text) > MAX_RAW or any(ord(c) < 32 or 127 <= ord(c) < 160 for c in text):
        return None
    return text


def observe(occurrence, source: Locator, value, evidence):
    """One observation for *occurrence*, or None when *value* states nothing."""
    raw = stated_value(value)
    if raw is None:
        return None
    parsed = parse_license(raw)
    values = dict(
        occurrence_id=occurrence.id,
        source=source,
        evidence=evidence,
        value_raw=raw,
        expression=parsed.expression,
        parse=parsed.parse,
    )
    return LicenseObservation(
        id=identifier("license", {**values, "source": source.model_dump()}),
        **values,
    )


def gap_reason(occurrence):
    """Why no license is recorded: the input kind that was read states none."""
    return f"{occurrence.ecosystem}-{occurrence.evidence_kind}-input-states-no-license"


def assess(occurrences, observations):
    """Gaps for every occurrence no observation covers, in occurrence order."""
    observed = {row.occurrence_id for row in observations}
    return [
        LicenseGap(
            id=identifier("license-gap", {"occurrence_id": row.id}),
            occurrence_id=row.id,
            reason=gap_reason(row),
        )
        for row in occurrences
        if row.id not in observed
    ]
