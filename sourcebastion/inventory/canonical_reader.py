"""Inactive exact canonical artifact reader; no accepted-run/upload authority."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re

from .contract import Inventory, _preflight_structure, canonical_bytes

MAX_BYTES = 64 * 1024**2
MAX_NODES = 2_000_000
MAX_DEPTH = 32
MAX_STRING_BYTES = 2 * 1024**2
_SHA = re.compile(r"[0-9a-f]{64}")


class CanonicalReaderError(ValueError):
    """Fixed diagnostics omit payload, package names and validation detail."""


def _preflight(raw, *, max_nodes, max_depth, max_string_bytes, check):
    # This is a structural admission pass, not a second JSON/schema parser.
    # The standard decoder supplies syntax/Unicode/duplicate-key validation.
    stack = []  # (opening byte, object currently expecting a key)
    quoted = escaped = atom = key = False
    nodes = start = 0

    def node():
        nonlocal nodes
        nodes += 1
        if nodes > max_nodes or len(stack) > max_depth:
            raise CanonicalReaderError("canonical_inventory_structure_limit")

    for offset, byte in enumerate(raw):
        if offset % 4096 == 0:
            check()
        if quoted:
            # One decoded byte needs at most six JSON escape bytes; raw UTF8
            # bytes are also covered. Exact decoded bounds follow before models.
            if offset - start > 6 * max_string_bytes:
                raise CanonicalReaderError("canonical_inventory_string_limit")
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
                if not key:
                    node()
            continue
        if byte in b' \t\r\n,:[]{}"':
            atom = False
        if byte == 34:
            quoted, escaped, start = True, False, offset
            key = bool(stack and stack[-1][0] == 123 and stack[-1][1])
        elif byte in (123, 91):
            node()
            stack.append([byte, byte == 123])
        elif byte in (125, 93):
            if not stack or stack[-1][0] != (123 if byte == 125 else 91):
                raise CanonicalReaderError("canonical_inventory_invalid")
            stack.pop()
        elif byte == 58:
            if stack and stack[-1][0] == 123:
                stack[-1][1] = False
        elif byte == 44:
            if stack and stack[-1][0] == 123:
                stack[-1][1] = True
        elif byte not in b" \t\r\n" and not atom:
            node()
            atom = True
    check()


def read_canonical(
    raw,
    *,
    expected_sha256,
    check,
    max_bytes=MAX_BYTES,
    max_nodes=MAX_NODES,
    max_depth=MAX_DEPTH,
    max_string_bytes=MAX_STRING_BYTES,
):
    """Return an exact typed Inventory from its exact canonical export bytes.

    expected_sha256 is supplied by the caller's independently admitted artifact
    binding. Equality checks that claim; it cannot authenticate the claim or
    accepted-run association. Limits can only tighten the frozen canonical caps.
    A parent supervisor must confine decoder/model/serializer resource use and
    terminate it on the shared deadline; callbacks cannot interrupt those calls.
    No HTTP streaming, artifact storage, matching or execution is enabled here.
    """
    if not callable(check):
        raise TypeError("shared-canonical-reader-ledger-required")
    ledger_check = check
    ledger_failure = None

    def check():
        nonlocal ledger_failure
        try:
            ledger_check()
        except Exception as failure:
            ledger_failure = failure
            raise

    for supplied, ceiling in (
        (max_bytes, MAX_BYTES),
        (max_nodes, MAX_NODES),
        (max_depth, MAX_DEPTH),
        (max_string_bytes, MAX_STRING_BYTES),
    ):
        if type(supplied) is not int or not 1 <= supplied <= ceiling:
            raise CanonicalReaderError("canonical_inventory_limits_invalid")
    if type(expected_sha256) is not str or len(expected_sha256) != 64 or _SHA.fullmatch(expected_sha256) is None:
        raise CanonicalReaderError("canonical_inventory_binding_invalid")
    check()
    if type(raw) is not bytes or not raw or len(raw) > max_bytes:
        raise CanonicalReaderError("canonical_inventory_byte_limit")
    digest = hashlib.sha256()
    for offset in range(0, len(raw), 65536):
        check()
        digest.update(raw[offset : offset + 65536])
    if not hmac.compare_digest(digest.hexdigest(), expected_sha256):
        raise CanonicalReaderError("canonical_inventory_digest_mismatch")
    _preflight(raw, max_nodes=max_nodes, max_depth=max_depth, max_string_bytes=max_string_bytes, check=check)

    def pairs(items):
        check()
        result = {}
        for key, child in items:
            if key in result:
                raise CanonicalReaderError("canonical_inventory_invalid")
            result[key] = child
        return result

    def integer(value):
        check()
        # Canonical integers come from bounded limit fields; this bound also
        # covers every signed64 value without admitting pathological bigints.
        if len(value) > 32:
            raise CanonicalReaderError("canonical_inventory_invalid")
        return int(value)

    def floating(value):
        check()
        if len(value) > 64:
            raise CanonicalReaderError("canonical_inventory_invalid")
        result = float(value)
        if not math.isfinite(result):
            raise CanonicalReaderError("canonical_inventory_invalid")
        return result

    def constant(_value):
        raise CanonicalReaderError("canonical_inventory_invalid")

    check()
    try:
        decoded = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_int=integer,
            parse_float=floating,
            parse_constant=constant,
        )
        _preflight_structure(decoded, max_nodes, max_depth, max_string_bytes)
        # Strict JSON-mode tuple semantics belong to the existing contract.
        # Drop the independent duplicate/syntax precheck tree before that parse.
        del decoded
    except CanonicalReaderError:
        raise
    except (ValueError, TypeError, RecursionError):
        if ledger_failure is not None:
            raise ledger_failure
        raise CanonicalReaderError("canonical_inventory_invalid") from None
    check()
    try:
        inventory = Inventory.model_validate_json(raw)
        rendered = canonical_bytes(inventory, max_bytes=max_bytes, max_nodes=max_nodes)
    except (ValueError, TypeError, RecursionError):
        raise CanonicalReaderError("canonical_inventory_invalid") from None
    check()
    if rendered != raw:
        raise CanonicalReaderError("canonical_inventory_noncanonical")
    return inventory
