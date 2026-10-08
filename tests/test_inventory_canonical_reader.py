"""Prepared pure artifact-reader proofs; no upload/server/worker execution."""

import hashlib
import json

import pytest

from sourcebastion.inventory import canonical_reader as reader
from sourcebastion.inventory.contract import Inventory, canonical_bytes
from sourcebastion.inventory.row_projection import project_rows
from tests.test_inventory_contract import inventory, occurrence


def read(raw, **kwargs):
    return reader.read_canonical(
        raw,
        expected_sha256=kwargs.pop("expected_sha256", hashlib.sha256(raw).hexdigest()),
        check=kwargs.pop("check", lambda: None),
        **kwargs,
    )


def test_exact_canonical_roundtrip_and_typed_projection():
    raw = canonical_bytes(inventory(occurrences=(occurrence(),)))
    value = read(raw)
    assert type(value) is Inventory and canonical_bytes(value) == raw
    projected = project_rows(value, max_rows=100, max_bytes=1024**2, check=lambda: None)
    assert projected.inventory_sha256 == hashlib.sha256(raw).hexdigest()


def test_digest_mismatch_refuses_before_decoder(monkeypatch):
    monkeypatch.setattr(reader.json, "loads", lambda *a, **k: pytest.fail("decoder reached"))
    with pytest.raises(reader.CanonicalReaderError, match="^canonical_inventory_digest_mismatch$"):
        read(b"{}", expected_sha256="a" * 64)


@pytest.mark.parametrize(
    "raw",
    [
        b"{}",
        b"{",
        b"[}",
        b'{"k":NaN}',
        b'{"k":Infinity}',
        b'{"k":1,"k":2}',
        b'{"k":' + b"9" * 100 + b"}",
        b'{"k":1e9999}',
        b'"\xff"',
        b'{"secret-path":1}',
    ],
)
def test_malformed_unbound_duplicate_nonfinite_and_bigint_are_fixed_refusals(raw):
    with pytest.raises(reader.CanonicalReaderError) as failure:
        read(raw)
    assert str(failure.value) == "canonical_inventory_invalid"


def test_whitespace_key_order_and_default_omission_are_not_canonical_exports():
    raw = canonical_bytes(inventory())
    altered = [raw + b"\n", json.dumps(json.loads(raw), indent=2).encode()]
    value = json.loads(raw)
    del value["limits"]  # valid model defaults are still not the claimed exact export
    altered.append(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
    for candidate in altered:
        with pytest.raises(reader.CanonicalReaderError, match="^canonical_inventory_noncanonical$"):
            read(candidate)


@pytest.mark.parametrize(
    "limits",
    [
        dict(max_bytes=0),
        dict(max_bytes=reader.MAX_BYTES + 1),
        dict(max_nodes=True),
        dict(max_nodes=reader.MAX_NODES + 1),
        dict(max_depth=33),
        dict(max_string_bytes=reader.MAX_STRING_BYTES + 1),
    ],
)
def test_structural_limits_cannot_widen_or_coerce(limits):
    with pytest.raises(reader.CanonicalReaderError, match="^canonical_inventory_limits_invalid$"):
        read(b"{}", **limits)


@pytest.mark.parametrize("digest", ["A" * 64, "x", True, None])
def test_digest_is_an_exact_lowercase_claim(digest):
    with pytest.raises(reader.CanonicalReaderError, match="^canonical_inventory_binding_invalid$"):
        read(b"{}", expected_sha256=digest)


def test_byte_limit_is_checked_before_hash_or_parse():
    with pytest.raises(reader.CanonicalReaderError, match="^canonical_inventory_byte_limit$"):
        read(b"{}", max_bytes=1)


@pytest.mark.parametrize(
    "raw,limits",
    [
        (b"[[[[]]]]", dict(max_depth=1)),
        (b"[1,2,3]", dict(max_nodes=3)),
        (b'{"key":"' + b"x" * 100 + b'"}', dict(max_string_bytes=1)),
    ],
)
def test_adversarial_shape_refuses_before_decoder(raw, limits, monkeypatch):
    monkeypatch.setattr(reader.json, "loads", lambda *a, **k: pytest.fail("decoder reached"))
    with pytest.raises(reader.CanonicalReaderError, match="^canonical_inventory_(structure|string)_limit$"):
        read(raw, **limits)


def test_valid_escaped_strings_and_keys_do_not_manufacture_tokens():
    raw = canonical_bytes(inventory(occurrences=(occurrence(declared_range='x\\"{:[1,2]'),)))
    assert canonical_bytes(read(raw)) == raw


@pytest.mark.parametrize("failure", [RuntimeError("trusted"), ValueError("trusted")])
def test_cancellation_inside_decode_retains_original_exception(failure, monkeypatch):
    raw = canonical_bytes(inventory())
    decode_active = False
    original = reader.json.loads

    def loads(*args, **kwargs):
        nonlocal decode_active
        decode_active = True
        return original(*args, **kwargs)

    monkeypatch.setattr(reader.json, "loads", loads)

    def check():
        if decode_active:
            raise failure

    with pytest.raises(type(failure)) as caught:
        read(raw, check=check)
    assert caught.value is failure


def test_reader_has_no_execution_or_accepted_run_receipt():
    value = read(canonical_bytes(inventory()))
    assert not hasattr(value, "account_id") and not hasattr(value, "run_id")
    assert not hasattr(value, "accepted") and not hasattr(value, "matching_receipt")
