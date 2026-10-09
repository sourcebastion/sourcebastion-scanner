"""Equivalent network-denied inputs produce equivalent inventories and findings.

S04 acceptance asks for this directly, and it is the property M036 reuse rests
on: if one source can compose two different inventories, a baseline built under
either cannot safely be reused against the other.

"Equivalent" here means the same source bytes in a different environment -- a
different root, a different creation order, no network. It deliberately does
not mean "different bytes that declare the same packages": identity is bound to
exact source bytes, so a reformatted file is a different source. The last test
pins that distinction, because it is the one a reader is most likely to assume
the other way round.

Network denial is enforced rather than assumed: `sockets_denied` replaces the
socket entry points and asserts the replacement bites, so a run on a machine
with working network cannot pass by accident.
"""

import json
import socket
import time

import pytest

from sourcebastion.inventory.compose_requirements import compose_requirements
from sourcebastion.inventory.contract import Producer, canonical_bytes
from sourcebastion.inventory.cyclonedx import export
from sourcebastion.inventory.inputs import Source
from sourcebastion.inventory.matching import recover
from sourcebastion.inventory.registry import DiscoveryConfig, REGISTRY_SHA256
from tests.test_inventory_matching import consumer, report

SHA = "a" * 64
CONTENT = "pip==26.0.1\nrequests==2.31.0\n"
#: Same declarations, different bytes: CRLF endings and the name casing pip
#: itself treats as equal.
REFORMATTED = "Pip==26.0.1\r\nrequests==2.31.0\r\n"


@pytest.fixture()
def sockets_denied(monkeypatch):
    def refuse(*_args, **_kwargs):
        raise AssertionError("network-denied")

    for name in ("socket", "create_connection", "getaddrinfo"):
        monkeypatch.setattr(socket, name, refuse)

    with pytest.raises(AssertionError, match="network-denied"):
        socket.getaddrinfo("example.invalid", 443)


def compose(root, content=CONTENT, *, extra=()):
    for name in extra:
        (root / name).write_text("# unrelated\n")
    (root / "requirements.txt").write_text(content)
    config = DiscoveryConfig()
    producer = Producer(
        name="test-controller",
        version="1",
        code_sha256=SHA,
        registry_sha256=REGISTRY_SHA256,
        config_sha256=config.sha256,
    )
    with Source(root) as source:
        return compose_requirements(
            source, source_sha256=SHA, producer=producer, config=config
        )


def test_the_same_source_at_two_roots_composes_one_inventory(
    tmp_path_factory, sockets_denied
):
    """Path independence: the inventory describes the source, not its location."""
    first = compose(tmp_path_factory.mktemp("first"))
    second = compose(tmp_path_factory.mktemp("second"))

    assert canonical_bytes(first) == canonical_bytes(second)
    assert first.stages.inventory == second.stages.inventory == "complete"


def test_unrelated_neighbouring_files_change_coverage_and_not_the_packages(
    tmp_path_factory, sockets_denied
):
    """Surrounding files are not evidence about dependencies, but they are
    evidence about what was examined.

    The occurrences are identical; the extra files appear in coverage as
    examined-and-ignored inputs. That asymmetry is the milestone's thesis in
    one assertion: what the scan looked at is reported separately from what it
    found, so "no packages here" never has to stand in for "nothing was read".
    """
    plain = compose(tmp_path_factory.mktemp("plain"))
    crowded = compose(
        tmp_path_factory.mktemp("crowded"), extra=("README.md", "aaa.txt", "zzz.txt")
    )

    assert [row.model_dump() for row in plain.occurrences] == [
        row.model_dump() for row in crowded.occurrences
    ]
    assert len(crowded.coverage.inputs) > len(plain.coverage.inputs)
    assert {row.disposition for row in crowded.coverage.inputs} >= {"ignored"}


def test_equivalent_inputs_export_one_artifact(tmp_path_factory, sockets_denied):
    """Export is downstream of the inventory, so equivalence must survive it."""
    deadline = time.monotonic() + 10
    first = export(
        compose(tmp_path_factory.mktemp("a")), deadline=deadline, check=lambda: None
    )
    second = export(
        compose(tmp_path_factory.mktemp("b")), deadline=deadline, check=lambda: None
    )

    assert first.sha256 == second.sha256
    assert first.content == second.content


def test_equivalent_inputs_recover_one_finding_set(tmp_path_factory, sockets_denied):
    """The findings half of the acceptance item, not just the inventory half."""
    deadline = time.monotonic() + 10
    recoveries = []
    for name in ("one", "two"):
        value = compose(tmp_path_factory.mktemp(name))
        artifact = export(value, deadline=deadline, check=lambda: None)
        recoveries.append(
            recover(
                value,
                artifact,
                json.dumps(report(value.occurrences), indent=2).encode(),
                consumer=consumer(),
                deadline=deadline,
                check=lambda: None,
            )
        )

    first, second = recoveries
    assert first.matching == second.matching == "succeeded"
    assert first.identity_sha256 == second.identity_sha256
    assert first.inventory_sha256 == second.inventory_sha256
    assert first.sbom_sha256 == second.sbom_sha256
    assert [binding.occurrence_id for binding in first.matches] == [
        binding.occurrence_id for binding in second.matches
    ]


def test_a_reformatted_source_keeps_its_packages_and_loses_its_identity(
    tmp_path_factory, sockets_denied
):
    """Reformatting is not equivalence, and that is the point.

    The declarations survive untouched -- same names, versions and declared
    ranges -- while every content-bound identity moves. M036 reuse keys on the
    identity, so a reformatted file correctly invalidates a baseline instead of
    quietly reusing one built from different bytes.
    """
    plain = compose(tmp_path_factory.mktemp("plain"))
    reformatted = compose(tmp_path_factory.mktemp("reformatted"), REFORMATTED)

    assert [
        (row.name, row.selected_version, row.declared_range) for row in plain.occurrences
    ] == [
        (row.name, row.selected_version, row.declared_range)
        for row in reformatted.occurrences
    ]
    assert canonical_bytes(plain) != canonical_bytes(reformatted)
    assert [row.id for row in plain.occurrences] != [
        row.id for row in reformatted.occurrences
    ]
