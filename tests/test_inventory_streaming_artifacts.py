"""Charge stream ceilings before buffering; retain partial unadmitted bytes."""

import hashlib
import os

import pytest

from sourcebastion.inventory.artifacts import ArtifactStore
from sourcebastion.inventory.contract import InventoryLimits
from sourcebastion.inventory.inputs import InputRefusal


def store(root, **limits):
    root.chmod(0o700)
    return ArtifactStore(root, limits=InventoryLimits(**limits), check=lambda: None)


def test_interleaved_streams_bind_exact_bytes_and_full_reservations(tmp_path):
    with store(tmp_path) as output:
        out = output.writer("grype.json", maximum=100)
        err = output.writer("grype.stderr", maximum=20)
        assert output.reserved_bytes == 120 and not output.facts
        out.write(b"one")
        err.write(b"warning")
        out.write(b"two")
        first, second = out.finish(), err.finish()
        assert first.sha256 == hashlib.sha256(b"onetwo").hexdigest() and first.bytes == 6
        assert second.bytes == 7 and output.reserved_bytes == 120
        output.validate()


def test_overflow_retains_only_bounded_prefix_and_admits_no_partial_file(tmp_path):
    with store(tmp_path) as output:
        stream = output.writer("grype.json", maximum=5)
        stream.write(b"123")
        with pytest.raises(InputRefusal, match="artifact-stream-budget-exceeded"):
            stream.write(b"456789")
        assert (tmp_path / "grype.json").read_bytes() == b"12345"
        assert output.reserved_bytes == 5 and not output.facts
        with pytest.raises(InputRefusal, match="artifact-stream-budget-exceeded"):
            stream.finish()


def test_unfinished_stream_cannot_be_validated_or_resumed_after_refusal(tmp_path):
    with store(tmp_path) as output:
        stream = output.writer("grype.json", maximum=10)
        stream.write(b"partial")
        with pytest.raises(InputRefusal, match="unfinished-artifact-stream"):
            output.validate()
        with pytest.raises(InputRefusal, match="unfinished-artifact-stream"):
            stream.finish()
        assert output.reserved_bytes == 10 and not output.facts


def test_streams_cannot_reserve_beyond_shared_retention(tmp_path):
    with store(tmp_path, diagnostic_job_bytes=10) as output:
        output.writer("grype.json", maximum=8)
        with pytest.raises(InputRefusal, match="artifact-retention-budget-exceeded"):
            output.writer("grype.stderr", maximum=3)
        assert output.reserved_bytes == 8 and not (tmp_path / "grype.stderr").exists()


@pytest.mark.parametrize("maximum", [True, -1, 1.5, "3"])
def test_stream_ceiling_is_strict(tmp_path, maximum):
    with store(tmp_path) as output:
        with pytest.raises(ValueError, match="invalid-artifact-write"):
            output.writer("grype.json", maximum=maximum)
        assert output.reserved_bytes == 0


def test_stream_chunks_are_bytes_not_element_counted_memoryviews(tmp_path):
    import array

    with store(tmp_path) as output:
        stream = output.writer("grype.json", maximum=1)
        with pytest.raises(ValueError, match="invalid-artifact-stream-bytes"):
            stream.write(memoryview(array.array("I", [1])))
        assert stream.written == 0
        stream.write(b"1")
        assert stream.finish().bytes == 1


def test_completed_stream_is_single_use(tmp_path):
    with store(tmp_path) as output:
        stream = output.writer("grype.json", maximum=0)
        assert stream.finish().bytes == 0
        for operation in (lambda: stream.write(b""), stream.finish):
            with pytest.raises(ValueError, match="artifact-stream-not-active"):
                operation()
        output.validate()


def test_mutated_pending_stream_refuses_finish_without_deleting_evidence(tmp_path):
    with store(tmp_path) as output:
        stream = output.writer("grype.json", maximum=20)
        stream.write(b"original")
        (tmp_path / "grype.json").write_bytes(b"replaced")
        with pytest.raises(InputRefusal, match="changed-artifact"):
            stream.finish()
        assert not output.facts and (tmp_path / "grype.json").read_bytes() == b"replaced"


def test_closing_pending_streams_closes_all_descriptors_without_cleanup(tmp_path):
    with store(tmp_path) as output:
        first = output.writer("grype.json", maximum=10)
        second = output.writer("grype.stderr", maximum=10)
        first.write(b"partial")
        second.write(b"error")
        descriptors = (first.fd, second.fd)
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    assert (tmp_path / "grype.json").read_bytes() == b"partial"
    assert (tmp_path / "grype.stderr").read_bytes() == b"error"
