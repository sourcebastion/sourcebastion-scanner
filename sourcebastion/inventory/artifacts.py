"""Private, exclusive artifact retention for one inactive dependency job.

These descriptor checks cover this invocation. The parent must independently
own the output mount, drain the job and admit its files; this is not persistent
custody or fencing against an administrator sharing the process identity.
"""

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat

from .contract import InventoryLimits
from .inputs import InputRefusal, Source


def _identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_nlink,
    )


@dataclass(frozen=True)
class ArtifactFact:
    name: str
    sha256: str
    bytes: int


class ArtifactStore:
    """Pin an existing empty owner-only directory; never overwrite or delete.

    Reservations include failed writes and cannot be refunded. A failed write
    leaves its available bytes as unadmitted diagnostic evidence. Every guard
    uses the same controller ledger; there is no finalization time allowance.
    """

    def __init__(self, root, *, limits, check):
        if not callable(check):
            raise TypeError("controller-ledger-required")
        self.limits = InventoryLimits.model_validate(limits)
        self.check = check
        self.root = Path(os.path.abspath(root))
        self._files = {}
        self._pending = {}
        self._names = set()
        self._reserved = 0
        self._control_reserved = False
        self._refusal = None
        self._closed = False
        self._ceilings = {
            "inventory.json": self.limits.inventory_bytes,
            "sbom.cdx.json": self.limits.sbom_bytes,
            "grype.json": self.limits.diagnostic_file_bytes,
            "grype.stderr": self.limits.diagnostic_file_bytes,
            "grype-version.json": min(65536, self.limits.diagnostic_file_bytes),
            "grype-version.stderr": min(65536, self.limits.diagnostic_file_bytes),
            "grype-status.json": min(65536, self.limits.diagnostic_file_bytes),
            "grype-status.stderr": min(65536, self.limits.diagnostic_file_bytes),
            "grype.yaml": min(4096, self.limits.diagnostic_file_bytes),
            "consumer-config.json": min(16384, self.limits.diagnostic_file_bytes),
            "recovery.json": self.limits.diagnostic_file_bytes,
            "execution.json": min(65536, self.limits.diagnostic_file_bytes),
        }
        check()
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(self.fd)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700
                or _identity(self.root.lstat()) != _identity(info)
            ):
                raise InputRefusal("unsafe-artifact-root")
            self._metadata = _identity(info)
            self._guard()
        except BaseException:
            os.close(self.fd)
            self._closed = True
            raise

    @property
    def reserved_bytes(self):
        return self._reserved

    @property
    def facts(self):
        return tuple(sorted((row[2] for row in self._files.values() if row[2] is not None), key=lambda row: row.name))

    def _directory(self):
        held = _identity(os.fstat(self.fd))
        if held != self._metadata or _identity(self.root.lstat()) != held:
            raise InputRefusal("changed-artifact-root")
        names = set()
        with os.scandir(self.fd) as entries:
            for entry in entries:
                self.check()
                if entry.name not in self._names or len(names) >= len(self._ceilings):
                    raise InputRefusal("unexpected-artifact-entry")
                names.add(entry.name)
        if names != self._names:
            raise InputRefusal("changed-artifact-entry")

    def _guard(self):
        if self._closed:
            raise InputRefusal("closed-artifact-store")
        if self._refusal is not None:
            raise InputRefusal(self._refusal)
        try:
            self.check()
            self._directory()
            rows = [(name, descriptor, expected) for name, (descriptor, expected, _fact) in self._files.items()]
            rows += [(name, row.fd, row.expected) for name, row in self._pending.items()]
            for name, descriptor, expected in rows:
                self.check()
                if (
                    _identity(os.fstat(descriptor)) != expected
                    or _identity(os.stat(name, dir_fd=self.fd, follow_symlinks=False)) != expected
                ):
                    raise InputRefusal("changed-artifact-file")
        except (OSError, InputRefusal) as exc:
            self._refusal = exc.reason if isinstance(exc, InputRefusal) else "unavailable-artifact"
            raise InputRefusal(self._refusal) from None

    def put(self, name, content):
        """Retain one complete byte artifact through the shared stream path."""
        if type(content) is not bytes:
            raise ValueError("invalid-artifact-write")
        writer = self.writer(name, maximum=len(content))
        writer.write(content)
        return writer.finish()

    def writer(self, name, *, maximum):
        """Reserve a stream's full ceiling before opening or buffering output."""
        if type(name) is not str or name not in self._ceilings or type(maximum) is not int or maximum < 0:
            raise ValueError("invalid-artifact-write")
        self._guard()
        if name in self._names:
            raise ValueError("artifact-already-attempted")
        if maximum > self._ceilings[name] or self._reserved + maximum > self.limits.diagnostic_job_bytes:
            self._refusal = "artifact-retention-budget-exceeded"
            raise InputRefusal(self._refusal)
        self._reserved += maximum
        descriptor = None
        try:
            descriptor = os.open(
                name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=self.fd
            )
            self._names.add(name)
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
                or info.st_dev != os.fstat(self.fd).st_dev
            ):
                raise InputRefusal("unsafe-artifact-file")
            current = _identity(os.fstat(self.fd))
            if current[:5] != self._metadata[:5]:
                raise InputRefusal("changed-artifact-root")
            self._metadata = current
            writer = ArtifactWriter(self, name, descriptor, maximum, _identity(info))
            self._pending[name] = writer
            descriptor = None
            self._guard()
            return writer
        except (OSError, InputRefusal) as exc:
            self._refusal = exc.reason if isinstance(exc, InputRefusal) else "artifact-write-failed"
            raise InputRefusal(self._refusal) from None
        except BaseException:
            self._refusal = "artifact-write-interrupted"
            raise
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def reserve_control(self):
        """Charge a bounded 64KiB control record before controller analysis.

        The reservation is never refunded, including on failure. It covers the
        returned record, rather than creating a success file before validation.
        A refused reservation raises to the parent; this job emits no record.
        """
        self._guard()
        if self._control_reserved:
            raise ValueError("control-record-already-reserved")
        if self.limits.diagnostic_file_bytes < 65536 or self._reserved + 65536 > self.limits.diagnostic_job_bytes:
            self._refusal = "artifact-retention-budget-exceeded"
            raise InputRefusal(self._refusal)
        self._reserved += 65536
        self._control_reserved = True

    def read(self, name):
        """Read finalized held bytes with the original bound size and digest."""
        self._guard()
        if name not in self._files or self._files[name][2] is None:
            raise ValueError("finalized-artifact-required")
        descriptor, _expected, fact = self._files[name]
        digest, chunks, offset = hashlib.sha256(), [], 0
        try:
            while offset < fact.bytes:
                self._guard()
                raw = os.pread(descriptor, min(65536, fact.bytes - offset), offset)
                if not raw:
                    raise InputRefusal("changed-artifact-content")
                chunks.append(raw)
                digest.update(raw)
                offset += len(raw)
            self._guard()
            if os.pread(descriptor, 1, offset) or digest.hexdigest() != fact.sha256:
                raise InputRefusal("changed-artifact-content")
            result = b"".join(chunks)
            self._guard()
            return result
        except (InputRefusal, OSError) as error:
            self._refusal = error.reason if isinstance(error, InputRefusal) else "unavailable-artifact"
            raise InputRefusal(self._refusal) from None

    def require_source_separation(self, source):
        """Refuse nested held roots even through symlinked path ancestors.

        This observes ancestry in the current mount namespace. The parent must
        separately admit bind-mount origins; child paths cannot prove that two
        distinct mount trees do not alias the same physical source subtree.
        """
        if not isinstance(source, Source):
            raise TypeError("controller-source-required")
        self._guard()
        source.check()
        try:
            self._refuse_ancestor(self.fd, source.fd)
            self._refuse_ancestor(source.fd, self.fd)
            source.check()
            self._guard()
        except (OSError, InputRefusal) as exc:
            self._refusal = exc.reason if isinstance(exc, InputRefusal) else "unavailable-artifact-ancestry"
            raise InputRefusal(self._refusal) from None

    def _refuse_ancestor(self, start, other):
        target = os.fstat(other)
        target = (target.st_dev, target.st_ino)
        descriptor = os.dup(start)
        try:
            for _ in range(256):
                self.check()
                current = os.fstat(descriptor)
                current = (current.st_dev, current.st_ino)
                if current == target:
                    raise InputRefusal("source-artifact-roots-overlap")
                parent = os.open("..", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                try:
                    info = os.fstat(parent)
                    at_root = (info.st_dev, info.st_ino) == current
                except BaseException:
                    os.close(parent)
                    raise
                os.close(descriptor)
                descriptor = parent
                if at_root:
                    return
            raise InputRefusal("artifact-ancestry-depth-exceeded")
        finally:
            os.close(descriptor)

    def validate(self):
        try:
            self._guard()
            if self._pending:
                raise InputRefusal("unfinished-artifact-stream")
            for descriptor, _expected, fact in self._files.values():
                if fact is not None:
                    self._verify_content(descriptor, fact)
            self._guard()
        except (OSError, InputRefusal) as exc:
            self._refusal = exc.reason if isinstance(exc, InputRefusal) else "unavailable-artifact"
            raise InputRefusal(self._refusal) from None

    def _verify_content(self, descriptor, fact):
        # Metadata can remain unchanged after a same-length rewrite on some
        # filesystems. Read held bytes again, never reopen a path as authority.
        digest, offset = hashlib.sha256(), 0
        while offset < fact.bytes:
            self.check()
            raw = os.pread(descriptor, min(65536, fact.bytes - offset), offset)
            if not raw:
                raise InputRefusal("changed-artifact-content")
            offset += len(raw)
            digest.update(raw)
        self.check()
        if os.pread(descriptor, 1, offset) or digest.hexdigest() != fact.sha256:
            raise InputRefusal("changed-artifact-content")

    def close(self):
        if not self._closed:
            self._closed = True
            descriptors = {row[0] for row in self._files.values()} | {row.fd for row in self._pending.values()}
            for descriptor in descriptors:
                os.close(descriptor)
            os.close(self.fd)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


class ArtifactWriter:
    """One store-owned bounded stream; partial bytes never become a fact.

    Only ArtifactStore creates these writers. The store retains descriptors on
    every exit and closes them at its own close; abandoning a writer never
    removes a file or releases its full reservation.
    """

    def __init__(self, store, name, descriptor, maximum, expected):
        self.store, self.name, self.fd = store, name, descriptor
        self.maximum, self.expected = maximum, expected
        self.written = 0
        self._digest = hashlib.sha256()
        self._finished = False

    def _active(self):
        if self._finished or self.store._pending.get(self.name) is not self:
            raise ValueError("artifact-stream-not-active")
        self.store._guard()

    def write(self, content):
        """Write bounded chunks, retaining the available prefix on overflow."""
        if type(content) is not bytes:
            raise ValueError("invalid-artifact-stream-bytes")
        self._active()
        try:
            view = memoryview(content)
            available = self.maximum - self.written
            overflow = len(view) > available
            view = view[:available]
            offset = 0
            while offset < len(view):
                self.store._guard()
                written = os.write(self.fd, view[offset : offset + 65536])
                if written <= 0:
                    raise InputRefusal("incomplete-artifact-write")
                self._digest.update(view[offset : offset + written])
                offset += written
                self.written += written
                current = _identity(os.fstat(self.fd))
                if current[:5] != self.expected[:5] or current[-1] != 1 or current[5] != self.written:
                    raise InputRefusal("changed-artifact-file")
                self.expected = current
                self.store._guard()
            if overflow:
                raise InputRefusal("artifact-stream-budget-exceeded")
        except (OSError, InputRefusal) as exc:
            self.store._refusal = exc.reason if isinstance(exc, InputRefusal) else "artifact-write-failed"
            raise InputRefusal(self.store._refusal) from None
        except BaseException:
            self.store._refusal = "artifact-write-interrupted"
            raise

    def finish(self):
        """Sync and rehash complete held bytes before publishing their fact."""
        self._active()
        try:
            os.fsync(self.fd)
            self.store._guard()
            fact = ArtifactFact(self.name, self._digest.hexdigest(), self.written)
            self.store._verify_content(self.fd, fact)
            self.store._guard()
            os.fsync(self.store.fd)
            self.store._guard()
            self.store._files[self.name] = (self.fd, self.expected, fact)
            del self.store._pending[self.name]
            self._finished = True
            return fact
        except (OSError, InputRefusal) as exc:
            if self.name in self.store._files:
                self.store._files[self.name] = (self.fd, self.expected, None)
            self.store._refusal = exc.reason if isinstance(exc, InputRefusal) else "artifact-write-failed"
            raise InputRefusal(self.store._refusal) from None
        except BaseException:
            if self.name in self.store._files:
                self.store._files[self.name] = (self.fd, self.expected, None)
            self.store._refusal = "artifact-write-interrupted"
            raise
