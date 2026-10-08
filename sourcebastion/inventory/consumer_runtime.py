"""Private held-file Grype/advisory binding, before parent kernel admission.

Expected digests come only from trusted runtime preparation. Filesystem checks
cannot establish read-only mounts, independent custody or a cgroup envelope.
The parent must supply those facts before admitting a dependency job.
"""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from .inputs import InputRefusal

BINARY = Path("/usr/local/bin/grype")
ADVISORIES = Path("/advisories")
MAX_BYTES = 4 * 1024**3


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


def _digest(value):
    return type(value) is str and re.fullmatch(r"[a-f0-9]{64}", value) is not None


@dataclass(frozen=True)
class RuntimeSpec:
    """Controller-only immutable preparation facts; no customer decoder."""

    binary_sha256: str
    binary_bytes: int
    advisory_files: tuple[tuple[str, str, int], ...]
    advisory_schema: str
    advisory_built: str
    version: str = "0.119.0"

    def __post_init__(self):
        if (
            not _digest(self.binary_sha256)
            or type(self.binary_bytes) is not int
            or not 0 < self.binary_bytes <= 128 * 1024**2
        ):
            raise ValueError("invalid-prepared-consumer-binary")
        if (
            self.version != "0.119.0"
            or type(self.advisory_files) is not tuple
            or not 1 <= len(self.advisory_files) <= 32
        ):
            raise ValueError("invalid-prepared-consumer")
        names, total = set(), 0
        for row in self.advisory_files:
            if type(row) is not tuple or len(row) != 3:
                raise ValueError("invalid-prepared-advisory")
            name, digest, size = row
            if (
                type(name) is not str
                or not name
                or len(name) > 1024
                or any(part in {"", ".", ".."} for part in name.split("/"))
                or len(name.split("/")) > 9
                or "\\" in name
                or "\x00" in name
                or name in names
                or not _digest(digest)
                or type(size) is not int
                or size < 0
                or (name == "snapshot.json" and size > 2 * 1024**2)
            ):
                raise ValueError("invalid-prepared-advisory")
            names.add(name)
            total += size
        if total > MAX_BYTES or not {"snapshot.json", "6/vulnerability.db"} <= names:
            raise ValueError("invalid-prepared-advisory")
        if any(
            type(value) is not str or not 0 < len(value) <= 128 for value in (self.advisory_schema, self.advisory_built)
        ):
            raise ValueError("invalid-prepared-advisory-status")

    @property
    def advisory_sha256(self):
        value = {name: {"sha256": digest, "bytes": size} for name, digest, size in self.advisory_files}
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class RuntimeBinding:
    """Hold the admitted native executable and bounded advisory tree open.

    Full content hashes are checked both at admission and finalization using
    the job's existing ledger. File and directory identities are retained
    across execution; no reopening or refreshed identity repairs uncertainty.
    """

    def __init__(self, spec, *, check):
        if type(spec) is not RuntimeSpec or not callable(check):
            raise TypeError("trusted-runtime-spec-and-ledger-required")
        self.spec, self.check = spec, check
        self.directories, self.files = {}, {}
        self.binary = None
        self.refusal = None
        self.closed = False
        try:
            check()
            self.binary, _metadata = self._open(BINARY, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            self.binary_identity = self._file_info(self.binary, spec.binary_bytes)
            if not self.binary_identity[2] & 0o111:
                raise InputRefusal("consumer-runtime-not-executable")
            self.directories[""] = self._open(ADVISORIES, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            expected = {name: (digest, size) for name, digest, size in spec.advisory_files}
            pending = [("", 0)]
            while pending:
                parent, depth = pending.pop()
                descriptor, _metadata = self.directories[parent]
                self._safe_directory(descriptor)
                seen = set()
                with os.scandir(descriptor) as entries:
                    for entry in entries:
                        check()
                        if entry.name in seen or len(seen) >= 64:
                            raise InputRefusal("consumer-advisory-tree-refused")
                        seen.add(entry.name)
                        name = parent + "/" + entry.name if parent else entry.name
                        info = entry.stat(follow_symlinks=False)
                        if stat.S_ISDIR(info.st_mode):
                            if (
                                depth >= 8
                                or len(self.directories) >= 32
                                or not any(key.startswith(name + "/") for key in expected)
                            ):
                                raise InputRefusal("consumer-advisory-tree-refused")
                            self.directories[name] = self._open(
                                entry.name,
                                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=descriptor,
                            )
                            child = self.directories[name][0]
                            if _identity(info) != self.directories[name][1]:
                                raise InputRefusal("changed-consumer-advisory")
                            pending.append((name, depth + 1))
                        else:
                            if name not in expected or len(self.files) >= 32:
                                raise InputRefusal("consumer-advisory-tree-refused")
                            self.files[name] = self._open(
                                entry.name,
                                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                dir_fd=descriptor,
                            )
                            child = self.files[name][0]
                            held = self._file_info(child, expected[name][1])
                            if held != _identity(info):
                                raise InputRefusal("changed-consumer-advisory")
            if self.files.keys() != expected.keys():
                raise InputRefusal("consumer-advisory-tree-refused")
            self.validate()
        except BaseException:
            self.close()
            raise

    def _safe_directory(self, descriptor):
        self.check()
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.geteuid()} or stat.S_IMODE(info.st_mode) & 0o022:
            raise InputRefusal("unsafe-consumer-advisory-directory")

    @staticmethod
    def _open(path, flags, **kwargs):
        descriptor = os.open(path, flags, **kwargs)
        try:
            return descriptor, _identity(os.fstat(descriptor))
        except BaseException:
            os.close(descriptor)
            raise

    def read_snapshot(self):
        """Read the already admitted, at-most2MiB snapshot from its held FD."""
        try:
            return self._snapshot_bytes()
        except (InputRefusal, OSError) as error:
            self.refusal = error.reason if isinstance(error, InputRefusal) else "unavailable-consumer-runtime"
            raise InputRefusal(self.refusal) from None

    def _snapshot_bytes(self):
        self._metadata()
        descriptor = self.files["snapshot.json"][0]
        _name, digest, size = next(row for row in self.spec.advisory_files if row[0] == "snapshot.json")
        chunks, offset = [], 0
        while offset < size:
            self.check()
            raw = os.pread(descriptor, min(65536, size - offset), offset)
            if not raw:
                raise InputRefusal("changed-consumer-advisory")
            offset += len(raw)
            chunks.append(raw)
        raw = b"".join(chunks)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise InputRefusal("changed-consumer-advisory")
        self._metadata()
        self.check()
        return raw

    def _file_info(self, descriptor, size):
        self.check()
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size != size
            or info.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise InputRefusal("unsafe-consumer-runtime-file")
        return _identity(info)

    def _hash(self, descriptor, size, expected):
        digest, offset = hashlib.sha256(), 0
        while offset < size:
            self.check()
            raw = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
            if not raw:
                raise InputRefusal("changed-consumer-runtime-content")
            offset += len(raw)
            digest.update(raw)
        self.check()
        if os.pread(descriptor, 1, offset) or digest.hexdigest() != expected:
            raise InputRefusal("changed-consumer-runtime-content")

    def validate(self):
        if self.closed or self.refusal is not None:
            raise InputRefusal(self.refusal or "closed-consumer-runtime")
        try:
            self.check()
            self._metadata()
            self._hash(self.binary, self.spec.binary_bytes, self.spec.binary_sha256)
            if os.pread(self.binary, 4, 0) != b"\x7fELF":
                raise InputRefusal("non-native-consumer-runtime")
            for name, digest, size in self.spec.advisory_files:
                self._hash(self.files[name][0], size, digest)
            self._metadata()
            self.check()
        except (InputRefusal, OSError) as error:
            self.refusal = error.reason if isinstance(error, InputRefusal) else "unavailable-consumer-runtime"
            raise InputRefusal(self.refusal) from None

    def _metadata(self):
        if self.closed or self.refusal is not None:
            raise InputRefusal(self.refusal or "closed-consumer-runtime")
        self.check()
        if (
            _identity(os.fstat(self.binary)) != self.binary_identity
            or _identity(BINARY.lstat()) != self.binary_identity
        ):
            raise InputRefusal("changed-consumer-runtime")
        for name, (descriptor, expected) in self.directories.items():
            self.check()
            if name:
                parent, _, leaf = name.rpartition("/")
                visible = os.stat(leaf, dir_fd=self.directories[parent][0], follow_symlinks=False)
            else:
                visible = ADVISORIES.lstat()
            if _identity(os.fstat(descriptor)) != expected or _identity(visible) != expected:
                raise InputRefusal("changed-consumer-advisory")
            prefix = name + "/" if name else ""
            wanted = {key[len(prefix) :].split("/")[0] for key in self.files if key.startswith(prefix)}
            seen = set()
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    self.check()
                    if entry.name not in wanted or len(seen) >= 64:
                        raise InputRefusal("changed-consumer-advisory")
                    seen.add(entry.name)
            if seen != wanted:
                raise InputRefusal("changed-consumer-advisory")
        for name, (descriptor, expected) in self.files.items():
            self.check()
            parent, _, leaf = name.rpartition("/")
            visible = os.stat(leaf, dir_fd=self.directories[parent][0], follow_symlinks=False)
            if _identity(os.fstat(descriptor)) != expected or _identity(visible) != expected:
                raise InputRefusal("changed-consumer-advisory")

    def close(self):
        if not self.closed:
            self.closed = True
            descriptors = {row[0] for row in self.directories.values()} | {row[0] for row in self.files.values()}
            if self.binary is not None:
                descriptors.add(self.binary)
            for descriptor in descriptors:
                os.close(descriptor)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()
