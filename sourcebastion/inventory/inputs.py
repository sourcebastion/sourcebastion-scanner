"""Descriptor-bound, bounded local inputs for dependency inventory.

The outer controller supplies immutable input and process/resource isolation. The
controller supplies the source root; customer configuration cannot change it.
Files and directories are opened relative to that pinned root without following
symlinks. No source contents are written, imported, executed or fetched.
"""

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
import time


class InputRefusal(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class Limits:
    entries: int = 100000
    depth: int = 64
    file_bytes: int = 2 * 1024 * 1024
    total_bytes: int = 256 * 1024 * 1024
    wall_seconds: float = 150

    def __post_init__(self):
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > ceiling
            for value, ceiling in zip(
                (self.entries, self.depth, self.file_bytes, self.total_bytes),
                (100000, 64, 2 * 1024 * 1024, 256 * 1024 * 1024),
            )
        ):
            raise ValueError("invalid-input-limits")
        if (
            not isinstance(self.wall_seconds, (float, int))
            or isinstance(self.wall_seconds, bool)
            or not 0 < self.wall_seconds <= 150
        ):
            raise ValueError("invalid-input-deadline")


@dataclass(frozen=True)
class Entry:
    path: str
    kind: str
    size: int


@dataclass(frozen=True)
class Input:
    path: str
    content: bytes
    sha256: str
    metadata: tuple

    def text(self):
        try:
            return self.content.decode("utf-8-sig")
        except UnicodeDecodeError:
            raise InputRefusal("invalid-input-encoding") from None


def metadata(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def relative_path(value):
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise InputRefusal("unsafe-input-path")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise InputRefusal("invalid-path-encoding") from None
    path = PurePosixPath(value)
    if len(encoded) > 4096 or path.is_absolute() or ".." in path.parts or not path.parts:
        raise InputRefusal("unsafe-input-path")
    return path.as_posix()


class Source:
    def __init__(self, root, limits=None):
        self.root = Path(os.path.abspath(root))
        self.limits = limits or Limits()
        self.deadline = time.monotonic() + self.limits.wall_seconds
        self.cache = {}
        self.directories = {}
        self.parsed_bytes = 0
        self.traversal_entries = 0
        self.closed = False
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            expected = self.root.lstat()
            self.fd = os.open(self.root, flags)
        except OSError:
            raise InputRefusal("unavailable-source-root") from None
        try:
            opened = os.fstat(self.fd)
            if not stat.S_ISDIR(opened.st_mode) or metadata(opened) != metadata(expected):
                raise InputRefusal("changed-source-root")
            self.root_metadata = metadata(opened)
            self.device = opened.st_dev
        except BaseException:
            os.close(self.fd)
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def close(self):
        if not self.closed:
            os.close(self.fd)
            self.closed = True

    def check(self):
        if self.closed:
            raise InputRefusal("closed-source")
        if time.monotonic() > self.deadline:
            raise InputRefusal("input-deadline-exceeded")
        try:
            if metadata(os.fstat(self.fd)) != self.root_metadata or metadata(self.root.lstat()) != self.root_metadata:
                raise InputRefusal("changed-source-root")
        except OSError:
            raise InputRefusal("changed-source-root") from None

    def parent(self, path):
        self.check()
        parts = PurePosixPath(relative_path(path)).parts
        if len(parts) - 1 > self.limits.depth:
            raise InputRefusal("input-depth-budget-exceeded")
        descriptor = os.dup(self.fd)
        try:
            for part in parts[:-1]:
                self.check()
                expected = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                if not stat.S_ISDIR(expected.st_mode):
                    raise InputRefusal("unsafe-input-ancestor")
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                try:
                    opened = os.fstat(child)
                    if opened.st_dev != self.device or metadata(opened) != metadata(expected):
                        raise InputRefusal("changed-input-ancestor")
                except BaseException:
                    os.close(child)
                    raise
                os.close(descriptor)
                descriptor = child
            return descriptor, parts[-1]
        except OSError:
            os.close(descriptor)
            raise InputRefusal("unavailable-input-path") from None
        except BaseException:
            os.close(descriptor)
            raise

    def visible_metadata(self, path):
        descriptor, name = self.parent(path)
        try:
            return metadata(os.stat(name, dir_fd=descriptor, follow_symlinks=False))
        except OSError:
            raise InputRefusal("changed-input-path") from None
        finally:
            os.close(descriptor)

    def read(self, path, *, _refresh=False):
        path = relative_path(path)
        self.check()
        cached = self.cache.get(path)
        if cached is not None and not _refresh:
            cached = self.cache[path]
            if self.visible_metadata(path) != cached.metadata:
                raise InputRefusal("changed-input-path")
            return cached
        if cached is None and len(self.cache) >= self.limits.entries:
            raise InputRefusal("input-count-budget-exceeded")
        parent, name = self.parent(path)
        descriptor = None
        try:
            expected = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISREG(expected.st_mode):
                raise InputRefusal("non-regular-input")
            if expected.st_dev != self.device:
                raise InputRefusal("cross-device-input")
            if expected.st_size > self.limits.file_bytes:
                raise InputRefusal("input-file-budget-exceeded")
            retained_bytes = self.parsed_bytes - (len(cached.content) if cached else 0)
            if expected.st_size + retained_bytes > self.limits.total_bytes:
                raise InputRefusal("input-total-budget-exceeded")
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or metadata(opened) != metadata(expected):
                raise InputRefusal("changed-input-path")
            chunks, remaining = [], opened.st_size
            while remaining:
                self.check()
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    raise InputRefusal("changed-input-bytes")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1) or metadata(os.fstat(descriptor)) != metadata(opened):
                raise InputRefusal("changed-input-bytes")
            self.check()
            if self.visible_metadata(path) != metadata(opened):
                raise InputRefusal("changed-input-path")
            content = b"".join(chunks)
            record = Input(path, content, hashlib.sha256(content).hexdigest(), metadata(opened))
            if not _refresh:
                self.parsed_bytes = retained_bytes + len(content)
                self.cache[path] = record
            return record
        except OSError:
            raise InputRefusal("unavailable-input-file") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent)

    def validate(self):
        """Revalidate paths and bytes, including same-timestamp rewrites.

        This adds at most one bounded reread per retained file. It does not
        establish persistent custody; outer isolation supplies immutable input.
        """
        self.check()
        self.validate_directories()
        for path, record in sorted(self.cache.items()):
            self.check()
            if self.visible_metadata(path) != record.metadata:
                raise InputRefusal("changed-input-path")
            refreshed = self.read(path, _refresh=True)
            if refreshed.metadata != record.metadata or refreshed.sha256 != record.sha256:
                raise InputRefusal("changed-input-path")
        self.validate_directories()
        self.check()

    def validate_directories(self):
        for path, expected in sorted(self.directories.items()):
            self.check()
            if self.visible_metadata(path) != expected:
                raise InputRefusal("changed-input-directory")

    def discover(self, *, ignored=()):
        """Deterministic traversal; refuse an overflowing directory before yield.

        Buffered names are bounded by the remaining global entry ceiling. No
        links or foreign devices are traversed, and every entry consumes budget.
        The caller must preserve refusals as partial discovery, never success.
        """
        self.traversal_entries = 0
        ignored = frozenset(relative_path(path) for path in ignored)

        def visit(descriptor, prefix, depth):
            self.check()
            before = metadata(os.fstat(descriptor))
            entries = []
            with os.scandir(descriptor) as iterator:
                for item in iterator:
                    self.check()
                    if self.traversal_entries >= self.limits.entries:
                        raise InputRefusal("input-traversal-budget-exceeded")
                    self.traversal_entries += 1
                    path = relative_path(prefix + item.name)
                    info = os.stat(item.name, dir_fd=descriptor, follow_symlinks=False)
                    entries.append((path, item.name, info))
            if metadata(os.fstat(descriptor)) != before:
                raise InputRefusal("changed-input-directory")
            for path, name, expected in sorted(entries, key=lambda entry: entry[0]):
                self.check()
                if metadata(os.stat(name, dir_fd=descriptor, follow_symlinks=False)) != metadata(expected):
                    raise InputRefusal("changed-input-directory")
                if path in ignored or name in {".git", ".hg", ".svn"}:
                    yield Entry(path, "ignored", expected.st_size)
                elif expected.st_dev != self.device:
                    yield Entry(path, "cross-device", expected.st_size)
                elif stat.S_ISLNK(expected.st_mode):
                    yield Entry(path, "symlink", expected.st_size)
                elif stat.S_ISDIR(expected.st_mode):
                    if depth >= self.limits.depth:
                        yield Entry(path, "depth-omission", expected.st_size)
                        continue
                    yield Entry(path, "directory", expected.st_size)
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                    try:
                        if metadata(os.fstat(child)) != metadata(expected):
                            raise InputRefusal("changed-input-directory")
                        self.directories[path] = metadata(expected)
                        yield from visit(child, path + "/", depth + 1)
                    finally:
                        os.close(child)
                else:
                    yield Entry(path, "file" if stat.S_ISREG(expected.st_mode) else "special", expected.st_size)
            if metadata(os.fstat(descriptor)) != before:
                raise InputRefusal("changed-input-directory")

        try:
            yield from visit(self.fd, "", 0)
            self.check()
        except OSError:
            raise InputRefusal("unavailable-discovery-entry") from None
