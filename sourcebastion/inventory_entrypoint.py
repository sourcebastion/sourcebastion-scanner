"""Private fixed-path inventory child; its output never admits a hosted scan."""

import time

_ENTRY_STARTED = time.monotonic()  # Before heavier imports and control parsing.

from contextlib import ExitStack
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import stat
import sys
from threading import Event

CONTROL = Path("/control")
SOURCE = Path("/source")
OUTPUT = Path("/out")
GO_BINARY = Path("/usr/local/bin/sourcebastion-go-source")
MAX_CONTROL_BYTES = 65536
_REASONS = frozenset({
    "inventory-control-unsafe", "inventory-control-changed", "inventory-control-invalid",
    "inventory-entrypoint-cancelled", "inventory-entrypoint-deadline",
    "inventory-entrypoint-receipt-invalid", "inventory-entrypoint-arguments-refused",
})


class Refusal(ValueError):
    """Only fixed private control diagnostics cross the process boundary."""

    def __init__(self, code):
        self.code = code if type(code) is str and code in _REASONS else "inventory-entrypoint-refused"
        super().__init__(self.code)


def _identity(info):
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


class _Control:
    def __init__(self, check):
        self.check, self.parent, self.file = check, None, None

    def __enter__(self):
        self.check()
        try:
            self.parent = os.open(CONTROL, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            parent = os.fstat(self.parent)
            if (
                not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid not in {0, os.geteuid()}
                or stat.S_IMODE(parent.st_mode) & 0o222
            ):
                raise Refusal("inventory-control-unsafe")
            self.parent_identity = _identity(parent)
            self.file = os.open(
                "job.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=self.parent,
            )
            info = os.fstat(self.file)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != parent.st_uid
                or stat.S_IMODE(info.st_mode) & 0o222
                or info.st_nlink != 1
                or not 0 < info.st_size <= MAX_CONTROL_BYTES
            ):
                raise Refusal("inventory-control-unsafe")
            self.file_identity = _identity(info)
            self.raw = self._read()
            self.digest = hashlib.sha256(self.raw).digest()
            self.validate()
            return self
        except BaseException:
            self.close()
            raise

    def _read(self):
        chunks, offset = [], 0
        while offset < self.file_identity[6]:
            self.check()
            raw = os.pread(self.file, min(8192, self.file_identity[6] - offset), offset)
            if not raw:
                raise Refusal("inventory-control-changed")
            chunks.append(raw)
            offset += len(raw)
        return b"".join(chunks)

    def _metadata(self):
        if (
            _identity(os.fstat(self.parent)) != self.parent_identity
            or _identity(CONTROL.lstat()) != self.parent_identity
            or _identity(os.fstat(self.file)) != self.file_identity
            or _identity(os.stat("job.json", dir_fd=self.parent, follow_symlinks=False)) != self.file_identity
        ):
            raise Refusal("inventory-control-changed")

    def validate(self):
        self.check()
        self._metadata()
        if hasattr(self, "digest") and hashlib.sha256(self._read()).digest() != self.digest:
            raise Refusal("inventory-control-changed")
        self._metadata()
        self.check()

    def close(self):
        for name in ("file", "parent"):
            descriptor = getattr(self, name)
            if descriptor is not None:
                os.close(descriptor)
                setattr(self, name, None)

    def __exit__(self, *_args):
        try:
            self.validate()
        finally:
            self.close()


def _exact(value, fields):
    if type(value) is not dict or set(value) != fields:
        raise Refusal("inventory-control-invalid")
    return value


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise Refusal("inventory-control-invalid")
        value[key] = item
    return value


def _integer(value):
    if len(value.lstrip("-")) > 64:
        raise Refusal("inventory-control-invalid")
    return int(value)


def _float(value):
    number = float(value)
    if not math.isfinite(number):
        raise Refusal("inventory-control-invalid")
    return number


def _constant(_value):
    raise Refusal("inventory-control-invalid")


def _decode(raw, check):
    # The fixed control document is at most64KiB. Bound nesting before stdlib
    # tree construction; this is not a parser for customer result artifacts.
    depth, quoted, escaped = 0, False, False
    for offset, byte in enumerate(raw):
        if offset % 4096 == 0:
            check()
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 16:
                raise Refusal("inventory-control-invalid")
        elif byte in (93, 125):
            depth -= 1
    value = json.loads(
        raw.decode("utf-8"), object_pairs_hook=_pairs, parse_int=_integer,
        parse_float=_float, parse_constant=_constant,
    )
    stack = [iter((value,))]
    visited = 0
    while stack:
        try:
            item = next(stack[-1])
        except StopIteration:
            stack.pop()
            continue
        if visited % 4096 == 0:
            check()
        visited += 1
        if type(item) is str:
            item.encode("utf-8")  # Refuse escaped surrogate scalars.
        elif type(item) is dict:
            stack.append(iter(item.keys()))
            stack.append(iter(item.values()))
        elif type(item) is list:
            stack.append(iter(item))
    check()
    return _exact(value, {
        "schema_version", "deadline_monotonic", "source_sha256", "producer",
        "discovery", "environment", "runtime", "go_sha256",
    })


def _deadline(value):
    if type(value) not in (float, int) or not math.isfinite(value) or value <= 0:
        raise Refusal("inventory-control-invalid")
    return value


def _typed(value):
    from .inventory.consumer_runtime import RuntimeSpec
    from .inventory.contract import Environment, Producer
    from .inventory.go_sources import Runtime as GoRuntime
    from .inventory.registry import DiscoveryConfig, REGISTRY_SHA256

    if value["schema_version"] != "sourcebastion.inventory-control/1":
        raise Refusal("inventory-control-invalid")
    source_sha = value["source_sha256"]
    if type(source_sha) is not str or len(source_sha) != 64 or any(c not in "0123456789abcdef" for c in source_sha):
        raise Refusal("inventory-control-invalid")
    discovery = _exact(value["discovery"], {
        "mappings", "ignored", "include_depth", "include_targets", "semantic_checks",
    })
    if (
        type(discovery["mappings"]) is not list
        or any(type(row) is not list or len(row) != 2 for row in discovery["mappings"])
        or type(discovery["ignored"]) is not list
    ):
        raise Refusal("inventory-control-invalid")
    config = DiscoveryConfig(
        mappings=tuple(tuple(row) for row in discovery["mappings"]),
        ignored=tuple(discovery["ignored"]), include_depth=discovery["include_depth"],
        include_targets=discovery["include_targets"], semantic_checks=discovery["semantic_checks"],
    )
    producer = Producer.model_validate(value["producer"])
    if producer.registry_sha256 != REGISTRY_SHA256 or producer.config_sha256 != config.sha256:
        raise Refusal("inventory-control-invalid")
    environment = Environment.model_validate_json(json.dumps(value["environment"]))
    runtime = _exact(value["runtime"], {
        "binary_sha256", "binary_bytes", "advisory_files", "advisory_schema", "advisory_built", "version",
    })
    if type(runtime["advisory_files"]) is not list or any(
        type(row) is not list or len(row) != 3 for row in runtime["advisory_files"]
    ):
        raise Refusal("inventory-control-invalid")
    spec = RuntimeSpec(**{**runtime, "advisory_files": tuple(tuple(row) for row in runtime["advisory_files"])})
    go = None if value["go_sha256"] is None else GoRuntime(GO_BINARY, value["go_sha256"])
    return source_sha, config, producer, environment, spec, go


def _run(started, cancelled):
    deadline = started + 150

    def check():
        if cancelled.is_set():
            raise Refusal("inventory-entrypoint-cancelled")
        if time.monotonic() >= deadline:
            raise Refusal("inventory-entrypoint-deadline")

    check()
    with ExitStack() as held:
        control = _Control(check)
        held.callback(control.close)
        control.__enter__()
        try:
            value = _decode(control.raw, check)
            deadline = min(deadline, _deadline(value["deadline_monotonic"]))
            check()
            source_sha, config, producer, environment, runtime, go = _typed(value)
            check()
            from .inventory.artifacts import ArtifactStore
            from .inventory.budget import PipelineBudget
            from .inventory.contract import InventoryLimits
            from .inventory.dependency_job import run_dependency
            from .inventory.inputs import Source

            check()
            source = held.enter_context(Source(SOURCE))
            budget = PipelineBudget(source, config=config, deadline=deadline)
            store = held.enter_context(ArtifactStore(
                OUTPUT, limits=InventoryLimits(), check=budget.check,
            ))
            check()
            result = run_dependency(
                source, budget=budget, config=config, producer=producer,
                source_sha256=source_sha, store=store, runtime=runtime,
                environment=environment, go_runtime=go, cancelled=cancelled,
            )
            control.validate()
            if (
                type(result.receipt) is not bytes
                or not 0 < len(result.receipt) <= MAX_CONTROL_BYTES
                or type(result.finalized) is not bool
            ):
                raise Refusal("inventory-entrypoint-receipt-invalid")
            receipt, finalized = result.receipt, result.finalized
        finally:
            # Recheck control content on every body exit while Source/store
            # descriptors are still held. No late control read follows their
            # final success validation below.
            control.validate()
        if finalized:
            check()
            store.validate()
            source.validate()
            control._metadata()
            check()
    check()
    return receipt, 0 if finalized else 2


def main():
    cancelled = Event()
    prior_handlers = {}
    prior_umask = os.umask(0o077)
    try:
        if sys.argv[1:]:
            raise Refusal("inventory-entrypoint-arguments-refused")
        for signum in (signal.SIGINT, signal.SIGTERM):
            prior_handlers[signum] = signal.signal(signum, lambda *_args: cancelled.set())
        receipt, status = _run(_ENTRY_STARTED, cancelled)
    except Exception as error:
        reason = error.code if type(error) is Refusal else "inventory-entrypoint-refused"
        receipt = json.dumps({
            "schema_version": "sourcebastion.inventory-entrypoint-refusal/1",
            "authority": "child-artifact-facts-only", "kernel_admission": "not_observed",
            "reason": reason,
        }, sort_keys=True, separators=(",", ":")).encode("ascii")
        status = 3
    finally:
        for signum, handler in prior_handlers.items():
            signal.signal(signum, handler)
        os.umask(prior_umask)
    # Parent must drain/cap stdout and enforce wall/cgroup/process-tree cleanup.
    # A blocked or incomplete delivery is not a successful parent acceptance.
    view = memoryview(receipt)
    while view:
        try:
            written = os.write(sys.stdout.fileno(), view)
        except OSError:
            return 3
        if written <= 0:
            return 3
        view = view[written:]
    return status


if __name__ == "__main__":
    raise SystemExit(main())
