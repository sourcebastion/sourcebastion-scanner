"""Controller-bound maintained Go parser bridge; no selected-version resolver."""

from __future__ import annotations

from dataclasses import dataclass
from bisect import bisect_right
import hashlib
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from typing import Literal

from pydantic import Field, ValidationError, model_validator

from .contract import Name, Record, SHA256, package_purl
from .inputs import InputRefusal
from .provider import _decode

VERSION = "sourcebastion.go-sources/1"


@dataclass(frozen=True)
class Runtime:
    """Trusted controller artifact, never deserialized from customer config."""

    binary: Path
    sha256: str

    def __post_init__(self):
        if not isinstance(self.binary, Path) or not self.binary.is_absolute():
            raise ValueError("absolute-trusted-go-parser-required")
        if type(self.sha256) is not str or re.fullmatch(r"[a-f0-9]{64}", self.sha256) is None:
            raise ValueError("trusted-go-parser-digest-required")


class Requirement(Record):
    ordinal: int = Field(ge=0, lt=100000)
    name: Name
    minimum_version: Name
    indirect: bool
    line: int = Field(ge=1, le=100001)
    start_byte: int = Field(ge=0, le=2 * 1024 * 1024)
    end_byte: int = Field(gt=0, le=2 * 1024 * 1024)

    @model_validator(mode="after")
    def source_identity(self):
        package_purl("golang", self.name, self.minimum_version)
        if self.end_byte <= self.start_byte:
            raise ValueError("invalid-go-requirement-span")
        return self


class Observation(Record):
    schema_version: Literal["sourcebastion.go-source-observation/1"]
    parser: Literal["golang.org/x/mod/modfile@v0.41.0"]
    source_sha256: SHA256
    module: Name
    requirements: tuple[Requirement, ...] = Field(max_length=100000)
    unassessed_directives: tuple[Name, ...] = Field(max_length=32)
    selected_versions: Literal["unreported"]
    graph: Literal["unreported"]


@dataclass(frozen=True)
class Document:
    disposition: str
    reason: str
    observation: Observation | None = None
    parser: str = VERSION


def _identity(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def decode(raw, content, *, check):
    value = _decode(raw, check)
    try:
        if type(value.get("requirements")) is not list or type(value.get("unassessed_directives")) is not list:
            raise ValueError("invalid-go-source-observation")
        value["requirements"] = tuple(value["requirements"])
        value["unassessed_directives"] = tuple(value["unassessed_directives"])
        result = Observation.model_validate(value)
        if result.source_sha256 != hashlib.sha256(content).hexdigest():
            raise ValueError("unbound-go-source-observation")
        if result.unassessed_directives != tuple(sorted(set(result.unassessed_directives))):
            raise ValueError("invalid-go-source-controls")
        allowed = {"duplicate-go-requirement"} | {
            "unassessed-" + directive + "-directive"
            for directive in ("replace", "exclude", "retract", "toolchain", "tool", "godebug", "ignore")
        }
        if set(result.unassessed_directives) - allowed:
            raise ValueError("unassessed-go-source-controls")
        line_starts = [0]
        for offset, byte in enumerate(content):
            if offset % 4096 == 0:
                check()
            if byte == 10:
                line_starts.append(offset + 1)
        duplicate = len({row.name for row in result.requirements}) != len(result.requirements)
        if duplicate != ("duplicate-go-requirement" in result.unassessed_directives):
            raise ValueError("contradictory-go-duplicate-disposition")
        end = 0
        for ordinal, row in enumerate(result.requirements):
            check()
            if row.ordinal != ordinal or row.start_byte < end or row.end_byte > len(content):
                raise ValueError("invalid-go-source-locator")
            if bisect_right(line_starts, row.start_byte) != row.line:
                raise ValueError("invalid-go-source-line")
            end = row.end_byte
        package_purl("golang", result.module, None)
        return result
    except (ValueError, ValidationError):
        raise InputRefusal("invalid-go-source-observation") from None


def parse(content, *, runtime, deadline, check, max_records=100000):
    if type(content) is not bytes or not callable(check):
        raise TypeError("trusted-go-parser-inputs-required")
    if runtime is not None and not isinstance(runtime, Runtime):
        raise TypeError("trusted-go-parser-runtime-required")
    if type(deadline) not in {int, float} or not math.isfinite(deadline):
        raise ValueError("invalid-controller-deadline")
    if type(max_records) is not int or not 0 <= max_records <= 100000:
        raise ValueError("invalid-go-source-record-limit")
    if runtime is None:
        return Document("unsupported", "go-parser-runtime-unavailable")
    descriptor = None
    initial = None
    try:
        check()
        if len(content) > 2 * 1024 * 1024:
            raise InputRefusal("input-file-budget-exceeded")
        descriptor = os.open(runtime.binary, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        initial = os.fstat(descriptor)
        if not stat.S_ISREG(initial.st_mode) or initial.st_size > 64 * 1024 * 1024:
            raise InputRefusal("go-parser-runtime-refused")
        digest = hashlib.sha256()
        prefix = b""
        total = 0
        while True:
            check()
            if time.monotonic() > deadline:
                raise InputRefusal("go-source-deadline-exceeded")
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > initial.st_size:
                raise InputRefusal("changed-go-parser-runtime")
            if not prefix:
                prefix = chunk[:4]
            digest.update(chunk)
        if prefix != b"\x7fELF" or digest.hexdigest() != runtime.sha256:
            raise InputRefusal("go-parser-runtime-refused")
        if _identity(os.fstat(descriptor)) != _identity(initial):
            raise InputRefusal("changed-go-parser-runtime")
        remaining = min(150, deadline - time.monotonic())
        if remaining <= 0:
            raise InputRefusal("go-source-deadline-exceeded")
        process = subprocess.run(
            [f"/proc/self/fd/{descriptor}", "--remaining", f"{remaining:.9f}s"],
            pass_fds=(descriptor,),
            input=content,
            capture_output=True,
            timeout=remaining,
            cwd=str(Path(__file__).resolve().parent),
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
        check()
        try:
            current_path = os.lstat(runtime.binary)
        except OSError:
            raise InputRefusal("changed-go-parser-runtime") from None
        if _identity(os.fstat(descriptor)) != _identity(initial) or _identity(current_path) != _identity(initial):
            raise InputRefusal("changed-go-parser-runtime")
        if len(process.stdout) > 64 * 1024 * 1024 or len(process.stderr) > 128:
            raise InputRefusal("go-parser-output-budget-exceeded")
        if process.returncode != 0:
            reason = process.stderr.strip()
            allowed = {
                b"invalid-go-source-syntax",
                b"unsupported-go-module-identity",
                b"unsupported-go-requirement-identity",
                b"go-source-input-refused",
                b"go-source-record-budget-exceeded",
                b"go-source-output-budget-exceeded",
                b"go-source-deadline-exceeded",
            }
            raise InputRefusal(reason.decode() if reason in allowed else "go-parser-runtime-refused")
        if process.stderr:
            raise InputRefusal("go-parser-runtime-refused")
        observation = decode(process.stdout, content, check=check)
        if len(observation.requirements) > max_records:
            raise InputRefusal("go-source-record-budget-exceeded")
        if time.monotonic() > deadline:
            raise InputRefusal("go-source-deadline-exceeded")
        return Document("unsupported", "unresolved-go-module-selection-and-graph", observation)
    except InputRefusal as error:
        if error.reason in {"composition-check-budget-exceeded", "changed-go-parser-runtime"}:
            raise
        reason = error.reason
    except subprocess.TimeoutExpired:
        reason = "go-source-deadline-exceeded"
    except OSError:
        reason = "go-parser-runtime-unavailable"
    finally:
        if descriptor is not None:
            changed = False
            try:
                changed = (
                    initial is None
                    or _identity(os.fstat(descriptor)) != _identity(initial)
                    or _identity(os.lstat(runtime.binary)) != _identity(initial)
                )
            except OSError:
                changed = True
            finally:
                os.close(descriptor)
            if changed:
                raise InputRefusal("changed-go-parser-runtime")
    return Document("bounded-omission" if "budget" in reason or "deadline" in reason else "failed", reason)
