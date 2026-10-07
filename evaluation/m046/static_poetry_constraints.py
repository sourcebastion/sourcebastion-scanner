"""Bounded maintained Poetry constraint grammar, without project factories."""

import re
import importlib.metadata
from contextlib import contextmanager
from threading import RLock

from poetry.core.constraints.version import parse_constraint
from poetry.core.constraints.version import Version
from poetry.core.version.pep440.parser import PEP440Parser

from .static_inputs import InputRefusal
from .static_requirements import MAX_LOGICAL_LINE

GRAMMAR_VERSION = importlib.metadata.version("poetry-core")
GRAMMAR_LOCK = RLock()


@contextmanager
def grammar_scope():
    # This prototype owns the grammar in a single-job CLI process. Serialize
    # helper calls and clear both known global caches on *every* path. It does
    # not change installed functions or support foreign concurrent grammar use.
    with GRAMMAR_LOCK:
        parse_constraint.cache_clear()
        PEP440Parser.parse.cache_clear()
        try:
            yield
        finally:
            parse_constraint.cache_clear()
            PEP440Parser.parse.cache_clear()


def text(value):
    if GRAMMAR_VERSION != "2.1.3":
        raise InputRefusal("unsupported-poetry-grammar-runtime")
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_LOGICAL_LINE:
        raise InputRefusal("invalid-lock-version-constraint")
    if re.search(r"\d{129,}", value) or len(re.findall(r"[^\s,|]+", value)) > 128:
        raise InputRefusal("requirement-complexity-budget-exceeded")
    return value


def constraint(value):
    with grammar_scope():
        value = text(value)
        try:
            return parse_constraint.__wrapped__(value)
        except (ValueError, RecursionError):
            raise InputRefusal("invalid-lock-version-constraint") from None


def version(value):
    with grammar_scope():
        value = text(value)
        try:
            return Version.parse(value)
        except (ValueError, RecursionError):
            raise InputRefusal("invalid-lock-version") from None
