"""Cooperative bookkeeping for one controller-owned dependency pipeline.

This ledger supplies neither kernel containment nor controller custody. A host
must separately enforce the job's CPU, memory, PID and process lifetime limits.
Create it at admission, retain it across stages, and pass ``check`` to export,
provider admission and matching recovery. Never create a fresh ledger per stage.
"""

import math
import time

from .inputs import InputRefusal, Source
from .registry import DiscoveryConfig


class PipelineBudget:
    """One Source, configuration, absolute deadline and semantic allowance.

    The deadline includes admission and is clamped to Source's existing limit.
    Clamping Source also bounds parsers that use its deadline directly. Limits
    in canonical inventory remain upper bounds, not elapsed/resource receipts.
    Exhaustion or an observed source epoch failure permanently poisons this
    ledger; catching an exception cannot replenish the remaining allowance.
    """

    def __init__(self, source, *, config, deadline):
        if not isinstance(source, Source) or not isinstance(config, DiscoveryConfig):
            raise TypeError("controller-source-and-discovery-config-required")
        if type(deadline) not in (int, float) or not math.isfinite(deadline):
            raise ValueError("invalid-pipeline-deadline")
        self._source = source
        self._config_sha256 = config.sha256
        self._maximum = config.semantic_checks
        self._deadline = min(float(deadline), source.deadline)
        self._consumed = 0
        self._refusal = None
        source.deadline = self._deadline
        self.guard()

    @property
    def deadline(self):
        return self._deadline

    @property
    def consumed(self):
        return self._consumed

    @property
    def maximum(self):
        return self._maximum

    @property
    def refusal_reason(self):
        return self._refusal

    def bind(self, source, config):
        """Refuse accidental reuse with another source or discovery policy."""
        if (
            source is not self._source
            or not isinstance(config, DiscoveryConfig)
            or config.sha256 != self._config_sha256
        ):
            raise ValueError("pipeline-budget-binding-mismatch")
        self.guard()

    def guard(self):
        """Check epoch/deadline without allocating a new semantic allowance."""
        if self._refusal is not None:
            raise InputRefusal(self._refusal)
        # A caller may shorten Source's deadline, but cannot extend this job.
        self._deadline = min(self._deadline, self._source.deadline)
        self._source.deadline = self._deadline
        try:
            if time.monotonic() > self._deadline:
                raise InputRefusal("pipeline-deadline-exceeded")
            self._source.check()
        except InputRefusal as exc:
            self._refusal = exc.reason
            raise

    def step(self, count=1):
        if type(count) is not int or count < 0:
            raise ValueError("invalid-pipeline-semantic-charge")
        self.guard()
        self._consumed += count
        if self._consumed > self._maximum:
            self._refusal = "pipeline-semantic-budget-exceeded"
            raise InputRefusal(self._refusal)

    def check(self):
        """Charge one shared semantic check; compatible with stage callbacks."""
        self.step()
