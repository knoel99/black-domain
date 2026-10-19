"""Decisions and verdicts.

Every layer answers a request with a :class:`Verdict`. Verdicts compose: the
control plane takes the most restrictive verdict across all consulted layers
(see :meth:`Verdict.combine`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Decision(IntEnum):
    """Ordered from least to most restrictive so ``max`` picks the strictest."""

    ALLOW = 0
    DELAY = 1
    DENY = 2
    QUARANTINE = 3

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass
class Verdict:
    decision: Decision
    delay_seconds: float = 0.0
    reason: str = ""
    obligations: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        """Whether the action may proceed (possibly after a delay)."""
        return self.decision in (Decision.ALLOW, Decision.DELAY)

    @classmethod
    def allow(cls, reason: str = "", **metadata) -> "Verdict":
        return cls(Decision.ALLOW, reason=reason, metadata=metadata)

    @classmethod
    def delay(cls, seconds: float, reason: str = "", **metadata) -> "Verdict":
        return cls(Decision.DELAY, delay_seconds=max(0.0, seconds), reason=reason, metadata=metadata)

    @classmethod
    def deny(cls, reason: str = "", **metadata) -> "Verdict":
        return cls(Decision.DENY, reason=reason, metadata=metadata)

    @classmethod
    def quarantine(cls, reason: str = "", **metadata) -> "Verdict":
        return cls(Decision.QUARANTINE, reason=reason, metadata=metadata)

    def combine(self, other: "Verdict") -> "Verdict":
        """Return the more restrictive of two verdicts.

        Delays are cumulative when both verdicts are non-terminal, so stacking
        Lightspeed throttles across dimensions adds up rather than masking.
        """
        if other.decision > self.decision:
            winner, loser = other, self
        else:
            winner, loser = self, other
        result = Verdict(
            decision=winner.decision,
            delay_seconds=winner.delay_seconds,
            reason=winner.reason,
            obligations=sorted(set(self.obligations) | set(other.obligations)),
            metadata={**loser.metadata, **winner.metadata},
        )
        if result.decision == Decision.DELAY:
            result.delay_seconds = self.delay_seconds + other.delay_seconds
        return result
