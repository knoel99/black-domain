"""Principal model.

A :class:`Principal` is whoever (or whatever) is attempting an action: a human
operator, an autonomous agent, or a service account. The ``kind`` matters a
great deal to BDOS -- the Lightspeed layer treats a declared agent far more
suspiciously than a human, and cadence analysis can *reclassify* a principal
that claims to be human but behaves like a machine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class PrincipalKind(str, Enum):
    HUMAN = "human"
    AGENT = "agent"
    SERVICE = "service"
    UNKNOWN = "unknown"


@dataclass
class Principal:
    """An actor in the system.

    ``id`` is the stable identifier used as the key for rate limiting,
    quarantine, and attestation scoping.
    """

    id: str
    kind: PrincipalKind = PrincipalKind.UNKNOWN
    attributes: dict = field(default_factory=dict)

    @classmethod
    def human(cls, id: str, **attributes) -> "Principal":
        return cls(id=id, kind=PrincipalKind.HUMAN, attributes=dict(attributes))

    @classmethod
    def agent(cls, id: str, **attributes) -> "Principal":
        return cls(id=id, kind=PrincipalKind.AGENT, attributes=dict(attributes))

    @classmethod
    def service(cls, id: str, **attributes) -> "Principal":
        return cls(id=id, kind=PrincipalKind.SERVICE, attributes=dict(attributes))

    @property
    def is_agentic(self) -> bool:
        """True if this principal should be held to machine-suspicion rules."""
        return self.kind in (PrincipalKind.AGENT, PrincipalKind.SERVICE)
