"""Shared spine for BDOS: clock, identity, events, decisions, crypto, config.

Every layer builds on these primitives. Nothing in :mod:`bdos.core` imports
from a specific layer, so the dependency graph stays acyclic.
"""

from bdos.core.clock import Clock, SystemClock, ManualClock
from bdos.core.decision import Decision, Verdict
from bdos.core.errors import (
    BDOSError,
    AttestationError,
    ReplayError,
    ExpiredError,
    RevokedError,
    PolicyViolation,
    SealedEnclaveError,
    ConfigError,
)
from bdos.core.events import Event, EventLog, LogRecord, Severity, GENESIS_HASH
from bdos.core.identity import Principal, PrincipalKind

__all__ = [
    "Clock",
    "SystemClock",
    "ManualClock",
    "Decision",
    "Verdict",
    "BDOSError",
    "AttestationError",
    "ReplayError",
    "ExpiredError",
    "RevokedError",
    "PolicyViolation",
    "SealedEnclaveError",
    "ConfigError",
    "Event",
    "EventLog",
    "LogRecord",
    "Severity",
    "GENESIS_HASH",
    "Principal",
    "PrincipalKind",
]
