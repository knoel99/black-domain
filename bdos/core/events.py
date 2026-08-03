"""Tamper-evident event log.

Every security-relevant thing that happens in BDOS is an :class:`Event`. The
:class:`EventLog` hash-chains records (each record commits to the hash of the
previous one), so an attacker who gains write access cannot quietly excise or
edit history without breaking the chain -- :meth:`EventLog.verify` detects it.

The log is also the nervous system: subscribers (the Sentinel) are notified
synchronously on every append, which is how BDOS reacts at machine speed.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, Iterable, Optional

GENESIS_HASH = "0" * 64
_SEP = b"\x1f"  # unit separator, cannot appear in JSON text


class Severity(IntEnum):
    DEBUG = 10
    INFO = 20
    NOTICE = 25
    WARNING = 30
    ALERT = 40
    CRITICAL = 50


@dataclass
class Event:
    ts: float
    kind: str
    severity: Severity = Severity.INFO
    principal_id: str = ""
    action_class: str = ""
    message: str = ""
    data: dict = field(default_factory=dict)

    def canonical(self) -> bytes:
        """Deterministic byte encoding used for hashing and persistence."""
        payload = {
            "ts": round(self.ts, 6),
            "kind": self.kind,
            "severity": int(self.severity),
            "principal_id": self.principal_id,
            "action_class": self.action_class,
            "message": self.message,
            "data": self.data,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class LogRecord:
    seq: int
    prev_hash: str
    event: Event
    hash: str


def _chain(prev_hash: str, event: Event) -> str:
    digest = hashlib.sha256()
    digest.update(prev_hash.encode())
    digest.update(_SEP)
    digest.update(event.canonical())
    return digest.hexdigest()


class EventLog:
    """Append-only, hash-chained, subscribable event log."""

    def __init__(self, path: Optional[str] = None) -> None:
        self._records: list[LogRecord] = []
        self._last_hash = GENESIS_HASH
        self.path = path
        self._subscribers: list[Callable[[Event], None]] = []
        if path:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    def subscribe(self, fn: Callable[[Event], None]) -> None:
        """Register a callback invoked synchronously on every append."""
        self._subscribers.append(fn)

    def append(self, event: Event) -> LogRecord:
        h = _chain(self._last_hash, event)
        rec = LogRecord(seq=len(self._records), prev_hash=self._last_hash, event=event, hash=h)
        self._records.append(rec)
        self._last_hash = h
        if self.path:
            self._persist(rec)
        for fn in self._subscribers:
            fn(event)
        return rec

    def verify(self) -> bool:
        """Recompute the chain; return False if any record was altered/removed."""
        prev = GENESIS_HASH
        for rec in self._records:
            if rec.prev_hash != prev or _chain(prev, rec.event) != rec.hash:
                return False
            prev = rec.hash
        return True

    def _persist(self, rec: LogRecord) -> None:
        line = json.dumps(
            {
                "seq": rec.seq,
                "prev_hash": rec.prev_hash,
                "hash": rec.hash,
                "event": json.loads(rec.event.canonical()),
            },
            separators=(",", ":"),
        )
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    @property
    def records(self) -> list[LogRecord]:
        return list(self._records)

    @property
    def head(self) -> str:
        return self._last_hash

    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self) -> Iterable[LogRecord]:
        return iter(self._records)
