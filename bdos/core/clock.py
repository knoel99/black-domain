"""Clock abstraction.

Every time-dependent decision in BDOS takes a :class:`Clock`. Production code
uses :class:`SystemClock`; tests use :class:`ManualClock` so that delays,
token-bucket refills, and token expiry are deterministic and instant.
"""

from __future__ import annotations

import time
from typing import Protocol, runtime_checkable


@runtime_checkable
class Clock(Protocol):
    """Time source used across BDOS.

    ``monotonic`` drives rate limiting and delays (never goes backwards).
    ``wall`` drives capability-token validity windows (real calendar time).
    ``sleep`` is how the Lightspeed layer actually spends imposed delay.
    """

    def monotonic(self) -> float: ...

    def wall(self) -> float: ...

    def sleep(self, seconds: float) -> None: ...


class SystemClock:
    """Real wall/monotonic clock backed by the OS."""

    def monotonic(self) -> float:
        return time.monotonic()

    def wall(self) -> float:
        return time.time()

    def sleep(self, seconds: float) -> None:
        if seconds and seconds > 0:
            time.sleep(seconds)


class ManualClock:
    """Deterministic clock for tests and simulation.

    ``sleep`` advances the clock instead of blocking, and records the total
    time "spent" so tests can assert on imposed delay without wall-clock waits.
    """

    def __init__(self, start_monotonic: float = 0.0, start_wall: float = 1_700_000_000.0) -> None:
        self._mono = float(start_monotonic)
        self._wall = float(start_wall)
        self.slept_total = 0.0

    def monotonic(self) -> float:
        return self._mono

    def wall(self) -> float:
        return self._wall

    def sleep(self, seconds: float) -> None:
        if seconds and seconds > 0:
            self._mono += seconds
            self._wall += seconds
            self.slept_total += seconds

    def advance(self, seconds: float) -> None:
        """Move time forward without counting it as imposed delay."""
        self._mono += seconds
        self._wall += seconds
