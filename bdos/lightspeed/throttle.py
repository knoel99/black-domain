"""The asymmetric-delay engine.

:class:`LightspeedThrottle` turns a principal's recent cadence and per-class
quota state into a :class:`Verdict`. It is pure logic -- no sleeping, no I/O --
so it is fully deterministic under a :class:`~bdos.core.clock.ManualClock` and
easy to test and simulate.
"""

from __future__ import annotations

from collections import defaultdict, deque

from bdos.core.config import LightspeedConfig
from bdos.core.decision import Verdict
from bdos.core.identity import Principal
from bdos.lightspeed.cadence import burst_score


class TokenBucket:
    """Classic token bucket that returns *how long to wait* on exhaustion.

    Consuming always succeeds; if it drives the balance negative, the returned
    wait is the time until the balance recovers to zero. Sustained abuse thus
    produces monotonically growing backpressure -- a queue the attacker cannot
    outrun, while a low-rate human never touches it.
    """

    def __init__(self, capacity: float, refill_per_sec: float, now: float) -> None:
        self.capacity = float(capacity)
        self.refill = float(refill_per_sec)
        self.tokens = float(capacity)
        self.ts = float(now)

    def _refill_to(self, now: float) -> None:
        if now > self.ts:
            self.tokens = min(self.capacity, self.tokens + (now - self.ts) * self.refill)
            self.ts = now

    def consume(self, now: float, amount: float = 1.0) -> float:
        """Consume ``amount`` tokens; return required wait in seconds (>= 0)."""
        self._refill_to(now)
        self.tokens -= amount
        if self.tokens >= 0:
            return 0.0
        if self.refill <= 0:
            return float("inf")
        return -self.tokens / self.refill


class LightspeedThrottle:
    def __init__(self, cfg: LightspeedConfig | None = None) -> None:
        self.cfg = cfg or LightspeedConfig()
        self._arrivals: dict[str, deque[float]] = defaultdict(deque)
        self._buckets: dict[tuple[str, str], TokenBucket] = {}
        self._suspicion: dict[str, float] = {}

    # -- Sentinel hooks -------------------------------------------------
    def set_suspicion(self, principal_id: str, factor: float) -> None:
        """Multiply this principal's imposed delay (Sentinel escalation)."""
        self._suspicion[principal_id] = max(1.0, float(factor))

    def clear_suspicion(self, principal_id: str) -> None:
        self._suspicion.pop(principal_id, None)

    # -- internals ------------------------------------------------------
    def _record(self, principal_id: str, at: float) -> None:
        dq = self._arrivals[principal_id]
        dq.append(at)
        horizon = at - self.cfg.window_seconds
        while dq and dq[0] < horizon:
            dq.popleft()

    def _bucket(self, principal_id: str, action_class: str, at: float) -> TokenBucket:
        key = (principal_id, action_class)
        bucket = self._buckets.get(key)
        if bucket is None:
            cap = self.cfg.quota_capacity.get(action_class, 60.0)
            refill = self.cfg.quota_refill_per_sec.get(action_class, 1.0)
            bucket = TokenBucket(cap, refill, at)
            self._buckets[key] = bucket
        return bucket

    # -- decision -------------------------------------------------------
    def evaluate(self, principal: Principal, action_class: str, at: float) -> Verdict:
        self._record(principal.id, at)
        score = burst_score(self._arrivals[principal.id], at, self.cfg)
        multiplier = self.cfg.multiplier(action_class)
        # Declared agents are held to stricter rules than humans.
        agent_factor = 2.0 if principal.is_agentic else 1.0

        progressive = self.cfg.base_delay + self.cfg.burst_penalty * multiplier * score * agent_factor
        backpressure = self._bucket(principal.id, action_class, at).consume(at)
        suspicion = self._suspicion.get(principal.id, 1.0)

        raw = max(progressive, backpressure) * suspicion
        delay = min(self.cfg.max_delay, raw)

        meta = {
            "burst_score": round(score, 4),
            "progressive": round(progressive, 4),
            "backpressure": round(backpressure, 4) if backpressure != float("inf") else "inf",
            "suspicion": suspicion,
            "capped": raw > self.cfg.max_delay,
        }
        if delay <= 0:
            return Verdict.allow(reason="within human cadence", **meta)
        reason = f"lightspeed throttle: {action_class} delayed {delay:.2f}s (burst={score:.2f})"
        return Verdict.delay(delay, reason=reason, **meta)
