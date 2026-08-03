"""The asymmetric-delay engine.

:class:`LightspeedThrottle` turns a principal's recent cadence and per-class
quota state into a :class:`Verdict`. It is pure logic -- no sleeping, no I/O --
so it is fully deterministic under a :class:`~bdos.core.clock.ManualClock` and
easy to test and simulate.

Two mechanisms combine. A *progressive* delay derived from cadence
(:func:`~bdos.lightspeed.cadence.burst_score`) taxes fast, metronomic bursts. A
per-``(principal, class)`` *token bucket* supplies backpressure: consuming past
empty returns the time until the balance recovers. When that backpressure
exceeds ``max_delay`` for a class listed in ``deny_on_saturation`` the action is
*refused outright* rather than merely slowed, so sustained abuse of a privileged
class is bounded to the refill rate -- not to one burst per ``max_delay``.
"""

from __future__ import annotations

from collections import OrderedDict, deque

from bdos.core.config import LightspeedConfig
from bdos.core.decision import Verdict
from bdos.core.identity import Principal
from bdos.lightspeed.cadence import burst_score


class TokenBucket:
    """Token bucket that returns *how long to wait* on exhaustion.

    Consuming always succeeds; if it drives the balance negative, the returned
    wait is the time until the balance recovers to zero. The debt is floored at
    ``-capacity`` so a burst cannot create days of carry-over for the next
    legitimate request, while still guaranteeing that a saturated privileged
    class produces a wait large enough to trip the caller's saturation DENY.
    """

    def __init__(self, capacity: float, refill_per_sec: float, now: float) -> None:
        self.capacity = float(capacity)
        self.refill = float(refill_per_sec)
        self.tokens = float(capacity)
        self.ts = float(now)
        # Deepest debt allowed: recovery from the floor takes capacity/refill.
        self._floor = -self.capacity

    def _refill_to(self, now: float) -> None:
        if now > self.ts:
            self.tokens = min(self.capacity, self.tokens + (now - self.ts) * self.refill)
            self.ts = now

    def consume(self, now: float, amount: float = 1.0) -> float:
        """Consume ``amount`` tokens; return required wait in seconds (>= 0)."""
        self._refill_to(now)
        self.tokens = max(self._floor, self.tokens - amount)
        if self.tokens >= 0:
            return 0.0
        if self.refill <= 0:
            return float("inf")
        return -self.tokens / self.refill

    @property
    def at_capacity(self) -> bool:
        return self.tokens >= self.capacity


class LightspeedThrottle:
    def __init__(self, cfg: LightspeedConfig | None = None) -> None:
        self.cfg = cfg or LightspeedConfig()
        self._arrivals: dict[str, deque[float]] = {}
        self._buckets: dict[str, dict[str, TokenBucket]] = {}
        self._suspicion: dict[str, float] = {}
        # LRU order of principals so per-principal state stays bounded.
        self._lru: "OrderedDict[str, None]" = OrderedDict()

    # -- Sentinel hooks -------------------------------------------------
    def set_suspicion(self, principal_id: str, factor: float) -> None:
        """Multiply this principal's imposed delay (Sentinel escalation)."""
        self._suspicion[principal_id] = max(1.0, float(factor))
        self._touch(principal_id)

    def clear_suspicion(self, principal_id: str) -> None:
        self._suspicion.pop(principal_id, None)

    # -- state bounding -------------------------------------------------
    def _touch(self, principal_id: str) -> None:
        """Mark a principal most-recently-seen and evict the coldest if over cap."""
        self._lru.pop(principal_id, None)
        self._lru[principal_id] = None
        while len(self._lru) > max(1, self.cfg.max_principals):
            old, _ = self._lru.popitem(last=False)
            self._arrivals.pop(old, None)
            self._buckets.pop(old, None)
            self._suspicion.pop(old, None)

    # -- internals ------------------------------------------------------
    def _record(self, principal_id: str, at: float) -> None:
        dq = self._arrivals.get(principal_id)
        if dq is None:
            dq = deque()
            self._arrivals[principal_id] = dq
        dq.append(at)
        horizon = at - self.cfg.window_seconds
        while dq and dq[0] < horizon:
            dq.popleft()
        if not dq:  # never keep an empty deque around
            self._arrivals.pop(principal_id, None)

    def _bucket(self, principal_id: str, action_class: str, at: float) -> TokenBucket:
        by_class = self._buckets.setdefault(principal_id, {})
        bucket = by_class.get(action_class)
        if bucket is None:
            cap = self.cfg.quota_capacity.get(action_class, 60.0)
            refill = self.cfg.quota_refill_per_sec.get(action_class, 1.0)
            bucket = TokenBucket(cap, refill, at)
            by_class[action_class] = bucket
        return bucket

    # -- decision -------------------------------------------------------
    def evaluate(self, principal: Principal, action_class: str, at: float) -> Verdict:
        self._touch(principal.id)
        self._record(principal.id, at)
        arrivals = self._arrivals.get(principal.id, ())
        score = burst_score(arrivals, at, self.cfg)
        multiplier = self.cfg.multiplier(action_class)
        # Held to stricter rules if declared agentic OR *behaving* like a script,
        # so claiming kind=human cannot halve the tax for a machine cadence.
        effective_agentic = principal.is_agentic or score >= 1.0
        agent_factor = 2.0 if effective_agentic else 1.0

        progressive = self.cfg.base_delay + self.cfg.burst_penalty * multiplier * score * agent_factor
        backpressure = self._bucket(principal.id, action_class, at).consume(at)
        suspicion = self._suspicion.get(principal.id, 1.0)

        meta = {
            "burst_score": round(score, 4),
            "progressive": round(progressive, 4),
            "backpressure": round(backpressure, 4) if backpressure != float("inf") else "inf",
            "suspicion": suspicion,
            "effective_agentic": effective_agentic,
        }

        # Quota saturation on a privileged class is a hard refusal, not a slow
        # yes: it bounds throughput to the refill rate instead of one burst per
        # max_delay.
        if action_class in self.cfg.deny_on_saturation and backpressure > self.cfg.max_delay:
            meta["saturated"] = True
            return Verdict.deny(
                reason=(
                    f"lightspeed quota saturated for {action_class}: "
                    f"required wait {backpressure:.1f}s exceeds max {self.cfg.max_delay:.1f}s"
                ),
                **meta,
            )

        raw = max(progressive, backpressure) * suspicion
        delay = min(self.cfg.max_delay, raw)
        meta["capped"] = raw > self.cfg.max_delay
        if delay <= 0:
            return Verdict.allow(reason="within human cadence", **meta)
        reason = f"lightspeed throttle: {action_class} delayed {delay:.2f}s (burst={score:.2f})"
        return Verdict.delay(delay, reason=reason, **meta)
