"""Enforcement front-end for the Lightspeed layer.

The throttle *decides*; the gateway *acts* -- it actually spends the imposed
delay via the clock and records an event so the Sentinel can watch delay
pressure build. ``bdos-exec`` (see controlplane) is a thin wrapper that runs a
real command behind this gateway.
"""

from __future__ import annotations

from typing import Optional

from bdos.core.clock import Clock, SystemClock
from bdos.core.decision import Decision, Verdict
from bdos.core.events import Event, EventLog, Severity
from bdos.core.identity import Principal
from bdos.lightspeed.throttle import LightspeedThrottle


class LightspeedGateway:
    def __init__(
        self,
        throttle: LightspeedThrottle,
        clock: Optional[Clock] = None,
        log: Optional[EventLog] = None,
    ) -> None:
        self.throttle = throttle
        self.clock = clock or SystemClock()
        self.log = log

    def guard(self, principal: Principal, action_class: str, at: Optional[float] = None) -> Verdict:
        """Evaluate, spend any imposed delay, log, and return the verdict."""
        when = at if at is not None else self.clock.monotonic()
        verdict = self.throttle.evaluate(principal, action_class, when)

        if verdict.decision == Decision.DELAY and verdict.delay_seconds > 0:
            self.clock.sleep(verdict.delay_seconds)

        if self.log is not None:
            severity = Severity.INFO
            if verdict.metadata.get("capped"):
                severity = Severity.WARNING
            self.log.append(
                Event(
                    ts=self.clock.wall(),
                    kind="lightspeed.guard",
                    severity=severity,
                    principal_id=principal.id,
                    action_class=action_class,
                    message=verdict.reason or "allowed",
                    data={
                        "decision": verdict.decision.label,
                        "delay_seconds": round(verdict.delay_seconds, 4),
                        **verdict.metadata,
                    },
                )
            )
        return verdict
