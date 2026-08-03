"""The control plane -- one decision point that wires every layer together.

Each BDOS layer answers a narrow question -- is this principal contained, is the
enclave sealed, is the notice valid, is the cadence machine-like -- and emits its
findings onto a single hash-chained :class:`~bdos.core.events.EventLog`. The
:class:`ControlPlane` is the spine that holds them in one place and exposes a
single :meth:`ControlPlane.authorize` call that consults them **in order, most
catastrophic first, short-circuiting on the first ``DENY``/``QUARANTINE``** and
combining the survivors with :meth:`~bdos.core.decision.Verdict.combine`.

The ordering is deliberate (see ``docs/ARCHITECTURE.md``): a quarantined
principal is refused before any work is done; a sealed-enclave violation is a
hard structural deny no notice can buy past; attestation is checked before
throttling so an unauthorized privileged action is denied outright rather than
merely slowed; and the Lightspeed gateway runs *last* because it is the only step
that spends wall-clock time. Because every step logs to the same chained log and
the :class:`~bdos.sentinel.Sentinel` subscribes to it, being throttled or
rejected feeds the very score that may quarantine the principal on the next
call -- a loop that tightens under sustained attack.
"""

from __future__ import annotations

import os
from typing import Optional

from bdos.core import crypto
from bdos.core.clock import Clock, SystemClock
from bdos.core.config import BDOSConfig, default as default_config
from bdos.core.decision import Verdict
from bdos.core.events import Event, EventLog, Severity
from bdos.core.identity import Principal
from bdos.lightspeed import LightspeedGateway, LightspeedThrottle
from bdos.safetynotice import SafetyNotice, SafetyNoticeIssuer, SafetyNoticeVerifier
from bdos.darkforest import Deception, MovingTarget
from bdos.blackdomain import Enclave, EnclaveRouter, compile_nftables
from bdos.sentinel import Sentinel


class ControlPlane:
    """Wires every BDOS layer to one event log and one decision point.

    Construction builds the whole spine from ``config``: a tamper-evident
    :class:`~bdos.core.events.EventLog`; the Lightspeed
    :class:`~bdos.lightspeed.LightspeedThrottle` and
    :class:`~bdos.lightspeed.LightspeedGateway`; a Safety Notice
    :class:`~bdos.safetynotice.SafetyNoticeIssuer` whose public key is
    registered with its :class:`~bdos.safetynotice.SafetyNoticeVerifier`; the
    Dark Forest :class:`~bdos.darkforest.MovingTarget` and
    :class:`~bdos.darkforest.Deception`; the Black Domain
    :class:`~bdos.blackdomain.Enclave` set (from config) and an
    :class:`~bdos.blackdomain.EnclaveRouter`; and a
    :class:`~bdos.sentinel.Sentinel` attached to the log so it reacts to every
    append at machine speed.

    Passing a shared ``clock`` (a :class:`~bdos.core.clock.ManualClock`) makes
    the whole plane deterministic and instant, so :meth:`authorize` sequences
    can be tested and simulated without wall-clock waits.
    """

    def __init__(
        self,
        config: Optional[BDOSConfig] = None,
        clock: Optional[Clock] = None,
        log: Optional[EventLog] = None,
    ) -> None:
        self.config = (config or default_config()).validate()
        self.cfg = self.config  # short alias used throughout
        self.clock = clock or SystemClock()
        self.log = log or EventLog()

        # -- Lightspeed: decide the delay, then spend it on the clock. -----
        self.throttle = LightspeedThrottle(self.config.lightspeed)
        self.gateway = LightspeedGateway(self.throttle, clock=self.clock, log=self.log)

        # -- Safety Notice: mint with a fresh key, trust its own public half.
        signing_key, _ = crypto.generate_keypair()
        self.issuer = SafetyNoticeIssuer(signing_key, clock=self.clock)
        self.verifier = SafetyNoticeVerifier(clock=self.clock, cfg=self.config.safetynotice)
        self.verifier.add_key(self.issuer.public_key, self.issuer.kid)

        # -- Dark Forest: rotate rendezvous, salt the ground with bait. ----
        secret = self.config.darkforest.mtd_secret or crypto.b64e(os.urandom(32))
        self.mtd = MovingTarget(secret, self.config.darkforest, clock=self.clock)
        self.deception = Deception(log=self.log, clock=self.clock)

        # -- Black Domain: build enclaves from config, keep a router. ------
        self.enclaves = [Enclave(spec) for spec in self.config.blackdomain.enclaves]
        self.router = EnclaveRouter(self.enclaves)

        # -- Sentinel: watch the log, hold the sword. ---------------------
        self.sentinel = Sentinel(
            self.config.sentinel,
            clock=self.clock,
            throttle=self.throttle,
            enclaves=self.enclaves,
            log=self.log,
        )
        self.sentinel.attach(self.log)

    # -- enclave lookup -------------------------------------------------
    def enclave_for(self, member: str) -> Optional[Enclave]:
        """Return the enclave that fences ``member`` in, or ``None``."""
        return self.router.enclave_for(member)

    # -- the single decision point --------------------------------------
    def authorize(
        self,
        principal: Principal,
        action_class: str,
        resource: str,
        notice: Optional[SafetyNotice] = None,
    ) -> Verdict:
        """Decide whether ``principal`` may perform ``action_class`` on ``resource``.

        Consults the layers in order -- Sentinel quarantine, Black Domain
        segmentation, Safety Notice attestation, Lightspeed throttle -- and
        short-circuits on the first ``DENY``/``QUARANTINE``. Verdicts that pass
        are folded together with :meth:`~bdos.core.decision.Verdict.combine`, so
        the returned verdict is the strictest of the survivors and any imposed
        delays sum. The Lightspeed step, evaluated last, is the one that actually
        spends the delay on the clock.
        """
        pid = principal.id

        # (1) Sentinel quarantine -- cheapest and most decisive: a contained
        #     principal is refused before any further work is done.
        if self.sentinel.is_quarantined(pid):
            return Verdict.quarantine(
                reason=f"principal {pid!r} is quarantined by the Sentinel",
                principal_id=pid,
                action_class=action_class,
            )

        verdict = Verdict.allow(reason="authorized")

        # (2) Black Domain -- a structural deny no valid notice can buy past.
        enclave = self.enclave_for(pid)
        if enclave is not None:
            action = enclave.decide_action(action_class)
            if not action.allowed:
                self._emit_denied("blackdomain.action_denied", principal, action_class, resource, action)
                return action
            # Exfil carries a destination: it must also clear egress policy.
            if action_class == "exfil":
                egress = enclave.decide_egress(resource)
                if not egress.allowed:
                    self._emit_denied("blackdomain.egress_denied", principal, action_class, resource, egress)
                    return egress
                action = action.combine(egress)
            verdict = verdict.combine(action)

        # (3) Safety Notice -- required for the configured privileged classes.
        if action_class in self.config.safetynotice.require_for:
            if notice is None:
                self._emit_missing_notice(principal, action_class, resource)
                return Verdict.deny(
                    reason=f"{action_class!r} on {resource!r} requires a safety notice",
                    principal_id=pid,
                    action_class=action_class,
                )
            attested = self.verifier.guard(
                notice, pid, action_class, resource, log=self.log, now=self.clock.wall()
            )
            if not attested.allowed:
                return attested  # guard already logged safetynotice.rejected
            verdict = verdict.combine(attested)

        # (4) Lightspeed gateway -- evaluate cadence + quota and spend delay.
        throttled = self.gateway.guard(principal, action_class, at=self.clock.monotonic())
        return verdict.combine(throttled)

    # -- event emission -------------------------------------------------
    def _emit_denied(
        self,
        kind: str,
        principal: Principal,
        action_class: str,
        resource: str,
        verdict: Verdict,
    ) -> Event:
        """Record a Black Domain denial (ALERT) so the Sentinel can weigh it."""
        return self.log.append(
            Event(
                ts=self.clock.wall(),
                kind=kind,
                severity=Severity.ALERT,
                principal_id=principal.id,
                action_class=action_class,
                message=verdict.reason,
                data={"resource": resource, **verdict.metadata},
            )
        )

    def _emit_missing_notice(
        self, principal: Principal, action_class: str, resource: str
    ) -> Event:
        """Record a missing-attestation rejection in the shape the verifier uses.

        A privileged action arriving without any notice is scored exactly like a
        forged or expired one: it appends ``safetynotice.rejected`` at
        :data:`~bdos.core.events.Severity.ALERT`, feeding the Sentinel's score.
        """
        return self.log.append(
            Event(
                ts=self.clock.wall(),
                kind="safetynotice.rejected",
                severity=Severity.ALERT,
                principal_id=principal.id,
                action_class=action_class,
                message=f"no safety notice presented for {action_class!r} on {resource!r}",
                data={"error": "MissingNotice", "resource": resource},
            )
        )

    # -- projections / helpers -----------------------------------------
    def nftables(self) -> str:
        """Render the current enclave set to an ``nftables`` ruleset string."""
        return compile_nftables(self.enclaves)

    def rendezvous(self) -> list[dict]:
        """Live moving-target rendezvous for every configured service."""
        return [self.mtd.current(service) for service in self.config.darkforest.services]

    def status(self) -> dict:
        """A snapshot of the plane's live state for status/telemetry callers."""
        return {
            "events": len(self.log),
            "log_intact": self.log.verify(),
            "quarantined": sorted(self.sentinel.quarantined),
            "enclaves": {enc.id: enc.sealed for enc in self.enclaves},
            "issuer_kid": self.issuer.kid,
            "mtd_epoch": self.mtd.epoch(),
        }


def main(argv: Optional[list[str]] = None) -> int:
    """Entry point for the ``bdosd`` service.

    Builds a control plane from the configured policy and prints a one-shot
    status banner. It is intentionally non-blocking by default so it stays
    importable and safe under tests; pass ``--serve`` to run the long-lived
    supervision loop the systemd unit expects.
    """
    import argparse
    import time

    parser = argparse.ArgumentParser(prog="bdosd", description="BDOS control-plane daemon")
    parser.add_argument("--config", help="path to a bdos.toml policy (default: built-in defaults)")
    parser.add_argument("--serve", action="store_true", help="run the supervision loop instead of exiting")
    args = parser.parse_args(argv)

    from bdos.controlplane.cli import _load_config  # local import: avoid a cycle at import time

    plane = ControlPlane(_load_config(args.config))
    snap = plane.status()
    print("bdosd: BDOS control plane up")
    print(f"  policy      : {args.config or 'built-in defaults'}")
    print(f"  issuer kid  : {snap['issuer_kid']}")
    print(f"  enclaves    : {', '.join(snap['enclaves']) or '(none)'}")
    print(f"  log intact  : {snap['log_intact']}")

    if not args.serve:
        return 0

    print("bdosd: entering supervision loop (Ctrl-C to stop)")
    try:  # pragma: no cover - the loop is exercised only by the running service
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("bdosd: shutting down")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
