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

import dataclasses
import json
import os
import socketserver
import threading
from typing import Iterable, Optional

from bdos.core import crypto
from bdos.core.clock import Clock, SystemClock
from bdos.core.config import BDOSConfig, default as default_config
from bdos.core.decision import Verdict
from bdos.core.events import Event, EventLog, Severity
from bdos.core.identity import Principal, PrincipalKind
from bdos.lightspeed import LightspeedGateway, LightspeedThrottle
from bdos.safetynotice import SafetyNotice, SafetyNoticeIssuer, SafetyNoticeVerifier
from bdos.darkforest import Deception, MovingTarget
from bdos.blackdomain import Enclave, EnclaveRouter, compile_nftables
from bdos.sentinel import Sentinel
from bdos.quorum import ActionRequest, Approval, QuorumGate


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

        # -- Quorum: the irreversible needs several hands and some time. --
        self.quorum = QuorumGate(self.config.quorum, clock=self.clock, log=self.log)

        # -- Sentinel: watch the log, hold the sword. ---------------------
        # When sealing needs a quorum, the Sentinel keeps its reversible reflex
        # (quarantine) and only recommends the irreversible one.
        sentinel_cfg = self.config.sentinel
        if self.config.quorum.seal_requires_quorum:
            sentinel_cfg = dataclasses.replace(sentinel_cfg, auto_seal=False)
        self.sentinel = Sentinel(
            sentinel_cfg,
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

    # -- the one irreversible operator action ----------------------------
    def seal(
        self,
        enclave_id: str,
        request: Optional[ActionRequest] = None,
        approvals: Iterable[Approval] = (),
    ) -> Verdict:
        """Seal ``enclave_id`` -- through the quorum gate when policy requires it.

        With ``quorum.seal_requires_quorum`` the request must name this exact
        action (``seal``) and target, and carry enough valid approvals; anything
        less is denied and logged, and the enclave stays open.
        """
        enclave = next((e for e in self.enclaves if e.id == enclave_id), None)
        if enclave is None:
            return Verdict.deny(f"no enclave named {enclave_id!r}")
        if self.config.quorum.seal_requires_quorum:
            if request is None:
                verdict = Verdict.deny("sealing requires a quorum-approved request")
            elif request.action != "seal" or request.target != enclave_id:
                verdict = Verdict.deny(
                    f"request is for {request.action!r} on {request.target!r}, not seal on {enclave_id!r}"
                )
            else:
                verdict = self.quorum.authorize(request, approvals)
            if not verdict.allowed:
                self.log.append(
                    Event(
                        ts=self.clock.wall(),
                        kind="blackdomain.seal_refused",
                        severity=Severity.WARNING,
                        message=f"seal of {enclave_id!r} refused: {verdict.reason}",
                        data={"enclave": enclave_id},
                    )
                )
                return verdict
        enclave.seal()
        self.log.append(
            Event(
                ts=self.clock.wall(),
                kind="blackdomain.sealed",
                severity=Severity.CRITICAL,
                message=f"enclave {enclave_id!r} sealed -- one-way door, cannot be reopened",
                data={"enclave": enclave_id, "quorum": self.config.quorum.seal_requires_quorum},
            )
        )
        return Verdict.allow(f"enclave {enclave_id!r} sealed")

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
        #     Fold over EVERY enclave that contains the principal so the most
        #     restrictive wins (a permissive enclave can never shadow a sealed
        #     one, even if config validation is bypassed).
        for enclave in self.router.enclaves_for(pid):
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


DEFAULT_SOCKET = "/run/bdos/bdosd.sock"


class _RequestHandler(socketserver.StreamRequestHandler):
    """One connection may carry many newline-delimited JSON requests."""

    def handle(self) -> None:
        server: "BdosServer" = self.server  # type: ignore[assignment]
        for raw in self.rfile:
            line = raw.strip()
            if not line:
                continue
            try:
                req = json.loads(line.decode())
            except (ValueError, UnicodeDecodeError):
                self._send({"error": "malformed request"})
                continue
            self._send(server.dispatch(req))

    def _send(self, obj: dict) -> None:
        self.wfile.write((json.dumps(obj) + "\n").encode())
        self.wfile.flush()


class BdosServer(socketserver.ThreadingUnixStreamServer):
    """A unix-socket server that owns ONE long-lived :class:`ControlPlane`.

    This is what makes enforcement real: every ``authorize`` request -- from
    every ``bdosctl guard`` / ``bdos-exec`` invocation on the host -- is served
    by the same plane, so Lightspeed cadence/quota, Sentinel scores, and the
    safety-notice replay cache accumulate *across* calls instead of resetting per
    process. A lock serializes access to the (non-thread-safe) plane state.
    """

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, socket_path: str, plane: ControlPlane) -> None:
        parent = os.path.dirname(os.path.abspath(socket_path))
        os.makedirs(parent, exist_ok=True)
        if os.path.exists(socket_path):
            os.unlink(socket_path)  # clear a stale socket from a prior run
        super().__init__(socket_path, _RequestHandler)
        self.socket_path = socket_path
        self.plane = plane
        self._lock = threading.Lock()

    def dispatch(self, req: dict) -> dict:
        op = req.get("op", "authorize")
        if op == "status":
            with self._lock:
                return self.plane.status()
        if op != "authorize":
            return {"error": f"unknown op {op!r}"}

        try:
            kind = PrincipalKind(req.get("kind", "agent"))
        except ValueError:
            kind = PrincipalKind.UNKNOWN
        principal = Principal(id=req.get("principal", ""), kind=kind)
        notice = None
        if req.get("notice"):
            try:
                notice = SafetyNotice.decode(req["notice"])
            except Exception:  # a malformed notice is simply "no valid notice"
                notice = None
        with self._lock:
            verdict = self.plane.authorize(
                principal,
                req.get("action_class", "read"),
                req.get("resource", ""),
                notice=notice,
            )
        return {
            "decision": verdict.decision.label,
            "allowed": verdict.allowed,
            "delay_seconds": verdict.delay_seconds,
            "reason": verdict.reason,
        }


def main(argv: Optional[list[str]] = None) -> int:
    """Entry point for the ``bdosd`` service.

    Without ``--serve`` it builds the plane, prints a one-shot status banner, and
    exits (importable and safe under tests). With ``--serve`` it runs the real
    enforcement server: one ControlPlane bound to a unix socket that
    ``bdosctl guard`` / ``bdos-exec`` connect to, so state is shared across every
    request on the host.
    """
    import argparse

    parser = argparse.ArgumentParser(prog="bdosd", description="BDOS control-plane daemon")
    parser.add_argument("--config", help="path to a bdos.toml policy (default: built-in defaults)")
    parser.add_argument("--serve", action="store_true", help="run the enforcement server instead of exiting")
    parser.add_argument(
        "--socket",
        help=f"unix socket to serve on (default: $BDOS_SOCKET or {DEFAULT_SOCKET})",
    )
    args = parser.parse_args(argv)

    from bdos.controlplane.cli import _load_config  # local import: avoid a cycle at import time

    plane = ControlPlane(_load_config(args.config))
    snap = plane.status()
    role = os.environ.get("BDOS_ROLE", "control-plane")
    print("bdosd: BDOS control plane up")
    print(f"  role        : {role}")
    print(f"  policy      : {args.config or 'built-in defaults'}")
    print(f"  issuer kid  : {snap['issuer_kid']}")
    print(f"  enclaves    : {', '.join(snap['enclaves']) or '(none)'}")
    print(f"  log intact  : {snap['log_intact']}")

    if not args.serve:
        return 0

    socket_path = args.socket or os.environ.get("BDOS_SOCKET") or DEFAULT_SOCKET
    server = BdosServer(socket_path, plane)
    print(f"bdosd: enforcement server listening on {socket_path}")
    try:  # pragma: no cover - the loop is exercised only by the running service
        server.serve_forever()
    except KeyboardInterrupt:
        print("bdosd: shutting down")
    finally:  # pragma: no cover
        server.server_close()
        if os.path.exists(socket_path):
            os.unlink(socket_path)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
