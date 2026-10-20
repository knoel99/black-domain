"""m-of-n signed approvals in front of irreversible actions.

The trilogy's Swordholder put the whole deterrent in one person's hand, and the
deterrent collapsed the moment the hand changed. This module is the opposite
design: an irreversible action (sealing an enclave) is described once as an
:class:`ActionRequest`, each approver signs that exact description with their
own Ed25519 key (:class:`Approval`), and :class:`QuorumGate` lets the action
through only when

* at least ``m`` *distinct, enrolled* approvers signed the same request;
* every counted signature verifies against the enrolled key;
* the request is still inside its validity window;
* the deliberate delay has elapsed since the moment quorum was reached
  (the ``m``-th approval), so a decision taken in a hurry can still be stopped;
* the request has not already been executed (single use).

Backdating the delay would require ``m`` approvers to lie about their own
signing time -- that is, the quorum itself colluding, which no gate can stop.
The executed-request set is per-process, like the Safety Notice replay cache.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Iterable, Optional

from bdos.core import crypto
from bdos.core.clock import Clock, SystemClock
from bdos.core.config import QuorumConfig
from bdos.core.decision import Verdict
from bdos.core.events import Event, EventLog, Severity

# Domain separation: an approval signature can never be mistaken for a safety
# notice or any other BDOS signature.
_DOMAIN = b"bdos-quorum-v1\x1f"


@dataclass
class ActionRequest:
    """The exact irreversible action being asked for, as approvers will sign it."""

    action: str
    target: str
    reason: str
    requested_by: str
    created: float
    nonce: str = field(default_factory=lambda: crypto.b64e(os.urandom(16)))

    def canonical(self) -> bytes:
        payload = {
            "action": self.action,
            "target": self.target,
            "reason": self.reason,
            "requested_by": self.requested_by,
            "created": round(self.created, 6),
            "nonce": self.nonce,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical()).hexdigest()

    def to_dict(self) -> dict:
        return json.loads(self.canonical())

    @classmethod
    def from_dict(cls, data: dict) -> "ActionRequest":
        return cls(
            action=str(data["action"]),
            target=str(data["target"]),
            reason=str(data["reason"]),
            requested_by=str(data["requested_by"]),
            created=float(data["created"]),
            nonce=str(data["nonce"]),
        )


@dataclass
class Approval:
    """One approver's signature over one request, at one declared time."""

    approver: str
    request_digest: str
    signed_at: float
    signature: str

    @staticmethod
    def _message(request_digest: str, approver: str, signed_at: float) -> bytes:
        return _DOMAIN + json.dumps(
            {"approver": approver, "request": request_digest, "signed_at": round(signed_at, 6)},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    @classmethod
    def sign(cls, request: ActionRequest, approver: str, key, signed_at: float) -> "Approval":
        msg = cls._message(request.digest, approver, signed_at)
        return cls(approver, request.digest, round(signed_at, 6), crypto.b64e(crypto.sign(key, msg)))

    def verifies(self, public_key) -> bool:
        try:
            sig = crypto.b64d(self.signature)
        except ValueError:
            return False
        return crypto.verify(public_key, sig, self._message(self.request_digest, self.approver, self.signed_at))

    def to_dict(self) -> dict:
        return {
            "approver": self.approver,
            "request_digest": self.request_digest,
            "signed_at": self.signed_at,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Approval":
        return cls(
            approver=str(data["approver"]),
            request_digest=str(data["request_digest"]),
            signed_at=float(data["signed_at"]),
            signature=str(data["signature"]),
        )


class QuorumGate:
    """Decides whether a set of approvals authorizes one irreversible action."""

    def __init__(
        self,
        cfg: Optional[QuorumConfig] = None,
        clock: Optional[Clock] = None,
        log: Optional[EventLog] = None,
    ) -> None:
        self.cfg = cfg or QuorumConfig()
        self.clock = clock or SystemClock()
        self.log = log
        self._keys = {
            approver: crypto.load_public(crypto.b64d(pub)) for approver, pub in self.cfg.approvers.items()
        }
        self._executed: set[str] = set()

    def check(
        self,
        request: ActionRequest,
        approvals: Iterable[Approval],
        now: Optional[float] = None,
    ) -> Verdict:
        """Return ALLOW if the approvals carry ``request`` through, else DENY.

        Pure: nothing is recorded. Call :meth:`consume` once the action is done.
        """
        now = self.clock.wall() if now is None else now
        cfg = self.cfg
        digest = request.digest
        if digest in self._executed:
            return Verdict.deny("quorum: request already executed (replay)", request=digest)
        if request.created > now + cfg.clock_skew:
            return Verdict.deny("quorum: request created in the future", request=digest)
        expires = request.created + cfg.validity_seconds
        if now > expires:
            return Verdict.deny("quorum: request expired", request=digest)

        valid: dict[str, float] = {}
        rejected: list[str] = []
        for ap in approvals:
            key = self._keys.get(ap.approver)
            if key is None:
                rejected.append(f"{ap.approver}: not enrolled")
            elif ap.request_digest != digest:
                rejected.append(f"{ap.approver}: signed another request")
            elif not (request.created - cfg.clock_skew <= ap.signed_at <= min(now, expires) + cfg.clock_skew):
                rejected.append(f"{ap.approver}: signing time outside the request window")
            elif not ap.verifies(key):
                rejected.append(f"{ap.approver}: bad signature")
            elif ap.approver in valid:
                rejected.append(f"{ap.approver}: duplicate approval")
            else:
                valid[ap.approver] = ap.signed_at

        meta = {"request": digest, "approvers": sorted(valid), "rejected": rejected, "m": cfg.m}
        if len(valid) < cfg.m:
            return Verdict.deny(f"quorum: {len(valid)} of {cfg.m} required approvals", **meta)
        reached_at = sorted(valid.values())[cfg.m - 1]
        ready_at = reached_at + cfg.delay_seconds
        if now < ready_at:
            return Verdict.deny(
                f"quorum: deliberate delay, {ready_at - now:.0f}s left before the action may run",
                ready_at=ready_at,
                **meta,
            )
        return Verdict.allow(f"quorum: {len(valid)} of {cfg.m} approvals, delay elapsed", **meta)

    def consume(self, request: ActionRequest) -> None:
        """Mark ``request`` executed so the same approvals cannot be replayed."""
        self._executed.add(request.digest)

    def authorize(self, request: ActionRequest, approvals: Iterable[Approval]) -> Verdict:
        """:meth:`check`, then log the decision and consume the request on ALLOW."""
        now = self.clock.wall()
        verdict = self.check(request, list(approvals), now=now)
        if verdict.allowed:
            self.consume(request)
        if self.log is not None:
            self.log.append(
                Event(
                    ts=now,
                    kind="quorum.allowed" if verdict.allowed else "quorum.denied",
                    severity=Severity.NOTICE if verdict.allowed else Severity.WARNING,
                    principal_id=request.requested_by,
                    action_class="admin",
                    message=verdict.reason,
                    data={"action": request.action, "target": request.target, **verdict.metadata},
                )
            )
        return verdict
