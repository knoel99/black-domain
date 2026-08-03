"""Verifying side of the Safety Notice layer.

The verifier is where trust is decided. It authenticates a notice against a
registered issuer key, then rejects anything out of scope, out of window,
revoked, or replayed. :meth:`SafetyNoticeVerifier.verify` is strict -- it
raises the precise error subclass so a caller can react to *why* a notice
failed. :meth:`SafetyNoticeVerifier.guard` is the safe front-end: it never
raises, folds every failure into a ``DENY`` verdict, and records the outcome on
the event log so the Sentinel can watch attestation pressure build.

Scope and durability. Replay and revocation state live *in this process*. A
spent nonce is remembered until its validity window closes (after which the
window check rejects it anyway), and the cache is bounded by issuance-rate x TTL
rather than by a raw count -- a still-valid nonce is never forgotten, and if the
cache genuinely fills with live nonces the verifier *fails closed* rather than
silently reopen replay. Across a restart or a second verifier instance this
state is not shared: a production deployment that runs more than one verifier, or
must survive restarts, has to back ``_seen``/revocation with a shared, durable
store (e.g. Redis/DB keyed by nonce with a TTL of ``not_after + clock_skew``).
See ``docs/THREAT_MODEL.md``.
"""

from __future__ import annotations

import heapq
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from bdos.core import crypto
from bdos.core.clock import Clock, SystemClock
from bdos.core.config import SafetyNoticeConfig
from bdos.core.decision import Verdict
from bdos.core.errors import (
    AttestationError,
    ExpiredError,
    ReplayError,
    RevokedError,
)
from bdos.core.events import Event, EventLog, Severity
from bdos.safetynotice.tokens import SafetyNotice


class SafetyNoticeVerifier:
    """Authenticates and authorizes safety notices against registered keys."""

    def __init__(
        self,
        clock: Optional[Clock] = None,
        cfg: Optional[SafetyNoticeConfig] = None,
    ) -> None:
        self.clock = clock or SystemClock()
        self.cfg = cfg or SafetyNoticeConfig()
        self._keys: dict[str, Ed25519PublicKey] = {}
        self._revoked_kids: set[str] = set()
        self._revoked_nonces: set[str] = set()
        # Expiry-aware replay cache: nonce -> not_after, plus a min-heap on
        # not_after so expired nonces (which the window check rejects anyway) are
        # pruned cheaply. A still-valid nonce is never dropped.
        self._seen: dict[str, float] = {}
        self._expiry_heap: list[tuple[float, str]] = []

    # -- registration / revocation --------------------------------------
    def add_key(self, pk: Ed25519PublicKey, kid: Optional[str] = None) -> str:
        """Trust notices signed by ``pk`` under key id ``kid`` (defaults to its
        :func:`~bdos.core.crypto.key_id`). Returns the kid used."""
        resolved = kid or crypto.key_id(pk)
        self._keys[resolved] = pk
        return resolved

    def revoke_nonce(self, nonce: str) -> None:
        """Permanently reject any notice carrying ``nonce``."""
        self._revoked_nonces.add(nonce)

    def revoke_key(self, kid: str) -> None:
        """Permanently reject every notice issued under ``kid``."""
        self._revoked_kids.add(kid)

    # -- internals ------------------------------------------------------
    def _prune_expired(self, now: float) -> None:
        """Drop nonces whose window has fully closed; those are safe to forget
        because the validity-window check rejects them regardless of the cache."""
        skew = self.cfg.clock_skew
        heap = self._expiry_heap
        while heap and heap[0][0] + skew < now:
            _, nonce = heapq.heappop(heap)
            if nonce in self._seen and self._seen[nonce] + skew < now:
                del self._seen[nonce]

    def _remember(self, nonce: str, not_after: float, now: float) -> None:
        """Record a spent nonce, or fail closed if the cache is full of live ones.

        Raises :class:`AttestationError` when the cache is already full of
        still-valid nonces: dropping one to make room would re-open replay, so
        the verifier refuses the action instead."""
        self._prune_expired(now)
        if len(self._seen) >= self.cfg.replay_cache_size and nonce not in self._seen:
            raise AttestationError(
                "replay cache full of live nonces; refusing to accept (fail closed)"
            )
        self._seen[nonce] = not_after
        heapq.heappush(self._expiry_heap, (not_after, nonce))

    # -- decision -------------------------------------------------------
    def verify(
        self,
        notice: SafetyNotice,
        principal_id: str,
        action_class: str,
        resource: str,
        now: Optional[float] = None,
    ) -> Verdict:
        """Validate ``notice`` for the requested action; ALLOW or raise.

        Raises :class:`AttestationError` for an unknown key, a bad signature, or
        a scope mismatch; :class:`RevokedError` for a revoked key or nonce;
        :class:`ExpiredError` outside the (skew-widened) validity window; and
        :class:`ReplayError` for a nonce already spent. On success the nonce is
        recorded in the bounded replay cache so it cannot be reused.
        """
        cap = notice.capability
        at = now if now is not None else self.clock.wall()

        # 1. Authenticate: the kid must be known and the signature must verify
        #    before any field of the capability can be trusted.
        pk = self._keys.get(cap.issuer_kid)
        if pk is None:
            raise AttestationError(f"unknown issuer kid {cap.issuer_kid!r}")
        if not crypto.verify(pk, notice.signature, cap.canonical()):
            raise AttestationError("safety notice signature is invalid")

        # 2. Revocation of the issuer key or this specific nonce.
        if cap.issuer_kid in self._revoked_kids:
            raise RevokedError(f"issuer key {cap.issuer_kid!r} is revoked")
        if cap.nonce in self._revoked_nonces:
            raise RevokedError("safety notice nonce is revoked")

        # 3. Scope: principal, action class, and resource must all match.
        if (
            cap.principal_id != principal_id
            or cap.action_class != action_class
            or cap.resource != resource
        ):
            raise AttestationError(
                "safety notice scope does not match the requested action"
            )

        # 4. Validity window, widened by the configured clock skew.
        skew = self.cfg.clock_skew
        if at < cap.not_before - skew or at > cap.not_after + skew:
            raise ExpiredError(
                f"safety notice outside validity window "
                f"[{cap.not_before}, {cap.not_after}] at {at}"
            )

        # 5. Replay: a nonce may be spent exactly once. Records the nonce (or
        #    fails closed if the cache is full of still-valid nonces).
        if cap.nonce in self._seen:
            raise ReplayError("safety notice nonce already spent (replay)")

        self._remember(cap.nonce, cap.not_after, at)
        return Verdict.allow(
            reason=f"safety notice valid for {action_class} on {resource}",
            kid=cap.issuer_kid,
            nonce=cap.nonce,
            counter=cap.counter,
        )

    def guard(
        self,
        notice: SafetyNotice,
        principal_id: str,
        action_class: str,
        resource: str,
        log: Optional[EventLog] = None,
        now: Optional[float] = None,
    ) -> Verdict:
        """Verify without raising; log the outcome and return a verdict.

        On success appends a ``safetynotice.verified`` (NOTICE) event and
        returns ALLOW. On any failure appends a ``safetynotice.rejected``
        (ALERT) event and returns ``Verdict.deny`` naming the reason.
        """
        at = now if now is not None else self.clock.wall()
        try:
            verdict = self.verify(notice, principal_id, action_class, resource, now=at)
        except AttestationError as exc:
            reason = str(exc)
            if log is not None:
                log.append(
                    Event(
                        ts=at,
                        kind="safetynotice.rejected",
                        severity=Severity.ALERT,
                        principal_id=principal_id,
                        action_class=action_class,
                        message=reason,
                        data={
                            "error": type(exc).__name__,
                            "resource": resource,
                            "kid": notice.capability.issuer_kid,
                        },
                    )
                )
            return Verdict.deny(reason=reason, error=type(exc).__name__)

        if log is not None:
            log.append(
                Event(
                    ts=at,
                    kind="safetynotice.verified",
                    severity=Severity.NOTICE,
                    principal_id=principal_id,
                    action_class=action_class,
                    message=verdict.reason,
                    data={
                        "resource": resource,
                        "kid": notice.capability.issuer_kid,
                        "nonce": notice.capability.nonce,
                        "counter": notice.capability.counter,
                    },
                )
            )
        return verdict
