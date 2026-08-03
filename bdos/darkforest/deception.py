"""Deception -- canary tokens and decoy credentials.

Moving-target defence hides the real system; deception fills the space it left
behind with bait. A canary is a secret that has no legitimate use: it is planted
where only someone rifling through the system would find it. Because nothing
benign ever touches it, *any* access is by definition hostile -- deception is the
rare detector with a near-zero false-positive rate.

When a canary is touched, :meth:`Deception.trip` records a
``darkforest.canary_tripped`` event at :data:`~bdos.core.events.Severity.CRITICAL`
onto the shared log, where the Sentinel is listening and can contain the intruder
at machine speed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional, Union

from bdos.core import crypto
from bdos.core.clock import Clock, SystemClock
from bdos.core.events import Event, EventLog, Severity


@dataclass
class CanaryToken:
    """A planted secret whose sole purpose is to be tripped.

    ``id`` and ``secret`` are both indexed for detection, so recognising the
    token by either half is enough to know a trap was sprung; ``label`` records
    where it was planted so a trip is actionable.
    """

    id: str
    secret: str
    label: str = ""


class Deception:
    """Mints, registers, and trips canaries and decoy credentials."""

    def __init__(
        self,
        log: Optional[EventLog] = None,
        clock: Optional[Clock] = None,
    ) -> None:
        self.log = log
        self.clock = clock or SystemClock()
        self._canaries: list[CanaryToken] = []
        # Both id and secret map back to the token so either half is detectable.
        self._registry: dict[str, CanaryToken] = {}

    # -- internals ------------------------------------------------------
    def _register(self, canary: CanaryToken, *keys: str) -> None:
        self._canaries.append(canary)
        for key in (canary.id, canary.secret, *keys):
            if key:
                self._registry[key] = canary

    # -- minting --------------------------------------------------------
    def mint_canary(self, label: str = "") -> CanaryToken:
        """Create and register a fresh canary with a random id and secret."""
        canary = CanaryToken(
            id=crypto.b64e(os.urandom(9)),
            secret=crypto.b64e(os.urandom(24)),
            label=label,
        )
        self._register(canary)
        return canary

    def mint_decoy_credential(self, label: str = "") -> dict:
        """Create a plausible-looking credential that is really a canary.

        The returned username, password, and token all look like a genuine
        service account, but each is registered so that any attempt to use them
        is recognised as a canary trip.
        """
        canary = CanaryToken(
            id="bdos_" + crypto.b64e(os.urandom(21)),
            secret=crypto.b64e(os.urandom(18)),
            label=label or "decoy-credential",
        )
        username = "svc_backup_" + crypto.b64e(os.urandom(4)).lower().replace("_", "x")
        # Index the username too: credential-stuffing on it is just as hostile.
        self._register(canary, username)
        return {
            "username": username,
            "password": canary.secret,
            "token": canary.id,
            "label": canary.label,
        }

    # -- detection ------------------------------------------------------
    def is_canary(self, token_id_or_secret: str) -> bool:
        """True iff the value is a registered canary id, secret, or username."""
        return token_id_or_secret in self._registry

    # -- tripping -------------------------------------------------------
    def _identify(self, token: Union[CanaryToken, dict, str]) -> tuple[str, str, bool]:
        """Resolve ``token`` into ``(identifier, label, recognised)``."""
        if isinstance(token, CanaryToken):
            return token.id, token.label, self.is_canary(token.id)
        if isinstance(token, dict):
            identifier = token.get("token") or token.get("id") or ""
            return identifier, token.get("label", ""), self.is_canary(identifier)
        identifier = str(token)
        known = self._registry.get(identifier)
        return identifier, (known.label if known else ""), known is not None

    def trip(
        self,
        token: Union[CanaryToken, dict, str],
        context: Optional[dict] = None,
        principal_id: str = "",
    ) -> Event:
        """Record a canary trip and return the emitted CRITICAL event.

        Touching a canary is unambiguously hostile, so the event is emitted
        whenever this is called -- the caller has already observed the access.
        """
        identifier, label, recognised = self._identify(token)
        event = Event(
            ts=self.clock.wall(),
            kind="darkforest.canary_tripped",
            severity=Severity.CRITICAL,
            principal_id=principal_id,
            message=f"canary tripped: {label or identifier or 'unknown'}",
            data={
                "token": identifier,
                "label": label,
                "recognised": recognised,
                "context": dict(context) if context else {},
            },
        )
        if self.log is not None:
            self.log.append(event)
        return event
