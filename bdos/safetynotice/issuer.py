"""Minting side of the Safety Notice layer.

The issuer holds a private Ed25519 key and hands out signed capability tokens.
Every mint draws a fresh random nonce and bumps a monotonic counter, so no two
notices are alike and their order is auditable. The issuer never blocks and
keeps no history beyond the counter -- it is the fast, stateless-ish authority;
all validation happens at the :class:`~bdos.safetynotice.verifier.SafetyNoticeVerifier`.
"""

from __future__ import annotations

import os
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from bdos.core import crypto
from bdos.core.clock import Clock, SystemClock
from bdos.core.config import SafetyNoticeConfig
from bdos.safetynotice.tokens import Capability, SafetyNotice


class SafetyNoticeIssuer:
    """Signs scoped, time-bounded capability tokens with an Ed25519 key."""

    def __init__(
        self,
        signing_key: Ed25519PrivateKey,
        clock: Optional[Clock] = None,
        kid: Optional[str] = None,
    ) -> None:
        self.signing_key = signing_key
        self._public_key = signing_key.public_key()
        self.clock = clock or SystemClock()
        self.kid = kid or crypto.key_id(self._public_key)
        # Monotonic ordinal stamped on every notice; starts at 0, ++ per mint.
        self.counter = 0
        self.default_ttl = SafetyNoticeConfig().default_ttl

    @property
    def public_key(self) -> Ed25519PublicKey:
        """The public half of the signing key (register it with a verifier)."""
        return self._public_key

    def mint(
        self,
        principal_id: str,
        action_class: str,
        resource: str,
        ttl: Optional[float] = None,
        now: Optional[float] = None,
    ) -> SafetyNotice:
        """Issue a signed notice valid for ``[now, now + ttl]`` (wall time).

        ``ttl`` defaults to :attr:`default_ttl` (300s). The signature covers the
        capability's canonical bytes, so any tampering with scope or window
        invalidates the notice.
        """
        at = now if now is not None else self.clock.wall()
        self.counter += 1
        window = ttl if ttl is not None else self.default_ttl
        capability = Capability(
            principal_id=principal_id,
            action_class=action_class,
            resource=resource,
            not_before=at,
            not_after=at + window,
            nonce=crypto.b64e(os.urandom(16)),
            counter=self.counter,
            issuer_kid=self.kid,
        )
        signature = crypto.sign(self.signing_key, capability.canonical())
        return SafetyNotice(capability=capability, signature=signature)
