"""Capability tokens -- the on-the-wire shape of a safety notice.

A :class:`Capability` is the *claim*: this principal may perform this action
class against this resource, within this window, exactly once (nonce +
monotonic counter). A :class:`SafetyNotice` is that claim plus an Ed25519
signature that makes it unforgeable. Both are plain data; all policy lives in
the issuer and verifier.

The wire form is a URL-safe base64 blob so a notice can ride in a header, a
query string, or an environment variable without escaping.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from bdos.core import crypto


@dataclass
class Capability:
    """A scoped, time-bounded, single-use grant.

    ``nonce`` makes a notice non-replayable; ``counter`` gives every notice an
    issuer-monotonic ordinal so a stream of grants can be audited for gaps.
    ``issuer_kid`` names the key the verifier must check the signature against.
    """

    principal_id: str
    action_class: str
    resource: str
    not_before: float
    not_after: float
    nonce: str
    counter: int
    issuer_kid: str

    def canonical(self) -> bytes:
        """Deterministic byte encoding -- the exact bytes that get signed.

        Sorted keys and tight separators guarantee that the issuer and the
        verifier hash identical bytes, so a signature made here validates there
        after a full encode/decode round-trip.
        """
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()


@dataclass
class SafetyNotice:
    """A :class:`Capability` bound to an Ed25519 signature over its canonical form."""

    capability: Capability
    signature: bytes

    def encode(self) -> str:
        """Serialize to a compact, URL-safe string (base64 of a JSON envelope)."""
        envelope = {
            "cap": json.loads(self.capability.canonical().decode()),
            "sig": crypto.b64e(self.signature),
        }
        raw = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
        return crypto.b64e(raw)

    @classmethod
    def decode(cls, text: str) -> "SafetyNotice":
        """Reconstruct a :class:`SafetyNotice` from :meth:`encode` output."""
        envelope = json.loads(crypto.b64d(text).decode())
        capability = Capability(**envelope["cap"])
        return cls(capability=capability, signature=crypto.b64d(envelope["sig"]))
