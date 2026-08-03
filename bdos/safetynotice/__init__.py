"""Safety Notice layer -- proof of *legitimacy*, not proof of work.

A privileged action does not have to burn CPU to earn the right to run; it has
to carry an unforgeable, scoped, single-use permission slip. That slip is a
:class:`~bdos.safetynotice.tokens.SafetyNotice`: an Ed25519-signed capability
naming exactly one principal, action class, and resource, valid only inside a
short window, and spendable only once.

The :class:`~bdos.safetynotice.issuer.SafetyNoticeIssuer` mints them; the
:class:`~bdos.safetynotice.verifier.SafetyNoticeVerifier` checks signature,
scope, window, revocation, and replay. Legitimate work carries a notice and
sails through; a rogue agent that cannot produce one is stopped at the door.
"""

from bdos.safetynotice.tokens import Capability, SafetyNotice
from bdos.safetynotice.issuer import SafetyNoticeIssuer
from bdos.safetynotice.verifier import SafetyNoticeVerifier

__all__ = [
    "Capability",
    "SafetyNotice",
    "SafetyNoticeIssuer",
    "SafetyNoticeVerifier",
]
