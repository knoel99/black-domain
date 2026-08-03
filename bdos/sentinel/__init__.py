"""Sentinel layer -- machine-speed containment ("who holds the sword").

An autonomous attacker moves faster than any human responder, so the decision to
contain cannot wait for a human in the loop. The :class:`Sentinel` subscribes to
the shared, tamper-evident event log and reacts synchronously: it keeps a
per-principal, time-decaying anomaly score and runs an escalation ladder --
quarantine, then seal the enclave -- the instant the evidence crosses a
threshold.

That reflex can be disarmed. With ``auto_contain`` off the Sentinel only
*recommends* containment and leaves the final cut to an operator, because in a
system that can act at machine speed the important question is not whether the
sword is sharp but who is allowed to swing it.
"""

from bdos.sentinel.sentinel import Sentinel

__all__ = [
    "Sentinel",
]
