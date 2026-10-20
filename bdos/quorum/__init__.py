"""Quorum -- the key must not be a person.

Irreversible actions (sealing an enclave) are gated by ``m`` distinct signed
approvals and a deliberate delay, so no single holder -- benign, coerced or
compromised -- can swing the sword alone, and a hurried decision can still be
stopped before it lands. Reversible containment (quarantine) stays automatic in
the Sentinel: automate the reversible, split the irreversible.
"""

from bdos.quorum.gate import ActionRequest, Approval, QuorumGate

__all__ = [
    "ActionRequest",
    "Approval",
    "QuorumGate",
]
