"""Black Domain layer -- seal the crown jewels behind a one-way door.

The crown jewels do not need faster locks; they need a room that only opens
inward. This layer draws that room. :class:`Enclave` fences a set of members
behind default-deny egress and can be *sealed* -- turned into a one-way door
through which data may still flow in, but nothing may be changed or carried out,
and which can never be reopened. :func:`compile_nftables` projects those
enclaves onto a real firewall, and :class:`EnclaveRouter` applies the same
policy to in-process flows.
"""

from bdos.blackdomain.enclave import Enclave
from bdos.blackdomain.compiler import compile_nftables, EnclaveRouter

__all__ = [
    "Enclave",
    "compile_nftables",
    "EnclaveRouter",
]
