"""Enclaves -- one-way, default-deny segments around the crown jewels.

An :class:`Enclave` is a fenced-off region of the system: a set of members whose
egress is denied by default and permitted only to an explicit allowlist. Its
decisive property is the *seal*. Sealing an enclave turns it into a one-way
door -- reads (ingress) still flow, but every mutation and every packet leaving
the enclave is refused, and there is no legitimate way back out:
:meth:`Enclave.unseal` always raises. A black domain, once closed, stays closed.

The enclave only *decides*; it never sleeps, logs, or resolves addresses, so it
is deterministic and trivially testable. Emitting the ``blackdomain.*`` events
that record a denial or a seal is the caller's job (the control plane and the
Sentinel).

Durability note. The seal is authoritative in memory and one-way through the
public API (there is no ``unseal``). To survive a restart it must also be
persisted: :meth:`seal` writes ``spec.sealed = True`` so a serialized policy
re-seals on reload, but the operator must actually write that policy back to
disk. A direct assignment to the private ``_sealed`` attribute would require
code execution inside the process -- a compromise already past this boundary --
so the guarantee here is "no benign or API path reopens a sealed domain", not
"tamper-proof against in-process code".
"""

from __future__ import annotations

import ipaddress

from bdos.core.config import EnclaveSpec
from bdos.core.decision import Verdict
from bdos.core.errors import SealedEnclaveError

# The only class that never mutates state or moves data out.
_NON_MUTATING = "read"


def _normalize(action_class: str) -> str:
    return action_class.strip().lower()


def _dst_matches(dst: str, entry: str) -> bool:
    """True if destination ``dst`` matches an allowlist ``entry``.

    An entry that parses as an IP network matches any address inside it (so a
    CIDR allowlist actually admits hosts); otherwise both sides are compared as
    hostnames, case-insensitively and with a trailing dot stripped."""
    try:
        network = ipaddress.ip_network(entry, strict=False)
    except ValueError:
        network = None
    if network is not None:
        try:
            return ipaddress.ip_address(dst.strip()) in network
        except ValueError:
            return False  # entry is a network but dst is not an address
    return dst.strip().rstrip(".").lower() == entry.strip().rstrip(".").lower()


class Enclave:
    """A default-deny segment that can be sealed shut but never reopened."""

    def __init__(self, spec: EnclaveSpec) -> None:
        self.spec = spec
        # The seal is one-way; its starting position comes from the spec.
        self._sealed = bool(spec.sealed)

    # -- identity -------------------------------------------------------
    @property
    def id(self) -> str:
        return self.spec.id

    def contains(self, member: str) -> bool:
        """True iff ``member`` belongs to this enclave."""
        return member in self.spec.members

    # -- state ----------------------------------------------------------
    @property
    def sealed(self) -> bool:
        return self._sealed

    def seal(self) -> None:
        """Close the one-way door. Idempotent: sealing a sealed enclave is a
        no-op, never an error. Also records the seal on the spec so a persisted
        policy re-seals on reload."""
        self._sealed = True
        self.spec.sealed = True

    def unseal(self) -> None:
        """There is no unseal. A black domain is a one-way door.

        Always raises :class:`~bdos.core.errors.SealedEnclaveError` so that no
        code path -- benign or hostile -- can quietly reopen a closed enclave.
        """
        raise SealedEnclaveError(f"enclave {self.id!r} is a one-way door and cannot be unsealed")

    # -- decisions ------------------------------------------------------
    def decide_egress(self, dst: str) -> Verdict:
        """Decide whether traffic to ``dst`` may leave the enclave.

        ALLOW only if the enclave is open and ``dst`` matches the egress
        allowlist (IP/CIDR or hostname); everything else is denied. A sealed
        enclave denies all egress unconditionally.
        """
        if self._sealed:
            return Verdict.deny(
                reason=f"black domain {self.id!r} sealed: all egress denied",
                enclave=self.id,
                dst=dst,
                sealed=True,
            )
        if any(_dst_matches(dst, entry) for entry in self.spec.egress_allow):
            return Verdict.allow(
                reason=f"egress to {dst!r} allowlisted for enclave {self.id!r}",
                enclave=self.id,
                dst=dst,
            )
        return Verdict.deny(
            reason=f"default-deny egress: {dst!r} not allowlisted for enclave {self.id!r}",
            enclave=self.id,
            dst=dst,
        )

    def decide_action(self, action_class: str) -> Verdict:
        """Decide whether an action of ``action_class`` may run in the enclave.

        Reads always ALLOW. Once the enclave is sealed the decision is
        *default-deny*: only a normalized ``read`` is permitted, and every other
        class -- including unknown or non-canonical ones an attacker might use to
        slip past a literal blocklist -- is refused. Data may enter a black
        domain, but nothing may change it or carry it out.
        """
        normalized = _normalize(action_class)
        if self._sealed and normalized != _NON_MUTATING:
            return Verdict.deny(
                reason=f"enclave {self.id!r} sealed: {action_class!r} refused",
                enclave=self.id,
                action_class=action_class,
                sealed=True,
            )
        return Verdict.allow(
            reason=f"{action_class!r} permitted in enclave {self.id!r}",
            enclave=self.id,
            action_class=action_class,
        )
