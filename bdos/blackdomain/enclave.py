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
"""

from __future__ import annotations

from bdos.core.config import EnclaveSpec
from bdos.core.decision import Verdict
from bdos.core.errors import SealedEnclaveError

# Action classes that mutate state or move data out; all are refused once sealed.
_MUTATING = ("write", "admin", "exfil")


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
        no-op, never an error."""
        self._sealed = True

    def unseal(self) -> None:
        """There is no unseal. A black domain is a one-way door.

        Always raises :class:`~bdos.core.errors.SealedEnclaveError` so that no
        code path -- benign or hostile -- can quietly reopen a closed enclave.
        """
        raise SealedEnclaveError(f"enclave {self.id!r} is a one-way door and cannot be unsealed")

    # -- decisions ------------------------------------------------------
    def decide_egress(self, dst: str) -> Verdict:
        """Decide whether traffic to ``dst`` may leave the enclave.

        ALLOW only if the enclave is open and ``dst`` is on the egress
        allowlist; everything else is denied. A sealed enclave denies all
        egress unconditionally.
        """
        if self._sealed:
            return Verdict.deny(
                reason=f"black domain {self.id!r} sealed: all egress denied",
                enclave=self.id,
                dst=dst,
                sealed=True,
            )
        if dst in self.spec.egress_allow:
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

        Reads always ALLOW. Once the enclave is sealed, every mutating action
        (write, admin, exfil) is denied -- data may enter a black domain but
        nothing may change it or carry it out.
        """
        if self._sealed and action_class in _MUTATING:
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
