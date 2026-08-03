"""Moving-target defence.

A static system is a legible one: an attacker who maps a service's port and
path once can return to it at leisure. :class:`MovingTarget` removes that
standing map. Each service's rendezvous (port + path) is a keyed HMAC of the
service name and the current *epoch*, so it is stable for exactly one epoch and
rotates to a fresh, unpredictable location the moment the epoch turns.

Legitimate clients derive the same rendezvous from the shared ``secret`` and the
wall clock; an attacker without the secret sees the map dissolve out from under
them. The derivation is pure and deterministic, so it is fully reproducible
under a :class:`~bdos.core.clock.ManualClock`.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Optional

from bdos.core.clock import Clock, SystemClock
from bdos.core.config import DarkForestConfig


class MovingTarget:
    """Deterministic, epoch-rotating rendezvous for services.

    ``secret`` is the shared key that makes the schedule unpredictable to
    outsiders; ``cfg`` supplies the epoch length and the port range. All
    derivation flows from a single HMAC-SHA256 over ``"service:epoch"`` so port
    and path always agree with each other for a given service and epoch.
    """

    def __init__(
        self,
        secret: bytes,
        cfg: DarkForestConfig,
        clock: Optional[Clock] = None,
    ) -> None:
        self.secret = secret.encode() if isinstance(secret, str) else bytes(secret)
        self.cfg = cfg
        self.clock = clock or SystemClock()

    # -- time -----------------------------------------------------------
    def epoch(self, now: Optional[float] = None) -> int:
        """Return the current epoch index (``wall // mtd_epoch_seconds``)."""
        wall = self.clock.wall() if now is None else float(now)
        return int(wall // self.cfg.mtd_epoch_seconds)

    def _resolve_epoch(self, epoch: Optional[int]) -> int:
        return self.epoch() if epoch is None else int(epoch)

    # -- derivation -----------------------------------------------------
    def _mac(self, service: str, epoch: int) -> hmac.HMAC:
        """Keyed HMAC-SHA256 over the ``"service:epoch"`` rendezvous label."""
        message = f"{service}:{epoch}".encode()
        return hmac.new(self.secret, message, hashlib.sha256)

    def port_for(self, service: str, epoch: Optional[int] = None) -> int:
        """Deterministic port in ``[mtd_port_low, mtd_port_high)`` for the epoch."""
        ep = self._resolve_epoch(epoch)
        span = self.cfg.mtd_port_high - self.cfg.mtd_port_low
        value = int.from_bytes(self._mac(service, ep).digest(), "big")
        return self.cfg.mtd_port_low + value % span

    def path_for(self, service: str, epoch: Optional[int] = None) -> str:
        """Deterministic URL path (``/`` + 16 hex chars) for the epoch."""
        ep = self._resolve_epoch(epoch)
        return "/" + self._mac(service, ep).hexdigest()[:16]

    # -- convenience ----------------------------------------------------
    def current(self, service: str) -> dict:
        """Return the live rendezvous ``{service, epoch, port, path}``."""
        ep = self.epoch()
        return {
            "service": service,
            "epoch": ep,
            "port": self.port_for(service, ep),
            "path": self.path_for(service, ep),
        }
