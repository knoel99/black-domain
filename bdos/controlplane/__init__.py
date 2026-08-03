"""Control plane -- the spine that wires every BDOS layer into one decision.

The Dark Forest, Lightspeed, Safety Notice, and Black Domain layers each answer
a narrow question and emit their findings onto one hash-chained event log; the
Sentinel watches that log and holds the sword. The control plane is what binds
them together: :class:`~bdos.controlplane.daemon.ControlPlane` builds the whole
stack from a :class:`~bdos.core.config.BDOSConfig` and exposes a single
:meth:`~bdos.controlplane.daemon.ControlPlane.authorize` call that consults the
layers most-catastrophic-first and short-circuits on the first hard verdict.

Two entry points ride on top of it: ``bdosd``
(:func:`bdos.controlplane.daemon.main`), the long-lived service, and ``bdosctl``
(:func:`bdos.controlplane.cli.main`), the operator CLI.
"""

from bdos.controlplane.daemon import ControlPlane

__all__ = [
    "ControlPlane",
]
