"""Dark Forest layer -- reduce legibility and lay traps.

The dark-forest doctrine: the safest thing in a hostile universe is to be
unseen. This layer pursues that on two fronts. :class:`MovingTarget` keeps the
real system illegible -- its rendezvous rotate on a keyed schedule only
legitimate clients can follow. :class:`Deception` fills the void with bait --
canary tokens and decoy credentials that nothing benign ever touches, so any
access lights up as a near-certain intrusion.
"""

from bdos.darkforest.mtd import MovingTarget
from bdos.darkforest.deception import CanaryToken, Deception

__all__ = [
    "MovingTarget",
    "CanaryToken",
    "Deception",
]
