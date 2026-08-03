"""Lightspeed layer -- "reduce the speed of light in the vacuum".

The single decisive advantage an autonomous agent has over a human operator is
speed: it can attempt tens of thousands of actions in the time a human tries a
handful. This layer removes that advantage by imposing *progressive,
asymmetric* delay on sensitive action sequences.

The delay is designed to be invisible to a human (who issues a few commands a
minute) and crushing to an agent (which wants thousands). It is an
"aggression tax": the more machine-like and bursty the cadence, the steeper
the toll -- proportional to the very behaviour that signals an attack.
"""

from bdos.lightspeed.cadence import burst_score, looks_agentic
from bdos.lightspeed.throttle import LightspeedThrottle, TokenBucket
from bdos.lightspeed.gateway import LightspeedGateway

__all__ = [
    "burst_score",
    "looks_agentic",
    "LightspeedThrottle",
    "TokenBucket",
    "LightspeedGateway",
]
