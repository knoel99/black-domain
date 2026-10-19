"""Black Domain OS (BDOS).

A Linux hardening overlay that defends production systems against rogue
autonomous agents, using a four-layer defensive doctrine adapted from the
"dark forest" and "black domain" strategies of Liu Cixin's *Remembrance of
Earth's Past* trilogy:

    1. Dark Forest        -- reduce legibility and surface (moving target,
                             deception, canary tripwires).
    2. Lightspeed         -- impose progressive, asymmetric delays and quotas
                             on sensitive action sequences: cheap for humans,
                             ruinous for machine-speed agents.
    3. Safety Notice      -- validate privileged actions with unforgeable,
                             non-replayable proof of *legitimacy* (signed
                             capability tokens), not proof of *work*.
    4. Black Domain       -- seal crown-jewel enclaves behind one-way,
                             default-deny segmentation.

A Sentinel control plane consumes the tamper-evident event stream from all
layers and enforces machine-speed containment.
"""

__version__ = "0.1.0"
