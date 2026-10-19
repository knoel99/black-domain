"""Run BDOS as a module: ``python -m bdos`` delegates to the ``bdosctl`` CLI.

This makes the control-plane command line reachable without an installed console
script, which is convenient in containers and during development. Every argument
is forwarded verbatim to :func:`bdos.controlplane.cli.main`.
"""

from __future__ import annotations

import sys

from bdos.controlplane.cli import main

if __name__ == "__main__":
    sys.exit(main())
