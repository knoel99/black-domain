"""Control registry -- the law, written down with its reasons.

Each control states the attack it is the scar of, the weapon it assumes, who can
lift it, whether it can be undone, how a third party can check it holds, and
when it must be looked at again. :func:`check` refuses a registry that claims
more than it can back; :func:`coverage` shows the principles left bare and the
effect classes defended only by recognising today's weapon.
"""

from bdos.registry.controls import PRINCIPLES, Control, ControlException, Registry, from_dict, load
from bdos.registry.validate import ERROR, WARNING, Finding, check, coverage

__all__ = [
    "PRINCIPLES",
    "Control",
    "ControlException",
    "Registry",
    "from_dict",
    "load",
    "ERROR",
    "WARNING",
    "Finding",
    "check",
    "coverage",
]
