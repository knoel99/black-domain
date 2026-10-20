"""Checks a control registry against the essay's principles.

:func:`check` returns :class:`Finding` objects, one per broken rule. ``error``
findings mean the registry claims something it cannot back (a "law" a
compromised admin can lift, an irreversible control one person can lift, an
expired waiver still in force); ``warning`` findings mean something is overdue
for a second look. :func:`coverage` answers the portfolio questions: which
principles have no control at all, and which effect classes are only defended by
recognising the current weapon -- the Bunker built against a photoid.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import Optional

from bdos.registry.controls import KINDS, PRINCIPLES, Registry

ERROR = "error"
WARNING = "warning"

# Fields every control must fill in, with the principle that asks for them.
_REQUIRED = {
    "scar": "3.13: which attack is this rule the scar of?",
    "threat_hypothesis": "3.9: which weapon was it designed against?",
    "effect_class": "3.9: which class of effect does it bound?",
    "indicator": "5.1: which indicator shows it works?",
    "owner": "3.8: who answers for it?",
}


@dataclass
class Finding:
    severity: str
    control_id: str
    principle: str
    message: str

    def __str__(self) -> str:
        return f"{self.severity.upper():<7} {self.control_id:<22} [{self.principle}] {self.message}"


def check(registry: Registry, today: Optional[_dt.date] = None) -> list[Finding]:
    today = today or _dt.date.today()
    out: list[Finding] = []
    seen: set[str] = set()

    for c in registry.controls:
        def add(sev: str, principle: str, msg: str) -> None:
            out.append(Finding(sev, c.id, principle, msg))

        if c.id in seen:
            add(ERROR, c.principle, "duplicate control id")
        seen.add(c.id)
        if c.principle not in PRINCIPLES:
            add(ERROR, c.principle, f"unknown principle {c.principle!r} (expected 3.1 to 3.13)")
        if c.kind not in KINDS:
            add(ERROR, "3.2", f"kind must be one of {KINDS}, got {c.kind!r}")
        for name, why in _REQUIRED.items():
            if not getattr(c, name):
                add(ERROR, why.split(":")[0], f"missing {name} ({why})")

        # 3.2 -- a law holds against a compromised admin, and a third party can see it hold.
        if c.kind == "loi":
            if not c.resists_compromised_admin:
                add(ERROR, "3.2", "declared a law but a compromised production admin can lift it: it is a rule")
            if not c.third_party_check:
                add(ERROR, "3.2", "declared a law but names no third-party check: a promise, not a proof")
        elif not c.lifted_by:
            add(ERROR, "3.2", "a rule must say who can lift it")

        # 3.8 -- nothing irreversible is in one person's hand.
        if not c.reversible and len(set(c.lifted_by)) == 1:
            add(ERROR, "3.8", f"irreversible, yet a single role ({c.lifted_by[0]!r}) can lift it")

        # 3.10 -- quiet years prove nothing; reviews and waivers expire.
        if c.review_by is None:
            add(WARNING, "3.10", "no review date")
        elif c.review_by < today:
            add(WARNING, "3.10", f"review overdue since {c.review_by.isoformat()}")
        for exc in c.exceptions:
            if exc.expires is None:
                add(ERROR, "3.10", f"exception {exc.id!r} has no expiry: a permanent waiver is a removed control")
            elif exc.expires < today:
                add(ERROR, "3.10", f"exception {exc.id!r} expired on {exc.expires.isoformat()}")
            if not c.reversible and len(set(exc.approved_by)) < 2:
                add(ERROR, "3.8", f"exception {exc.id!r} on an irreversible control approved by fewer than two people")

    return out


def active_exceptions(registry: Registry, today: Optional[_dt.date] = None) -> list[tuple[str, str, int]]:
    """(control id, exception id, age in days) for every waiver still in force."""
    today = today or _dt.date.today()
    rows = []
    for c in registry.controls:
        for exc in c.exceptions:
            if exc.expires is None or exc.expires >= today:
                age = (today - exc.granted).days if exc.granted else -1
                rows.append((c.id, exc.id, age))
    return rows


def coverage(registry: Registry, today: Optional[_dt.date] = None) -> dict:
    """Portfolio view: principles left bare, effect classes without a property-based control."""
    by_p = registry.by_principle()
    effects: dict[str, bool] = {}
    for c in registry.controls:
        if c.effect_class:
            effects[c.effect_class] = effects.get(c.effect_class, False) or c.property_based
    return {
        "controls": len(registry.controls),
        "laws": sum(1 for c in registry.controls if c.kind == "loi"),
        "principles_without_control": [p for p in PRINCIPLES if not by_p.get(p)],
        "effect_classes_detection_only": sorted(e for e, prop in effects.items() if not prop),
        "active_exceptions": active_exceptions(registry, today),
    }
