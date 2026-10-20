"""The control registry -- every rule carries its scar and its weapon.

A security control that nobody can explain is either kept forever out of fear or
dropped the day it gets in the way. The registry makes each control state, in
data, what the essay's principles ask of it:

* ``scar`` -- the attack it is the scar of (principle 3.13);
* ``threat_hypothesis`` / ``effect_class`` -- the weapon it was designed against,
  and whether it holds by *property* or only by detecting that weapon (3.9);
* ``kind`` -- a ``loi`` (law: holds against a compromised production admin and
  can be checked by a third party) or a ``regle`` (rule: someone can lift it)
  (3.2);
* ``lifted_by`` / ``reversible`` -- who can lift it, and whether lifting or
  acting on it can be undone (3.8);
* ``review_by`` and dated ``exceptions`` -- so "nothing happened for years" is
  re-examined rather than trusted (3.10).

The registry loads from TOML (stdlib ``tomllib``, like :mod:`bdos.core.config`);
:mod:`bdos.registry.validate` checks it.
"""

from __future__ import annotations

import datetime as _dt
import tomllib
from dataclasses import dataclass, field, fields
from typing import Any, Optional

from bdos.core.errors import ConfigError

# The thirteen principles of docs/domaine-noir-cyberdefense.md, section 3.
PRINCIPLES = {
    "3.1": "ce qui sort, pas seulement ce qui entre",
    "3.2": "une loi, pas une règle ; une preuve, pas une promesse",
    "3.3": "toute émission est une coordonnée",
    "3.4": "une émission ne se rappelle pas",
    "3.5": "la réponse est l'information",
    "3.6": "le sortilège : mesurer avec un leurre",
    "3.7": "sous les intellectrons",
    "3.8": "la clé ne doit pas être une personne",
    "3.9": "le Bunker : modèle de menace contre propriété",
    "3.10": "deux siècles sans défaite ne prouvent rien",
    "3.11": "ne masse jamais la flotte",
    "3.12": "la chaîne de suspicion se déplace",
    "3.13": "le milieu",
}
KINDS = ("loi", "regle")


def _date(value: Any, what: str) -> _dt.date:
    if isinstance(value, _dt.datetime):
        return value.date()
    if isinstance(value, _dt.date):
        return value
    if isinstance(value, str):
        try:
            return _dt.date.fromisoformat(value)
        except ValueError as exc:
            raise ConfigError(f"{what}: {value!r} is not an ISO date") from exc
    raise ConfigError(f"{what}: expected a date, got {type(value).__name__}")


@dataclass
class ControlException:
    """A dated, approved waiver of one control."""

    id: str
    reason: str
    expires: Optional[_dt.date] = None
    approved_by: list[str] = field(default_factory=list)
    granted: Optional[_dt.date] = None


@dataclass
class Control:
    id: str
    principle: str
    title: str
    kind: str = "regle"
    scar: str = ""
    threat_hypothesis: str = ""
    effect_class: str = ""
    # True if the control holds whatever the weapon (a diode, a quorum), False if
    # it works by recognising one particular weapon (a signature, a blocklist).
    property_based: bool = False
    lifted_by: list[str] = field(default_factory=list)
    resists_compromised_admin: bool = False
    third_party_check: str = ""
    reversible: bool = True
    indicator: str = ""
    owner: str = ""
    review_by: Optional[_dt.date] = None
    exceptions: list[ControlException] = field(default_factory=list)


@dataclass
class Registry:
    controls: list[Control] = field(default_factory=list)

    def by_principle(self) -> dict[str, list[Control]]:
        out: dict[str, list[Control]] = {p: [] for p in PRINCIPLES}
        for c in self.controls:
            out.setdefault(c.principle, []).append(c)
        return out


def _build_exception(data: dict, where: str) -> ControlException:
    known = {f.name for f in fields(ControlException)}
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"{where}: unknown exception keys {sorted(unknown)}")
    if "id" not in data or "reason" not in data:
        raise ConfigError(f"{where}: an exception needs an id and a reason")
    kw = dict(data)
    for key in ("expires", "granted"):
        if kw.get(key) is not None:
            kw[key] = _date(kw[key], f"{where}.{key}")
    return ControlException(**kw)


def _build_control(data: dict, index: int) -> Control:
    where = f"control[{index}]"
    if not isinstance(data, dict):
        raise ConfigError(f"{where}: expected a table")
    known = {f.name for f in fields(Control)} | {"exception"}
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"{where}: unknown keys {sorted(unknown)}")
    for key in ("id", "principle", "title"):
        if not data.get(key):
            raise ConfigError(f"{where}: missing {key!r}")
    kw = {k: v for k, v in data.items() if k not in ("exception", "exceptions")}
    kw["principle"] = str(kw["principle"])
    if kw.get("review_by") is not None:
        kw["review_by"] = _date(kw["review_by"], f"{where}.review_by")
    raw_exc = data.get("exception", []) + data.get("exceptions", [])
    kw["exceptions"] = [_build_exception(e, f"{where}.exception[{i}]") for i, e in enumerate(raw_exc)]
    return Control(**kw)


def from_dict(data: dict) -> Registry:
    unknown = set(data) - {"control"}
    if unknown:
        raise ConfigError(f"unknown registry sections: {sorted(unknown)}")
    return Registry([_build_control(c, i) for i, c in enumerate(data.get("control", []))])


def load(path: str) -> Registry:
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except FileNotFoundError as exc:
        raise ConfigError(f"registry not found: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc
    return from_dict(data)
