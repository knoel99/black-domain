"""Configuration schema and loader.

Config is a set of frozen-ish dataclasses with safe defaults. It loads from
TOML (via the stdlib ``tomllib``) or a plain dict, and validates on the way in
so a malformed policy fails fast at boot rather than silently at runtime.

The defaults encode the BDOS doctrine: reads are free, writes are slowed,
admin/exfil actions are slowed hard and require a signed safety notice.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field, fields, is_dataclass
from typing import Any

from bdos.core.errors import ConfigError

# Action classes, ordered by blast radius. Everything maps onto one of these.
ACTION_CLASSES = ("read", "write", "admin", "exfil")


@dataclass
class LightspeedConfig:
    """Progressive-delay / rate-limit parameters (the 'reduce c' layer)."""

    base_delay: float = 0.0
    max_delay: float = 30.0
    window_seconds: float = 60.0
    # Seconds of delay added per unit of burst score (see cadence.py).
    burst_penalty: float = 0.75
    # Per-action-class delay multiplier applied to the burst penalty.
    tier_multiplier: dict[str, float] = field(
        default_factory=lambda: {"read": 0.0, "write": 1.0, "admin": 3.0, "exfil": 8.0}
    )
    # Token bucket per action class: burst capacity and refill rate (per second).
    quota_capacity: dict[str, float] = field(
        default_factory=lambda: {"read": 1000.0, "write": 60.0, "admin": 10.0, "exfil": 3.0}
    )
    quota_refill_per_sec: dict[str, float] = field(
        default_factory=lambda: {"read": 50.0, "write": 1.0, "admin": 0.05, "exfil": 0.01}
    )
    # Mean inter-arrival (s) at/above which a cadence looks humanlike.
    human_cadence_threshold: float = 1.0

    def multiplier(self, action_class: str) -> float:
        return self.tier_multiplier.get(action_class, 1.0)


@dataclass
class SafetyNoticeConfig:
    """Signed-capability (proof-of-legitimacy) parameters."""

    default_ttl: float = 300.0
    clock_skew: float = 5.0
    # Action classes that MUST carry a valid safety notice to proceed.
    require_for: list[str] = field(default_factory=lambda: ["admin", "exfil"])
    replay_cache_size: int = 100_000


@dataclass
class DarkForestConfig:
    """Moving-target + deception parameters."""

    mtd_epoch_seconds: float = 300.0
    mtd_secret: str = ""  # empty => generated at boot; set for reproducibility
    mtd_port_low: int = 20000
    mtd_port_high: int = 60000
    services: list[str] = field(default_factory=list)
    canary_paths: list[str] = field(default_factory=list)


@dataclass
class EnclaveSpec:
    id: str
    members: list[str] = field(default_factory=list)
    egress_allow: list[str] = field(default_factory=list)  # CIDRs / hostnames
    sealed: bool = False


@dataclass
class BlackDomainConfig:
    enclaves: list[EnclaveSpec] = field(default_factory=list)


@dataclass
class SentinelConfig:
    """Machine-speed containment ('who holds the sword') parameters."""

    # Cumulative anomaly score at which a principal is quarantined.
    quarantine_threshold: float = 100.0
    # Score at which the affected enclave is auto-sealed.
    seal_threshold: float = 200.0
    # Rolling window for score decay.
    decay_half_life_seconds: float = 300.0
    # If False, the Sentinel only recommends; a human must confirm containment.
    auto_contain: bool = True
    # Multiplier applied to Lightspeed delay when a principal is under suspicion.
    suspicion_delay_factor: float = 5.0


@dataclass
class BDOSConfig:
    lightspeed: LightspeedConfig = field(default_factory=LightspeedConfig)
    safetynotice: SafetyNoticeConfig = field(default_factory=SafetyNoticeConfig)
    darkforest: DarkForestConfig = field(default_factory=DarkForestConfig)
    blackdomain: BlackDomainConfig = field(default_factory=BlackDomainConfig)
    sentinel: SentinelConfig = field(default_factory=SentinelConfig)

    def validate(self) -> "BDOSConfig":
        ls = self.lightspeed
        if ls.max_delay < 0 or ls.base_delay < 0:
            raise ConfigError("lightspeed delays must be non-negative")
        if ls.window_seconds <= 0:
            raise ConfigError("lightspeed.window_seconds must be positive")
        for ac in self.safetynotice.require_for:
            if ac not in ACTION_CLASSES:
                raise ConfigError(f"safetynotice.require_for has unknown action class {ac!r}")
        if self.darkforest.mtd_port_low >= self.darkforest.mtd_port_high:
            raise ConfigError("darkforest mtd port range is empty")
        ids = [e.id for e in self.blackdomain.enclaves]
        if len(ids) != len(set(ids)):
            raise ConfigError("duplicate enclave id")
        if self.sentinel.seal_threshold < self.sentinel.quarantine_threshold:
            raise ConfigError("sentinel.seal_threshold must be >= quarantine_threshold")
        return self


def _build(cls, data: Any):
    """Recursively coerce a dict into dataclass ``cls`` (shallow, one level of
    nested dataclasses and lists of dataclasses supported)."""
    if not is_dataclass(cls):
        return data
    if not isinstance(data, dict):
        raise ConfigError(f"expected table for {cls.__name__}, got {type(data).__name__}")
    kwargs = {}
    known = {f.name: f for f in fields(cls)}
    for key, value in data.items():
        if key not in known:
            raise ConfigError(f"unknown config key {key!r} in {cls.__name__}")
        f = known[key]
        # list[EnclaveSpec]
        if key == "enclaves":
            kwargs[key] = [_build(EnclaveSpec, item) for item in value]
        else:
            kwargs[key] = value
    return cls(**kwargs)


def from_dict(data: dict) -> BDOSConfig:
    sections = {
        "lightspeed": LightspeedConfig,
        "safetynotice": SafetyNoticeConfig,
        "darkforest": DarkForestConfig,
        "blackdomain": BlackDomainConfig,
        "sentinel": SentinelConfig,
    }
    kwargs = {}
    for name, cls in sections.items():
        if name in data:
            kwargs[name] = _build(cls, data[name])
    unknown = set(data) - set(sections)
    if unknown:
        raise ConfigError(f"unknown config sections: {sorted(unknown)}")
    return BDOSConfig(**kwargs).validate()


def load(path: str) -> BDOSConfig:
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except FileNotFoundError as exc:
        raise ConfigError(f"config not found: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc
    return from_dict(data)


def default() -> BDOSConfig:
    return BDOSConfig().validate()
