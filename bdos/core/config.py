"""Configuration schema and loader.

Config is a set of frozen-ish dataclasses with safe defaults. It loads from
TOML (via the stdlib ``tomllib``) or a plain dict, and validates on the way in
so a malformed policy fails fast at boot rather than silently at runtime.

The defaults encode the BDOS doctrine: reads are free, writes are slowed,
admin/exfil actions are slowed hard and require a signed safety notice.
"""

from __future__ import annotations

import ipaddress
import re
import tomllib
from dataclasses import dataclass, field, fields, is_dataclass
from typing import Any

from bdos.core.crypto import b64d
from bdos.core.errors import ConfigError

# Action classes, ordered by blast radius. Everything maps onto one of these.
ACTION_CLASSES = ("read", "write", "admin", "exfil")
# The only class that never mutates or moves data; everything else is "hard".
NON_MUTATING = ("read",)

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)


def is_valid_egress_entry(entry: str) -> bool:
    """True if ``entry`` is a well-formed IP, CIDR, or hostname.

    Egress allowlist entries are interpolated into an ``nftables`` ruleset, so an
    entry that is neither a valid network nor a valid hostname is rejected at
    config load rather than injected into the firewall (see the compiler)."""
    if not isinstance(entry, str) or not entry or any(c.isspace() for c in entry):
        return False
    if any(c in entry for c in ";{}#\n\r\\\"'"):
        return False
    try:
        ipaddress.ip_network(entry, strict=False)
        return True
    except ValueError:
        pass
    return bool(_HOSTNAME_RE.match(entry))


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
    # Classes for which saturating the quota (required wait > max_delay) is a
    # hard DENY rather than a capped DELAY -- so throughput is bounded to the
    # refill rate, not to one burst per max_delay.
    deny_on_saturation: list[str] = field(default_factory=lambda: ["admin", "exfil"])
    # Upper bound on tracked principals; the least-recently-seen are evicted so
    # per-principal state cannot be grown without bound by id rotation.
    max_principals: int = 100_000

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
    # Number of high-confidence "hard" signals (canary trips, attestation
    # rejections) that trigger immediate quarantine regardless of decay. 1 means
    # a single tripped canary contains at once.
    hard_signal_quarantine: int = 1
    # Aggregate (decay-immune) score against a single enclave, summed across all
    # principals, that triggers containment -- defeats id-rotation attacks that
    # keep each principal below the per-principal threshold.
    enclave_aggregate_threshold: float = 150.0
    # Upper bound on tracked principals (LRU eviction of the lowest scorers).
    max_principals: int = 100_000
    # If False, the Sentinel still quarantines on its own (reversible) but only
    # *recommends* sealing (irreversible). Set by the control plane when sealing
    # requires a quorum.
    auto_seal: bool = True


@dataclass
class QuorumConfig:
    """m-of-n approval in front of irreversible actions ("the key must not be a person")."""

    # When True, sealing an enclave needs ``m`` distinct signed approvals and the
    # Sentinel stops sealing on its own.
    seal_requires_quorum: bool = False
    m: int = 2
    # approver id -> Ed25519 public key (url-safe base64, as printed by keygen).
    approvers: dict[str, str] = field(default_factory=dict)
    # Deliberate slowness: time between reaching quorum and being allowed to act.
    delay_seconds: float = 900.0
    # A request (and its approvals) is void this long after it was created.
    validity_seconds: float = 3600.0
    clock_skew: float = 5.0


@dataclass
class BDOSConfig:
    lightspeed: LightspeedConfig = field(default_factory=LightspeedConfig)
    safetynotice: SafetyNoticeConfig = field(default_factory=SafetyNoticeConfig)
    darkforest: DarkForestConfig = field(default_factory=DarkForestConfig)
    blackdomain: BlackDomainConfig = field(default_factory=BlackDomainConfig)
    sentinel: SentinelConfig = field(default_factory=SentinelConfig)
    quorum: QuorumConfig = field(default_factory=QuorumConfig)

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
        # A member in two enclaves could let a permissive enclave shadow a
        # sealed/strict one; forbid overlap so the router's decision is unique.
        seen_members: dict[str, str] = {}
        for enc in self.blackdomain.enclaves:
            for member in enc.members:
                if member in seen_members:
                    raise ConfigError(
                        f"member {member!r} is in both {seen_members[member]!r} and {enc.id!r}; "
                        "enclaves must not overlap"
                    )
                seen_members[member] = enc.id
            for dst in enc.egress_allow:
                if not is_valid_egress_entry(dst):
                    raise ConfigError(
                        f"enclave {enc.id!r} egress_allow entry {dst!r} is not a valid IP/CIDR/hostname"
                    )
        if self.sentinel.seal_threshold < self.sentinel.quarantine_threshold:
            raise ConfigError("sentinel.seal_threshold must be >= quarantine_threshold")
        if self.sentinel.decay_half_life_seconds <= 0:
            raise ConfigError("sentinel.decay_half_life_seconds must be positive")
        self._validate_quorum()
        return self

    def _validate_quorum(self) -> None:
        q = self.quorum
        if q.delay_seconds < 0 or q.clock_skew < 0:
            raise ConfigError("quorum.delay_seconds and quorum.clock_skew must be non-negative")
        if q.validity_seconds <= q.delay_seconds:
            raise ConfigError("quorum.validity_seconds must exceed quorum.delay_seconds")
        keys: dict[str, str] = {}
        for approver, pub in q.approvers.items():
            try:
                raw = b64d(pub)
            except (ValueError, TypeError) as exc:
                raise ConfigError(f"quorum approver {approver!r} has an undecodable key") from exc
            if len(raw) != 32:
                raise ConfigError(f"quorum approver {approver!r} key is not a 32-byte Ed25519 key")
            if raw in keys:
                raise ConfigError(
                    f"quorum approvers {keys[raw]!r} and {approver!r} share a key; "
                    "one person holding two seats is not a quorum"
                )
            keys[raw] = approver
        if q.seal_requires_quorum:
            if q.m < 2:
                raise ConfigError("quorum.m must be >= 2: a single approver is not a quorum")
            if len(q.approvers) < q.m:
                raise ConfigError(f"quorum.m = {q.m} but only {len(q.approvers)} approvers are enrolled")


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
        "quorum": QuorumConfig,
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
