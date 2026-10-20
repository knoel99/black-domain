"""Machine-speed containment -- "who holds the sword".

The other layers slow, attest, and segment; the Sentinel *decides when the
system has seen enough*. It listens to the tamper-evident event stream and
maintains a per-principal, time-decaying anomaly score. Each hostile signal --
a canary tripped, a safety notice rejected, a Lightspeed throttle pinned at its
ceiling -- pushes the score up; quiet time lets it bleed back down. When the
score crosses a threshold the Sentinel escalates on a ladder: first quarantine
(raise the principal's Lightspeed suspicion so every further action is
crushingly slow), then seal the associated black-domain enclave outright.

Two mechanisms harden this against a patient or shape-shifting attacker. A
*decay-immune hard-signal counter* means a single unambiguously hostile event (a
tripped canary) contains at once, no matter how slowly it is paced -- decay can
never erode a high-confidence signal below the line. And a *per-enclave aggregate*
sums hostile pressure against each protected enclave across all principals, so an
attacker who rotates principal ids to keep each one under the per-principal
threshold still trips containment on the enclave they are hammering.

Containment happens at machine speed only when ``cfg.auto_contain`` is set. When
it is not, the Sentinel merely *recommends* -- it emits a recommendation event
and stays its hand, because the human holds the sword.
"""

from __future__ import annotations

from typing import Iterable, Mapping, Optional, Union

from bdos.core.clock import Clock, SystemClock
from bdos.core.config import SentinelConfig
from bdos.core.events import Event, EventLog, Severity

# Events that are, on their own, unambiguous evidence of hostility (near-zero
# false positives): touching a canary is never legitimate. These drive the
# decay-immune immediate-quarantine counter. An attestation rejection is
# deliberately NOT here -- a human who forgets a notice once should be denied,
# not quarantined; repeated rejections still accumulate via the decaying score.
_HARD_QUARANTINE_KINDS = ("darkforest.canary_tripped",)
# Hostile signals that add to an enclave's aggregate pressure (the id-rotation
# defence), even when no single principal crosses its own threshold.
_AGGREGATE_KINDS = (
    "darkforest.canary_tripped",
    "safetynotice.rejected",
    "blackdomain.action_denied",
    "blackdomain.egress_denied",
)
_EPSILON = 1e-9


class Sentinel:
    """Consumes the event stream and enforces the escalation ladder.

    :param cfg: thresholds, decay half-life, and the ``auto_contain`` switch.
    :param clock: time source; :meth:`score_of` decays to ``clock.wall()`` by
        default and defaults to a :class:`~bdos.core.clock.SystemClock`.
    :param throttle: an object exposing ``set_suspicion(principal_id, factor)``
        (a :class:`~bdos.lightspeed.LightspeedThrottle`); used to make a
        quarantined principal's actions ruinously slow.
    :param enclaves: how to find the enclave to seal for a principal. Either a
        mapping ``{principal_id_or_enclave_id: enclave}`` (looked up directly) or
        an iterable of enclaves (matched by ``enclave.contains(principal_id)``).
        Each enclave need only provide ``seal()``, a ``sealed`` flag, and ideally
        an ``id``/``spec.id``.
    :param log: the event log the Sentinel writes its own containment events to.
        Usually the same log it observes; :meth:`attach` sets it if unset.
    """

    # Points contributed by a single event, by dotted kind.
    _KIND_SCORES = {
        "darkforest.canary_tripped": 80.0,
        "safetynotice.rejected": 40.0,
    }
    # Points contributed by a single event, by severity.
    _SEVERITY_SCORES = {
        Severity.ALERT: 25.0,
        Severity.CRITICAL: 50.0,
    }
    # Points for a Lightspeed action that hit the delay ceiling.
    _CAPPED_LIGHTSPEED = 15.0

    def __init__(
        self,
        cfg: Optional[SentinelConfig] = None,
        clock: Optional[Clock] = None,
        throttle=None,
        enclaves: Union[Mapping[str, object], Iterable[object], None] = None,
        log: Optional[EventLog] = None,
    ) -> None:
        self.cfg = cfg or SentinelConfig()
        self.clock = clock or SystemClock()
        self.throttle = throttle
        self.log = log
        # principal_id -> (score_at_stamp, stamp_wall_time)
        self._scores: dict[str, tuple[float, float]] = {}
        # principal_id -> count of high-confidence hostile signals (no decay)
        self._hard_signals: dict[str, int] = {}
        # enclave_id -> aggregate hostile pressure across all principals (no decay)
        self._enclave_scores: dict[str, float] = {}
        self._quarantined: set[str] = set()
        # Latches so each rung of the ladder fires exactly once.
        self._acted_quarantine: set[str] = set()
        self._acted_seal: set[str] = set()
        self._acted_enclave_seal: set[str] = set()
        self._enclaves, self._enclave_list = self._normalize_enclaves(enclaves)

    # -- wiring ---------------------------------------------------------
    def attach(self, log: EventLog) -> None:
        """Subscribe to ``log`` so every append flows through :meth:`observe`.

        If no output log was supplied at construction, ``log`` also becomes the
        sink for the Sentinel's own containment events.
        """
        if self.log is None:
            self.log = log
        log.subscribe(self.observe)

    # -- observation ----------------------------------------------------
    def observe(self, event: Event) -> None:
        """Fold one event into the emitting principal's score and escalate.

        The Sentinel's own ``sentinel.*`` events are ignored so it never scores
        its own reactions, and events without a principal have nothing to
        attribute and are skipped.
        """
        if event.kind.startswith("sentinel."):
            return
        pid = event.principal_id
        if not pid:
            return
        now = event.ts
        points = self._score_event(event)

        new_score = self._decayed(pid, now) + points
        if new_score < _EPSILON and not self._is_sticky(pid):
            self._scores.pop(pid, None)
        else:
            self._scores[pid] = (new_score, now)

        if event.kind in _HARD_QUARANTINE_KINDS:
            self._hard_signals[pid] = self._hard_signals.get(pid, 0) + 1
        if event.kind in _AGGREGATE_KINDS:
            enclave = self._enclave_for_event(event, pid)
            eid = self._enclave_id(enclave)
            if eid is not None:
                self._enclave_scores[eid] = self._enclave_scores.get(eid, 0.0) + points

        self._escalate(pid, now)
        self._escalate_enclave(event, pid, now)
        self._bound_state(now)

    def score_of(self, principal_id: str, now: Optional[float] = None) -> float:
        """Return ``principal_id``'s anomaly score decayed to ``now``."""
        if now is None:
            now = self.clock.wall()
        return self._decayed(principal_id, now)

    def is_quarantined(self, principal_id: str) -> bool:
        """True once the Sentinel has actually contained this principal."""
        return principal_id in self._quarantined

    @property
    def quarantined(self) -> set[str]:
        """The set of currently contained principals (a copy)."""
        return set(self._quarantined)

    # -- scoring internals ---------------------------------------------
    def _score_event(self, event: Event) -> float:
        """Points a single event contributes -- the strongest matching signal."""
        points = self._KIND_SCORES.get(event.kind, 0.0)
        if event.kind.startswith("lightspeed.") and event.data.get("capped") is True:
            points = max(points, self._CAPPED_LIGHTSPEED)
        return max(points, self._SEVERITY_SCORES.get(event.severity, 0.0))

    def _decayed(self, principal_id: str, now: float) -> float:
        """Exponentially decay a stored score to ``now`` (half-life from cfg)."""
        entry = self._scores.get(principal_id)
        if entry is None:
            return 0.0
        value, stamp = entry
        half = self.cfg.decay_half_life_seconds
        if value <= 0.0 or half <= 0.0 or now <= stamp:
            return value
        return value * (0.5 ** ((now - stamp) / half))

    def _is_sticky(self, principal_id: str) -> bool:
        """Principals we must never forget: already contained or hard-flagged."""
        return (
            principal_id in self._quarantined
            or principal_id in self._acted_quarantine
            or self._hard_signals.get(principal_id, 0) > 0
        )

    # -- state bounding -------------------------------------------------
    def _bound_state(self, now: float) -> None:
        """Cap the number of tracked principals; evict the coldest non-sticky."""
        cap = max(1, self.cfg.max_principals)
        if len(self._scores) <= cap:
            return
        evictable = [
            (self._decayed(pid, now), pid)
            for pid in self._scores
            if not self._is_sticky(pid)
        ]
        evictable.sort()
        for _, pid in evictable[: len(self._scores) - cap]:
            self._scores.pop(pid, None)

    # -- escalation ladder (per principal) -----------------------------
    def _escalate(self, principal_id: str, now: float) -> None:
        """Apply the quarantine-then-seal ladder for the current score."""
        score = self._decayed(principal_id, now)
        hard = self._hard_signals.get(principal_id, 0)

        crosses_quarantine = (
            score >= self.cfg.quarantine_threshold
            or hard >= self.cfg.hard_signal_quarantine
        )
        if crosses_quarantine and principal_id not in self._acted_quarantine:
            self._acted_quarantine.add(principal_id)
            self._quarantine(principal_id, score, now)

        if score >= self.cfg.seal_threshold and principal_id not in self._acted_seal:
            self._acted_seal.add(principal_id)
            self._seal_enclave(principal_id, self._enclave_for(principal_id), score, now,
                               reason=f"per-principal score {score:.1f}")

    def _escalate_enclave(self, event: Event, principal_id: str, now: float) -> None:
        """Seal an enclave whose aggregate hostile pressure crosses the line.

        This is the id-rotation defence: N principals each staying below the
        per-principal threshold still sum past ``enclave_aggregate_threshold`` on
        the enclave they are attacking.
        """
        enclave = self._enclave_for_event(event, principal_id)
        eid = self._enclave_id(enclave)
        if eid is None or eid in self._acted_enclave_seal:
            return
        if self._enclave_scores.get(eid, 0.0) >= self.cfg.enclave_aggregate_threshold:
            self._acted_enclave_seal.add(eid)
            self._seal_enclave(
                principal_id, enclave, self._enclave_scores[eid], now,
                reason=f"enclave aggregate pressure {self._enclave_scores[eid]:.1f}",
            )

    def _quarantine(self, principal_id: str, score: float, now: float) -> None:
        """Contain (or, without auto-contain, merely recommend containing)."""
        data = {"score": round(score, 4), "threshold": self.cfg.quarantine_threshold,
                "hard_signals": self._hard_signals.get(principal_id, 0)}
        if not self.cfg.auto_contain:
            self._emit(
                "sentinel.recommend_quarantine",
                Severity.WARNING,
                principal_id,
                f"recommend quarantine of {principal_id} (anomaly score {score:.1f})",
                data,
                now,
            )
            return
        if self.throttle is not None:
            self.throttle.set_suspicion(principal_id, self.cfg.suspicion_delay_factor)
        self._quarantined.add(principal_id)
        self._emit(
            "sentinel.quarantine",
            Severity.ALERT,
            principal_id,
            f"quarantined {principal_id} (anomaly score {score:.1f})",
            {**data, "suspicion_factor": self.cfg.suspicion_delay_factor},
            now,
        )

    def _seal_enclave(self, principal_id: str, enclave, score: float, now: float, reason: str) -> None:
        """Seal an enclave (or recommend it) at machine speed."""
        data = {
            "score": round(score, 4),
            "enclave": self._enclave_id(enclave),
            "trigger": reason,
        }
        # Sealing is irreversible: with auto_seal off (sealing needs a quorum)
        # the Sentinel keeps its reversible reflex -- quarantine -- and only
        # recommends the irreversible one.
        if not self.cfg.auto_contain or not self.cfg.auto_seal:
            if not self.cfg.auto_seal:
                data["requires_quorum"] = True
            self._emit(
                "sentinel.recommend_seal",
                Severity.WARNING,
                principal_id,
                f"recommend sealing enclave for {principal_id} ({reason})",
                data,
                now,
            )
            return
        # If the enclave is already sealed (e.g. the per-principal rung fired
        # first, or the aggregate rung), don't emit a second seal event.
        if enclave is not None and getattr(enclave, "sealed", False):
            return
        if enclave is not None:
            enclave.seal()
        self._emit(
            "sentinel.seal",
            Severity.CRITICAL,
            principal_id,
            f"sealed enclave for {principal_id} ({reason})",
            data,
            now,
        )

    # -- enclave resolution --------------------------------------------
    @staticmethod
    def _normalize_enclaves(
        enclaves: Union[Mapping[str, object], Iterable[object], None],
    ) -> tuple[dict[str, object], list[object]]:
        """Split the ``enclaves`` argument into a direct map and a scan list."""
        if enclaves is None:
            return {}, []
        if isinstance(enclaves, Mapping):
            return dict(enclaves), list(enclaves.values())
        listed = list(enclaves)
        mapping: dict[str, object] = {}
        for enclave in listed:
            eid = Sentinel._enclave_id(enclave)
            if eid:
                mapping[eid] = enclave
        return mapping, listed

    def _enclave_for(self, principal_id: str) -> Optional[object]:
        """Find the enclave to seal: direct key first, then membership scan."""
        enclave = self._enclaves.get(principal_id)
        if enclave is not None:
            return enclave
        for enclave in self._enclave_list:
            contains = getattr(enclave, "contains", None)
            if callable(contains) and contains(principal_id):
                return enclave
        return None

    def _enclave_for_event(self, event: Event, principal_id: str) -> Optional[object]:
        """Resolve the enclave an event pertains to (event data, then principal)."""
        eid = event.data.get("enclave")
        if eid and eid in self._enclaves:
            return self._enclaves[eid]
        return self._enclave_for(principal_id)

    @staticmethod
    def _enclave_id(enclave: Optional[object]) -> Optional[str]:
        """Best-effort id for an enclave (``spec.id`` or an ``id`` attribute)."""
        if enclave is None:
            return None
        spec = getattr(enclave, "spec", None)
        spec_id = getattr(spec, "id", None)
        if spec_id:
            return spec_id
        return getattr(enclave, "id", None)

    # -- emission -------------------------------------------------------
    def _emit(
        self,
        kind: str,
        severity: Severity,
        principal_id: str,
        message: str,
        data: dict,
        now: float,
    ) -> Event:
        """Append a Sentinel event to the log (if any) and return it."""
        event = Event(
            ts=now,
            kind=kind,
            severity=severity,
            principal_id=principal_id,
            message=message,
            data=data,
        )
        if self.log is not None:
            self.log.append(event)
        return event
