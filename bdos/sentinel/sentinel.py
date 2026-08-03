"""Machine-speed containment -- "who holds the sword".

The other layers slow, attest, and segment; the Sentinel *decides when the
system has seen enough*. It listens to the tamper-evident event stream and
maintains a per-principal, time-decaying anomaly score. Each hostile signal --
a canary tripped, a safety notice rejected, a Lightspeed throttle pinned at its
ceiling -- pushes the score up; quiet time lets it bleed back down. When the
score crosses a threshold the Sentinel escalates on a ladder: first quarantine
(raise the principal's Lightspeed suspicion so every further action is
crushingly slow), then seal the associated black-domain enclave outright.

Containment happens at machine speed only when ``cfg.auto_contain`` is set. When
it is not, the Sentinel merely *recommends* -- it emits a recommendation event
and stays its hand, because the human holds the sword.
"""

from __future__ import annotations

from typing import Iterable, Mapping, Optional, Union

from bdos.core.clock import Clock, SystemClock
from bdos.core.config import SentinelConfig
from bdos.core.events import Event, EventLog, Severity


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
        Each enclave need only provide ``seal()`` and a ``sealed`` flag.
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
        self._quarantined: set[str] = set()
        # Latches so each rung of the ladder fires exactly once per principal.
        self._acted_quarantine: set[str] = set()
        self._acted_seal: set[str] = set()
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
        current = self._decayed(pid, now)
        self._scores[pid] = (current + points, now)
        self._escalate(pid, now)

    def score_of(self, principal_id: str, now: Optional[float] = None) -> float:
        """Return ``principal_id``'s anomaly score decayed to ``now``.

        ``now`` defaults to the clock's wall time, so a score read long after
        the last event reflects the decay that has elapsed since.
        """
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
        """Points a single event contributes -- the strongest matching signal.

        The kind-specific, capped-Lightspeed, and severity signals are combined
        by taking the maximum so a single event is scored by its worst aspect
        rather than double-counted.
        """
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

    # -- escalation ladder ---------------------------------------------
    def _escalate(self, principal_id: str, now: float) -> None:
        """Apply the quarantine-then-seal ladder for the current score."""
        score = self._decayed(principal_id, now)

        if (
            score >= self.cfg.quarantine_threshold
            and principal_id not in self._acted_quarantine
        ):
            self._acted_quarantine.add(principal_id)
            self._quarantine(principal_id, score, now)

        if score >= self.cfg.seal_threshold and principal_id not in self._acted_seal:
            self._acted_seal.add(principal_id)
            self._seal_enclave(principal_id, score, now)

    def _quarantine(self, principal_id: str, score: float, now: float) -> None:
        """Contain (or, without auto-contain, merely recommend containing)."""
        data = {"score": round(score, 4), "threshold": self.cfg.quarantine_threshold}
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

    def _seal_enclave(self, principal_id: str, score: float, now: float) -> None:
        """Seal the principal's enclave (or recommend it) at machine speed."""
        enclave = self._enclave_for(principal_id)
        data = {
            "score": round(score, 4),
            "threshold": self.cfg.seal_threshold,
            "enclave": self._enclave_id(enclave),
        }
        if not self.cfg.auto_contain:
            self._emit(
                "sentinel.recommend_seal",
                Severity.WARNING,
                principal_id,
                f"recommend sealing enclave for {principal_id} (anomaly score {score:.1f})",
                data,
                now,
            )
            return
        if enclave is not None and not getattr(enclave, "sealed", False):
            enclave.seal()
        self._emit(
            "sentinel.seal",
            Severity.CRITICAL,
            principal_id,
            f"sealed enclave for {principal_id} (anomaly score {score:.1f})",
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
