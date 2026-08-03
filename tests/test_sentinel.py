from bdos.core.clock import ManualClock
from bdos.core.config import SentinelConfig
from bdos.core.events import Event, EventLog, Severity
from bdos.core.identity import Principal
from bdos.lightspeed import LightspeedThrottle
from bdos.sentinel import Sentinel


# -- local test doubles (kept independent of the black-domain layer) ------
class FakeEnclave:
    """Duck-typed stand-in for a black-domain enclave (seal() + sealed flag)."""

    def __init__(self, id: str = "crown-jewels") -> None:
        self.id = id
        self.sealed = False

    def seal(self) -> None:
        self.sealed = True


class FakeMemberEnclave(FakeEnclave):
    """A fake enclave that also answers membership, for list-form lookup."""

    def __init__(self, id: str, members) -> None:
        super().__init__(id)
        self._members = set(members)

    def contains(self, member: str) -> bool:
        return member in self._members


class RecordingThrottle:
    """Records set_suspicion calls so tests can assert on containment."""

    def __init__(self) -> None:
        self.suspicion: dict[str, float] = {}

    def set_suspicion(self, principal_id: str, factor: float) -> None:
        self.suspicion[principal_id] = factor

    def clear_suspicion(self, principal_id: str) -> None:
        self.suspicion.pop(principal_id, None)


# -- helpers --------------------------------------------------------------
def _cfg(**kw) -> SentinelConfig:
    return SentinelConfig(**kw)


def _canary(clk: ManualClock, pid: str) -> Event:
    return Event(
        ts=clk.wall(),
        kind="darkforest.canary_tripped",
        severity=Severity.CRITICAL,
        principal_id=pid,
        message="canary tripped",
    )


def _rejection(clk: ManualClock, pid: str) -> Event:
    return Event(
        ts=clk.wall(),
        kind="safetynotice.rejected",
        severity=Severity.ALERT,
        principal_id=pid,
        message="safety notice rejected",
    )


def _benign(clk: ManualClock, pid: str) -> Event:
    return Event(
        ts=clk.wall(),
        kind="lightspeed.guard",
        severity=Severity.INFO,
        principal_id=pid,
        action_class="read",
        data={"capped": False},
    )


def _sentinel_kinds(log: EventLog) -> list[str]:
    return [r.event.kind for r in log.records if r.event.kind.startswith("sentinel.")]


# -- tests ----------------------------------------------------------------
def test_benign_events_do_not_quarantine():
    clk = ManualClock()
    log = EventLog()
    throttle = RecordingThrottle()
    sent = Sentinel(_cfg(), clock=clk, throttle=throttle, log=log)
    sent.attach(log)

    pid = "alice"
    for _ in range(25):
        log.append(_benign(clk, pid))

    assert sent.score_of(pid) == 0.0
    assert not sent.is_quarantined(pid)
    assert throttle.suspicion == {}
    assert _sentinel_kinds(log) == []
    assert log.verify()


def test_canary_and_rejections_cross_quarantine_and_set_suspicion():
    clk = ManualClock()
    log = EventLog()
    throttle = RecordingThrottle()
    cfg = _cfg()  # quarantine at 100, seal at 200 (defaults)
    sent = Sentinel(cfg, clock=clk, throttle=throttle, log=log)
    sent.attach(log)

    pid = "rogue"
    log.append(_canary(clk, pid))  # +80 -> 80, below threshold
    assert not sent.is_quarantined(pid)

    log.append(_rejection(clk, pid))  # +40 -> 120, crosses quarantine
    log.append(_rejection(clk, pid))  # +40 -> 160, still below seal

    assert sent.is_quarantined(pid)
    assert pid in sent.quarantined
    assert throttle.suspicion[pid] == cfg.suspicion_delay_factor

    # The Sentinel does not score its own ALERT quarantine event: 160, not 185.
    assert abs(sent.score_of(pid) - 160.0) < 1e-9

    quarantines = [r.event for r in log.records if r.event.kind == "sentinel.quarantine"]
    assert len(quarantines) == 1  # fires once, not on every further event
    assert quarantines[0].severity is Severity.ALERT
    assert quarantines[0].principal_id == pid

    # An unrelated principal is untouched.
    assert not sent.is_quarantined("bob")
    assert log.verify()


def test_decay_reduces_score_over_time():
    clk = ManualClock()
    log = EventLog()
    cfg = _cfg(decay_half_life_seconds=300.0)
    sent = Sentinel(cfg, clock=clk, log=log)
    sent.attach(log)

    pid = "p"
    t0 = clk.wall()
    log.append(_canary(clk, pid))  # +80 at t0

    assert abs(sent.score_of(pid, now=t0) - 80.0) < 1e-9
    assert abs(sent.score_of(pid, now=t0 + 300.0) - 40.0) < 1e-9  # one half-life
    assert abs(sent.score_of(pid, now=t0 + 600.0) - 20.0) < 1e-9  # two half-lives


def test_score_accumulates_with_decay_between_events():
    clk = ManualClock()
    log = EventLog()
    # High thresholds so nothing escalates -- this test is purely about scoring.
    cfg = _cfg(decay_half_life_seconds=300.0, quarantine_threshold=1e6, seal_threshold=1e6)
    sent = Sentinel(cfg, clock=clk, log=log)
    sent.attach(log)

    pid = "p"
    log.append(_canary(clk, pid))  # 80 at t0
    clk.advance(300.0)             # one half-life passes: 80 -> 40
    log.append(_canary(clk, pid))  # +80 -> 120

    assert abs(sent.score_of(pid, now=clk.wall()) - 120.0) < 1e-9


def test_auto_contain_false_recommends_but_does_not_contain():
    clk = ManualClock()
    log = EventLog()
    throttle = RecordingThrottle()
    enclave = FakeEnclave()
    cfg = _cfg(auto_contain=False, quarantine_threshold=100.0, seal_threshold=150.0)
    sent = Sentinel(cfg, clock=clk, throttle=throttle, enclaves={"rogue": enclave}, log=log)
    sent.attach(log)

    pid = "rogue"
    log.append(_canary(clk, pid))  # 80
    log.append(_canary(clk, pid))  # 160 -> crosses BOTH thresholds

    # The human holds the sword: nothing is actually contained.
    assert not sent.is_quarantined(pid)
    assert pid not in sent.quarantined
    assert throttle.suspicion == {}
    assert enclave.sealed is False

    kinds = _sentinel_kinds(log)
    assert "sentinel.recommend_quarantine" in kinds
    assert "sentinel.quarantine" not in kinds
    assert "sentinel.seal" not in kinds

    recs = [r.event for r in log.records if r.event.kind == "sentinel.recommend_quarantine"]
    assert recs[0].severity is Severity.WARNING
    assert log.verify()


def test_crossing_seal_threshold_seals_enclave():
    clk = ManualClock()
    log = EventLog()
    throttle = RecordingThrottle()
    enclave = FakeEnclave(id="crown-jewels")
    cfg = _cfg(quarantine_threshold=100.0, seal_threshold=150.0)
    sent = Sentinel(cfg, clock=clk, throttle=throttle, enclaves={"rogue": enclave}, log=log)
    sent.attach(log)

    pid = "rogue"
    assert not enclave.sealed
    log.append(_canary(clk, pid))  # 80 -> below quarantine
    log.append(_canary(clk, pid))  # 160 -> quarantine (100) AND seal (150)

    assert sent.is_quarantined(pid)
    assert throttle.suspicion[pid] == cfg.suspicion_delay_factor
    assert enclave.sealed is True

    seals = [r.event for r in log.records if r.event.kind == "sentinel.seal"]
    assert len(seals) == 1
    assert seals[0].severity is Severity.CRITICAL
    assert seals[0].data["enclave"] == "crown-jewels"
    assert log.verify()


def test_enclave_lookup_by_membership_from_list():
    clk = ManualClock()
    log = EventLog()
    enclave = FakeMemberEnclave("vault", members=["rogue"])
    cfg = _cfg(quarantine_threshold=100.0, seal_threshold=150.0)
    sent = Sentinel(cfg, clock=clk, enclaves=[enclave], log=log)
    sent.attach(log)

    pid = "rogue"
    log.append(_canary(clk, pid))
    log.append(_canary(clk, pid))  # 160 -> seal

    assert enclave.sealed is True


def test_integrates_with_real_lightspeed_throttle():
    clk = ManualClock()
    log = EventLog()
    throttle = LightspeedThrottle()
    cfg = _cfg()
    sent = Sentinel(cfg, clock=clk, throttle=throttle, log=log)
    sent.attach(log)

    pid = "rogue"
    log.append(_canary(clk, pid))     # 80
    log.append(_rejection(clk, pid))  # 120 -> quarantine
    assert sent.is_quarantined(pid)

    # The real throttle now applies the suspicion multiplier to this principal.
    verdict = throttle.evaluate(Principal.agent(pid), "exfil", clk.monotonic())
    assert verdict.metadata["suspicion"] == cfg.suspicion_delay_factor


def test_sentinel_ignores_its_own_events_and_unattributed_events():
    clk = ManualClock()
    log = EventLog()
    sent = Sentinel(_cfg(), clock=clk, log=log)
    sent.attach(log)

    # An event with no principal has nothing to attribute.
    log.append(_canary(clk, ""))
    assert sent.score_of("") == 0.0

    # A stray sentinel.* event must not feed back into scoring.
    log.append(
        Event(
            ts=clk.wall(),
            kind="sentinel.quarantine",
            severity=Severity.ALERT,
            principal_id="ghost",
            message="injected",
        )
    )
    assert sent.score_of("ghost") == 0.0
    assert not sent.is_quarantined("ghost")
