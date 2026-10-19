from bdos.core.clock import ManualClock
from bdos.core.config import DarkForestConfig
from bdos.core.events import EventLog, Severity
from bdos.darkforest.mtd import MovingTarget
from bdos.darkforest.deception import CanaryToken, Deception


def _cfg(**kw):
    return DarkForestConfig(**kw)


def _mtd(clock=None, **kw):
    return MovingTarget(secret=b"shared-mtd-secret", cfg=_cfg(**kw), clock=clock)


def test_epoch_derives_from_wall_clock():
    clk = ManualClock(start_wall=1000.0)
    mtd = _mtd(clock=clk, mtd_epoch_seconds=300.0)
    assert mtd.epoch() == 1000 // 300
    # Explicit `now` overrides the clock.
    assert mtd.epoch(now=900.0) == 3


def test_mtd_deterministic_within_epoch():
    mtd = _mtd()
    ep = 42
    assert mtd.port_for("api", ep) == mtd.port_for("api", ep)
    assert mtd.path_for("api", ep) == mtd.path_for("api", ep)


def test_mtd_rotates_across_epochs():
    mtd = _mtd()
    ports = {mtd.port_for("api", e) for e in range(50)}
    paths = {mtd.path_for("api", e) for e in range(50)}
    # A keyed HMAC over 50 epochs should land on many distinct rendezvous.
    assert len(ports) > 40
    assert len(paths) == 50


def test_port_in_configured_range():
    mtd = _mtd(mtd_port_low=20000, mtd_port_high=60000)
    for svc in ("api", "db", "queue", "cache"):
        for e in range(200):
            port = mtd.port_for(svc, e)
            assert 20000 <= port < 60000


def test_path_shape():
    mtd = _mtd()
    path = mtd.path_for("api", 7)
    assert path.startswith("/")
    assert len(path) == 17  # leading slash + 16 hex chars
    int(path[1:], 16)  # must be valid hex


def test_different_services_differ():
    mtd = _mtd()
    assert mtd.port_for("api", 1) != mtd.port_for("db", 1) or \
        mtd.path_for("api", 1) != mtd.path_for("db", 1)


def test_secret_changes_the_schedule():
    cfg = _cfg()
    a = MovingTarget(secret=b"secret-a", cfg=cfg)
    b = MovingTarget(secret=b"secret-b", cfg=cfg)
    # Same service and epoch, different key -> the map is unpredictable.
    assert a.path_for("api", 5) != b.path_for("api", 5)


def test_current_reports_live_rendezvous():
    clk = ManualClock(start_wall=3000.0)
    mtd = _mtd(clock=clk, mtd_epoch_seconds=300.0)
    live = mtd.current("api")
    assert live == {
        "service": "api",
        "epoch": 10,
        "port": mtd.port_for("api", 10),
        "path": mtd.path_for("api", 10),
    }


def test_canary_mint_and_trip_emits_critical():
    log = EventLog()
    dec = Deception(log=log, clock=ManualClock())
    canary = dec.mint_canary(label="/etc/shadow.bak")
    assert isinstance(canary, CanaryToken)
    assert dec.is_canary(canary.id)
    assert dec.is_canary(canary.secret)

    event = dec.trip(canary, context={"src": "10.0.0.9"}, principal_id="rogue")
    assert event.kind == "darkforest.canary_tripped"
    assert event.severity is Severity.CRITICAL
    assert event.principal_id == "rogue"
    assert event.data["recognised"] is True
    assert event.data["context"] == {"src": "10.0.0.9"}
    # The trip landed on the shared log for the Sentinel to observe.
    assert len(log) == 1
    assert log.records[0].event.kind == "darkforest.canary_tripped"
    assert log.verify()


def test_decoy_credential_recognised_as_canary():
    dec = Deception()
    cred = dec.mint_decoy_credential(label="prod-backup")
    assert set(cred) >= {"username", "password", "token"}
    assert dec.is_canary(cred["token"])
    assert dec.is_canary(cred["password"])
    assert dec.is_canary(cred["username"])
    # Tripping via the returned dict is recognised.
    event = dec.trip(cred, principal_id="attacker")
    assert event.severity is Severity.CRITICAL
    assert event.data["recognised"] is True


def test_unknown_token_is_not_a_canary():
    dec = Deception()
    dec.mint_canary()
    assert not dec.is_canary("not-a-real-token")
    assert not dec.is_canary("")
    # Tripping an unknown value still emits CRITICAL but flags it unrecognised.
    log = EventLog()
    dec2 = Deception(log=log, clock=ManualClock())
    event = dec2.trip("mystery-value")
    assert event.severity is Severity.CRITICAL
    assert event.data["recognised"] is False
    assert len(log) == 1


def test_trip_without_log_still_returns_event():
    dec = Deception(clock=ManualClock())
    canary = dec.mint_canary()
    event = dec.trip(canary)
    assert event.kind == "darkforest.canary_tripped"
    assert event.severity is Severity.CRITICAL
