from bdos.core import (
    Decision,
    Event,
    EventLog,
    ManualClock,
    Principal,
    PrincipalKind,
    Severity,
    Verdict,
)
from bdos.core import config as cfgmod
from bdos.core import crypto
from bdos.core.errors import ConfigError


def test_manual_clock_sleep_advances_and_accounts():
    clk = ManualClock()
    start = clk.monotonic()
    clk.sleep(2.5)
    assert clk.monotonic() == start + 2.5
    assert clk.slept_total == 2.5
    clk.advance(10)  # advancing is not "sleeping"
    assert clk.slept_total == 2.5


def test_verdict_combine_takes_most_restrictive():
    allow = Verdict.allow()
    deny = Verdict.deny("nope")
    assert allow.combine(deny).decision is Decision.DENY
    assert deny.combine(allow).decision is Decision.DENY


def test_verdict_combine_sums_delays():
    a = Verdict.delay(1.0)
    b = Verdict.delay(2.5)
    combined = a.combine(b)
    assert combined.decision is Decision.DELAY
    assert combined.delay_seconds == 3.5
    assert combined.allowed


def test_quarantine_beats_everything():
    v = Verdict.delay(5).combine(Verdict.quarantine("contained"))
    assert v.decision is Decision.QUARANTINE
    assert not v.allowed


def test_principal_agentic_classification():
    assert Principal.agent("a").is_agentic
    assert Principal.service("s").is_agentic
    assert not Principal.human("h").is_agentic
    assert Principal.human("h").kind is PrincipalKind.HUMAN


def test_eventlog_hash_chain_detects_tampering():
    log = EventLog()
    for i in range(5):
        log.append(Event(ts=float(i), kind="test", severity=Severity.INFO, message=f"e{i}"))
    assert log.verify()
    # Tamper with a record in the middle.
    log.records  # snapshot copy, does not mutate internal
    log._records[2].event.message = "forged"
    assert not log.verify()


def test_eventlog_subscribers_fire_synchronously():
    seen = []
    log = EventLog()
    log.subscribe(lambda e: seen.append(e.kind))
    log.append(Event(ts=0.0, kind="alpha"))
    log.append(Event(ts=1.0, kind="beta"))
    assert seen == ["alpha", "beta"]


def test_eventlog_persistence(tmp_path):
    path = tmp_path / "log" / "events.jsonl"
    log = EventLog(path=str(path))
    log.append(Event(ts=0.0, kind="persist", message="hello"))
    lines = path.read_text().strip().splitlines()
    assert len(lines) == 1
    assert "persist" in lines[0]


def test_crypto_sign_verify_roundtrip():
    sk, pk = crypto.generate_keypair()
    sig = crypto.sign(sk, b"payload")
    assert crypto.verify(pk, sig, b"payload")
    assert not crypto.verify(pk, sig, b"tampered")


def test_crypto_key_serialization_roundtrip():
    sk, pk = crypto.generate_keypair()
    sk2 = crypto.load_private(crypto.private_bytes(sk))
    pk2 = crypto.load_public(crypto.public_bytes(pk))
    sig = crypto.sign(sk2, b"x")
    assert crypto.verify(pk2, sig, b"x")
    assert crypto.key_id(pk) == crypto.key_id(pk2)


def test_b64_roundtrip():
    for raw in (b"", b"a", b"abc", b"\x00\xff\x10"):
        assert crypto.b64d(crypto.b64e(raw)) == raw


def test_config_defaults_valid():
    c = cfgmod.default()
    assert c.lightspeed.multiplier("exfil") > c.lightspeed.multiplier("write")
    assert "admin" in c.safetynotice.require_for


def test_config_from_dict_and_validation():
    c = cfgmod.from_dict({"lightspeed": {"max_delay": 10.0}})
    assert c.lightspeed.max_delay == 10.0


def test_config_rejects_unknown_section():
    try:
        cfgmod.from_dict({"bogus": {}})
    except ConfigError:
        return
    raise AssertionError("expected ConfigError")


def test_config_rejects_bad_seal_threshold():
    try:
        cfgmod.from_dict({"sentinel": {"quarantine_threshold": 100, "seal_threshold": 50}})
    except ConfigError:
        return
    raise AssertionError("expected ConfigError")
