from bdos.core.config import LightspeedConfig
from bdos.core.clock import ManualClock
from bdos.core.decision import Decision
from bdos.core.events import EventLog
from bdos.core.identity import Principal
from bdos.lightspeed.cadence import burst_score, looks_agentic
from bdos.lightspeed.throttle import LightspeedThrottle, TokenBucket
from bdos.lightspeed.gateway import LightspeedGateway


def test_token_bucket_backpressure_grows():
    b = TokenBucket(capacity=2, refill_per_sec=1.0, now=0.0)
    assert b.consume(0.0) == 0.0  # 1 left
    assert b.consume(0.0) == 0.0  # 0 left
    w1 = b.consume(0.0)  # -1 -> wait 1s
    w2 = b.consume(0.0)  # -2 -> wait 2s
    assert w1 == 1.0
    assert w2 == 2.0


def test_token_bucket_refills_over_time():
    b = TokenBucket(capacity=1, refill_per_sec=1.0, now=0.0)
    b.consume(0.0)  # empty
    assert b.consume(0.0) > 0  # immediate re-consume waits
    # after 5s the bucket has refilled
    assert b.consume(5.0) == 0.0


def _cfg():
    return LightspeedConfig(human_cadence_threshold=1.0, window_seconds=60.0)


def test_burst_score_zero_for_human_cadence():
    cfg = _cfg()
    # one action per second for 30s == human rate
    arrivals = [float(i) for i in range(30)]
    assert burst_score(arrivals, now=29.0, cfg=cfg) == 0.0


def test_burst_score_positive_for_machine_cadence():
    cfg = _cfg()
    # 300 actions in 30s == 10x human rate
    arrivals = [i * 0.1 for i in range(300)]
    score = burst_score(arrivals, now=29.9, cfg=cfg)
    assert score > 5.0


def test_regularity_amplifies_score():
    cfg = _cfg()
    # Perfectly regular fast cadence should score higher than the same count
    # delivered irregularly.
    regular = [i * 0.1 for i in range(120)]
    import random

    rng = random.Random(0)
    t = 0.0
    irregular = []
    for _ in range(120):
        irregular.append(t)
        t += rng.uniform(0.01, 0.19)  # same mean ~0.1, high variance
    now = 12.0
    assert burst_score(regular, now, cfg) >= burst_score(irregular, now, cfg)


def test_looks_agentic_flags_fast_streams():
    cfg = _cfg()
    human = [float(i) for i in range(20)]  # 1/s
    machine = [i * 0.05 for i in range(200)]  # 20/s
    assert not looks_agentic(human, now=19.0, cfg=cfg)
    assert looks_agentic(machine, now=9.95, cfg=cfg)


def test_human_operator_sees_no_delay():
    cfg = LightspeedConfig()
    throttle = LightspeedThrottle(cfg)
    human = Principal.human("alice")
    # ten admin actions, 30s apart -> well within cadence and quota
    t = 0.0
    for _ in range(10):
        v = throttle.evaluate(human, "admin", t)
        assert v.decision is Decision.ALLOW
        assert v.delay_seconds == 0.0
        t += 30.0


def test_agent_burst_gets_throttled_hard():
    cfg = LightspeedConfig()
    throttle = LightspeedThrottle(cfg)
    agent = Principal.agent("rogue")
    delays = []
    t = 0.0
    for _ in range(50):
        v = throttle.evaluate(agent, "admin", t)
        delays.append(v.delay_seconds)
        t += 0.05  # 20 admin ops/sec
    # Delay should climb and eventually hit the cap.
    assert delays[-1] > delays[0]
    assert max(delays) == cfg.max_delay


def test_reads_are_cheap_even_in_bursts():
    cfg = LightspeedConfig()
    throttle = LightspeedThrottle(cfg)
    agent = Principal.agent("scanner")
    t = 0.0
    delays = []
    for _ in range(200):
        v = throttle.evaluate(agent, "read", t)
        delays.append(v.delay_seconds)
        t += 0.01
    # Reads have multiplier 0 and a huge bucket: minimal delay.
    assert max(delays) < 1.0


def test_suspicion_multiplier_raises_delay():
    cfg = LightspeedConfig()
    throttle = LightspeedThrottle(cfg)
    agent = Principal.agent("suspect")
    t = 0.0
    for _ in range(5):
        throttle.evaluate(agent, "write", t)
        t += 0.1
    base = throttle.evaluate(agent, "write", t)
    throttle.set_suspicion("suspect", 5.0)
    t += 0.1
    raised = throttle.evaluate(agent, "write", t)
    assert raised.delay_seconds >= base.delay_seconds


def test_gateway_spends_delay_on_clock():
    cfg = LightspeedConfig()
    clk = ManualClock()
    log = EventLog()
    gw = LightspeedGateway(LightspeedThrottle(cfg), clock=clk, log=log)
    agent = Principal.agent("rogue")
    for _ in range(30):
        gw.guard(agent, "admin", at=clk.monotonic())
        clk.advance(0.05)
    assert clk.slept_total > 0.0
    assert len(log) == 30
    assert log.verify()
