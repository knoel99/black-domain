from bdos.core import crypto
from bdos.core.clock import ManualClock
from bdos.core.config import SafetyNoticeConfig
from bdos.core.decision import Decision
from bdos.core.errors import (
    AttestationError,
    ExpiredError,
    ReplayError,
    RevokedError,
)
from bdos.core.events import EventLog, Severity
from bdos.safetynotice.issuer import SafetyNoticeIssuer
from bdos.safetynotice.tokens import Capability, SafetyNotice
from bdos.safetynotice.verifier import SafetyNoticeVerifier


def _issuer(clk):
    sk, _ = crypto.generate_keypair()
    return SafetyNoticeIssuer(sk, clock=clk)


def _verifier(clk, issuer, **cfg_kwargs):
    verifier = SafetyNoticeVerifier(clock=clk, cfg=SafetyNoticeConfig(**cfg_kwargs))
    verifier.add_key(issuer.public_key, issuer.kid)
    return verifier


def test_happy_path_allows_scoped_action():
    clk = ManualClock()
    issuer = _issuer(clk)
    verifier = _verifier(clk, issuer)
    notice = issuer.mint("agent-7", "admin", "db://prod")
    verdict = verifier.verify(notice, "agent-7", "admin", "db://prod")
    assert verdict.decision is Decision.ALLOW
    assert verdict.allowed


def test_counter_is_monotonic():
    clk = ManualClock()
    issuer = _issuer(clk)
    first = issuer.mint("a", "admin", "r")
    second = issuer.mint("a", "admin", "r")
    assert second.capability.counter > first.capability.counter


def test_kid_defaults_to_key_id():
    clk = ManualClock()
    sk, pk = crypto.generate_keypair()
    issuer = SafetyNoticeIssuer(sk, clock=clk)
    assert issuer.kid == crypto.key_id(pk)


def test_forged_signature_is_rejected():
    clk = ManualClock()
    issuer = _issuer(clk)
    verifier = _verifier(clk, issuer)
    notice = issuer.mint("agent-7", "admin", "db://prod")
    forged = SafetyNotice(capability=notice.capability, signature=b"\x00" * 64)
    try:
        verifier.verify(forged, "agent-7", "admin", "db://prod")
    except AttestationError:
        return
    raise AssertionError("expected AttestationError for forged signature")


def test_unknown_kid_is_rejected():
    clk = ManualClock()
    issuer = _issuer(clk)
    # A verifier that has never been told about this key.
    verifier = SafetyNoticeVerifier(clock=clk)
    notice = issuer.mint("agent-7", "admin", "db://prod")
    try:
        verifier.verify(notice, "agent-7", "admin", "db://prod")
    except AttestationError:
        return
    raise AssertionError("expected AttestationError for unknown kid")


def test_expired_notice_is_rejected():
    clk = ManualClock()
    issuer = _issuer(clk)
    verifier = _verifier(clk, issuer, clock_skew=5.0)
    notice = issuer.mint("agent-7", "admin", "db://prod", ttl=10.0)
    clk.advance(100.0)  # well past not_after + skew
    try:
        verifier.verify(notice, "agent-7", "admin", "db://prod")
    except ExpiredError:
        return
    raise AssertionError("expected ExpiredError")


def test_clock_skew_tolerates_small_drift():
    clk = ManualClock()
    issuer = _issuer(clk)
    verifier = _verifier(clk, issuer, clock_skew=5.0)
    notice = issuer.mint("agent-7", "admin", "db://prod", ttl=10.0)
    clk.advance(13.0)  # past not_after (10s) but within skew (5s)
    verdict = verifier.verify(notice, "agent-7", "admin", "db://prod")
    assert verdict.decision is Decision.ALLOW


def test_replay_is_rejected():
    clk = ManualClock()
    issuer = _issuer(clk)
    verifier = _verifier(clk, issuer)
    notice = issuer.mint("agent-7", "admin", "db://prod")
    assert verifier.verify(notice, "agent-7", "admin", "db://prod").allowed
    try:
        verifier.verify(notice, "agent-7", "admin", "db://prod")
    except ReplayError:
        return
    raise AssertionError("expected ReplayError on second use")


def test_replay_cache_never_evicts_a_live_nonce():
    # A still-valid spent nonce must never be re-accepted, even under a tiny cache.
    clk = ManualClock()
    issuer = _issuer(clk)
    verifier = _verifier(clk, issuer, replay_cache_size=2, clock_skew=5.0)
    first = issuer.mint("a", "admin", "r", ttl=100.0)
    assert verifier.verify(first, "a", "admin", "r").allowed
    try:
        verifier.verify(first, "a", "admin", "r")
    except ReplayError:
        return
    raise AssertionError("a still-valid nonce was replayed after size pressure")


def test_replay_cache_fails_closed_when_full_of_live_nonces():
    # Rather than silently drop a live nonce (which would reopen replay), the
    # verifier refuses once the cache is full of still-valid nonces.
    clk = ManualClock()
    issuer = _issuer(clk)
    verifier = _verifier(clk, issuer, replay_cache_size=2)
    verifier.verify(issuer.mint("a", "admin", "r", ttl=100.0), "a", "admin", "r")
    verifier.verify(issuer.mint("a", "admin", "r", ttl=100.0), "a", "admin", "r")
    try:
        verifier.verify(issuer.mint("a", "admin", "r", ttl=100.0), "a", "admin", "r")
    except AttestationError:
        return
    raise AssertionError("expected fail-closed AttestationError when cache full of live nonces")


def test_expired_nonce_is_pruned_then_rejected_by_window():
    # Once a nonce's window closes it may be forgotten -- but re-presenting it is
    # then rejected by the window check, never accepted.
    clk = ManualClock()
    issuer = _issuer(clk)
    verifier = _verifier(clk, issuer, replay_cache_size=2, clock_skew=5.0)
    first = issuer.mint("a", "admin", "r", ttl=10.0)
    assert verifier.verify(first, "a", "admin", "r").allowed
    clk.advance(100.0)  # past not_after + skew
    try:
        verifier.verify(first, "a", "admin", "r")
    except ExpiredError:
        return
    raise AssertionError("expected ExpiredError for a re-presented expired notice")


def test_scope_mismatch_on_action_class():
    clk = ManualClock()
    issuer = _issuer(clk)
    verifier = _verifier(clk, issuer)
    notice = issuer.mint("agent-7", "admin", "db://prod")
    try:
        verifier.verify(notice, "agent-7", "exfil", "db://prod")
    except AttestationError:
        return
    raise AssertionError("expected AttestationError for action_class mismatch")


def test_scope_mismatch_on_resource():
    clk = ManualClock()
    issuer = _issuer(clk)
    verifier = _verifier(clk, issuer)
    notice = issuer.mint("agent-7", "admin", "db://prod")
    try:
        verifier.verify(notice, "agent-7", "admin", "db://staging")
    except AttestationError:
        return
    raise AssertionError("expected AttestationError for resource mismatch")


def test_scope_mismatch_on_principal():
    clk = ManualClock()
    issuer = _issuer(clk)
    verifier = _verifier(clk, issuer)
    notice = issuer.mint("agent-7", "admin", "db://prod")
    try:
        verifier.verify(notice, "agent-8", "admin", "db://prod")
    except AttestationError:
        return
    raise AssertionError("expected AttestationError for principal mismatch")


def test_revoked_nonce_is_rejected():
    clk = ManualClock()
    issuer = _issuer(clk)
    verifier = _verifier(clk, issuer)
    notice = issuer.mint("agent-7", "admin", "db://prod")
    verifier.revoke_nonce(notice.capability.nonce)
    try:
        verifier.verify(notice, "agent-7", "admin", "db://prod")
    except RevokedError:
        return
    raise AssertionError("expected RevokedError for revoked nonce")


def test_revoked_key_is_rejected():
    clk = ManualClock()
    issuer = _issuer(clk)
    verifier = _verifier(clk, issuer)
    verifier.revoke_key(issuer.kid)
    notice = issuer.mint("agent-7", "admin", "db://prod")
    try:
        verifier.verify(notice, "agent-7", "admin", "db://prod")
    except RevokedError:
        return
    raise AssertionError("expected RevokedError for revoked key")


def test_encode_decode_round_trip():
    clk = ManualClock()
    issuer = _issuer(clk)
    verifier = _verifier(clk, issuer)
    notice = issuer.mint("agent-7", "admin", "db://prod")
    restored = SafetyNotice.decode(notice.encode())
    assert restored.capability == notice.capability
    assert restored.signature == notice.signature
    # A decoded notice still verifies -- the canonical bytes survived the trip.
    assert verifier.verify(restored, "agent-7", "admin", "db://prod").allowed


def test_capability_canonical_is_deterministic():
    cap = Capability(
        principal_id="a",
        action_class="admin",
        resource="r",
        not_before=1.0,
        not_after=2.0,
        nonce="n",
        counter=1,
        issuer_kid="k",
    )
    assert cap.canonical() == cap.canonical()


def test_guard_logs_verified_on_success():
    clk = ManualClock()
    issuer = _issuer(clk)
    verifier = _verifier(clk, issuer)
    log = EventLog()
    notice = issuer.mint("agent-7", "admin", "db://prod")
    verdict = verifier.guard(notice, "agent-7", "admin", "db://prod", log=log)
    assert verdict.decision is Decision.ALLOW
    assert len(log) == 1
    rec = log.records[0]
    assert rec.event.kind == "safetynotice.verified"
    assert rec.event.severity is Severity.NOTICE


def test_guard_never_raises_and_logs_rejected():
    clk = ManualClock()
    issuer = _issuer(clk)
    verifier = _verifier(clk, issuer)
    log = EventLog()
    notice = issuer.mint("agent-7", "admin", "db://prod")
    # Wrong scope -> guard must swallow the error and return DENY.
    verdict = verifier.guard(notice, "agent-7", "exfil", "db://prod", log=log)
    assert verdict.decision is Decision.DENY
    assert not verdict.allowed
    assert len(log) == 1
    rec = log.records[0]
    assert rec.event.kind == "safetynotice.rejected"
    assert rec.event.severity is Severity.ALERT


def test_guard_deny_carries_error_name():
    clk = ManualClock()
    issuer = _issuer(clk)
    verifier = _verifier(clk, issuer)
    notice = issuer.mint("agent-7", "admin", "db://prod")
    verifier.verify(notice, "agent-7", "admin", "db://prod")  # spend it once
    verdict = verifier.guard(notice, "agent-7", "admin", "db://prod")
    assert verdict.decision is Decision.DENY
    assert verdict.metadata.get("error") == "ReplayError"
