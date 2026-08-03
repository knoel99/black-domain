import pytest

from bdos.core.clock import ManualClock
from bdos.core.config import (
    BDOSConfig,
    BlackDomainConfig,
    DarkForestConfig,
    EnclaveSpec,
    LightspeedConfig,
    SentinelConfig,
    default,
)
from bdos.core.decision import Decision
from bdos.core.identity import Principal
from bdos.controlplane.cli import main as cli_main
from bdos.controlplane.daemon import ControlPlane
from bdos.controlplane.daemon import main as daemon_main


# -- helpers --------------------------------------------------------------
def _demo_config() -> BDOSConfig:
    """Aggressive quotas + a crown-jewels enclave so a burst bites quickly."""
    return BDOSConfig(
        lightspeed=LightspeedConfig(
            max_delay=30.0,
            quota_capacity={"read": 1000.0, "write": 3.0, "admin": 3.0, "exfil": 2.0},
            quota_refill_per_sec={"read": 50.0, "write": 0.5, "admin": 0.05, "exfil": 0.01},
        ),
        darkforest=DarkForestConfig(mtd_secret="test-secret", services=["api", "db"]),
        blackdomain=BlackDomainConfig(
            enclaves=[EnclaveSpec(id="crown-jewels", members=["svc-db"], egress_allow=["10.0.0.5"])]
        ),
        sentinel=SentinelConfig(quarantine_threshold=100.0, seal_threshold=200.0),
    ).validate()


# -- construction ---------------------------------------------------------
def test_control_plane_builds_every_layer():
    cp = ControlPlane(_demo_config(), clock=ManualClock())
    # The whole spine is present and shares one log.
    assert cp.throttle is cp.gateway.throttle
    assert cp.gateway.log is cp.log
    # The issuer's public key is trusted by the verifier it was paired with.
    notice = cp.issuer.mint("bob", "admin", "db://prod", now=cp.clock.wall())
    assert cp.verifier.verify(notice, "bob", "admin", "db://prod").allowed
    # Enclaves came from config and the Sentinel is attached to the log.
    assert [e.id for e in cp.enclaves] == ["crown-jewels"]
    assert cp.log.verify()


def test_defaults_construct_without_a_config():
    cp = ControlPlane()  # built-in defaults, real clock
    assert cp.enclaves == []
    assert cp.status()["log_intact"] is True


# -- end-to-end authorize: human vs rogue agent ---------------------------
def test_human_operator_authorizes_fast_and_free():
    clk = ManualClock()
    cp = ControlPlane(_demo_config(), clock=clk)
    human = Principal.human("alice")

    for _ in range(3):
        v = cp.authorize(human, "write", "db://reports")
        assert v.decision is Decision.ALLOW
        assert v.delay_seconds == 0.0
        clk.advance(20.0)  # human pace: quota refills between actions

    assert not cp.sentinel.is_quarantined(human.id)
    assert cp.log.verify()


def test_rogue_agent_burst_delays_climb_then_quarantine_fires():
    clk = ManualClock()
    cp = ControlPlane(_demo_config(), clock=clk)
    rogue = Principal.agent("rogue-agent-7")  # a member of no enclave

    # A machine-cadence write burst: the Lightspeed tax climbs off zero.
    delays = [cp.authorize(rogue, "write", "db://reports").delay_seconds for _ in range(8)]
    assert delays[0] == 0.0
    assert max(delays) > delays[0]  # the tax escalates
    assert not cp.sentinel.is_quarantined(rogue.id)  # writes alone don't contain

    # Unattested exfil attempts are denied and drive the anomaly score up.
    for _ in range(3):
        v = cp.authorize(rogue, "exfil", "10.9.9.9")
        assert v.decision is Decision.DENY
        assert not v.allowed

    # The Sentinel has now crossed the quarantine threshold.
    assert cp.sentinel.is_quarantined(rogue.id)

    # Every further request short-circuits to QUARANTINE before any work.
    after = cp.authorize(rogue, "write", "db://reports")
    assert after.decision is Decision.QUARANTINE
    assert not after.allowed
    assert after.delay_seconds == 0.0  # not even the throttle ran
    assert cp.log.verify()


# -- attestation: required for admin/exfil --------------------------------
def test_admin_denied_without_notice_and_allowed_with_valid_one():
    clk = ManualClock()
    cp = ControlPlane(_demo_config(), clock=clk)
    operator = Principal.human("ops")

    # No notice -> hard deny for a require_for class.
    denied = cp.authorize(operator, "admin", "db://prod")
    assert denied.decision is Decision.DENY
    assert not denied.allowed

    # A valid, in-scope notice from the plane's own issuer -> allowed.
    notice = cp.issuer.mint("ops", "admin", "db://prod", now=clk.wall())
    allowed = cp.authorize(operator, "admin", "db://prod", notice=notice)
    assert allowed.allowed
    assert allowed.decision in (Decision.ALLOW, Decision.DELAY)


def test_wrong_scope_notice_is_rejected():
    clk = ManualClock()
    cp = ControlPlane(_demo_config(), clock=clk)
    operator = Principal.human("ops")
    # Notice scoped to a different resource must not authorize this action.
    notice = cp.issuer.mint("ops", "admin", "db://staging", now=clk.wall())
    v = cp.authorize(operator, "admin", "db://prod", notice=notice)
    assert v.decision is Decision.DENY
    assert v.metadata.get("error") == "AttestationError"


def test_reads_need_no_notice_and_are_free():
    clk = ManualClock()
    cp = ControlPlane(_demo_config(), clock=clk)
    v = cp.authorize(Principal.agent("scanner"), "read", "db://prod")
    assert v.decision is Decision.ALLOW
    assert v.delay_seconds == 0.0


# -- black domain segmentation --------------------------------------------
def test_sealed_enclave_denies_mutations_but_allows_reads():
    cfg = BDOSConfig(
        blackdomain=BlackDomainConfig(
            enclaves=[EnclaveSpec(id="cj", members=["svc-db"], egress_allow=[], sealed=True)]
        )
    ).validate()
    cp = ControlPlane(cfg, clock=ManualClock())
    svc = Principal.service("svc-db")

    write = cp.authorize(svc, "write", "anything")
    assert write.decision is Decision.DENY
    assert "sealed" in write.reason

    read = cp.authorize(svc, "read", "anything")
    assert read.decision is Decision.ALLOW
    assert cp.log.verify()


def test_enclave_egress_denied_for_unlisted_exfil_destination():
    clk = ManualClock()
    cp = ControlPlane(_demo_config(), clock=clk)
    svc = Principal.service("svc-db")  # inside crown-jewels (egress_allow 10.0.0.5)
    # Exfil needs a valid notice AND must clear egress; give it a notice so the
    # decision turns on the Black Domain egress allowlist.
    good = cp.issuer.mint("svc-db", "exfil", "10.0.0.5", now=clk.wall())
    assert cp.authorize(svc, "exfil", "10.0.0.5", notice=good).allowed

    bad = cp.issuer.mint("svc-db", "exfil", "8.8.8.8", now=clk.wall())
    denied = cp.authorize(svc, "exfil", "8.8.8.8", notice=bad)
    assert denied.decision is Decision.DENY
    assert "default-deny" in denied.reason


# -- projections ----------------------------------------------------------
def test_nftables_and_rendezvous_projections():
    cp = ControlPlane(_demo_config(), clock=ManualClock())
    ruleset = cp.nftables()
    assert "table inet bdos {" in ruleset
    assert "crown-jewels" in ruleset

    rvs = cp.rendezvous()
    assert {rv["service"] for rv in rvs} == {"api", "db"}
    for rv in rvs:
        assert 20000 <= rv["port"] < 60000


# -- CLI ------------------------------------------------------------------
def test_cli_simulate_runs_without_error(capsys):
    assert cli_main(["simulate"]) == 0
    out = capsys.readouterr().out
    assert "QUARANTINE" in out
    assert "quarantined" in out


def test_cli_keygen_mint_verify_round_trip(capsys):
    assert cli_main(["mint", "--principal", "a7", "--class", "admin", "--resource", "db://p"]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    pub = next(ln.split()[-1] for ln in lines if ln.startswith("# pubkey"))
    notice = lines[-1]

    assert cli_main(
        ["verify", "--notice", notice, "--pubkey", pub, "--principal", "a7", "--class", "admin", "--resource", "db://p"]
    ) == 0
    assert "ALLOW" in capsys.readouterr().out

    # Wrong scope -> the verify command signals denial via exit code 3.
    assert cli_main(
        ["verify", "--notice", notice, "--pubkey", pub, "--principal", "a7", "--class", "exfil", "--resource", "db://p"]
    ) == 3


def test_cli_guard_exit_codes(capsys):
    # A read needs no notice and is allowed -> exit 0.
    assert cli_main(["guard", "--principal", "u", "--kind", "human", "--class", "read", "--resource", "x"]) == 0
    # An admin with no notice is denied -> exit 3 (bdos-exec fails closed on this).
    assert cli_main(["guard", "--principal", "u", "--kind", "agent", "--class", "admin", "--resource", "x"]) == 3
    capsys.readouterr()


def test_cli_status_and_seal(tmp_path, capsys):
    policy = tmp_path / "bdos.toml"
    policy.write_text(
        "[[blackdomain.enclaves]]\n"
        'id = "crown-jewels"\n'
        'members = ["svc-db"]\n'
        "egress_allow = []\n"
    )
    assert cli_main(["status", "--config", str(policy)]) == 0
    assert "crown-jewels" in capsys.readouterr().out

    assert cli_main(["seal", "crown-jewels", "--config", str(policy)]) == 0
    assert "one-way door" in capsys.readouterr().out

    # Sealing an unknown enclave is refused.
    assert cli_main(["seal", "no-such", "--config", str(policy)]) == 3
    capsys.readouterr()


def test_daemon_main_prints_status_and_returns_zero(capsys):
    assert daemon_main([]) == 0
    assert "control plane up" in capsys.readouterr().out
