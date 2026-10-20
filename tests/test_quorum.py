import json

import pytest

from bdos.core import crypto
from bdos.core.clock import ManualClock
from bdos.core.config import (
    BDOSConfig,
    BlackDomainConfig,
    EnclaveSpec,
    QuorumConfig,
    from_dict,
)
from bdos.core.errors import ConfigError
from bdos.core.events import Event, Severity
from bdos.controlplane.cli import main as cli_main
from bdos.controlplane.daemon import ControlPlane
from bdos.quorum import ActionRequest, Approval, QuorumGate


# -- helpers --------------------------------------------------------------
def _keys(*names):
    out = {}
    for name in names:
        sk, pk = crypto.generate_keypair()
        out[name] = (sk, crypto.b64e(crypto.public_bytes(pk)))
    return out


def _cfg(keys, m=2, delay=900.0, validity=3600.0, required=True) -> QuorumConfig:
    return QuorumConfig(
        seal_requires_quorum=required,
        m=m,
        approvers={name: pub for name, (_, pub) in keys.items()},
        delay_seconds=delay,
        validity_seconds=validity,
    )


def _request(clk, target="crown-jewels") -> ActionRequest:
    return ActionRequest("seal", target, "canary tripped on svc-db", "soc-1", created=clk.wall())


def _approve(req, keys, name, at):
    return Approval.sign(req, name, keys[name][0], at)


# -- the gate -------------------------------------------------------------
def test_quorum_reached_and_delay_elapsed_allows_once():
    clk = ManualClock()
    keys = _keys("alice", "bob", "carol")
    gate = QuorumGate(_cfg(keys), clock=clk)
    req = _request(clk)
    approvals = [_approve(req, keys, "alice", clk.wall()), _approve(req, keys, "bob", clk.wall() + 60)]
    clk.advance(60 + 900)
    assert gate.authorize(req, approvals).allowed
    # Single use: the same request and approvals cannot be replayed.
    replay = gate.authorize(req, approvals)
    assert not replay.allowed and "replay" in replay.reason


def test_deliberate_delay_counts_from_the_mth_approval():
    clk = ManualClock()
    keys = _keys("alice", "bob")
    gate = QuorumGate(_cfg(keys), clock=clk)
    req = _request(clk)
    a = _approve(req, keys, "alice", clk.wall())
    b = _approve(req, keys, "bob", clk.wall() + 600)
    clk.advance(1000)  # 1000s after alice, only 400s after bob: quorum reached at bob
    verdict = gate.check(req, [a, b])
    assert not verdict.allowed and "deliberate delay" in verdict.reason
    clk.advance(500)
    assert gate.check(req, [a, b]).allowed


def test_one_approver_twice_is_not_a_quorum():
    clk = ManualClock()
    keys = _keys("alice", "bob")
    gate = QuorumGate(_cfg(keys, delay=0.0), clock=clk)
    req = _request(clk)
    approvals = [_approve(req, keys, "alice", clk.wall()), _approve(req, keys, "alice", clk.wall() + 1)]
    clk.advance(2)
    verdict = gate.check(req, approvals)
    assert not verdict.allowed
    assert "1 of 2" in verdict.reason
    assert any("duplicate" in r for r in verdict.metadata["rejected"])


def test_unknown_approver_forged_signature_and_other_request_are_rejected():
    clk = ManualClock()
    keys = _keys("alice", "bob")
    outsider = _keys("mallory")
    gate = QuorumGate(_cfg(keys, delay=0.0), clock=clk)
    req = _request(clk)
    other = _request(clk, target="control-plane")
    forged = Approval.sign(req, "bob", outsider["mallory"][0], clk.wall())  # bob's name, wrong key
    approvals = [
        _approve(req, keys, "alice", clk.wall()),
        Approval.sign(req, "mallory", outsider["mallory"][0], clk.wall()),
        forged,
        _approve(other, keys, "bob", clk.wall()),
    ]
    clk.advance(1)
    verdict = gate.check(req, approvals)
    assert not verdict.allowed
    rejected = " | ".join(verdict.metadata["rejected"])
    assert "not enrolled" in rejected and "bad signature" in rejected and "another request" in rejected


def test_tampered_request_invalidates_approvals():
    clk = ManualClock()
    keys = _keys("alice", "bob")
    gate = QuorumGate(_cfg(keys, delay=0.0), clock=clk)
    req = _request(clk)
    approvals = [_approve(req, keys, n, clk.wall()) for n in ("alice", "bob")]
    req.target = "control-plane"
    clk.advance(1)
    assert not gate.check(req, approvals).allowed


def test_expired_request_is_denied():
    clk = ManualClock()
    keys = _keys("alice", "bob")
    gate = QuorumGate(_cfg(keys, delay=10.0, validity=100.0), clock=clk)
    req = _request(clk)
    approvals = [_approve(req, keys, n, clk.wall()) for n in ("alice", "bob")]
    clk.advance(101)
    verdict = gate.check(req, approvals)
    assert not verdict.allowed and "expired" in verdict.reason


def test_request_and_approval_round_trip_through_json():
    clk = ManualClock()
    keys = _keys("alice")
    req = _request(clk)
    ap = _approve(req, keys, "alice", clk.wall())
    req2 = ActionRequest.from_dict(json.loads(json.dumps(req.to_dict())))
    ap2 = Approval.from_dict(json.loads(json.dumps(ap.to_dict())))
    assert req2.digest == req.digest
    assert ap2.verifies(crypto.load_public(crypto.b64d(keys["alice"][1])))


# -- configuration ---------------------------------------------------------
def test_config_refuses_a_single_approver_quorum_and_shared_keys():
    keys = _keys("alice", "bob")
    with pytest.raises(ConfigError, match="m must be >= 2"):
        BDOSConfig(quorum=_cfg(keys, m=1)).validate()
    with pytest.raises(ConfigError, match="only 2 approvers"):
        BDOSConfig(quorum=_cfg(keys, m=3)).validate()
    shared = QuorumConfig(approvers={"alice": keys["alice"][1], "alias": keys["alice"][1]})
    with pytest.raises(ConfigError, match="share a key"):
        BDOSConfig(quorum=shared).validate()
    with pytest.raises(ConfigError, match="32-byte"):
        BDOSConfig(quorum=QuorumConfig(approvers={"alice": "c2hvcnQ"})).validate()


def test_quorum_section_loads_from_dict():
    keys = _keys("alice", "bob")
    cfg = from_dict({"quorum": {"seal_requires_quorum": True, "approvers": {n: p for n, (_, p) in keys.items()}}})
    assert cfg.quorum.seal_requires_quorum and set(cfg.quorum.approvers) == {"alice", "bob"}


# -- the control plane -------------------------------------------------------
def _plane(keys, clk, delay=900.0):
    cfg = BDOSConfig(
        blackdomain=BlackDomainConfig(enclaves=[EnclaveSpec(id="crown-jewels", members=["svc-db"])]),
        quorum=_cfg(keys, delay=delay),
    ).validate()
    return ControlPlane(cfg, clock=clk)


def test_plane_seal_requires_quorum():
    clk = ManualClock()
    keys = _keys("alice", "bob", "carol")
    cp = _plane(keys, clk)
    enclave = cp.enclaves[0]
    assert not cp.seal("crown-jewels").allowed
    req = _request(clk)
    approvals = [_approve(req, keys, n, clk.wall()) for n in ("alice", "carol")]
    assert not cp.seal("crown-jewels", req, approvals).allowed  # delay not elapsed
    assert not enclave.sealed
    clk.advance(901)
    wrong_target = ActionRequest("seal", "control-plane", "x", "soc-1", created=clk.wall())
    assert not cp.seal("crown-jewels", wrong_target, approvals).allowed
    assert cp.seal("crown-jewels", req, approvals).allowed
    assert enclave.sealed
    kinds = [r.event.kind for r in cp.log]
    assert "blackdomain.seal_refused" in kinds and "quorum.allowed" in kinds and "blackdomain.sealed" in kinds
    assert cp.log.verify()


def test_sentinel_quarantines_but_does_not_seal_when_quorum_required():
    clk = ManualClock()
    keys = _keys("alice", "bob")
    cp = _plane(keys, clk)
    for _ in range(4):
        cp.log.append(Event(ts=clk.wall(), kind="darkforest.canary_tripped", severity=Severity.CRITICAL,
                            principal_id="svc-db", message="canary tripped"))
    assert "svc-db" in cp.sentinel.quarantined  # the reversible reflex still fires
    assert not cp.enclaves[0].sealed  # the irreversible one waits for the quorum
    recs = [r.event for r in cp.log if r.event.kind == "sentinel.recommend_seal"]
    assert recs and recs[0].data.get("requires_quorum") is True


def test_cli_end_to_end_seal_with_quorum(tmp_path, capsys):
    keys = _keys("alice", "bob")
    for name, (sk, _) in keys.items():
        (tmp_path / f"{name}.key").write_text(crypto.b64e(crypto.private_bytes(sk)) + "\n")
    approvers = "\n".join(f'{n} = "{p}"' for n, (_, p) in keys.items())
    policy = tmp_path / "bdos.toml"
    policy.write_text(
        '[[blackdomain.enclaves]]\nid = "crown-jewels"\nmembers = ["svc-db"]\n\n'
        "[quorum]\nseal_requires_quorum = true\nm = 2\ndelay_seconds = 0.0\n\n"
        f"[quorum.approvers]\n{approvers}\n"
    )
    req = tmp_path / "req.json"
    assert cli_main(["quorum", "request", "--target", "crown-jewels", "--reason", "drill",
                     "--requested-by", "soc-1", "--out", str(req)]) == 0
    assert cli_main(["seal", "crown-jewels", "--config", str(policy)]) == 3
    for name in keys:
        assert cli_main(["quorum", "approve", "--request", str(req), "--approver", name,
                         "--key", str(tmp_path / f"{name}.key"), "--out", str(tmp_path / f"{name}.json")]) == 0
    one = ["--approval", str(tmp_path / "alice.json")]
    assert cli_main(["seal", "crown-jewels", "--config", str(policy), "--request", str(req), *one]) == 3
    both = one + ["--approval", str(tmp_path / "bob.json")]
    assert cli_main(["seal", "crown-jewels", "--config", str(policy), "--request", str(req), *both]) == 0
    assert "sealed enclave 'crown-jewels'" in capsys.readouterr().out
