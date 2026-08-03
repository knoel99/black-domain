import pytest

from bdos.core.config import EnclaveSpec
from bdos.core.decision import Decision
from bdos.core.errors import SealedEnclaveError
from bdos.blackdomain.enclave import Enclave
from bdos.blackdomain.compiler import compile_nftables, EnclaveRouter


def _enclave(id="vault", members=None, egress=None, sealed=False):
    return Enclave(
        EnclaveSpec(
            id=id,
            members=list(members or ["db-primary"]),
            egress_allow=list(egress or []),
            sealed=sealed,
        )
    )


# -- membership -----------------------------------------------------------

def test_contains_reports_membership():
    enc = _enclave(members=["a", "b"])
    assert enc.contains("a")
    assert enc.contains("b")
    assert not enc.contains("c")


# -- egress ---------------------------------------------------------------

def test_default_deny_egress():
    enc = _enclave(egress=[])
    v = enc.decide_egress("10.0.0.9")
    assert v.decision is Decision.DENY
    assert not v.allowed
    assert "default-deny" in v.reason


def test_allowlisted_egress_is_permitted():
    enc = _enclave(egress=["10.0.0.5", "10.0.0.0/24"])
    allowed = enc.decide_egress("10.0.0.5")
    assert allowed.decision is Decision.ALLOW
    assert allowed.allowed
    # An address not on the exact allowlist is still denied.
    denied = enc.decide_egress("10.0.0.6")
    assert denied.decision is Decision.DENY


# -- actions --------------------------------------------------------------

def test_reads_always_allowed_open_enclave():
    enc = _enclave()
    for ac in ("read", "write", "admin", "exfil"):
        assert enc.decide_action(ac).decision is Decision.ALLOW


# -- sealing --------------------------------------------------------------

def test_seal_blocks_writes_and_egress_but_not_reads():
    enc = _enclave(egress=["10.0.0.5"])
    assert not enc.sealed
    enc.seal()
    assert enc.sealed

    # Reads still flow into the black domain.
    assert enc.decide_action("read").decision is Decision.ALLOW
    # Every mutation is refused, and the reason names the seal.
    for ac in ("write", "admin", "exfil"):
        v = enc.decide_action(ac)
        assert v.decision is Decision.DENY
        assert "sealed" in v.reason

    # Even a previously-allowlisted destination is now denied.
    egress = enc.decide_egress("10.0.0.5")
    assert egress.decision is Decision.DENY
    assert "sealed" in egress.reason


def test_seal_is_idempotent():
    enc = _enclave()
    enc.seal()
    enc.seal()  # must not raise
    assert enc.sealed


def test_spec_can_start_sealed():
    enc = _enclave(egress=["10.0.0.5"], sealed=True)
    assert enc.sealed
    assert enc.decide_egress("10.0.0.5").decision is Decision.DENY


def test_unseal_always_raises():
    enc = _enclave()
    enc.seal()
    with pytest.raises(SealedEnclaveError):
        enc.unseal()


def test_unseal_raises_even_when_open():
    # A black domain is a one-way door: there is no legitimate unseal path.
    enc = _enclave()
    with pytest.raises(SealedEnclaveError):
        enc.unseal()


# -- nftables compilation -------------------------------------------------

def test_nftables_contains_each_enclave_and_drop_policy():
    encs = [
        _enclave(id="vault", egress=["10.0.0.5"]),
        _enclave(id="mint", egress=["192.168.1.0/24", "backup.internal"]),
    ]
    ruleset = compile_nftables(encs)

    assert "table inet bdos {" in ruleset
    for enc in encs:
        assert enc.id in ruleset
    # Default-deny is expressed both as chain policy and an explicit drop.
    assert "policy drop;" in ruleset
    assert "drop" in ruleset
    # Allowlisted destinations become accept rules.
    assert "ip daddr 10.0.0.5 accept" in ruleset
    assert "ip daddr 192.168.1.0/24 accept" in ruleset
    assert "ip daddr backup.internal accept" in ruleset


def test_nftables_is_deterministic_and_order_independent():
    a = _enclave(id="alpha", egress=["10.0.0.1"])
    b = _enclave(id="bravo", egress=["10.0.0.2"])
    assert compile_nftables([a, b]) == compile_nftables([b, a])


def test_nftables_sealed_enclave_has_no_accept_rules():
    enc = _enclave(id="vault", egress=["10.0.0.5"], sealed=True)
    ruleset = compile_nftables([enc])
    assert "SEALED" in ruleset
    assert "10.0.0.5 accept" not in ruleset
    assert "policy drop;" in ruleset


def test_nftables_ipv6_uses_ip6_match():
    enc = _enclave(id="vault", egress=["2001:db8::1"])
    ruleset = compile_nftables([enc])
    assert "ip6 daddr 2001:db8::1 accept" in ruleset


# -- router ---------------------------------------------------------------

def test_router_routes_members_to_their_enclave():
    vault = _enclave(id="vault", members=["db-primary"], egress=["10.0.0.5"])
    mint = _enclave(id="mint", members=["signer"], egress=[])
    router = EnclaveRouter([vault, mint])

    assert router.enclave_for("db-primary") is vault
    assert router.enclave_for("signer") is mint
    assert router.enclave_for("laptop") is None


def test_router_applies_enclave_egress_policy():
    vault = _enclave(id="vault", members=["db-primary"], egress=["10.0.0.5"])
    router = EnclaveRouter([vault])

    assert router.decide("db-primary", "10.0.0.5").decision is Decision.ALLOW
    assert router.decide("db-primary", "8.8.8.8").decision is Decision.DENY


def test_router_treats_unsegmented_members_as_allowed():
    router = EnclaveRouter([_enclave(id="vault", members=["db-primary"])])
    v = router.decide("laptop", "8.8.8.8")
    assert v.decision is Decision.ALLOW
    assert v.reason == "unsegmented"


def test_router_denies_through_sealed_enclave():
    vault = _enclave(id="vault", members=["db-primary"], egress=["10.0.0.5"])
    vault.seal()
    router = EnclaveRouter([vault])
    v = router.decide("db-primary", "10.0.0.5")
    assert v.decision is Decision.DENY
    assert "sealed" in v.reason
