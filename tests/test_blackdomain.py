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
    # A CIDR allowlist entry admits any host inside it (the router agrees with
    # the firewall, which resolves CIDRs).
    assert enc.decide_egress("10.0.0.6").decision is Decision.ALLOW
    # An address outside every allowlisted network is denied.
    assert enc.decide_egress("10.0.1.6").decision is Decision.DENY


def test_hostname_egress_matches_case_insensitively():
    enc = _enclave(egress=["Backup.Internal"])
    assert enc.decide_egress("backup.internal.").decision is Decision.ALLOW
    assert enc.decide_egress("evil.internal").decision is Decision.DENY


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
    # Per-enclave chains default-deny via an explicit counter drop.
    assert 'counter drop comment "bdos vault default-deny egress"' in ruleset
    assert 'counter drop comment "bdos mint default-deny egress"' in ruleset
    # The single base output chain accepts by default so the host is not
    # blackholed, and dispatches only member-sourced traffic into enclave chains.
    assert "hook output priority filter; policy accept;" in ruleset
    assert "ip saddr @bdos_vault_src jump vault_egress" in ruleset
    # Allowlisted destinations become accept rules.
    assert "ip daddr 10.0.0.5 accept" in ruleset
    assert "ip daddr 192.168.1.0/24 accept" in ruleset
    assert "ip daddr backup.internal accept" in ruleset


def test_nftables_does_not_blackhole_the_host():
    # A restrictive enclave must not drop non-member egress: exactly one base
    # hook, and its policy is accept.
    ruleset = compile_nftables([_enclave(id="vault", egress=[])])
    assert ruleset.count("hook output") == 1
    assert "policy drop;" not in ruleset
    assert "policy accept;" in ruleset


def test_nftables_rejects_injected_egress_entry():
    bad = _enclave(id="evil", egress=["1.2.3.4 accept; drop #"])
    with pytest.raises(ValueError):
        compile_nftables([bad])


def test_nftables_is_deterministic_and_order_independent():
    a = _enclave(id="alpha", egress=["10.0.0.1"])
    b = _enclave(id="bravo", egress=["10.0.0.2"])
    assert compile_nftables([a, b]) == compile_nftables([b, a])


def test_nftables_sealed_enclave_has_no_accept_rules():
    enc = _enclave(id="vault", egress=["10.0.0.5"], sealed=True)
    ruleset = compile_nftables([enc])
    assert "SEALED" in ruleset
    assert "10.0.0.5 accept" not in ruleset
    # The sealed enclave's chain still ends in the default-deny counter drop.
    assert 'counter drop comment "bdos vault default-deny egress"' in ruleset


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


def test_router_folds_all_containing_enclaves_most_restrictive():
    # If a member is (mis)configured into two enclaves, the strictest wins: a
    # permissive enclave cannot shadow a sealed one.
    open_enc = _enclave(id="open", members=["m"], egress=["10.0.0.5"])
    sealed = _enclave(id="sealed", members=["m"], egress=["10.0.0.5"], sealed=True)
    router = EnclaveRouter([open_enc, sealed])
    assert router.enclaves_for("m") == [open_enc, sealed]
    assert router.decide("m", "10.0.0.5").decision is Decision.DENY


def test_config_rejects_overlapping_enclave_members():
    from bdos.core.config import from_dict
    from bdos.core.errors import ConfigError

    with pytest.raises(ConfigError):
        from_dict(
            {
                "blackdomain": {
                    "enclaves": [
                        {"id": "a", "members": ["shared"]},
                        {"id": "b", "members": ["shared"]},
                    ]
                }
            }
        )
