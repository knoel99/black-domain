import datetime as dt
from pathlib import Path

import pytest

from bdos.core.errors import ConfigError
from bdos.controlplane.cli import main as cli_main
from bdos.registry import ERROR, WARNING, check, coverage, from_dict, load

SAMPLE = Path(__file__).resolve().parent.parent / "os" / "etc" / "bdos" / "controls.toml"
TODAY = dt.date(2026, 10, 20)


def _control(**over) -> dict:
    base = {
        "id": "C-1",
        "principle": "3.1",
        "title": "egress deny",
        "kind": "regle",
        "scar": "dns exfiltration",
        "threat_hypothesis": "implant calling home",
        "effect_class": "exfiltration",
        "property_based": True,
        "lifted_by": ["net", "ciso"],
        "indicator": "share of egress via proxy",
        "owner": "net",
        "review_by": dt.date(2027, 1, 1),
    }
    base.update(over)
    return base


def _findings(*controls):
    return check(from_dict({"control": list(controls)}), TODAY)


def test_clean_control_has_no_findings():
    assert _findings(_control()) == []


def test_law_must_resist_a_compromised_admin_and_be_checkable():
    msgs = [f.message for f in _findings(_control(kind="loi"))]
    assert any("compromised production admin" in m for m in msgs)
    assert any("third-party check" in m for m in msgs)
    ok = _control(kind="loi", resists_compromised_admin=True, third_party_check="auditor reads config", lifted_by=[])
    assert _findings(ok) == []


def test_irreversible_control_in_one_hand_is_an_error():
    f = _findings(_control(reversible=False, lifted_by=["on-call"]))
    assert [(x.severity, x.principle) for x in f] == [(ERROR, "3.8")]


def test_missing_scar_and_hypothesis_are_errors():
    f = _findings(_control(scar="", threat_hypothesis=""))
    assert {x.principle for x in f} == {"3.13", "3.9"}


def test_overdue_review_warns_and_expired_exception_errors():
    exc = {"id": "EX-1", "reason": "legacy", "expires": dt.date(2026, 1, 1), "approved_by": ["ciso"]}
    f = _findings(_control(review_by=dt.date(2026, 6, 1), exception=[exc]))
    assert {(x.severity, x.principle) for x in f} == {(WARNING, "3.10"), (ERROR, "3.10")}


def test_permanent_exception_is_an_error():
    f = _findings(_control(exception=[{"id": "EX-1", "reason": "forever"}]))
    assert any("no expiry" in x.message for x in f)


def test_unknown_principle_duplicate_id_and_rule_without_lifter():
    f = _findings(_control(principle="4.2"), _control(lifted_by=[]))
    msgs = " | ".join(x.message for x in f)
    assert "unknown principle" in msgs and "duplicate" in msgs and "who can lift" in msgs


def test_unknown_keys_are_refused():
    with pytest.raises(ConfigError, match="unknown keys"):
        from_dict({"control": [_control(colour="red")]})
    with pytest.raises(ConfigError, match="missing 'title'"):
        from_dict({"control": [_control(title="")]})


def test_coverage_finds_bare_principles_and_detection_only_effects():
    reg = from_dict({"control": [
        _control(),
        _control(id="C-2", principle="3.10", effect_class="exploitation", property_based=False),
    ]})
    cov = coverage(reg, TODAY)
    assert "3.1" not in cov["principles_without_control"]
    assert len(cov["principles_without_control"]) == 11
    assert cov["effect_classes_detection_only"] == ["exploitation"]


def test_sample_registry_covers_every_principle_and_shows_its_two_planted_defects():
    reg = load(str(SAMPLE))
    cov = coverage(reg, TODAY)
    assert cov["principles_without_control"] == []
    errors = [f for f in check(reg, TODAY) if f.severity == ERROR]
    assert sorted(f.control_id for f in errors) == ["C-3.5-uniform-errors", "C-3.8-seal-enclave"]


def test_cli_registry_exit_codes(capsys):
    assert cli_main(["registry", "check", str(SAMPLE), "--today", "2026-10-20"]) == 3
    assert cli_main(["registry", "coverage", str(SAMPLE), "--today", "2026-10-20"]) == 0
    out = capsys.readouterr().out
    assert "2 errors" in out and "detection-only" in out
