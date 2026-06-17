"""Tests for the pivot-mapping registry (backend/pivot_mapping.py).

Covers the cross-vertical extension point (register_pivots) and the
iso-functional guarantee that CTI types are unaffected and unknown types return
no pivots.
"""
import pytest

from backend import pivot_mapping as pm


def _no_key(_src):  # pretend every keyed source has no API key
    return False


def _has_key(_src):  # pretend every keyed source has a key
    return True


def test_unknown_type_returns_no_pivots():
    assert pm.pivots_for("totally_unknown_type", "x", has_key=_has_key) == []


def test_cti_domain_pivots_present():
    ops = [op for op, _, _ in pm.pivots_for("domain", "evil.com", has_key=_has_key)]
    assert "rdap_domain" in ops and "crtsh_subdomains" in ops


def test_register_new_osint_type():
    pm.register_pivots("osint_handle_test", [
        ("some_osint_tool", 3, None, False),
        ("keyed_osint_tool", 3, "someprovider", False),
    ])
    assert "osint_handle_test" in pm.known_pivot_types()
    # has_key True → both pivots pending
    out = pm.pivots_for("osint_handle_test", "alice", has_key=_has_key)
    assert ("some_osint_tool", 3, None) in out
    # missing key → keyed pivot gets skip_reason
    out2 = pm.pivots_for("osint_handle_test", "alice", has_key=_no_key)
    assert ("keyed_osint_tool", 3, "no_api_key") in out2


def test_register_dedups_by_op():
    pm.register_pivots("dedup_test", [("t1", 2, None, False)])
    pm.register_pivots("dedup_test", [("t1", 9, None, False), ("t2", 3, None, False)])
    ops = [op for op, _, _ in pm.pivots_for("dedup_test", "x", has_key=_has_key)]
    assert ops.count("t1") == 1   # first registration wins, no duplicate
    assert "t2" in ops


def test_register_replace():
    pm.register_pivots("replace_test", [("old", 2, None, False)])
    pm.register_pivots("replace_test", [("new", 2, None, False)], replace=True)
    ops = [op for op, _, _ in pm.pivots_for("replace_test", "x", has_key=_has_key)]
    assert ops == ["new"]


def test_register_validates_tuple_shape():
    with pytest.raises(ValueError):
        pm.register_pivots("bad_test", [("op", "not_an_int", None, False)])
    with pytest.raises(ValueError):
        pm.register_pivots("bad_test", [("op", 2, None)])  # wrong arity


def test_kit_handle_for_tag():
    # canonicalises spacing/case; unambiguous PhaaS kits only
    assert pm.kit_handle_for_tag("tycoon_2fa") == "Tycoon 2FA"
    assert pm.kit_handle_for_tag("Tycoon 2FA") == "Tycoon 2FA"
    assert pm.kit_handle_for_tag("evilproxy") == "EvilProxy"
    # dual-use tech must NOT promote (benign sites use Turnstile)
    assert pm.kit_handle_for_tag("turnstile") is None
    assert pm.kit_handle_for_tag("not_a_kit") is None


def test_actor_handle_for_tag_still_works():
    assert pm.actor_handle_for_tag("storm-1747") == "Storm-1747"
    assert pm.actor_handle_for_tag("muddywater") == "MuddyWater"
