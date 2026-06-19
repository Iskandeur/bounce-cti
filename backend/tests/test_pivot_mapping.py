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


def test_is_mail_host():
    assert pm.is_mail_host("mx3.mail.ovh.net")
    assert pm.is_mail_host("aspmx.l.google.com")
    assert pm.is_mail_host("acme-com.mail.protection.outlook.com")
    assert not pm.is_mail_host("evil.com")
    assert not pm.is_mail_host("")


def test_cti_domain_pivots_present():
    ops = [op for op, _, _ in pm.pivots_for("domain", "evil.com", has_key=_has_key)]
    assert "rdap_domain" in ops and "crtsh_subdomains" in ops


def _reasons(node, value, vertical):
    return {op: reason for op, _, reason in
            pm.pivots_for(node, value, has_key=_has_key, vertical=vertical)}


def test_dd_ops_scoped_out_of_non_dd_verticals():
    # sanctions_screen (a person pivot) must NOT enqueue as pending in OSINT —
    # wrong domain + criminal-data legal risk (2026-06-19 OSINT retro).
    assert _reasons("person", "Jane", "osint")["sanctions_screen"] == "vertical_scope"
    assert _reasons("person", "Jane", "cti")["sanctions_screen"] == "vertical_scope"
    # ...but it's live in DD.
    assert _reasons("person", "Jane", "dd")["sanctions_screen"] is None


def test_company_dd_ops_only_in_dd():
    cti = _reasons("company", "Acme", "cti")
    assert cti.get("gleif_lookup") == "vertical_scope"
    dd = _reasons("company", "Acme", "dd")
    assert dd.get("gleif_lookup") is None and dd.get("sanctions_screen") is None


def test_osint_suppresses_threat_noise_keeps_identity_ops():
    r = _reasons("url", "https://github.com/jane", "osint")
    # threat-feed noise suppressed on a benign profile URL
    assert r.get("pulsedive_indicator") == "vertical_scope"
    assert r.get("dom_fingerprints") == "vertical_scope"
    # identity-useful ops kept live
    assert r.get("website_extract") is None
    assert r.get("wayback") is None
    # threatfox IS suppressed where it appears (domain node)
    rd = _reasons("domain", "janedoe.dev", "osint")
    assert rd.get("threatfox_search") == "vertical_scope"
    assert rd.get("rdap_domain") is None and rd.get("crtsh_subdomains") is None


def test_cti_unchanged_for_normal_nodes():
    # CTI url pivots keep their threat ops (no suppression) — EVAL invariant.
    r = _reasons("url", "http://evil.com", "cti")
    assert r.get("threatfox_search") is None or "threatfox_search" not in r
    assert r.get("website_extract") is None


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
