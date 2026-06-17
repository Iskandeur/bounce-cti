"""Tests for agent_runner._is_parked() — the parked/blackhole/sinkhole
short-circuit gate that, when True, skips the hypothesis + followup phases.

Locks FIX-1 (2026-06-17 eval c12): a malicious seed must NOT be short-circuited
just because its registrar parking nameservers carry a `parking` tag, while a
genuinely parked seed still short-circuits.
"""
from backend import agent_runner as ar


def _patch_graph(monkeypatch, nodes):
    monkeypatch.setattr(ar.gs, "get_graph", lambda inv_id: {"nodes": nodes})


def test_malicious_seed_with_parking_ns_is_not_parked(monkeypatch):
    # c12 ClearFake shape: malicious seed domain + parking nameservers.
    _patch_graph(monkeypatch, [
        {"type": "domain", "value": "921hapudyqwdvy.com",
         "tags": ["seed", "clearfake_c2", "c2", "malicious", "dga"]},
        {"type": "ns", "value": "ns1.renewyourname.net", "tags": ["parking"]},
        {"type": "ns", "value": "ns2.renewyourname.net", "tags": ["parking"]},
    ])
    assert ar._is_parked("x") is False


def test_campaign_only_tag_via_substring(monkeypatch):
    # Only a campaign-specific c2 tag on the seed (no generic 'c2'/'malicious').
    _patch_graph(monkeypatch, [
        {"type": "domain", "value": "evil.com", "tags": ["seed", "lummac2"]},
        {"type": "ns", "value": "ns1.park.test", "tags": ["parking"]},
    ])
    assert ar._is_parked("x") is False


def test_genuinely_parked_seed_is_parked(monkeypatch):
    # Benign parked domain: the SEED node itself is tagged parking.
    _patch_graph(monkeypatch, [
        {"type": "domain", "value": "forsale.test", "tags": ["seed", "parking"]},
    ])
    assert ar._is_parked("x") is True


def test_parking_on_non_ns_node_still_short_circuits(monkeypatch):
    # Benign seed whose resolved IP is a parking lander → still parked.
    _patch_graph(monkeypatch, [
        {"type": "domain", "value": "benign.test", "tags": ["seed"]},
        {"type": "ip", "value": "1.2.3.4", "tags": ["parking"]},
    ])
    assert ar._is_parked("x") is True


def test_le_seized_seed_is_not_parked(monkeypatch):
    # Unchanged: LE-takedown seed keeps the full historical workflow.
    _patch_graph(monkeypatch, [
        {"type": "domain", "value": "rugtou.shop", "tags": ["seed", "le_seized", "sinkhole"]},
        {"type": "ip", "value": "172.234.24.211", "tags": ["parking"]},
    ])
    assert ar._is_parked("x") is False
