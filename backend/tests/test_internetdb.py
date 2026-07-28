"""InternetDB source tests — normalisation and the no-key/no-credit contract.

InternetDB is the one Shodan surface that needs no API key and cannot consume
credits, so it is the fallback that keeps IP exposure data available even on an
instance with no Shodan key at all. These tests are offline.
"""
import asyncio

import pytest

from backend.sources import internetdb


def test_normalise_populates_counts_and_caveats():
    out = internetdb._normalise("1.2.3.4", {
        "ip": "1.2.3.4",
        "ports": [22, 80, 443, 8787],
        "vulns": ["CVE-2021-44228", "CVE-2023-1234"],
        "cpes": ["cpe:/a:apache:http_server"],
        "hostnames": ["host.example.com"],
        "tags": ["cloud"],
    })
    assert out["found"] is True
    assert out["port_count"] == 4 and out["vuln_count"] == 2
    assert out["ports"] == [22, 80, 443, 8787]
    # The freshness caveat must ride along — a weekly-refreshed port list read
    # as live state is the main way to misuse this source.
    assert "weekly" in out["_freshness"]
    assert out["_cost"].startswith("free")


def test_normalise_tolerates_missing_fields():
    out = internetdb._normalise("1.2.3.4", {})
    assert out["found"] is False
    assert out["ports"] == [] and out["vulns"] == []
    assert out["port_count"] == 0


def test_empty_ip_short_circuits_without_network(monkeypatch):
    def _explode(*a, **k):
        raise AssertionError("network call attempted for an empty IP")
    monkeypatch.setattr(internetdb.httpx, "AsyncClient", _explode)
    out = asyncio.run(internetdb.internetdb_ip("  "))
    assert out["found"] is False and "no IP" in out["reason"]


def test_empty_shape_is_consistent_with_found_shape():
    """A miss must expose the same keys as a hit, so callers never KeyError."""
    hit = internetdb._normalise("1.2.3.4", {"ports": [80]})
    miss = internetdb._empty("1.2.3.4", "not indexed")
    for key in ("ip", "found", "ports", "vulns", "cpes", "hostnames", "tags"):
        assert key in hit and key in miss, key


def test_source_needs_no_key():
    """Guard against someone wiring a key requirement into the keyless source."""
    src = (internetdb.__file__)
    text = open(src, encoding="utf-8").read()
    assert "key_pool" not in text
    assert "API_KEY" not in text


# ── hint behaviour (what the agent actually reacts to) ─────────────────────

def test_hint_flags_cves_as_inferred_not_confirmed():
    from backend.hints import hint_for_internetdb_ip
    hints = hint_for_internetdb_ip(
        {"found": True, "vulns": ["CVE-2021-44228"], "ports": [], "hostnames": []},
        "1.2.3.4")
    assert hints and "INFERRED" in hints[0]


def test_no_hints_when_nothing_found():
    from backend.hints import hint_for_internetdb_ip
    assert hint_for_internetdb_ip({"found": False}, "1.2.3.4") == []


def test_host_count_hint_calls_out_a_zero_cluster():
    from backend.hints import hint_for_shodan_host_count
    hints = hint_for_shodan_host_count({"total": 0}, "ssl.jarm:abc")
    assert hints and "0 hosts" in hints[0]
    # It must actively discourage re-running the query through the paid path.
    assert "credit" in hints[0]


def test_host_count_hint_reads_facets():
    from backend.hints import hint_for_shodan_host_count
    hints = hint_for_shodan_host_count({
        "total": 42,
        "facets": {"asn": [{"value": "AS9009", "count": 40},
                           {"value": "AS16509", "count": 2}]},
    }, "ssl.jarm:abc")
    joined = " ".join(hints)
    assert "42 host(s)" in joined and "AS9009" in joined
    # And it should point at free ways to graph the members.
    assert "netlas" in joined
