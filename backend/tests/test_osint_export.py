"""Unit tests for the OSINT identity dossier renderer (pure, no DB)."""
from backend import osint_export as ox

_GRAPH = {
    "nodes": [
        {"id": "n1", "type": "username", "value": "janedoe", "tags": ["seed"],
         "metadata": {"platform": "github", "url": "https://github.com/janedoe"}},
        {"id": "n2", "type": "email", "value": "jane@example.com", "tags": [],
         "metadata": {"source": "gravatar"}},
        {"id": "n3", "type": "phone", "value": "+16502530000", "tags": ["voip_line"],
         "metadata": {"region": "US", "carrier": "Acme", "line_type": "voip"}},
        {"id": "n4", "type": "wallet_address", "value": "bc1xyz", "tags": [],
         "metadata": {"chain": "btc", "balance_btc": 1.25, "tx_count": 42}},
        {"id": "n5", "type": "ip", "value": "1.2.3.4", "tags": ["cdn"], "metadata": {}},
        {"id": "rep", "type": "report", "value": "investigation_summary",
         "metadata": {"summary": "Jane is active on GitHub.",
                      "key_findings": ["Linked GitHub + email"]}},
    ],
    "edges": [
        {"source": "n1", "target": "n2", "relation": "linked_to"},
    ],
}
_INV = {"id": "inv1", "seed_type": "username", "seed_value": "janedoe", "title": "Jane"}


def test_dossier_header_and_summary():
    md = ox.render_dossier(_GRAPH, _INV)
    assert md.startswith("# OSINT Dossier — janedoe")
    assert "(username)" in md
    assert "Jane is active on GitHub." in md
    assert "5 nodes · 1 connections" in md  # report node excluded from count


def test_dossier_identity_sections_with_detail():
    md = ox.render_dossier(_GRAPH, _INV)
    assert "## Usernames & handles (1)" in md
    assert "github" in md and "https://github.com/janedoe" in md
    assert "## Phone numbers (1)" in md
    assert "US · Acme · voip" in md
    assert "_voip_line_" in md          # tag suffix
    assert "## Crypto wallets (1)" in md
    assert "BTC · 1.25 BTC · 42 tx" in md
    assert "## Emails (1)" in md


def test_dossier_infra_and_connections_and_findings():
    md = ox.render_dossier(_GRAPH, _INV)
    assert "## Infrastructure (1)" in md and "1.2.3.4" in md
    assert "## Connections (1)" in md
    assert "`janedoe` —[linked_to]→ `jane@example.com`" in md
    assert "## Key findings" in md and "Linked GitHub + email" in md
    assert "## Provenance" in md and "gravatar" in md


def test_dossier_handles_empty_graph():
    md = ox.render_dossier({"nodes": [], "edges": []}, {"id": "x", "seed_value": "?"})
    assert "# OSINT Dossier" in md
    assert "No summary" in md
    assert "0 nodes · 0 connections" in md
