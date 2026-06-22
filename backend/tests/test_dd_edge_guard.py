"""Vertical guard on add_edge: DD graphs reject CTI-style relations."""
from backend.mcp_servers import graph_mcp as gm


def test_dd_rejects_cti_relations(monkeypatch):
    monkeypatch.setattr(gm.gs, "get_vertical", lambda inv: "dd")
    calls = []
    monkeypatch.setattr(gm.gs, "add_edge", lambda *a, **k: calls.append(a) or {"ok": True})
    r = gm.add_edge("company", "SAP", "domain", "sap.com", "known_ioc")
    assert r.get("skipped") == "vertical_scope" and not calls  # not persisted


def test_dd_allows_corporate_relations(monkeypatch):
    monkeypatch.setattr(gm.gs, "get_vertical", lambda inv: "dd")
    calls = []
    monkeypatch.setattr(gm.gs, "add_edge", lambda *a, **k: calls.append(k.get("evidence", a)) or {"ok": True})
    gm.add_edge("company", "SAP SE", "company", "SAP America Inc", "subsidiary_of")
    assert len(calls) == 1  # corporate relation passes through


def test_cti_vertical_unaffected(monkeypatch):
    monkeypatch.setattr(gm.gs, "get_vertical", lambda inv: "cti")
    calls = []
    monkeypatch.setattr(gm.gs, "add_edge", lambda *a, **k: calls.append(a) or {"ok": True})
    gm.add_edge("domain", "a.com", "ip", "1.2.3.4", "resolves_to")  # CTI relation
    assert len(calls) == 1  # still added in CTI
