"""Mechanical DD sanctions sweep — guaranteed screen + evidence node."""
import asyncio

from backend import agent_runner as ar
import backend.sources.sanctions as s


def test_dd_sanctions_sweep_tags_and_emits_evidence(monkeypatch):
    graph = {"nodes": [
        {"type": "company", "value": "BadCo"},
        {"type": "person", "value": "Jane Clean"},
        {"type": "company", "value": "CleanCo"},
    ]}
    monkeypatch.setattr(ar.gs, "get_graph", lambda inv: graph)
    added = []
    monkeypatch.setattr(ar.gs, "add_node",
                        lambda inv, t, v, **k: added.append((t, v, k.get("tags"), k.get("metadata"))) or {"id": "x"})

    async def fake_batch(names, lists=None):
        return {"flagged": ["BadCo"], "results": [
            {"name": "BadCo", "hits": [{"list": "OFAC", "programs": ["UKRAINE"], "name": "BADCO"}], "hit_count": 1},
            {"name": "Jane Clean", "hits": [], "hit_count": 0},
            {"name": "CleanCo", "hits": [], "hit_count": 0},
        ]}
    monkeypatch.setattr(s, "screen_batch", fake_batch)

    asyncio.run(ar._dd_sanctions_sweep("inv1"))

    # Flagged company tagged `sanctioned` with match metadata
    badco = [a for a in added if a[1] == "BadCo"]
    assert badco and "sanctioned" in (badco[0][2] or [])
    assert badco[0][3]["sanctions_list"] == "OFAC"
    # Clean nodes are NOT tagged sanctioned
    assert not any(a[1] in ("Jane Clean", "CleanCo") and a[0] in ("company", "person")
                   for a in added)
    # Evidence report node always emitted (provenance), with the flagged list
    rep = [a for a in added if a[0] == "report" and a[1] == "sanctions_screen"]
    assert rep and rep[0][3]["flagged"] == ["BadCo"] and rep[0][3]["screened_count"] == 3


def test_dd_sanctions_sweep_noop_without_entities(monkeypatch):
    monkeypatch.setattr(ar.gs, "get_graph", lambda inv: {"nodes": [{"type": "domain", "value": "x.com"}]})
    added = []
    monkeypatch.setattr(ar.gs, "add_node", lambda *a, **k: added.append(a) or {"id": "x"})
    asyncio.run(ar._dd_sanctions_sweep("inv1"))
    assert added == []  # nothing to screen → no evidence node, no calls
