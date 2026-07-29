"""End-to-end lifecycle tests for a context-pool lead, against a real SQLite DB.

test_context_pool.py locks the predicates and test_lead_exclusion.py locks the
export wiring; this file exercises the actual graph mutations through
``graph_mcp`` — the layer where the confidence cap and the forced `lead` type are
enforced, and where a bug would let a hallucination through as a typed IOC.
"""
import importlib
import os

import pytest


@pytest.fixture
def gm(tmp_path, monkeypatch):
    """graph_mcp bound to a throwaway DB and investigation."""
    monkeypatch.setenv("BOUNCE_INV_ID", "inv-lifecycle")
    db = tmp_path / "test.db"
    monkeypatch.setenv("BOUNCE_DB_PATH", str(db))

    from backend import config, graph_store
    monkeypatch.setattr(config, "DB_PATH", db, raising=False)
    monkeypatch.setattr(graph_store, "DB_PATH", db, raising=False)
    graph_store.init_db()
    with graph_store.conn() as c:
        c.execute(
            "INSERT INTO investigations(id, seed_type, seed_value, status, created_at, vertical) "
            "VALUES (?,?,?,?,?,?)",
            ("inv-lifecycle", "username", "someone", "running", 0.0, "osint"))

    from backend.mcp_servers import graph_mcp
    importlib.reload(graph_mcp)
    monkeypatch.setattr(graph_mcp, "INV_ID", "inv-lifecycle")
    return graph_mcp


def _node(gm, value, type_="lead"):
    from backend import graph_store
    for n in graph_store.list_nodes_of_type("inv-lifecycle", type_):
        if n["value"] == value:
            return n
    return None


# ── The tier boundary, enforced in the store ───────────────────────────────

def test_memory_sourced_ip_is_collapsed_to_a_lead(gm):
    """The core guarantee: the agent asks for a typed IOC with memory as the
    source, and gets a lead — not an ip node — no matter what it passes."""
    res = gm._add_node_impl(
        type="ip", value="203.0.113.7", source="parametric_memory",
        confidence=0.95, metadata={"note": "I recall this being C2"})
    assert res["type"] == "lead"

    assert _node(gm, "203.0.113.7", "ip") is None, "must not exist as an ip node"
    lead = _node(gm, "203.0.113.7")
    assert lead is not None
    assert lead["confidence"] <= 0.35
    assert "unverified" in lead["tags"]
    # What the agent wanted is preserved for the promotion path.
    assert lead["metadata"]["proposed_type"] == "ip"


def test_web_sourced_node_is_also_collapsed(gm):
    gm._add_node_impl(type="domain", value="from-a-blog.example",
                      source="web:blog.example", confidence=0.9)
    assert _node(gm, "from-a-blog.example", "domain") is None
    assert _node(gm, "from-a-blog.example") is not None


def test_real_source_is_untouched(gm):
    """Regression guard: the tier boundary must not affect ordinary sources."""
    res = gm._add_node_impl(type="domain", value="observed.example",
                            source="crtsh", confidence=0.8)
    assert res["type"] == "domain"
    n = _node(gm, "observed.example", "domain")
    assert n["confidence"] == 0.8
    assert "unverified" not in n["tags"]


def test_lead_cannot_launder_an_actor_attribution(gm):
    """Tag promotion turns a known actor handle into a threat_actor node. A lead
    must not be able to trigger it — that would launder a guess into a
    first-class attribution."""
    from backend import graph_store
    gm._add_node_impl(type="lead", value="probably MuddyWater infrastructure",
                      source="parametric_memory", tags=["muddywater"])
    assert graph_store.list_nodes_of_type("inv-lifecycle", "threat_actor") == []


def test_lead_enqueues_only_a_verification_pivot(gm):
    from backend import graph_store
    gm._add_node_impl(type="lead", value="some claim", source="parametric_memory")
    with graph_store.conn() as c:
        ops = [r["pivot_op"] for r in c.execute(
            "SELECT pivot_op FROM pivot_tasks WHERE investigation_id=? AND node_value=?",
            ("inv-lifecycle", "some claim")).fetchall()]
    assert ops == ["verify_lead"]


# ── Corroboration ──────────────────────────────────────────────────────────

def test_corroboration_requires_a_primary_tool(gm):
    gm._add_node_impl(type="lead", value="claim A", source="parametric_memory")
    out = gm.corroborate_lead("claim A", "corroborated",
                              evidence_tool="mcp__ctx__web_search",
                              evidence_value="a blog said so")
    assert out["ok"] is False
    assert "memory cannot corroborate memory" in out["error"]


def test_corroboration_requires_an_evidence_value(gm):
    gm._add_node_impl(type="lead", value="claim B", source="parametric_memory")
    out = gm.corroborate_lead("claim B", "corroborated",
                              evidence_tool="mcp__cti__dns_resolve")
    assert out["ok"] is False


def test_refuting_a_lead_is_a_valid_terminal_state(gm):
    gm._add_node_impl(type="lead", value="claim C", source="parametric_memory")
    out = gm.corroborate_lead("claim C", "refuted",
                              evidence_tool="mcp__cti__crtsh_subdomains",
                              note="no such cert exists")
    assert out["ok"] is True
    lead = _node(gm, "claim C")
    assert "refuted" in lead["tags"]
    assert "unverified" not in lead["tags"], "lifecycle tags must be exclusive"


def test_corroboration_promotes_to_a_real_typed_node(gm):
    gm._add_node_impl(type="lead", value="claim D", source="parametric_memory")
    out = gm.corroborate_lead(
        "claim D", "corroborated",
        evidence_tool="mcp__cti__dns_resolve", evidence_value="198.51.100.9",
        promote_as_type="ip", promote_as_value="198.51.100.9")
    assert out["ok"] is True and out["promoted"]["type"] == "ip"

    promoted = _node(gm, "198.51.100.9", "ip")
    assert promoted is not None
    # The promoted node carries the PRIMARY tool as provenance, not the lead —
    # otherwise the tier boundary would re-collapse it.
    assert promoted["source"] == "mcp__cti__dns_resolve"
    assert promoted["confidence"] > 0.35
    assert "unverified" not in promoted["tags"]


def test_promotion_cannot_target_the_lead_type(gm):
    gm._add_node_impl(type="lead", value="claim E", source="parametric_memory")
    out = gm.corroborate_lead("claim E", "corroborated",
                              evidence_tool="mcp__cti__dns_resolve",
                              evidence_value="x",
                              promote_as_type="lead", promote_as_value="y")
    assert out.get("promoted") is False


def test_corroborate_rejects_unknown_verdict_and_unknown_lead(gm):
    gm._add_node_impl(type="lead", value="claim F", source="parametric_memory")
    assert gm.corroborate_lead("claim F", "probably-true")["ok"] is False
    assert gm.corroborate_lead("no such lead", "refuted",
                               evidence_tool="mcp__cti__dns_resolve")["ok"] is False


def test_corroboration_closes_the_verification_pivot(gm):
    from backend import graph_store
    gm._add_node_impl(type="lead", value="claim G", source="parametric_memory")
    gm.corroborate_lead("claim G", "unverifiable")
    with graph_store.conn() as c:
        row = c.execute(
            "SELECT status FROM pivot_tasks WHERE investigation_id=? AND node_value=?",
            ("inv-lifecycle", "claim G")).fetchone()
    assert row["status"] == "done"


def test_lead_status_reports_the_corroboration_rate(gm):
    gm._add_node_impl(type="lead", value="L1", source="parametric_memory")
    gm._add_node_impl(type="lead", value="L2", source="parametric_memory")
    gm.corroborate_lead("L1", "corroborated",
                        evidence_tool="mcp__cti__dns_resolve",
                        evidence_value="1.2.3.4")
    st = gm.lead_status()
    assert st["total_leads"] == 2
    assert st["corroborated"] == 1
    assert st["corroboration_rate"] == 0.5
    assert [p["value"] for p in st["pending"]] == ["L2"]
