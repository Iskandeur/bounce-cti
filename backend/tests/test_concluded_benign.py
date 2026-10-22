"""A CTI seed the investigation itself concluded legitimate is not pivot-drained.

N2 (`cdn.jsdelivr.net`, 2026-10-21, claude-opus-5): main + followup concluded
"legitimate" / "benign" at 31 nodes (RST 100 if scored there). The autonomous
pivot drain then ran urlhaus_host on the CDN and graphed an unrelated
ACRStealer / ClearFake cluster from its abuse URLs: 65 nodes, 8 infra nodes
tagged malicious, 3 kit/family nodes, RST 0. The system prompt already says
"legitimate → … write benign report and STOP"; the drain was the one phase
that did not hear it.

Replayed on the production database (169 drains, graph rebuilt from the events
as it was when each drain started): the gate skips 19 CTI drains, all on
benign seeds, 2 of which had produced malicious nodes; every positive case of
the 2026-10-21 bench still drains; no kept drain with a `legitimate`
hypothesis adds a malicious node.
"""
import asyncio

import pytest

from backend import agent_runner as ar


def _graph(hypothesis="legitimate", assessment="benign", seed_tags=("seed", "benign", "cdn"),
           extra_hypothesis=None, summary=True):
    nodes = [
        {"type": "domain", "value": "cdn.example.net", "tags": list(seed_tags)},
        {"type": "ip", "value": "104.16.0.1", "tags": ["cdn"]},
        {"type": "report", "value": "working_hypothesis",
         "metadata": {"candidate_category": hypothesis, "confidence": "high"}},
    ]
    if extra_hypothesis:
        nodes.append({"type": "report", "value": "working_hypothesis_2",
                      "metadata": {"category": extra_hypothesis}})
    if summary:
        nodes.append({"type": "report", "value": "investigation_summary",
                      "metadata": {"threat_assessment": assessment}})
    return nodes


# ── The verdict ───────────────────────────────────────────────────────────────

def test_n2_shape_at_drain_start_is_a_benign_verdict():
    v = ar._concluded_benign(_graph())
    assert v == {"hypothesis": "legitimate", "threat_assessment": "benign"}


@pytest.mark.parametrize("hypothesis", ["unclear", "fronted_c2", "commodity_malware", "", None])
def test_any_other_hypothesis_is_no_verdict(hypothesis):
    assert ar._concluded_benign(_graph(hypothesis=hypothesis)) is None


@pytest.mark.parametrize("assessment", ["suspicious", "likely_malicious", "malicious", None, "unknown"])
def test_a_summary_that_is_not_benign_is_no_verdict(assessment):
    assert ar._concluded_benign(_graph(assessment=assessment)) is None


def test_no_summary_yet_is_no_verdict():
    assert ar._concluded_benign(_graph(summary=False)) is None


def test_a_second_hypothesis_that_disagrees_is_no_verdict():
    # Re-hypothesized after a surprise: the two statements disagree.
    assert ar._concluded_benign(_graph(extra_hypothesis="fronted_c2")) is None
    assert ar._concluded_benign(_graph(extra_hypothesis="legitimate")) is not None


@pytest.mark.parametrize("tag", ["malicious", "c2", "clearfake_c2", "lummac2", "phishing_page"])
def test_a_seed_tagged_malicious_is_never_a_benign_verdict(tag):
    assert ar._concluded_benign(_graph(seed_tags=("seed", "benign", tag))) is None


def test_without_a_seed_node_there_is_no_verdict():
    nodes = [n for n in _graph() if n["type"] == "report"]
    assert ar._concluded_benign(nodes) is None


# Phrasings found in the production summaries (45 of 262 are off the enum).
@pytest.mark.parametrize("value", [
    "benign", "BENIGN", " benign ", "benign_infrastructure", "likely_benign",
    "BENIGN — IANA reserved example domain. No threat actor infrastructure",
    "Not malicious. Independent reputation telemetry corroborates the verdict",
    "LOW — no malicious indicators across all enrichment sources",
    "benign_seed_with_malicious_abuse_cluster",
])
def test_benign_phrasings_read_as_benign(value):
    assert ar._assessment_is_benign(value)


@pytest.mark.parametrize("value", [
    "malicious", "suspicious", "likely_malicious", "likely_scam", "unknown", "", None,
    "High confidence malicious. 30/61 VT engines flag it",
    "HIGH — Active state-sponsored operation",
    "Risque élevé - infrastructure de fraude multi-domaines",
    "lowered confidence after pivots, still malicious",
])
def test_other_phrasings_do_not(value):
    assert not ar._assessment_is_benign(value)


def test_is_parked_still_uses_the_shared_malicious_tags(monkeypatch):
    # The tag set moved to module level; _is_parked keeps its c12 behaviour.
    monkeypatch.setattr(ar.gs, "get_graph", lambda inv_id: {"nodes": [
        {"type": "domain", "value": "evil.test", "tags": ["seed", "clearfake_c2"]},
        {"type": "ns", "value": "ns1.park.test", "tags": ["parking"]},
    ]})
    assert ar._is_parked("x") is False


# ── The drain gate, through run_investigation ─────────────────────────────────

@pytest.fixture
def db(tmp_path, monkeypatch):
    path = tmp_path / "test.db"
    from backend import config, graph_store
    monkeypatch.setattr(config, "DB_PATH", path, raising=False)
    monkeypatch.setattr(graph_store, "DB_PATH", path, raising=False)
    graph_store.init_db()
    root = tmp_path / "root"
    (root / "data").mkdir(parents=True)
    monkeypatch.setattr(ar, "ROOT", root)
    monkeypatch.delenv("BOUNCE_PIVOT_DRAIN_ON_BENIGN", raising=False)
    monkeypatch.setenv("BOUNCE_PIVOT_DRAIN_ROUNDS", "3")
    return graph_store


def _run(db, monkeypatch, *, vertical="cti", hypothesis="legitimate", assessment="benign"):
    """Run the whole workflow with a fake agent. The main phase writes the
    seed, the hypothesis and the summary; each drain round adds 5 nodes (so
    the loop would not converge on its own). Returns the phases spawned and
    the event kinds logged."""
    inv = db.create_investigation("domain", "cdn.example.net", user_id=1, vertical=vertical)
    phases = []

    async def fake_phase(inv_id, prompt, system_prompt, model, env, mcp_cfg_path,
                         phase="main", **kw):
        phases.append(phase)
        if phase == "main":
            db.add_node(inv_id, "domain", "cdn.example.net", tags=["seed", "benign", "cdn"])
            db.add_node(inv_id, "report", "working_hypothesis",
                        metadata={"candidate_category": hypothesis})
            db.add_node(inv_id, "report", "investigation_summary",
                        metadata={"threat_assessment": assessment, "summary": "x"})
        elif phase.startswith("pivot_drain_"):
            for i in range(5):
                db.add_node(inv_id, "domain", f"{phase}-{i}.abuse.test", tags=["malicious"])
        return 0, True, True, {"hit": False}

    monkeypatch.setattr(ar, "_run_claude_phase", fake_phase)
    asyncio.run(ar.run_investigation(inv, "domain", "cdn.example.net", model="haiku"))
    with db.conn() as c:
        kinds = [r[0] for r in c.execute(
            "SELECT kind FROM events WHERE investigation_id=? ORDER BY id", (inv,))]
    return phases, kinds


def test_a_benign_cti_verdict_skips_the_drain(db, monkeypatch):
    phases, kinds = _run(db, monkeypatch)
    assert not [p for p in phases if p.startswith("pivot_drain_")]
    assert "phase_pivot_drain_skipped" in kinds
    assert "phase_pivot_drain_starting" not in kinds
    assert "lessons_learned" in phases  # the run still finishes normally


def test_a_malicious_verdict_still_drains(db, monkeypatch):
    phases, kinds = _run(db, monkeypatch, hypothesis="commodity_malware", assessment="malicious")
    assert [p for p in phases if p.startswith("pivot_drain_")] == [
        "pivot_drain_1", "pivot_drain_2", "pivot_drain_3"]
    assert "phase_pivot_drain_skipped" not in kinds


@pytest.mark.parametrize("vertical", ["osint", "dd"])
def test_osint_and_dd_still_drain_a_legitimate_subject(db, monkeypatch, vertical):
    phases, kinds = _run(db, monkeypatch, vertical=vertical)
    assert "pivot_drain_1" in phases
    assert "phase_pivot_drain_skipped" not in kinds


def test_the_switch_restores_the_drain_on_benign(db, monkeypatch):
    monkeypatch.setenv("BOUNCE_PIVOT_DRAIN_ON_BENIGN", "1")
    phases, kinds = _run(db, monkeypatch)
    assert "pivot_drain_1" in phases
    assert "phase_pivot_drain_skipped" not in kinds
