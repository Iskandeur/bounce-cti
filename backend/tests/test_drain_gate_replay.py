"""eval/drain_gate_replay.py rebuilds each graph as it stood when its drain
started and applies the pivot-drain gate to it."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("drain_gate_replay", ROOT / "eval" / "drain_gate_replay.py")
replay = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(replay)


@pytest.fixture
def gs(tmp_path, monkeypatch):
    path = tmp_path / "bounce.db"
    from backend import config, graph_store
    monkeypatch.setattr(config, "DB_PATH", path, raising=False)
    monkeypatch.setattr(graph_store, "DB_PATH", path, raising=False)
    graph_store.init_db()
    return graph_store


def _phase(gs, inv, kind):
    from backend import agent_runner
    agent_runner._log(inv, kind, {})


def _investigation(gs, *, hypothesis, assessment, vertical="cti", drained_malicious=0):
    inv = gs.create_investigation("domain", "seed.example", user_id=1, vertical=vertical)
    gs.add_node(inv, "domain", "seed.example", tags=["seed"])
    gs.add_node(inv, "report", "working_hypothesis", metadata={"candidate_category": hypothesis})
    gs.add_node(inv, "report", "investigation_summary", metadata={"threat_assessment": assessment})
    _phase(gs, inv, "phase_pivot_drain_starting")
    for i in range(drained_malicious):
        gs.add_node(inv, "domain", f"c2-{i}.test", tags=["malicious"])
    # A summary rewritten by the drain must not count: the gate decides before it.
    gs.add_node(inv, "report", "investigation_summary", metadata={"threat_assessment": "malicious"})
    _phase(gs, inv, "phase_lessons_learned_starting")
    return inv


def test_the_replay_reads_the_graph_at_drain_start(gs, capsys):
    _investigation(gs, hypothesis="legitimate", assessment="benign", drained_malicious=2)
    _investigation(gs, hypothesis="commodity_malware", assessment="malicious", drained_malicious=3)
    _investigation(gs, hypothesis="legitimate", assessment="benign", vertical="osint")
    assert replay.main(["--db", str(gs.DB_PATH)]) == 0
    out = capsys.readouterr().out
    assert "drains replayed: 3" in out
    assert "skipped by the gate: 1 " in out
    assert "of which added malicious nodes: 1)" in out
    assert "malicious added 2" in out
    assert "seed.example" not in out  # seed values only with --seeds
    assert "kept drains on a `legitimate` hypothesis that added malicious nodes: 0" in out


def test_a_miss_is_reported(gs, capsys):
    # legitimate hypothesis but a summary that is not benign: the gate keeps the
    # drain, and the drain adds malicious nodes → reported as a miss.
    _investigation(gs, hypothesis="legitimate", assessment="suspicious", drained_malicious=1)
    replay.main(["--db", str(gs.DB_PATH), "--seeds"])
    out = capsys.readouterr().out
    assert "skipped by the gate: 0 " in out
    assert "that added malicious nodes: 1" in out
    assert "seed.example" in out
