"""Evidence → Load: the cached source answers that mention a node's value."""
import backend.graph_store as gs


def test_evidence_returns_source_answers_for_the_value(tmp_path, monkeypatch):
    monkeypatch.setattr(gs, "DB_PATH", str(tmp_path / "t.db"))
    gs.init_db()
    gs.cache_set("GET|https://rdap.org/domain/evil.example|None", {"handle": "X1"})
    gs.cache_set("GET|https://rdap.org/domain/other.example|None", {"handle": "X2"})
    # A bookkeeping row that happens to carry the value is not evidence.
    gs.cache_set("counter|inv1|evil.example", 3)

    evidence = gs.get_evidence_for_value("evil.example")

    # Until 2026-11 the row was read as r["cache_key"], a column the query never
    # selected: any node with a cached answer answered HTTP 500.
    assert [e["cache_key"] for e in evidence] == ["GET|https://rdap.org/domain/evil.example|None"]
    assert evidence[0]["data"] == {"handle": "X1"}
    assert evidence[0]["cached_at"] > 0


def test_evidence_is_empty_when_nothing_was_cached(tmp_path, monkeypatch):
    monkeypatch.setattr(gs, "DB_PATH", str(tmp_path / "t.db"))
    gs.init_db()
    assert gs.get_evidence_for_value("nothing.example") == []
