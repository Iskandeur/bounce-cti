"""A `node_updated` event describes the node as it is stored."""
import backend.graph_store as gs


def test_second_report_keeps_the_first_source_and_confidence(tmp_path, monkeypatch):
    monkeypatch.setattr(gs, "DB_PATH", str(tmp_path / "t.db"))
    gs.init_db()
    gs.add_node("inv1", "domain", "evil.example", source="crtsh", confidence=0.9)
    gs.add_node("inv1", "domain", "evil.example", source="urlscan", confidence=0.4,
                metadata={"title": "login"})

    added, updated = [e for e in gs.get_events_since("inv1")
                      if e["kind"] in ("node_added", "node_updated")]
    stored = gs.get_graph("inv1")["nodes"][0]

    # An upsert merges metadata, tags and sources_seen; `source` and
    # `confidence` are written once. Until 2026-11 the event carried the second
    # caller's, values stored nowhere: a live client showed another confidence
    # than the same page after a reload.
    assert (stored["source"], stored["confidence"]) == ("crtsh", 0.9)
    assert (updated["node"]["source"], updated["node"]["confidence"]) == ("crtsh", 0.9)
    assert updated["node"]["created_at"] == added["node"]["created_at"]
    assert sorted(updated["node"]["metadata"]["sources_seen"]) == ["crtsh", "urlscan"]
    assert updated["node"]["metadata"]["title"] == "login"
