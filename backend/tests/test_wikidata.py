"""Unit tests for the Wikidata identity source (no network)."""
import asyncio

from backend.sources import wikidata as wd


_ENT = {
    "labels": {"en": {"value": "Linus Torvalds"}},
    "descriptions": {"en": {"value": "Finnish-American software engineer"}},
    "claims": {
        "P856": [{"mainsnak": {"datavalue": {"value": "https://torvalds.example"}}}],
        "P2002": [{"mainsnak": {"datavalue": {"value": "Linus__Torvalds"}}}],
        "P2037": [{"mainsnak": {"datavalue": {"value": "torvalds"}}}],
        "P571": [{"mainsnak": {"datavalue": {"value": {"time": "+1969-12-28T00:00:00Z"}}}}],
        "P17": [{"mainsnak": {"datavalue": {"value": {"id": "Q33"}}}}],  # QID-valued → skipped
    },
}


def test_parse_entity_extracts_handles_and_skips_qids():
    out = wd._parse_entity("Q34253", _ENT)
    assert out["qid"] == "Q34253"
    assert out["url"].endswith("/Q34253")
    assert out["label"] == "Linus Torvalds"
    assert out["github"] == "torvalds"
    assert out["twitter"] == "Linus__Torvalds"
    assert out["official_website"] == "https://torvalds.example"
    assert out["inception"].startswith("1969")   # time value, '+' stripped
    assert "P17" not in out and "country" not in out  # QID-valued claim skipped


def test_claim_value_variants():
    assert wd._claim_value({}, "P856") is None
    assert wd._claim_value({"P2037": [{"mainsnak": {"datavalue": {"value": "x"}}}]}, "P2037") == "x"


def test_lookup_empty():
    out = asyncio.run(wd.lookup("  "))
    assert out["found"] is False and "error" in out


def test_lookup_no_match(monkeypatch):
    async def fake(url, params=None, ttl=0, cache_key=None, **kw):
        return {"search": []}
    monkeypatch.setattr(wd, "get_json", fake)
    out = asyncio.run(wd.lookup("zzz nonexistent"))
    assert out["found"] is False


def test_lookup_end_to_end(monkeypatch):
    async def fake(url, params=None, ttl=0, cache_key=None, **kw):
        if params.get("action") == "wbsearchentities":
            return {"search": [{"id": "Q34253", "label": "Linus Torvalds",
                                "description": "engineer"},
                               {"id": "Q999", "label": "Other", "description": "x"}]}
        return {"entities": {"Q34253": _ENT}}
    monkeypatch.setattr(wd, "get_json", fake)
    out = asyncio.run(wd.lookup("Linus Torvalds"))
    assert out["found"] is True and out["qid"] == "Q34253"
    assert out["github"] == "torvalds"
    assert out["match_count"] == 2 and out["alternates"][0]["qid"] == "Q999"
