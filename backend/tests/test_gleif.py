"""Unit tests for the GLEIF (DD) source parser (no network)."""
import asyncio

from backend.sources import gleif


_REC = {
    "id": "529900T8BM49AURSDO55",
    "attributes": {
        "lei": "529900T8BM49AURSDO55",
        "entity": {
            "legalName": {"name": "Allianz SE"},
            "jurisdiction": "DE",
            "status": "ACTIVE",
            "legalForm": {"id": "6QQB"},
            "legalAddress": {"addressLines": ["Koeniginstrasse 28"], "city": "Muenchen",
                             "postalCode": "80802", "country": "DE"},
        },
        "registration": {"status": "ISSUED", "lastUpdateDate": "2026-01-02T00:00:00Z"},
    },
}


def test_parse_record():
    out = gleif._parse_record(_REC)
    assert out["lei"] == "529900T8BM49AURSDO55"
    assert out["name"] == "Allianz SE"
    assert out["jurisdiction"] == "DE"
    assert out["status"] == "ACTIVE"
    assert out["legal_form"] == "6QQB"
    assert out["country"] == "DE"
    assert "Muenchen" in out["address"]


def test_parse_record_tolerates_missing():
    assert gleif._parse_record({})["lei"] is None
    assert gleif._parse_record(None) == {}
    # plain-string legalName variant
    out = gleif._parse_record({"attributes": {"lei": "X", "entity": {"legalName": "Foo Ltd"}}})
    assert out["name"] == "Foo Ltd"


def test_lei_regex():
    assert gleif._LEI_RE.match("529900T8BM49AURSDO55")
    assert not gleif._LEI_RE.match("Allianz SE")
    assert not gleif._LEI_RE.match("529900T8BM49AURSDO5")  # 19 chars


def test_lookup_empty():
    out = asyncio.run(gleif.lookup("   "))
    assert out["found"] is False and "error" in out


def test_lookup_by_lei_with_relationships(monkeypatch):
    async def fake_get_json(url, params=None, ttl=0, cache_key=None, **kw):
        if url.endswith("/529900T8BM49AURSDO55"):
            return {"data": _REC}
        if url.endswith("/direct-parent"):
            return {"data": {"id": "PARENTLEI", "attributes": {"lei": "PARENTLEI",
                    "entity": {"legalName": {"name": "Parent Holding"}}}}}
        if url.endswith("/ultimate-parent"):
            return {"data": None}
        if url.endswith("/direct-children"):
            return {"data": [{"id": "CHILDLEI", "attributes": {"lei": "CHILDLEI",
                    "entity": {"legalName": {"name": "Sub Co"}}}}]}
        return {"data": None}

    monkeypatch.setattr(gleif, "get_json", fake_get_json)
    out = asyncio.run(gleif.lookup("529900T8BM49AURSDO55"))
    assert out["found"] is True and out["name"] == "Allianz SE"
    assert out["relationships"]["direct_parent"]["name"] == "Parent Holding"
    assert "ultimate_parent" not in out["relationships"]
    assert out["relationships"]["direct_children"][0]["name"] == "Sub Co"
    assert "beneficial ownership" in out["ubo_disclaimer"].lower()


def test_lookup_by_name_search(monkeypatch):
    async def fake_get_json(url, params=None, ttl=0, cache_key=None, **kw):
        assert params and params.get("filter[entity.legalName]") == "Allianz"
        return {"data": [_REC]}

    monkeypatch.setattr(gleif, "get_json", fake_get_json)
    out = asyncio.run(gleif.lookup("Allianz"))
    assert out["found"] is True and out["match_count"] == 1
    assert out["matches"][0]["name"] == "Allianz SE"
