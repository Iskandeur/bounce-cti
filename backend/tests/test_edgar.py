"""Unit tests for the SEC EDGAR (DD) source — parsers + resolver (no network)."""
import asyncio

from backend.sources import edgar


_TICKERS = {
    "0": {"cik_str": 320193, "ticker": "AAPL", "title": "Apple Inc."},
    "1": {"cik_str": 789019, "ticker": "MSFT", "title": "MICROSOFT CORP"},
    "2": {"cik_str": 1318605, "ticker": "TSLA", "title": "Tesla, Inc."},
}

_SUBS = {
    "cik": "320193", "name": "Apple Inc.", "tickers": ["AAPL"], "exchanges": ["Nasdaq"],
    "sic": "3571", "sicDescription": "Electronic Computers",
    "stateOfIncorporation": "CA", "entityType": "operating",
    "addresses": {"business": {"street1": "One Apple Park Way", "city": "Cupertino",
                               "stateOrCountry": "CA", "zipCode": "95014"}},
    "formerNames": [{"name": "Apple Computer Inc"}],
    "filings": {"recent": {"form": ["10-K", "10-Q", "8-K", "10-Q", "4", "4"]}},
}


def test_resolve_by_ticker_exact():
    out = edgar._resolve("AAPL", _TICKERS)
    assert out and out[0]["cik"] == 320193 and out[0]["score"] == 100


def test_resolve_by_name():
    out = edgar._resolve("Apple", _TICKERS)
    assert out and out[0]["name"] == "Apple Inc."
    # suffix-insensitive: "Microsoft" matches "MICROSOFT CORP"
    assert edgar._resolve("microsoft", _TICKERS)[0]["cik"] == 789019


def test_resolve_no_match():
    assert edgar._resolve("Nonexistent Zzz Co", _TICKERS) == []


def test_parse_submissions():
    out = edgar._parse_submissions(_SUBS)
    assert out["cik"] == 320193 and out["name"] == "Apple Inc."
    assert out["tickers"] == ["AAPL"] and out["exchanges"] == ["Nasdaq"]
    assert out["sic_description"] == "Electronic Computers"
    assert out["incorporated_in"] == "CA"
    assert "Cupertino" in out["address"]
    assert out["former_names"] == ["Apple Computer Inc"]
    # recent_form_types deduped, order-preserved
    assert out["recent_form_types"][:3] == ["10-K", "10-Q", "8-K"]


def test_parse_submissions_empty():
    assert edgar._parse_submissions({}) == {}


def test_lookup_by_cik(monkeypatch):
    async def fake_get_json(url, headers=None, ttl=0, cache_key=None, **kw):
        assert "CIK0000320193" in url
        return _SUBS
    monkeypatch.setattr(edgar, "get_json", fake_get_json)
    out = asyncio.run(edgar.lookup("CIK320193"))
    assert out["found"] is True and out["name"] == "Apple Inc."


def test_lookup_by_name_enriches_best(monkeypatch):
    async def fake_get_json(url, headers=None, ttl=0, cache_key=None, **kw):
        return _TICKERS if url.endswith("company_tickers.json") else _SUBS
    monkeypatch.setattr(edgar, "get_json", fake_get_json)
    out = asyncio.run(edgar.lookup("Apple"))
    assert out["found"] is True
    assert out["matches"][0]["ticker"] == "AAPL"
    assert out["best"]["sic_description"] == "Electronic Computers"


def test_lookup_empty():
    out = asyncio.run(edgar.lookup("  "))
    assert out["found"] is False and "error" in out
