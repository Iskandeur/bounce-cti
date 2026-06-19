"""Unit tests for the Companies House (DD) parsers (no network)."""
import asyncio

from backend.sources import companies_house as ch


def test_company_number_regex():
    assert ch._NUM_RE.match("09876543")
    assert ch._NUM_RE.match("SC123456")
    assert not ch._NUM_RE.match("Acme Ltd")
    assert not ch._NUM_RE.match("123")


def test_parse_profile_and_address():
    p = {
        "company_number": "09876543", "company_name": "ACME WIDGETS LTD",
        "company_status": "active", "type": "ltd", "jurisdiction": "england-wales",
        "date_of_creation": "2015-11-02",
        "registered_office_address": {"address_line_1": "1 High St", "locality": "London",
                                      "postal_code": "EC1A 1AA", "country": "United Kingdom"},
        "sic_codes": ["62010"],
    }
    out = ch._parse_profile(p)
    assert out["name"] == "ACME WIDGETS LTD" and out["status"] == "active"
    assert out["incorporated"] == "2015-11-02"
    assert "London" in out["address"] and "EC1A 1AA" in out["address"]
    assert out["sic_codes"] == ["62010"]


def test_parse_officer_dob_month_year_only():
    o = {"name": "DOE, Jane", "officer_role": "director", "appointed_on": "2016-01-01",
         "nationality": "British", "occupation": "Engineer",
         "date_of_birth": {"month": 4, "year": 1980}}
    out = ch._parse_officer(o)
    assert out["name"] == "DOE, Jane" and out["role"] == "director"
    assert out["dob"] == "1980-04"  # day never exposed


def test_parse_psc():
    p = {"name": "John Smith", "kind": "individual-person-with-significant-control",
         "nationality": "British", "natures_of_control": ["ownership-of-shares-75-to-100-percent"],
         "date_of_birth": {"month": 7, "year": 1975}}
    out = ch._parse_psc(p)
    assert out["name"] == "John Smith"
    assert out["natures_of_control"] == ["ownership-of-shares-75-to-100-percent"]
    assert out["dob"] == "1975-07"


def test_lookup_without_key_degrades(monkeypatch):
    monkeypatch.setattr(ch.key_pool, "acquire", lambda src: None)
    out = asyncio.run(ch.lookup("09876543"))
    assert out["available"] is False and "COMPANIES_HOUSE_API_KEY" in out["reason"]


def test_lookup_by_number_with_officers_psc(monkeypatch):
    monkeypatch.setattr(ch.key_pool, "acquire", lambda src: "k")

    async def fake_get_json(url, params=None, headers=None, ttl=0, cache_key=None):
        if url.endswith("/company/09876543"):
            return {"company_number": "09876543", "company_name": "ACME LTD",
                    "company_status": "active"}
        if url.endswith("/officers"):
            return {"items": [{"name": "DOE, Jane", "officer_role": "director",
                               "date_of_birth": {"month": 4, "year": 1980}}]}
        if url.endswith("persons-with-significant-control"):
            return {"items": [{"name": "John Smith", "kind": "individual-person-with-significant-control",
                               "natures_of_control": ["ownership-of-shares-75-to-100-percent"]}]}
        return {}

    monkeypatch.setattr(ch, "get_json", fake_get_json)
    out = asyncio.run(ch.lookup("09876543"))
    assert out["found"] is True and out["name"] == "ACME LTD"
    assert out["officers"][0]["name"] == "DOE, Jane"
    assert out["psc"][0]["name"] == "John Smith"


def test_lookup_by_name_search(monkeypatch):
    monkeypatch.setattr(ch.key_pool, "acquire", lambda src: "k")

    async def fake_get_json(url, params=None, headers=None, ttl=0, cache_key=None):
        assert url.endswith("/search/companies") and params["q"] == "acme"
        return {"items": [{"company_number": "09876543", "title": "ACME LTD",
                           "company_status": "active", "address_snippet": "London"}]}

    monkeypatch.setattr(ch, "get_json", fake_get_json)
    out = asyncio.run(ch.lookup("acme"))
    assert out["found"] is True and out["matches"][0]["company_number"] == "09876543"
