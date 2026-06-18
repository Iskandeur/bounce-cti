"""Unit tests for the offline phone enricher (libphonenumber, no network)."""
import asyncio

from backend.sources import phone_enrich as pe


def test_valid_us_number():
    out = pe._parse("+16502530000")  # Google HQ (a known-valid US line)
    assert out["valid"] is True
    assert out["country_code"] == 1
    assert out["region"] == "US"
    assert out["e164"] == "+16502530000"
    assert out["line_type"] in pe._TYPE_NAMES.values()
    assert isinstance(out["timezones"], list)


def test_international_format_and_country():
    out = pe._parse("+442079460958")  # UK
    assert out["valid"] is True
    assert out["region"] == "GB"
    assert out["country_code"] == 44
    assert out["international"].startswith("+44 ")


def test_bare_national_number_is_invalid_with_hint():
    out = pe._parse("5551234")  # no +, no region → cannot parse
    assert out["valid"] is False
    assert "E.164" in out["reason"]


def test_empty_is_invalid():
    assert pe._parse("")["valid"] is False
    assert pe._parse("   ")["valid"] is False


def test_implausible_number_not_valid():
    out = pe._parse("+1234")
    assert out["valid"] is False


def test_lookup_phone_async_wrapper():
    out = asyncio.run(pe.lookup_phone("+16502530000"))
    assert out["valid"] is True and out["region"] == "US"
