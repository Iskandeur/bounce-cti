"""Unit tests for the Gravatar email→profile parser (no network)."""
import asyncio

from backend.sources import gravatar as gv


def test_parse_profile_found():
    raw = {"entry": [{
        "profileUrl": "https://gravatar.com/jdoe",
        "preferredUsername": "jdoe",
        "displayName": "J. Doe",
        "currentLocation": "Paris",
        "accounts": [
            {"shortname": "github", "username": "jdoe", "url": "https://github.com/jdoe"},
            {"domain": "twitter.com", "display": "@jd", "url": "https://twitter.com/jd"},
        ],
        "urls": [{"value": "https://jdoe.dev", "title": "Blog"}],
    }]}
    out = gv._parse_profile(raw, "jdoe@example.com")
    assert out["found"] is True
    assert out["display_name"] == "J. Doe"
    assert out["preferred_username"] == "jdoe"
    assert out["account_count"] == 2
    assert {a["service"] for a in out["accounts"]} == {"github", "twitter.com"}
    assert out["urls"] == ["https://jdoe.dev"]


def test_parse_profile_not_found_variants():
    # 404 surfaced by http_client as a non-JSON status dict
    assert gv._parse_profile({"_status": 404, "_text": "User not found"}, "x@y.com")["found"] is False
    # empty entry list / missing key / non-dict input
    assert gv._parse_profile({"entry": []}, "x@y.com")["found"] is False
    assert gv._parse_profile({}, "x@y.com")["found"] is False
    assert gv._parse_profile(None, "x@y.com")["found"] is False


def test_lookup_email_rejects_non_email():
    out = asyncio.run(gv.lookup_email("not-an-email"))
    assert out["found"] is False and "error" in out


def test_lookup_email_hashes_normalised_address(monkeypatch):
    seen = {}

    async def fake_get_json(url, ttl=0, cache_key=None, **kw):
        seen["url"] = url
        seen["cache_key"] = cache_key
        return {"entry": [{"displayName": "N"}]}

    monkeypatch.setattr(gv, "get_json", fake_get_json)
    out = asyncio.run(gv.lookup_email("  Jdoe@Example.COM "))
    # MD5 of the trimmed/lowercased address
    import hashlib
    h = hashlib.md5("jdoe@example.com".encode()).hexdigest()
    assert h in seen["url"] and seen["cache_key"] == f"gravatar|{h}"
    assert out["found"] is True and out["email"] == "jdoe@example.com"
