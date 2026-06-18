"""Unit tests for the GitHub profile parser (no network)."""
import asyncio

from backend.sources import github_profile as ghp


def test_parse_found():
    raw = {
        "login": "octocat", "name": "The Octocat", "company": "@github",
        "location": "SF", "bio": "hi", "blog": "https://oct.example",
        "twitter_username": "octo", "email": None, "public_repos": 8,
        "followers": 1000, "created_at": "2011-01-25T18:44:36Z",
        "html_url": "https://github.com/octocat",
    }
    out = ghp._parse(raw, "octocat")
    assert out["found"] is True
    assert out["name"] == "The Octocat"
    assert out["twitter_username"] == "octo"
    assert out["blog"] == "https://oct.example"
    assert out["profile_url"] == "https://github.com/octocat"


def test_parse_not_found_variants():
    assert ghp._parse({"message": "Not Found"}, "nope")["found"] is False
    assert ghp._parse({"_status": 404, "_text": "x"}, "nope")["found"] is False
    assert ghp._parse({}, "nope")["found"] is False
    assert ghp._parse(None, "nope")["found"] is False


def test_parse_blank_blog_becomes_none():
    out = ghp._parse({"login": "u", "blog": ""}, "u")
    assert out["found"] is True and out["blog"] is None


def test_lookup_user_rejects_empty():
    out = asyncio.run(ghp.lookup_user("   "))
    assert out["found"] is False and "error" in out


def test_lookup_user_strips_handle_and_caches(monkeypatch):
    seen = {}

    async def fake_get_json(url, headers=None, ttl=0, cache_key=None, **kw):
        seen["url"] = url
        seen["cache_key"] = cache_key
        return {"login": "jdoe"}

    monkeypatch.setattr(ghp, "get_json", fake_get_json)
    out = asyncio.run(ghp.lookup_user("@jDoe"))
    assert seen["url"].endswith("/jDoe")        # @ stripped, case preserved in path
    assert seen["cache_key"] == "ghuser|jdoe"   # cache key lowercased
    assert out["found"] is True
