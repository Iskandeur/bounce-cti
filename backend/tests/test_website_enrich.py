"""Unit tests for the website extraction parser (no network)."""
import asyncio

from backend.sources import website_enrich as we

_HTML = """
<html><head><title>  Jane Doe — Home </title>
<style>.x{color:red}</style></head>
<body>
<h1>Welcome</h1>
<script>var a=1;</script>
<p>Contact me at jane@example.com or via the links below.</p>
<a href="/about">About</a>
<a href="https://www.example.com/blog">Blog (internal www)</a>
<a href="https://github.com/janedoe">GitHub</a>
<a href="https://twitter.com/janed">Twitter</a>
<a href="https://t.me/janedoe_tg">Telegram</a>
<a href="https://other-site.org/page">Outbound</a>
<a href="mailto:hello@janedoe.dev">Mail</a>
<img src="logo@2x.png">
</body></html>
"""


def test_extract_links_internal_vs_external():
    out = we._extract(_HTML, "https://example.com/")
    assert any(u.endswith("/about") for u in out["internal_links"])
    assert "https://www.example.com/blog" in out["internal_links"]  # www == base
    assert "github.com" in out["external_domains"]
    assert "other-site.org" in out["external_domains"]
    assert "example.com" not in out["external_domains"]


def test_extract_socials():
    out = we._extract(_HTML, "https://example.com/")
    by_platform = {s["platform"]: s["handle"] for s in out["social_profiles"]}
    assert by_platform["github"] == "janedoe"
    assert by_platform["twitter"] == "janed"
    assert by_platform["telegram"] == "janedoe_tg"


def test_extract_emails_and_drops_asset():
    out = we._extract(_HTML, "https://example.com/")
    assert "jane@example.com" in out["emails"]
    assert "hello@janedoe.dev" in out["emails"]
    assert not any(e.endswith(".png") for e in out["emails"])  # logo@2x.png dropped


def test_extract_title_and_text_strip_scripts():
    out = we._extract(_HTML, "https://example.com/")
    assert out["title"] == "Jane Doe — Home"
    assert "var a=1" not in out["text_excerpt"]
    assert "color:red" not in out["text_excerpt"]
    assert "Welcome" in out["text_excerpt"]


def test_extract_handles_empty():
    out = we._extract("<html></html>", "https://x.com/")
    assert out["title"] is None and out["emails"] == [] and out["social_profiles"] == []


def test_extract_async_empty_url():
    out = asyncio.run(we.extract("   "))
    assert out["fetched"] is False


def test_extract_async_end_to_end_mocked(monkeypatch):
    async def fake_get_text(url, ttl=0, cache_key=None, **kw):
        return {"status": 200, "final_url": url, "text": _HTML}

    monkeypatch.setattr(we, "get_text", fake_get_text)
    out = asyncio.run(we.extract("example.com"))  # bare host → http:// prefixed
    assert out["fetched"] is True and out["status"] == 200
    assert any(s["platform"] == "github" for s in out["social_profiles"])


def test_extract_async_dead_fetch(monkeypatch):
    async def fake_get_text(url, ttl=0, cache_key=None, **kw):
        return {"status": 0, "final_url": url, "text": "", "error": "boom"}

    monkeypatch.setattr(we, "get_text", fake_get_text)
    out = asyncio.run(we.extract("http://dead.example"))
    assert out["fetched"] is False and out["error"] == "boom"
