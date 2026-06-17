"""Unit tests for the username-enumeration detection core (no network).

Exercises _classify across the three detection styles (status-only,
e_string, m_string) and the username validator, plus a mocked end-to-end
enumerate_username run with get_text monkeypatched so no HTTP happens.
"""
import asyncio

import pytest

from backend.sources import username_enum as ue


# status-only site (clean 404-on-missing): GitHub-style
STATUS_SITE = {"app": "X", "cat": "dev", "url": "https://x/{u}", "e_code": 200, "e_string": None, "m_string": None}
# soft-404 site that answers 200 for everyone, distinguished by a missing marker
MSTRING_SITE = {"app": "Y", "cat": "forum", "url": "https://y/{u}", "e_code": 200, "e_string": None, "m_string": "No such user."}
# site that needs a positive marker to count as found
ESTRING_SITE = {"app": "Z", "cat": "social", "url": "https://z/{u}", "e_code": 200, "e_string": "profile_title", "m_string": None}


def test_classify_status_only():
    assert ue._classify(STATUS_SITE, 200, "") == "found"
    assert ue._classify(STATUS_SITE, 404, "") == "not_found"
    assert ue._classify(STATUS_SITE, 403, "") == "unknown"   # blocked → not a verdict


def test_classify_mstring_soft404():
    assert ue._classify(MSTRING_SITE, 200, "welcome dang") == "found"
    assert ue._classify(MSTRING_SITE, 200, "No such user.") == "not_found"


def test_classify_estring_positive_marker():
    assert ue._classify(ESTRING_SITE, 200, "<h1>profile_title</h1>") == "found"
    assert ue._classify(ESTRING_SITE, 200, "generic landing page") == "not_found"


def test_username_validation_rejects_garbage():
    bad = asyncio.run(ue.enumerate_username("has spaces!"))
    assert "error" in bad and bad["found_count"] == 0 and bad["checked"] == 0


def test_manifest_is_well_formed():
    for s in ue._SITES:
        assert "{u}" in s["url"]
        assert set(s) >= {"app", "cat", "url", "e_code", "e_string", "m_string"}


def test_enumerate_end_to_end_mocked(monkeypatch):
    # Map app -> canned probe response; @handle is stripped, found list sorted.
    canned = {
        "GitHub": {"status": 200, "text": ""},                       # found (status)
        "Steam": {"status": 200, "text": "The specified profile could not be found"},  # not_found (m_string)
        "Telegram": {"status": 200, "text": "tgme_page_title"},      # found (e_string)
        "Reddit": {"status": 404, "text": ""},                       # not_found
        "Patreon": {"status": 403, "text": ""},                      # unknown (blocked)
    }

    async def fake_get_text(url, ttl=0, cache_key=None, **kw):
        app = cache_key.split("|")[1]
        return canned.get(app, {"status": 404, "text": ""})

    monkeypatch.setattr(ue, "get_text", fake_get_text)
    out = asyncio.run(ue.enumerate_username("@someUser"))
    assert out["username"] == "someUser"                 # @ stripped
    found_apps = {f["app"] for f in out["found"]}
    assert "GitHub" in found_apps and "Telegram" in found_apps
    assert "Steam" not in found_apps                     # m_string ⇒ not found
    assert [f["app"] for f in out["found"]] == sorted(found_apps, key=str.lower)
    assert any(u["app"] == "Patreon" for u in out["unknown"])
    assert out["found_count"] == len(out["found"])
