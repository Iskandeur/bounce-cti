"""Gravatar — email → public profile / linked accounts (free, no API key).

Gravatar's legacy public profile endpoint maps the MD5 of a lowercased,
trimmed email address to whatever profile the owner has made public:
display name, preferred username, linked social accounts, and personal URLs.
A strong, free email→identity pivot for the OSINT vertical (and a useful
enrichment for a registrant email surfaced via RDAP/Whoxy in CTI).

Only public profile data is read; nothing is submitted. Many addresses have
no public Gravatar — that simply returns ``found=False`` (absence of a public
profile, not absence of the person).
"""
from __future__ import annotations

import hashlib

from .http_client import get_json

_BASE = "https://en.gravatar.com"


def _parse_profile(raw: dict, email: str) -> dict:
    """Shape the Gravatar JSON into a compact profile. Pure (unit-tested).

    The legacy endpoint returns ``{"entry": [ {...} ]}`` for a public profile,
    or a non-JSON 404 (surfaced by http_client as ``{"_status": 404, ...}``)
    when there's no public profile."""
    entries = (raw or {}).get("entry") if isinstance(raw, dict) else None
    if not entries:
        return {"email": email, "found": False}
    e = entries[0] or {}
    accounts = []
    for a in e.get("accounts") or []:
        accounts.append({
            "service": a.get("shortname") or a.get("name") or a.get("domain"),
            "username": a.get("username") or a.get("display"),
            "url": a.get("url"),
        })
    urls = [u.get("value") for u in (e.get("urls") or []) if u.get("value")]
    return {
        "email": email,
        "found": True,
        "profile_url": e.get("profileUrl"),
        "display_name": e.get("displayName"),
        "preferred_username": e.get("preferredUsername"),
        "location": e.get("currentLocation"),
        "accounts": accounts,
        "account_count": len(accounts),
        "urls": urls,
        "source": "gravatar (public profile)",
    }


async def lookup_email(email: str) -> dict:
    """Look up a public Gravatar profile for an email address."""
    norm = (email or "").strip().lower()
    if "@" not in norm:
        return {"email": email, "found": False, "error": "not an email address"}
    digest = hashlib.md5(norm.encode("utf-8")).hexdigest()
    cache_key = f"gravatar|{digest}"
    raw = await get_json(f"{_BASE}/{digest}.json", ttl=86400, cache_key=cache_key)
    return _parse_profile(raw, norm)
