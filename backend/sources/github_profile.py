"""GitHub user profile enrichment (free, no API key — 60 req/h unauthenticated).

Once a username sweep (``username_enum``) shows a GitHub presence, this pulls
the public profile detail GitHub's REST API exposes: real name, company,
location, bio, blog URL, the self-declared Twitter/X handle, and account age.
A strong identity-correlation pivot — the blog/Twitter/company fields routinely
link a handle to a person or other accounts.

Only public profile fields are read. ``found=False`` simply means no public
GitHub user by that login. A ``GITHUB_TOKEN`` in the environment, if present,
lifts the rate limit but is not required.
"""
from __future__ import annotations

import os

from .http_client import get_json

_API = "https://api.github.com/users"


def _parse(raw: dict, username: str) -> dict:
    """Shape the GitHub user JSON into a compact profile. Pure (unit-tested).

    A real user carries a ``login``; a 404 returns ``{"message": "Not Found"}``
    (GitHub answers JSON even on 404, surfaced by http_client as-is)."""
    if not isinstance(raw, dict) or not raw.get("login"):
        return {"username": username, "found": False}
    return {
        "username": raw.get("login"),
        "found": True,
        "name": raw.get("name"),
        "company": raw.get("company"),
        "location": raw.get("location"),
        "bio": raw.get("bio"),
        "blog": raw.get("blog") or None,
        "twitter_username": raw.get("twitter_username"),
        "email": raw.get("email"),                 # public only; usually null
        "public_repos": raw.get("public_repos"),
        "followers": raw.get("followers"),
        "created_at": raw.get("created_at"),
        "profile_url": raw.get("html_url"),
        "source": "github (public profile)",
    }


async def lookup_user(username: str) -> dict:
    """Look up a public GitHub profile by login."""
    u = (username or "").strip().lstrip("@").strip()
    if not u:
        return {"username": username, "found": False, "error": "empty username"}
    headers = {"Accept": "application/vnd.github+json"}
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    raw = await get_json(f"{_API}/{u}", headers=headers, ttl=86400,
                         cache_key=f"ghuser|{u.lower()}")
    return _parse(raw, u)
