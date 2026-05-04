"""OpenPhish — community phishing URL feed. No auth required.

Fetches the public feed (~1.5 MB plaintext, refreshed every ~30 min) and
indexes it in the SQLite cache so subsequent lookups are O(1) per URL/host
within the cache TTL window."""
from __future__ import annotations

import httpx

from ..graph_store import cache_get, cache_set
from .http_client import UA

_FEED_URL = "https://openphish.com/feed.txt"
_CACHE_KEY = "openphish|feed"
_TTL = 1800  # 30 minutes


async def _fetch_feed() -> list[str]:
    cached = cache_get(_CACHE_KEY, ttl=_TTL)
    if cached is not None:
        return cached
    headers = {"User-Agent": UA}
    async with httpx.AsyncClient(timeout=30, follow_redirects=True,
                                  headers=headers) as c:
        r = await c.get(_FEED_URL)
        if r.status_code != 200:
            return []
        urls = [line.strip() for line in r.text.splitlines() if line.strip()]
    cache_set(_CACHE_KEY, urls)
    return urls


async def check_url(url: str) -> dict:
    """Return ``{listed: bool, matches: [...]}`` for a URL. Exact match."""
    feed = await _fetch_feed()
    matches = [u for u in feed if u == url]
    return {"listed": bool(matches), "matches": matches[:10],
             "feed_size": len(feed)}


async def check_host(host: str) -> dict:
    """Return ``{listed: bool, matches: [...]}`` for a host (any URL whose
    netloc contains `host`). Useful for "is this domain in the OpenPhish
    feed regardless of path"."""
    feed = await _fetch_feed()
    h = host.lower()
    matches = [u for u in feed if h in u.lower()]
    return {"listed": bool(matches), "matches": matches[:20],
             "feed_size": len(feed)}
