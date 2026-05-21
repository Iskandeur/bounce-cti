"""AlienVault IP reputation feed — http://reputation.alienvault.com/reputation.data

Plaintext list of ``ip#reliability#risk#type#country#city#lat,lon#code``
records (semicolon-delimited reputation tags). Refreshes ~daily. We mirror
the feed to the local SQLite cache and serve lookups out of an in-memory
index that's rebuilt opportunistically when the cache TTL expires.

A hit is a strong "this IP is on the OTX historical bad-actor list" signal
— useful as a corroborating reputation source even on IPs that AbuseIPDB /
VT have no data for."""
from __future__ import annotations

import asyncio
import time

import httpx

from ..graph_store import cache_get, cache_set
from .http_client import UA

_FEED = "http://reputation.alienvault.com/reputation.data"
_CACHE_KEY = "alienvault_rep|feed"
_TTL = 6 * 3600  # refresh every 6h max

_index: dict[str, dict] = {}
_index_built_at: float = 0.0
_index_lock = asyncio.Lock()


def _parse_line(line: str) -> tuple[str, dict] | None:
    parts = line.strip().split("#")
    if not parts or not parts[0]:
        return None
    ip = parts[0].strip()
    rec = {
        "ip": ip,
        "reliability": parts[1] if len(parts) > 1 else "",
        "risk": parts[2] if len(parts) > 2 else "",
        "type": parts[3] if len(parts) > 3 else "",
        "country": parts[4] if len(parts) > 4 else "",
        "city": parts[5] if len(parts) > 5 else "",
        "latlon": parts[6] if len(parts) > 6 else "",
    }
    return ip, rec


async def _fetch_feed() -> list[str]:
    cached = cache_get(_CACHE_KEY, ttl=_TTL)
    if cached is not None:
        return cached
    headers = {"User-Agent": UA}
    async with httpx.AsyncClient(timeout=60, follow_redirects=True,
                                  headers=headers) as c:
        r = await c.get(_FEED)
        if r.status_code != 200:
            return []
        lines = [l for l in r.text.splitlines() if l.strip() and not l.startswith("#")]
    cache_set(_CACHE_KEY, lines)
    return lines


async def _ensure_index() -> None:
    global _index, _index_built_at
    async with _index_lock:
        if _index and (time.time() - _index_built_at) < _TTL:
            return
        lines = await _fetch_feed()
        idx: dict[str, dict] = {}
        for line in lines:
            parsed = _parse_line(line)
            if parsed:
                idx[parsed[0]] = parsed[1]
        _index = idx
        _index_built_at = time.time()


async def check_ip(ip: str) -> dict:
    """Return ``{listed: bool, record?: {...}, feed_size: int}``."""
    await _ensure_index()
    rec = _index.get(ip.strip())
    return {
        "listed": bool(rec),
        "record": rec,
        "feed_size": len(_index),
    }
