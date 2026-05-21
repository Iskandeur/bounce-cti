"""Tor exit-node list — https://check.torproject.org/exit-addresses

Plaintext, refreshed every ~30 min. We mirror it to the SQLite cache and
serve membership checks out of an in-memory set. A hit means the IP is a
currently-advertised Tor exit relay — useful as a *noise filter* (treat
hits in passive DNS as low-signal) but also as a *behavioural signal* on
C2-style infrastructure that exclusively talks through Tor exits."""
from __future__ import annotations

import asyncio
import time

import httpx

from ..graph_store import cache_get, cache_set
from .http_client import UA

_FEED = "https://check.torproject.org/exit-addresses"
_CACHE_KEY = "tor_exits|feed"
_TTL = 30 * 60  # refresh every 30 min

_set: set[str] = set()
_built_at: float = 0.0
_lock = asyncio.Lock()


def _parse(text: str) -> set[str]:
    out: set[str] = set()
    for line in text.splitlines():
        if line.startswith("ExitAddress "):
            parts = line.split()
            if len(parts) >= 2:
                out.add(parts[1].strip())
    return out


async def _ensure_set() -> None:
    global _set, _built_at
    async with _lock:
        if _set and (time.time() - _built_at) < _TTL:
            return
        cached_text = cache_get(_CACHE_KEY, ttl=_TTL)
        if cached_text is None:
            try:
                async with httpx.AsyncClient(timeout=30, follow_redirects=True,
                                              headers={"User-Agent": UA}) as c:
                    r = await c.get(_FEED)
                    cached_text = r.text if r.status_code == 200 else ""
            except Exception as exc:  # noqa: BLE001
                cached_text = ""
                _set = _set or set()
                _built_at = time.time()
                return
            cache_set(_CACHE_KEY, cached_text)
        _set = _parse(cached_text or "")
        _built_at = time.time()


async def is_exit(ip: str) -> bool:
    await _ensure_set()
    return ip.strip() in _set


async def check_ip(ip: str) -> dict:
    """Return ``{exit_node: bool, feed_size: int}``."""
    listed = await is_exit(ip)
    return {"exit_node": listed, "ip": ip, "feed_size": len(_set)}


async def all_exits() -> set[str]:
    """Return a snapshot of the current exit-relay set. Used by
    `defuse_lists` to tag IP nodes at add-time without paying the HTTP cost
    per node (the set is in-process)."""
    await _ensure_set()
    return set(_set)
