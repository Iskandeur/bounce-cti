"""LeakIX — open-source intelligence on exposed services + data leaks.

Free tier: register at https://leakix.net/auth/register, generate a token
in the account settings. Returns structured findings (open ports, software
banners, exposed databases, secret leaks, geoip) per host / IP / domain.

Two complementary endpoints:
  - ``/host/<value>``    — all events for an IP or domain
  - ``/search?q=...``    — generic Lucene-style search

Documented at https://leakix.net/api-documentation."""
from __future__ import annotations

from .. import key_pool
from .http_client import get_json

_BASE = "https://leakix.net"


async def host(value: str) -> dict:
    """Aggregate of all leaks/services for an IP or domain."""
    key = key_pool.acquire("leakix")
    headers = {"Accept": "application/json"}
    if key:
        headers["api-key"] = key
    cache_key = f"leakix|host|{value}"
    return await get_json(f"{_BASE}/host/{value}", headers=headers,
                           ttl=3600, cache_key=cache_key)


async def search(query: str, page: int = 0, scope: str = "leak") -> dict:
    """Lucene query against the LeakIX index. `scope` in {"leak", "service"}."""
    key = key_pool.acquire("leakix")
    headers = {"Accept": "application/json"}
    if key:
        headers["api-key"] = key
    params = {"q": query, "page": str(page), "scope": scope}
    cache_key = f"leakix|search|{scope}|{page}|{query}"
    return await get_json(f"{_BASE}/search", headers=headers, params=params,
                           ttl=3600, cache_key=cache_key)
