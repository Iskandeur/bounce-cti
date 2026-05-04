"""Netlas — internet scanner DB. Free 50 req/day. Lucene query syntax."""
from __future__ import annotations

from .. import key_pool
from .http_client import get_json

_BASE = "https://app.netlas.io/api"


async def host_search(query: str, size: int = 20) -> dict:
    """Generic host search. Supports Lucene-like syntax:
      domain:evil.com
      ip:1.2.3.4
      jarm:<jarm_fingerprint>
      http.favicon.hash:<int>
      asn:AS12345
    """
    key = key_pool.acquire("netlas")
    if not key:
        return {"error": "no Netlas key configured or all keys exhausted"}
    headers = {"X-Api-Key": key, "Accept": "application/json"}
    params = {"q": query, "start": "0", "size": str(min(size, 100))}
    cache_key = f"netlas|search|{query}|{size}"
    return await get_json(f"{_BASE}/responses/", headers=headers, params=params,
                           ttl=3600, cache_key=cache_key)


async def jarm_search(jarm: str, size: int = 20) -> dict:
    """Find hosts matching a JARM fingerprint."""
    return await host_search(f"jarm:{jarm}", size=size)


async def favicon_search(favicon_hash: int | str, size: int = 20) -> dict:
    """Find hosts matching a favicon mmh3 hash (Shodan-compat)."""
    return await host_search(f"http.favicon.hash:{favicon_hash}", size=size)


async def asn_search(asn: str, size: int = 20) -> dict:
    """Find hosts in an ASN (e.g. AS12345)."""
    asn_clean = asn.upper().replace("AS", "")
    return await host_search(f"asn:AS{asn_clean}", size=size)
