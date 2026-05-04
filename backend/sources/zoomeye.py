"""ZoomEye — internet scanner DB. Free 10k/month."""
from __future__ import annotations

from .. import key_pool
from .http_client import get_json

_BASE = "https://api.zoomeye.org"


async def host_search(query: str, page: int = 1) -> dict:
    """Generic ZoomEye host search. Examples:
      ip:"1.2.3.4"
      hostname:"evil.com"
      iconhash:"<mmh3_hash>"
      ssl.jarm:"<jarm>"
    """
    key = key_pool.acquire("zoomeye")
    if not key:
        return {"error": "no ZoomEye key configured or all keys exhausted"}
    headers = {"API-KEY": key, "Accept": "application/json"}
    params = {"query": query, "page": str(page)}
    cache_key = f"zoomeye|host|{query}|{page}"
    return await get_json(f"{_BASE}/host/search", headers=headers, params=params,
                           ttl=3600, cache_key=cache_key)


async def jarm_search(jarm: str, page: int = 1) -> dict:
    return await host_search(f'ssl.jarm:"{jarm}"', page=page)


async def favicon_search(favicon_hash: int | str, page: int = 1) -> dict:
    return await host_search(f'iconhash:"{favicon_hash}"', page=page)
