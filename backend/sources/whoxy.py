"""Whoxy — reverse WHOIS lookup (registrant email/name → domains).
Free tier: 1500 lifetime requests."""
from __future__ import annotations

from .. import key_pool
from .http_client import get_json

_BASE = "https://api.whoxy.com/"


async def reverse_by_email(email: str, page: int = 1, mode: str = "mini") -> dict:
    """List domains registered by `email`. mode: 'mini' (just names)
    or 'micro' (with creation dates). Free tier: 'mini' costs 1 cr,
    'micro' costs 2 cr."""
    key = key_pool.acquire("whoxy")
    if not key:
        return {"error": "no Whoxy key configured or all keys exhausted"}
    params = {"key": key, "reverse": "whois", "email": email,
              "page": str(page), "mode": mode}
    cache_key = f"whoxy|email|{email}|{page}|{mode}"
    return await get_json(_BASE, params=params, ttl=86400, cache_key=cache_key)


async def reverse_by_name(name: str, page: int = 1, mode: str = "mini") -> dict:
    """List domains registered by `name`."""
    key = key_pool.acquire("whoxy")
    if not key:
        return {"error": "no Whoxy key configured or all keys exhausted"}
    params = {"key": key, "reverse": "whois", "name": name,
              "page": str(page), "mode": mode}
    cache_key = f"whoxy|name|{name}|{page}|{mode}"
    return await get_json(_BASE, params=params, ttl=86400, cache_key=cache_key)


async def reverse_by_keyword(keyword: str, page: int = 1, mode: str = "mini") -> dict:
    """List domains matching `keyword` (in name, registrant fields, etc.)."""
    key = key_pool.acquire("whoxy")
    if not key:
        return {"error": "no Whoxy key configured or all keys exhausted"}
    params = {"key": key, "reverse": "whois", "keyword": keyword,
              "page": str(page), "mode": mode}
    cache_key = f"whoxy|kw|{keyword}|{page}|{mode}"
    return await get_json(_BASE, params=params, ttl=86400, cache_key=cache_key)
