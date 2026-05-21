"""Censys — host + cert lookup.

This client targets the **Censys Platform API v3** (`api.platform.censys.io`),
which authenticates with the modern Personal Access Token format
`censys_<id>_<secret>` sent as a Bearer token. For users still on the
legacy free-tier Search API (`search.censys.io/api/v2`) we fall back to
HTTP-Basic auth when the configured key contains a colon (`id:secret`).

Free community tier: 250 queries / month per token.
API docs: https://docs.censys.com/docs/personal-access-tokens
"""
from __future__ import annotations

import base64

from .. import key_pool
from .http_client import get_json

_PLATFORM = "https://api.platform.censys.io/v3/global"
_LEGACY = "https://search.censys.io/api/v2"


def _auth(key: str) -> tuple[str, dict]:
    """Return ``(base_url, headers)`` picking the correct endpoint family
    for the key format.
      - ``censys_<id>_<secret>``  -> Platform v3, Bearer
      - ``<id>:<secret>``         -> Legacy Search v2, HTTP Basic
      - anything else             -> Platform v3, Bearer (best guess)
    """
    if ":" in key:
        encoded = base64.b64encode(key.encode()).decode()
        return _LEGACY, {"Authorization": f"Basic {encoded}",
                          "Accept": "application/json"}
    return _PLATFORM, {"Authorization": f"Bearer {key}",
                        "Accept": "application/json"}


async def host_view(ip: str) -> dict:
    """Host record for an IP. Returns Platform v3 shape (``result.resource``)
    or legacy Search v2 shape (``result``) depending on the configured key."""
    key = key_pool.acquire("censys")
    if not key:
        return {"error": "no Censys key configured or all keys exhausted"}
    base, headers = _auth(key)
    if base == _PLATFORM:
        url = f"{base}/asset/host/{ip}"
    else:
        url = f"{base}/hosts/{ip}"
    cache_key = f"censys|host|{ip}"
    return await get_json(url, headers=headers, ttl=3600, cache_key=cache_key)


async def host_search(query: str, per_page: int = 25) -> dict:
    """Host search. Query syntax follows the Censys query language
    (the Search v2 API). The Platform API exposes the equivalent
    ``/asset/host/search`` endpoint."""
    key = key_pool.acquire("censys")
    if not key:
        return {"error": "no Censys key configured or all keys exhausted"}
    base, headers = _auth(key)
    if base == _PLATFORM:
        url = f"{base}/asset/host/search"
        params = {"q": query, "page_size": str(per_page)}
    else:
        url = f"{base}/hosts/search"
        params = {"q": query, "per_page": str(per_page)}
    cache_key = f"censys|search|hosts|{per_page}|{query}"
    return await get_json(url, headers=headers, params=params,
                           ttl=3600, cache_key=cache_key)


async def cert_view(fingerprint_sha256: str) -> dict:
    """Single certificate record by SHA-256 fingerprint (lower-case hex)."""
    key = key_pool.acquire("censys")
    if not key:
        return {"error": "no Censys key configured or all keys exhausted"}
    base, headers = _auth(key)
    if base == _PLATFORM:
        url = f"{base}/asset/certificate/{fingerprint_sha256.lower()}"
    else:
        url = f"{base}/certificates/{fingerprint_sha256.lower()}"
    cache_key = f"censys|cert|{fingerprint_sha256.lower()}"
    return await get_json(url, headers=headers, ttl=86400, cache_key=cache_key)
