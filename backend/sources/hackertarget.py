"""HackerTarget — free network/DNS recon endpoints.

The public endpoints (https://api.hackertarget.com/<tool>/?q=<value>) return
plaintext and are throttled to ~50 anonymous queries / day per IP. An
optional API key (sent via the ``X-API-Key`` header) lifts the quota and
enables JSON output via ``&output=json``. Free to register.

We use four endpoints today:
  - ``reverseiplookup``  — hosts sharing an IP (free Shodan/VT alternative)
  - ``hostsearch``       — passive subdomain enum for a domain
  - ``dnslookup``        — basic A/MX/NS dump (fallback for our own resolver)
  - ``geoip``            — IP geolocation (fallback for ip_api)

All return ``{"results": [...]}`` (list of strings) on success or
``{"error": "..."}`` on quota/auth failures. We pass the API key when
configured so the same source works at both anonymous and authenticated
rate."""
from __future__ import annotations

import httpx

from .. import key_pool
from ..graph_store import cache_get, cache_set
from .http_client import UA

_BASE = "https://api.hackertarget.com"


async def _get_lines(path: str, q: str, cache_key: str, ttl: float = 3600) -> dict:
    cached = cache_get(cache_key, ttl=ttl)
    if cached is not None:
        return cached
    headers = {"User-Agent": UA, "Accept": "text/plain"}
    key = key_pool.acquire("hackertarget")
    if key:
        headers["X-API-Key"] = key
    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as c:
        r = await c.get(f"{_BASE}/{path}/", headers=headers,
                          params={"q": q})
        text = r.text or ""
        if r.status_code != 200:
            data = {"error": f"http_{r.status_code}", "raw": text[:500]}
        elif text.lower().startswith("error") or "api count" in text.lower():
            data = {"error": text.strip()[:500]}
        else:
            lines = [l.strip() for l in text.splitlines() if l.strip()]
            data = {"results": lines, "count": len(lines)}
    cache_set(cache_key, data)
    return data


async def reverse_ip(ip: str) -> dict:
    """Domains pointing at ``ip`` (passive — HackerTarget's own resolver
    history). Free alternative to Shodan/VT's reverse-resolution endpoints."""
    return await _get_lines("reverseiplookup", ip, f"hackertarget|rev|{ip}")


async def host_search(domain: str) -> dict:
    """Discovered subdomains of ``domain`` (passive). Lines of the form
    ``sub.domain.tld,1.2.3.4``."""
    return await _get_lines("hostsearch", domain, f"hackertarget|hosts|{domain}")


async def dns_lookup(domain: str) -> dict:
    """Basic DNS dump (A/MX/NS/TXT). Fallback when our resolver is
    unreachable / sandboxed."""
    return await _get_lines("dnslookup", domain, f"hackertarget|dns|{domain}")


async def geoip(ip: str) -> dict:
    """Plaintext geolocation block — fallback for ip_api."""
    return await _get_lines("geoip", ip, f"hackertarget|geo|{ip}", ttl=86400)
