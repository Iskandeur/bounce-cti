"""DNSDumpster — passive subdomain enumeration via the HackerTarget-hosted
API. Free tier: 50 queries/day per account, key required.

The v2 API returns DNS records (A, AAAA, CNAME, MX, NS, TXT) and discovered
subdomains in a single JSON payload. Complements crt.sh by surfacing hosts
that never appeared in a public CT log (internal-only certs, dyn-DNS,
brute-forced records)."""
from __future__ import annotations

from .. import key_pool
from .http_client import get_json

_BASE = "https://api.dnsdumpster.com/domain"


async def domain_lookup(domain: str) -> dict:
    """Look up DNS records + discovered subdomains for ``domain``.

    Returns the raw DNSDumpster JSON (``{a: [...], cname: [...], ns: [...],
    mx: [...], txt: [...], domain: "..."}``), or an error dict when no key
    is configured / the quota is exhausted."""
    key = key_pool.acquire("dnsdumpster")
    if not key:
        return {"error": "no DNSDumpster key configured or all keys exhausted"}
    headers = {"X-API-Key": key, "Accept": "application/json"}
    cache_key = f"dnsdumpster|{domain}"
    return await get_json(f"{_BASE}/{domain}", headers=headers,
                           ttl=3600, cache_key=cache_key)
