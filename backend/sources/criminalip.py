"""CriminalIP — IP / domain intelligence. Free tier ~50 req/day."""
from __future__ import annotations

from .. import key_pool
from .http_client import get_json

_BASE = "https://api.criminalip.io/v1"


async def ip_report(ip: str, full: bool = False) -> dict:
    """Full IP report: ASN, geo, ports, scoring, malicious flags."""
    key = key_pool.acquire("criminalip")
    if not key:
        return {"error": "no CriminalIP key configured or all keys exhausted"}
    headers = {"x-api-key": key, "Accept": "application/json"}
    params = {"ip": ip, "full": "true" if full else "false"}
    cache_key = f"criminalip|ip|{ip}|{full}"
    return await get_json(f"{_BASE}/asset/ip/report", headers=headers, params=params,
                           ttl=3600, cache_key=cache_key)


async def domain_report(domain: str) -> dict:
    """Domain summary: scoring, related malware, screenshots, hosting."""
    key = key_pool.acquire("criminalip")
    if not key:
        return {"error": "no CriminalIP key configured or all keys exhausted"}
    headers = {"x-api-key": key, "Accept": "application/json"}
    params = {"query": domain}
    cache_key = f"criminalip|domain|{domain}"
    return await get_json(f"{_BASE}/domain/scan", headers=headers, params=params,
                           ttl=3600, cache_key=cache_key)
