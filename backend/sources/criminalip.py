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


# The GET path that reads a domain report is NOT established: the old
# ``/domain/scan`` submits a scan (GET answers 405 in prod, a POST would submit:
# EVAL_PROTOCOL §4.E rule 5). The candidates are read-only GETs, tried only by
# ``probe_domain_paths`` (admin route). Once one is confirmed in prod, set
# ``DOMAIN_READ_PATH`` to it.
DOMAIN_READ_PATH: str | None = None
DOMAIN_READ_CANDIDATES = ("/domain/report", "/domain/reports")


def shape_of(data, depth: int = 3):
    """Structure of a JSON value with no value in it: dict keys with the type of
    each, list length + shape of the first item. Safe to hand to an admin."""
    if isinstance(data, dict):
        if depth == 0:
            return {"type": "object", "keys": len(data)}
        return {k: shape_of(v, depth - 1) for k, v in list(data.items())[:40]}
    if isinstance(data, list):
        return {"type": "array", "len": len(data),
                "item": shape_of(data[0], depth - 1) if data else None}
    return type(data).__name__


async def domain_report(domain: str) -> dict:
    """Domain summary: scoring, related malware, screenshots, hosting.

    Mute until ``DOMAIN_READ_PATH`` is established: no HTTP request is made."""
    if not DOMAIN_READ_PATH:
        return {"error": "criminalip_domain unavailable: the GET path that reads a domain "
                         "report is not established (the scan endpoint is never "
                         "called). Use criminalip_ip or other sources."}
    key = key_pool.acquire("criminalip")
    if not key:
        return {"error": "no CriminalIP key configured or all keys exhausted"}
    headers = {"x-api-key": key, "Accept": "application/json"}
    return await get_json(f"{_BASE}{DOMAIN_READ_PATH}", headers=headers,
                          params={"query": domain}, ttl=3600,
                          cache_key=f"criminalip|domain|{domain}")


async def probe_domain_paths(domain: str) -> dict:
    """Admin diagnostic: GET each candidate read path once with the server's key
    and report only the HTTP status and the shape of the answer (never the key,
    never a value). Not cached, GET only."""
    import httpx
    key = key_pool.acquire("criminalip")
    if not key:
        return {"error": "no CriminalIP key configured or all keys exhausted"}
    headers = {"x-api-key": key, "Accept": "application/json"}
    out = {}
    async with httpx.AsyncClient(timeout=30) as c:
        for path in DOMAIN_READ_CANDIDATES:
            try:
                r = await c.get(f"{_BASE}{path}", headers=headers, params={"query": domain})
                try:
                    shape = shape_of(r.json())
                except Exception:
                    shape = "non-json"
                out[path] = {"status": r.status_code, "shape": shape}
            except Exception as e:
                out[path] = {"error": type(e).__name__}
    return out
