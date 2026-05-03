"""CertSpotter (SSLMate) — continuous CT log monitoring. Free 100 req/day."""
from __future__ import annotations

from .. import key_pool
from .http_client import get_json

_BASE = "https://api.certspotter.com/v1"


async def issuances_for_domain(domain: str, include_subdomains: bool = True) -> dict:
    """Return certs issued for `domain` (and optionally its subdomains).
    Each issuance has: id, dns_names[], issuer{...}, not_before, not_after, cert{sha256,...}.
    """
    key = key_pool.acquire("certspotter")
    if not key:
        return {"error": "no CertSpotter key configured or all keys exhausted"}
    headers = {"Authorization": f"Bearer {key}"}
    params = {
        "domain": domain,
        "include_subdomains": "true" if include_subdomains else "false",
        "expand": "dns_names,issuer,cert",
    }
    cache_key = f"certspotter|issuances|{domain}|{include_subdomains}"
    return await get_json(f"{_BASE}/issuances", headers=headers, params=params,
                           ttl=3600, cache_key=cache_key)


async def issuances_for_serial(serial_hex: str) -> dict:
    """Look up certs by serial number (hex). Useful for cross-host reuse
    detection (Cobalt Strike default certs, etc.)."""
    key = key_pool.acquire("certspotter")
    if not key:
        return {"error": "no CertSpotter key configured or all keys exhausted"}
    headers = {"Authorization": f"Bearer {key}"}
    params = {"serial": serial_hex.lower(), "expand": "dns_names,issuer,cert"}
    cache_key = f"certspotter|serial|{serial_hex}"
    return await get_json(f"{_BASE}/issuances", headers=headers, params=params,
                           ttl=86400, cache_key=cache_key)
