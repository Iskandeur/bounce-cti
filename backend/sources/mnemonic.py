"""Mnemonic Passive DNS — https://passivedns.mnemonic.no/
Free public API, no key required. Returns historical A/AAAA/CNAME/NS/MX
records for a domain or IP. Complements VirusTotal pDNS with a different
collection vantage point (European telco).
"""
from .http_client import get_json

BASE = "https://api.mnemonic.no/pdns/v3"


async def pdns_query(query: str, limit: int = 50) -> dict:
    """Query Mnemonic pDNS for a domain or IP. Works for both."""
    return await get_json(f"{BASE}/{query}",
                          params={"limit": limit, "aggregateResult": "true"},
                          ttl=3600)
