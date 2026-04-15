"""Onyphe CTI source. Summary endpoints (domain/ip) plus Griffin View+
expansion endpoints: datascan, threatlist, resolver (fwd/rev), ctl,
pastries, geoloc. Every function degrades gracefully when no key is set."""
from .http_client import get_json
from ..config import ONYPHE_KEY


def _auth() -> dict:
    return {"Authorization": f"bearer {ONYPHE_KEY}"}


def _missing_key() -> dict:
    return {"error": "no Onyphe key"}


async def onyphe_summary_domain(domain: str) -> dict:
    if not ONYPHE_KEY:
        return _missing_key()
    return await get_json(f"https://www.onyphe.io/api/v2/summary/domain/{domain}",
                          headers=_auth(), ttl=3600)


async def onyphe_summary_ip(ip: str) -> dict:
    if not ONYPHE_KEY:
        return _missing_key()
    return await get_json(f"https://www.onyphe.io/api/v2/summary/ip/{ip}",
                          headers=_auth(), ttl=3600)


# ── Griffin View+ endpoints (require a Griffin-tier key) ──────────────────
async def onyphe_datascan(query: str) -> dict:
    """Onyphe datascan — banners/HTTP/TLS across the internet. `query` is a
    raw Onyphe query (e.g. `ip:1.2.3.4`, `jarm:<jarm>`, `product:nginx`)."""
    if not ONYPHE_KEY:
        return _missing_key()
    return await get_json(f"https://www.onyphe.io/api/v2/simple/datascan/{query}",
                          headers=_auth(), ttl=3600)


async def onyphe_threatlist(ip: str) -> dict:
    """Onyphe threatlist — known-malicious IP hits from curated feeds."""
    if not ONYPHE_KEY:
        return _missing_key()
    return await get_json(f"https://www.onyphe.io/api/v2/simple/threatlist/{ip}",
                          headers=_auth(), ttl=3600)


async def onyphe_resolver_forward(domain: str) -> dict:
    """Onyphe forward DNS resolution history for a domain."""
    if not ONYPHE_KEY:
        return _missing_key()
    return await get_json(f"https://www.onyphe.io/api/v2/simple/resolver/forward/{domain}",
                          headers=_auth(), ttl=3600)


async def onyphe_resolver_reverse(ip: str) -> dict:
    """Onyphe reverse DNS resolution history for an IP (pDNS)."""
    if not ONYPHE_KEY:
        return _missing_key()
    return await get_json(f"https://www.onyphe.io/api/v2/simple/resolver/reverse/{ip}",
                          headers=_auth(), ttl=3600)


async def onyphe_ctl(domain: str) -> dict:
    """Onyphe Certificate Transparency Logs — SAN pivots for a domain."""
    if not ONYPHE_KEY:
        return _missing_key()
    return await get_json(f"https://www.onyphe.io/api/v2/simple/ctl/{domain}",
                          headers=_auth(), ttl=3600)


async def onyphe_pastries(query: str) -> dict:
    """Onyphe pastries — mentions of an IOC in pastebin-like dumps."""
    if not ONYPHE_KEY:
        return _missing_key()
    return await get_json(f"https://www.onyphe.io/api/v2/simple/pastries/{query}",
                          headers=_auth(), ttl=3600)


async def onyphe_geoloc(ip: str) -> dict:
    """Onyphe geolocation — authoritative country/city per their dataset."""
    if not ONYPHE_KEY:
        return _missing_key()
    return await get_json(f"https://www.onyphe.io/api/v2/simple/geoloc/{ip}",
                          headers=_auth(), ttl=3600)
