from .http_client import get_json
from ..config import VT_KEY

BASE = "https://www.virustotal.com/api/v3"


def _h():
    return {"x-apikey": VT_KEY} if VT_KEY else {}


async def vt_domain(domain: str) -> dict:
    if not VT_KEY:
        return {"error": "no VT key"}
    return await get_json(f"{BASE}/domains/{domain}", headers=_h(), ttl=3600)


async def vt_ip(ip: str) -> dict:
    if not VT_KEY:
        return {"error": "no VT key"}
    return await get_json(f"{BASE}/ip_addresses/{ip}", headers=_h(), ttl=3600)


async def vt_file(h: str) -> dict:
    if not VT_KEY:
        return {"error": "no VT key"}
    return await get_json(f"{BASE}/files/{h}", headers=_h(), ttl=3600)


async def vt_domain_resolutions(domain: str) -> dict:
    if not VT_KEY:
        return {"error": "no VT key"}
    return await get_json(f"{BASE}/domains/{domain}/resolutions", headers=_h(), ttl=3600)


async def vt_ip_resolutions(ip: str) -> dict:
    if not VT_KEY:
        return {"error": "no VT key"}
    return await get_json(f"{BASE}/ip_addresses/{ip}/resolutions", headers=_h(), ttl=3600)
