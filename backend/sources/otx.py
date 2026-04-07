from .http_client import get_json
from ..config import OTX_KEY

BASE = "https://otx.alienvault.com/api/v1/indicators"


def _h():
    return {"X-OTX-API-KEY": OTX_KEY} if OTX_KEY else {}


async def otx_domain(domain: str) -> dict:
    return await get_json(f"{BASE}/domain/{domain}/general", headers=_h(), ttl=3600)


async def otx_ip(ip: str) -> dict:
    return await get_json(f"{BASE}/IPv4/{ip}/general", headers=_h(), ttl=3600)


async def otx_file(h: str) -> dict:
    return await get_json(f"{BASE}/file/{h}/general", headers=_h(), ttl=3600)
