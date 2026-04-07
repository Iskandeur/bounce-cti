from .http_client import get_json
from ..config import ONYPHE_KEY


async def onyphe_summary_domain(domain: str) -> dict:
    if not ONYPHE_KEY:
        return {"error": "no Onyphe key"}
    return await get_json(f"https://www.onyphe.io/api/v2/summary/domain/{domain}",
                          headers={"Authorization": f"bearer {ONYPHE_KEY}"}, ttl=3600)


async def onyphe_summary_ip(ip: str) -> dict:
    if not ONYPHE_KEY:
        return {"error": "no Onyphe key"}
    return await get_json(f"https://www.onyphe.io/api/v2/summary/ip/{ip}",
                          headers={"Authorization": f"bearer {ONYPHE_KEY}"}, ttl=3600)
