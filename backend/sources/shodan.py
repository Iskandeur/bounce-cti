from .http_client import get_json
from ..config import SHODAN_KEY


async def shodan_host(ip: str) -> dict:
    if not SHODAN_KEY:
        return {"error": "no Shodan key"}
    return await get_json(f"https://api.shodan.io/shodan/host/{ip}",
                          params={"key": SHODAN_KEY}, ttl=3600)


async def shodan_search(query: str) -> dict:
    if not SHODAN_KEY:
        return {"error": "no Shodan key"}
    return await get_json("https://api.shodan.io/shodan/host/search",
                          params={"key": SHODAN_KEY, "query": query}, ttl=3600)
