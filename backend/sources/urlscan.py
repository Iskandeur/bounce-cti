from .http_client import get_json
from ..config import URLSCAN_KEY


async def urlscan_search(query: str) -> dict:
    headers = {"API-Key": URLSCAN_KEY} if URLSCAN_KEY else {}
    return await get_json("https://urlscan.io/api/v1/search/", headers=headers,
                          params={"q": query, "size": 50}, ttl=3600)
