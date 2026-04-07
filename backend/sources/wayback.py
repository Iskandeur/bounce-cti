from .http_client import get_json


async def wayback_snapshots(url: str) -> dict:
    return await get_json("https://archive.org/wayback/available",
                          params={"url": url}, ttl=86400)
