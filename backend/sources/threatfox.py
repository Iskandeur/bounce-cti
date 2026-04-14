from .http_client import post_json
from ..config import ABUSECH_KEY


async def threatfox_search(ioc: str) -> dict:
    body = {"query": "search_ioc", "search_term": ioc}
    headers = {}
    if ABUSECH_KEY:
        headers["Auth-Key"] = ABUSECH_KEY
    return await post_json("https://threatfox-api.abuse.ch/api/v1/",
                           headers=headers, json_body=body, ttl=3600)
