from .http_client import post_json


async def threatfox_search(ioc: str) -> dict:
    return await post_json("https://threatfox-api.abuse.ch/api/v1/",
                           json_body={"query": "search_ioc", "search_term": ioc}, ttl=3600)
