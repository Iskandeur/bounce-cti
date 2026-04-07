from .http_client import get_json


async def rdap_domain(domain: str) -> dict:
    return await get_json(f"https://rdap.org/domain/{domain}", ttl=86400)


async def rdap_ip(ip: str) -> dict:
    return await get_json(f"https://rdap.org/ip/{ip}", ttl=86400)
