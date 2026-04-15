"""IP-API.com geolocation / ASN source.

Free tier (no key): 45 req/min, HTTP-only. Returns country, region, city,
ISP, org, AS number + name, plus proxy/hosting/mobile hints. Useful as a
second-opinion next to rdap_ip / virustotal_ip. Caches for an hour by
default (geolocation rarely changes).
"""
from .http_client import get_json, post_json

# Field mask — keep this aligned with what ip-api advertises; "status" is
# required for client-side success checks.
_FIELDS = ("status,message,country,countryCode,region,regionName,city,zip,"
          "lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query")


async def ip_api_single(ip: str) -> dict:
    """Single-IP lookup via http://ip-api.com/json/<ip>."""
    return await get_json(
        f"http://ip-api.com/json/{ip}",
        params={"fields": _FIELDS},
        ttl=3600,
    )


async def ip_api_batch(ips: list[str]) -> dict:
    """Batch lookup (up to 100 IPs per request) via POST /batch.
    Returns {"results": [<per-ip dict>, ...]} so callers always see a list."""
    if not ips:
        return {"results": []}
    batch = ips[:100]
    payload = [{"query": ip, "fields": _FIELDS} for ip in batch]
    data = await post_json(
        "http://ip-api.com/batch",
        json_body=payload,
        ttl=3600,
    )
    # ip-api returns either a list on success or a dict on error; normalize.
    if isinstance(data, list):
        return {"results": data}
    return {"results": [], "error": data}


async def ip_api_edns(ip: str) -> dict:
    """eDNS client-subnet-aware variant — http://edns.ip-api.com/json/<ip>.
    Useful when the IP is a CDN edge and you want to know which POP responded."""
    return await get_json(f"http://edns.ip-api.com/json/{ip}", ttl=3600)
