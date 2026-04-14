from .http_client import get_json
from ..config import VT_KEY

BASE = "https://www.virustotal.com/api/v3"


def _h():
    return {"x-apikey": VT_KEY} if VT_KEY else {}


def _slim_collection(data: dict, max_items: int = 40) -> dict:
    """VT collection responses (resolutions/subdomains/communicating_files) are
    huge: each item carries last_analysis_results / engine details that bloat
    the response to 250KB+. Strip to just the fields the agent actually needs
    so the result fits in claude's tool_result token cap.
    """
    if not isinstance(data, dict) or "data" not in data:
        return data
    items = data.get("data") or []
    slim = []
    for it in items[:max_items]:
        if not isinstance(it, dict):
            continue
        attrs = it.get("attributes") or {}
        slim.append({
            "id": it.get("id"),
            "type": it.get("type"),
            "ip_address": attrs.get("ip_address"),
            "host_name": attrs.get("host_name"),
            "date": attrs.get("date"),
            "last_analysis_stats": attrs.get("last_analysis_stats"),
            "last_modification_date": attrs.get("last_modification_date"),
            "reputation": attrs.get("reputation"),
            "tags": attrs.get("tags"),
            "names": (attrs.get("names") or [])[:5],
            "type_description": attrs.get("type_description"),
            "meaningful_name": attrs.get("meaningful_name"),
        })
    return {"data": slim, "meta": data.get("meta"),
            "total": len(items), "returned": len(slim)}


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
    # VT default is 10 results, max is 40 — always request max so the agent
    # sees the full passive-DNS history rather than only the first 10.
    return _slim_collection(await get_json(f"{BASE}/domains/{domain}/resolutions",
                          headers=_h(), params={"limit": 40}, ttl=3600))


async def vt_subdomains(domain: str) -> dict:
    """Subdomains known to VirusTotal — complements crt.sh (catches subs with no public cert)."""
    if not VT_KEY:
        return {"error": "no VT key"}
    return _slim_collection(await get_json(f"{BASE}/domains/{domain}/subdomains",
                          headers=_h(), params={"limit": 40}, ttl=3600))


async def vt_communicating_files(kind: str, value: str) -> dict:
    """Files (samples) that communicated with the given domain or IP.
    kind ∈ {'domain','ip'}. Opens a hash-pivot from a network IOC.
    """
    if not VT_KEY:
        return {"error": "no VT key"}
    path = "domains" if kind == "domain" else "ip_addresses"
    return _slim_collection(await get_json(f"{BASE}/{path}/{value}/communicating_files",
                          headers=_h(), params={"limit": 20}, ttl=3600), max_items=20)


async def vt_ip_resolutions(ip: str) -> dict:
    if not VT_KEY:
        return {"error": "no VT key"}
    return _slim_collection(await get_json(f"{BASE}/ip_addresses/{ip}/resolutions",
                          headers=_h(), params={"limit": 40}, ttl=3600))
