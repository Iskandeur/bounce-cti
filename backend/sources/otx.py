import json
from .http_client import get_json
from ..config import OTX_KEY

BASE = "https://otx.alienvault.com/api/v1/indicators"


def _h():
    return {"X-OTX-API-KEY": OTX_KEY} if OTX_KEY else {}


def _slim_otx(data: dict, max_pulses: int = 10) -> dict:
    """OTX general endpoint returns huge pulse lists with full IOC arrays.
    Trim to just the fields the agent needs to keep under the token limit.
    """
    if not isinstance(data, dict):
        return data
    result = {}
    # Keep top-level fields that are small
    for k in ("indicator", "type_title", "base_indicator", "alexa", "whois",
              "reputation", "country_name", "city", "asn", "validation"):
        if k in data:
            result[k] = data[k]
    # Slim pulses: keep name, tags, adversary, TLP, created — drop indicators/references
    pulses = data.get("pulse_info", {}).get("pulses", [])
    slim_pulses = []
    for p in pulses[:max_pulses]:
        slim = {
            "name": p.get("name", ""),
            "tags": p.get("tags", [])[:10],
            "adversary": p.get("adversary", ""),
            "tlp": p.get("tlp", ""),
            "created": p.get("created", ""),
            "description": (p.get("description") or "")[:300],
            "malware_families": p.get("malware_families", []),
            "attack_ids": p.get("attack_ids", []),
        }
        # Extract referenced file hashes from indicators if present
        indicators = p.get("indicators", [])
        file_hashes = [i.get("indicator") for i in indicators
                       if i.get("type") in ("FileHash-SHA256", "FileHash-MD5", "FileHash-SHA1")][:10]
        if file_hashes:
            slim["file_hashes"] = file_hashes
        slim_pulses.append(slim)
    result["pulse_count"] = data.get("pulse_info", {}).get("count", 0)
    result["pulses"] = slim_pulses
    if len(pulses) > max_pulses:
        result["pulses_truncated"] = True
        result["total_pulses"] = len(pulses)
    # Keep sections summary if present
    if "sections" in data:
        result["sections"] = data["sections"]
    return result


async def otx_domain(domain: str) -> dict:
    raw = await get_json(f"{BASE}/domain/{domain}/general", headers=_h(), ttl=3600)
    return _slim_otx(raw)


async def otx_ip(ip: str) -> dict:
    raw = await get_json(f"{BASE}/IPv4/{ip}/general", headers=_h(), ttl=3600)
    return _slim_otx(raw)


async def otx_file(h: str) -> dict:
    raw = await get_json(f"{BASE}/file/{h}/general", headers=_h(), ttl=3600)
    return _slim_otx(raw)
