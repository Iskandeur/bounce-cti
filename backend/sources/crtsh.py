from .http_client import get_json


async def subdomains_for(domain: str) -> list[dict]:
    data = await get_json("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, ttl=3600)
    if not isinstance(data, list):
        return []
    seen = set()
    out = []
    for row in data:
        for n in (row.get("name_value") or "").split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n and n not in seen:
                seen.add(n)
                out.append({"name": n, "issuer": row.get("issuer_name"), "not_before": row.get("not_before")})
    # Cap aggressively — claude tool_result has a max size and 500 entries can
    # exceed it (~118KB observed). 80 most-recent is enough for the agent to
    # pick representatives; total count is preserved for context.
    out.sort(key=lambda r: r.get("not_before") or "", reverse=True)
    return out[:80]
