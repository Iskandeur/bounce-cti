"""crt.sh — Certificate Transparency search.

Free, no-key, most common use: subdomain enumeration from CT logs. The CT
corpus also lets us do serial-number and subject/issuer-CN pivots, which
is the free-tier equivalent of Shodan's `ssl.cert.serial:` query.
"""
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


async def by_serial(serial: str) -> dict:
    """Look up certs by serial number (hex). Use when a cert serial is in-hand and
    you want to find OTHER hosts that presented the same serial — e.g. reused
    self-signed Cobalt Strike staging certs.

    Returns a digest suitable for graphing: cert_count, issuer_count, host_count,
    hosts[] (up to 80 most recent), plus the raw rows capped.
    """
    s = (serial or "").strip().lower().removeprefix("0x")
    if not s:
        return {"error": "empty serial", "hosts": []}
    data = await get_json("https://crt.sh/",
                          params={"serial": s, "output": "json"}, ttl=3600)
    return _digest_rows(data, note=f"serial={s}")


async def by_query(q: str, match: str = "ILIKE") -> dict:
    """Generic crt.sh search. `q` can be an org name, subject CN pattern, etc.
    `match` is passed through to crt.sh (e.g. ILIKE, LIKE, =). Use for pivots
    like a distinctive issuer organisation (O=1314520.com) — a common reuse
    signal for actor-operated TLS staging infra.

    Returns the same digest shape as by_serial().
    """
    if not q:
        return {"error": "empty query", "hosts": []}
    data = await get_json("https://crt.sh/",
                          params={"q": q, "match": match, "output": "json"},
                          ttl=3600)
    return _digest_rows(data, note=f"q={q!r} match={match}")


def _digest_rows(data, *, note: str = "") -> dict:
    if not isinstance(data, list):
        return {"error": "crt.sh returned non-list", "hosts": [], "note": note}
    hosts = set(); issuers = set(); serials = set(); cns = set()
    rows = []
    for row in data:
        serials.add((row.get("serial_number") or "").strip().lower())
        issuers.add(row.get("issuer_name") or "")
        cn = (row.get("common_name") or "").strip().lower().lstrip("*.")
        if cn: cns.add(cn)
        for n in (row.get("name_value") or "").split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n: hosts.add(n)
        rows.append({
            "id": row.get("id"),
            "serial": row.get("serial_number"),
            "issuer": row.get("issuer_name"),
            "common_name": row.get("common_name"),
            "name_value": (row.get("name_value") or "")[:200],
            "not_before": row.get("not_before"),
            "not_after": row.get("not_after"),
        })
    rows.sort(key=lambda r: r.get("not_before") or "", reverse=True)
    return {
        "digest": {
            "host_count": len(hosts),
            "hosts": sorted(hosts)[:80],
            "issuer_count": len(issuers),
            "issuers": sorted(i for i in issuers if i)[:20],
            "serial_count": len(serials),
            "common_names": sorted(cns)[:40],
        },
        "rows": rows[:80],
        "total_rows": len(data),
        "note": note,
    }
