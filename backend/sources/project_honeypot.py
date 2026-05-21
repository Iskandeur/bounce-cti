"""Project Honey Pot — http:BL DNSBL lookup.

http:BL exposes its data over DNS: querying
``<access_key>.<octet-reversed-ip>.dnsbl.httpbl.org`` returns ``127.X.Y.Z``
where:
  - the first octet is always 127 (sanity check),
  - the second is "days since last activity" (0..255),
  - the third is "threat score" (0..255 — 25+ is bad),
  - the fourth encodes the type bitfield (0=search engine, 1=suspicious,
    2=harvester, 4=comment spammer, combinations possible).

A NXDOMAIN means the IP is unknown to http:BL (clean by Project Honey Pot
standards). Documented at https://www.projecthoneypot.org/httpbl_api.php.
"""
from __future__ import annotations

import asyncio
import os
import socket

from ..graph_store import cache_get, cache_set

_KEY_ENV = "PROJECTHONEYPOT_API_KEY"
_DOMAIN = "dnsbl.httpbl.org"

_TYPE_FLAGS = {1: "suspicious", 2: "harvester", 4: "comment_spammer"}


def _decode(answer: str) -> dict | None:
    parts = answer.split(".")
    if len(parts) != 4 or parts[0] != "127":
        return None
    try:
        days, score, kind = int(parts[1]), int(parts[2]), int(parts[3])
    except ValueError:
        return None
    types = [name for bit, name in _TYPE_FLAGS.items() if kind & bit]
    if kind == 0:
        types = ["search_engine"]
    return {
        "days_since_last_activity": days,
        "threat_score": score,
        "type_flags": kind,
        "types": types,
        "raw": answer,
    }


def _lookup_sync(query_host: str) -> str | None:
    try:
        return socket.gethostbyname(query_host)
    except (socket.gaierror, socket.herror):
        return None


async def check_ip(ip: str) -> dict:
    """Return ``{listed: bool, ...}`` for an IPv4 address. IPv6 not supported
    by http:BL — returns ``{"error": "ipv6_unsupported"}`` in that case."""
    key = os.getenv(_KEY_ENV, "").strip()
    if not key:
        return {"error": f"no {_KEY_ENV} configured"}
    if ":" in ip:
        return {"error": "ipv6_unsupported"}
    octets = ip.split(".")
    if len(octets) != 4:
        return {"error": f"not an IPv4 address: {ip}"}
    rev = ".".join(reversed(octets))
    query_host = f"{key}.{rev}.{_DOMAIN}"
    cache_key = f"projecthoneypot|{ip}"
    cached = cache_get(cache_key, ttl=6 * 3600)
    if cached is not None:
        return cached
    loop = asyncio.get_running_loop()
    answer = await loop.run_in_executor(None, _lookup_sync, query_host)
    if not answer:
        result = {"listed": False, "ip": ip}
    else:
        decoded = _decode(answer)
        if decoded:
            result = {"listed": True, "ip": ip, **decoded}
        else:
            result = {"listed": False, "ip": ip, "raw": answer,
                       "note": "unexpected response shape"}
    cache_set(cache_key, result)
    return result
