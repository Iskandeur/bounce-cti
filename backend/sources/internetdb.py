"""Shodan InternetDB — the free, keyless exposure lookup.

``https://internetdb.shodan.io/{ip}`` returns what Shodan's crawler last saw
on an IP, with **no API key, no account, and no credit cost of any kind**
(https://book.shodan.io/developer-apis/internetdb/). That makes it the
default first probe for any IP node: it answers "what is exposed here" for
free, so the credit-metered Shodan endpoints are only needed when the answer
isn't enough.

Fields returned by the API: ``ports``, ``cpes``, ``hostnames``, ``tags``,
``vulns``, ``ip``.

Two limits that matter for interpretation, surfaced in every response so the
agent doesn't over-read the data:

  - **Weekly-ish refresh, not real time.** A closed port may still be listed
    and a freshly opened one may be missing. Never present it as live state.
  - **No banners.** You get the port list and CPE/CVE inferences, not the
    service banner. Banner-level detail requires ``shodan_host`` (also free
    on a Membership key, but it needs the key).

A 404 from the API means "Shodan has no record for this IP" — a legitimate,
useful answer (the host is not indexed), not an error. It is normalised to
``{"found": false}`` rather than surfaced as a failure.
"""
from __future__ import annotations

import httpx

from ..graph_store import cache_get, cache_set
from .http_client import UA

_BASE = "https://internetdb.shodan.io"
_TTL = 6 * 3600  # the upstream data only moves weekly; 6h is already generous


def _empty(ip: str, reason: str) -> dict:
    return {
        "ip": ip,
        "found": False,
        "ports": [],
        "vulns": [],
        "cpes": [],
        "hostnames": [],
        "tags": [],
        "reason": reason,
        "_source": "internetdb",
        "_cost": "free (no key, no credits)",
    }


def _normalise(ip: str, data: dict) -> dict:
    """Coerce the upstream payload into a stable shape.

    The API returns bare lists; we keep them but add ``found``/counts so the
    agent can branch without len() gymnastics, plus the freshness caveat so a
    stale port list is never read as live state.
    """
    ports = data.get("ports") or []
    vulns = data.get("vulns") or []
    cpes = data.get("cpes") or []
    hostnames = data.get("hostnames") or []
    tags = data.get("tags") or []
    return {
        "ip": ip,
        "found": bool(ports or vulns or cpes or hostnames or tags),
        "ports": ports,
        "port_count": len(ports),
        "vulns": vulns,
        "vuln_count": len(vulns),
        "cpes": cpes,
        "hostnames": hostnames,
        "tags": tags,
        "_source": "internetdb",
        "_cost": "free (no key, no credits)",
        "_freshness": "Shodan InternetDB refreshes roughly weekly and carries no "
                      "banners — treat ports/vulns as last-seen exposure, not live state.",
    }


async def internetdb_ip(ip: str) -> dict:
    """Look up an IP's last-seen exposure. Free, keyless, cached 6h."""
    ip = (ip or "").strip()
    if not ip:
        return _empty(ip, "no IP supplied")

    cache_key = f"internetdb|{ip}"
    cached = cache_get(cache_key, ttl=_TTL)
    if cached is not None:
        return cached

    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True,
                                     headers={"User-Agent": UA}) as c:
            r = await c.get(f"{_BASE}/{ip}")
    except Exception as e:  # network blip — surface, never cache
        return _empty(ip, f"request failed: {str(e)[:200]}")

    if r.status_code == 404:
        # Not an error: Shodan simply has no record for this IP.
        out = _empty(ip, "no InternetDB record for this IP (not indexed by Shodan)")
        cache_set(cache_key, out)
        return out
    if r.status_code != 200:
        return _empty(ip, f"HTTP {r.status_code}")

    try:
        data = r.json()
    except Exception:
        return _empty(ip, "unparseable response")
    if not isinstance(data, dict):
        return _empty(ip, "unexpected response shape")

    out = _normalise(ip, data)
    cache_set(cache_key, out)
    return out
