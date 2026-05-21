"""Classic WHOIS (RFC 3912) — async TCP port-43 client.

RDAP is the modern replacement, but the legacy WHOIS protocol still
returns fields some registries don't yet publish over RDAP (abuse contacts
on certain ccTLDs, full registrant org for thin TLDs after referral, RIR
"OrgAbuseEmail" comments, etc.). This module complements ``rdap.py`` by
talking directly to the authoritative WHOIS server.

The lookup is two-stage:
  1. Query ``whois.iana.org`` for the TLD (domains) or the IP/ASN
     allocation (numbers), parse the ``refer:`` / ``whois:`` line.
  2. Query the referred server. Some registrars need a second hop via
     ``Registrar WHOIS Server:`` — we follow at most one extra level.

Output shape::
    {
      "raw": "<concatenated raw text>",
      "servers": ["whois.iana.org", "whois.verisign-grs.com", ...],
      "parsed": {
        "registrar": "...",
        "creation_date": "...",
        "updated_date": "...",
        "expiration_date": "...",
        "name_servers": [...],
        "registrant_email": "...",
        "registrant_name": "...",
        "registrant_organization": "...",
        "abuse_email": "...",
        "status": [...],
        # for IPs / ASNs:
        "netname": "...", "org": "...", "country": "...", "cidr": "..."
      }
    }
"""
from __future__ import annotations

import asyncio
import re

from ..graph_store import cache_get, cache_set

_IANA = "whois.iana.org"
_PORT = 43
_TIMEOUT = 15.0
_TTL = 86400  # 24h — registration data is slow-moving


async def _query(server: str, value: str) -> str:
    """Open TCP/43 to ``server``, send ``value\\r\\n``, read until EOF."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, _PORT), timeout=_TIMEOUT
        )
    except (asyncio.TimeoutError, OSError) as e:
        return f"__error__: connect {server}: {e}"
    try:
        writer.write((value + "\r\n").encode("utf-8", errors="replace"))
        await writer.drain()
        chunks: list[bytes] = []
        try:
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=_TIMEOUT)
                if not chunk:
                    break
                chunks.append(chunk)
                if sum(len(c) for c in chunks) > 200_000:  # 200KB ceiling
                    break
        except asyncio.TimeoutError:
            pass
        return b"".join(chunks).decode("utf-8", errors="replace")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


_REFER_RE = re.compile(r"^\s*(?:refer|whois):\s*(\S+)", re.MULTILINE | re.IGNORECASE)
_REGISTRAR_WS_RE = re.compile(
    r"Registrar WHOIS Server:\s*(\S+)", re.IGNORECASE
)


def _parse(raw: str) -> dict:
    """Extract common fields from concatenated WHOIS text.

    Field names vary wildly across registries; we accept a few synonyms
    and surface the *first* non-empty value we see for each canonical
    key. The raw text is always preserved separately."""
    out: dict = {}
    name_servers: list[str] = []
    statuses: list[str] = []

    field_map = {
        "registrar": [r"Registrar:\s*(.+)", r"Sponsoring Registrar:\s*(.+)"],
        "creation_date": [r"Creation Date:\s*(.+)", r"Created On:\s*(.+)",
                          r"Registered:\s*(.+)", r"created:\s*(.+)"],
        "updated_date": [r"Updated Date:\s*(.+)", r"Last Updated On:\s*(.+)",
                         r"changed:\s*(.+)", r"last-modified:\s*(.+)"],
        "expiration_date": [r"Registry Expiry Date:\s*(.+)",
                            r"Expiration Date:\s*(.+)",
                            r"Registrar Registration Expiration Date:\s*(.+)",
                            r"paid-till:\s*(.+)"],
        "registrant_email": [r"Registrant Email:\s*(.+)", r"e-mail:\s*(.+)"],
        "registrant_name": [r"Registrant Name:\s*(.+)", r"person:\s*(.+)"],
        "registrant_organization": [r"Registrant Organization:\s*(.+)",
                                     r"Registrant Org:\s*(.+)",
                                     r"organization:\s*(.+)"],
        "abuse_email": [r"Registrar Abuse Contact Email:\s*(.+)",
                        r"abuse-mailbox:\s*(.+)",
                        r"OrgAbuseEmail:\s*(.+)"],
        "netname": [r"netname:\s*(.+)", r"NetName:\s*(.+)"],
        "org": [r"org-name:\s*(.+)", r"OrgName:\s*(.+)", r"Organization:\s*(.+)"],
        "country": [r"country:\s*(.+)", r"Country:\s*(.+)"],
        "cidr": [r"CIDR:\s*(.+)", r"inetnum:\s*(.+)", r"inet6num:\s*(.+)"],
    }
    for key, patterns in field_map.items():
        for pat in patterns:
            m = re.search(pat, raw, re.IGNORECASE)
            if m:
                val = m.group(1).strip()
                if val and not val.startswith("REDACTED") and val.lower() != "n/a":
                    out[key] = val
                    break

    for m in re.finditer(r"(?:Name Server|nserver|nameserver):\s*(\S+)",
                          raw, re.IGNORECASE):
        ns = m.group(1).strip().lower().rstrip(".")
        if ns and ns not in name_servers:
            name_servers.append(ns)
    if name_servers:
        out["name_servers"] = name_servers

    for m in re.finditer(r"(?:Domain Status|status):\s*(.+)",
                          raw, re.IGNORECASE):
        s = m.group(1).strip()
        if s and s not in statuses:
            statuses.append(s)
    if statuses:
        out["status"] = statuses

    return out


async def _chain_query(initial_server: str, value: str,
                        max_hops: int = 2) -> tuple[str, list[str]]:
    """Query ``initial_server``, follow ``Registrar WHOIS Server:`` hints
    up to ``max_hops`` extra times, return (concatenated_raw, servers)."""
    servers = [initial_server]
    raws = [await _query(initial_server, value)]
    last = raws[-1]
    for _ in range(max_hops):
        m = _REGISTRAR_WS_RE.search(last)
        if not m:
            break
        nxt = m.group(1).strip().lower()
        if nxt in servers:
            break
        servers.append(nxt)
        last = await _query(nxt, value)
        raws.append(last)
    return ("\n\n--- next server ---\n\n".join(raws), servers)


async def whois_domain(domain: str) -> dict:
    """Two-stage WHOIS lookup for a domain. Cached 24h."""
    domain = domain.strip().lower().rstrip(".")
    if not domain or "." not in domain:
        return {"error": "invalid domain"}
    cache_key = f"whois|domain|{domain}"
    cached = cache_get(cache_key, ttl=_TTL)
    if cached is not None:
        return cached

    tld = domain.rsplit(".", 1)[-1]
    iana_raw = await _query(_IANA, tld)
    if iana_raw.startswith("__error__"):
        result = {"raw": iana_raw, "servers": [_IANA], "parsed": {},
                  "error": iana_raw}
        cache_set(cache_key, result)
        return result

    m = _REFER_RE.search(iana_raw)
    if not m:
        result = {"raw": iana_raw, "servers": [_IANA],
                  "parsed": _parse(iana_raw),
                  "warning": f"no WHOIS server referral for TLD .{tld}"}
        cache_set(cache_key, result)
        return result

    tld_server = m.group(1).strip().lower()
    raw, servers = await _chain_query(tld_server, domain)
    result = {
        "raw": raw,
        "servers": [_IANA] + servers,
        "parsed": _parse(raw),
    }
    cache_set(cache_key, result)
    return result


async def whois_ip(ip_or_asn: str) -> dict:
    """WHOIS lookup for an IP address or ASN. Cached 24h.

    Pass an IPv4/IPv6 address (e.g. ``8.8.8.8``) or an ASN
    (e.g. ``AS15169`` or ``15169``). IANA refers to the responsible RIR
    (ARIN / RIPE / APNIC / LACNIC / AFRINIC) which holds the allocation
    record."""
    value = ip_or_asn.strip()
    if not value:
        return {"error": "empty value"}
    cache_key = f"whois|ip|{value.lower()}"
    cached = cache_get(cache_key, ttl=_TTL)
    if cached is not None:
        return cached

    iana_raw = await _query(_IANA, value)
    if iana_raw.startswith("__error__"):
        result = {"raw": iana_raw, "servers": [_IANA], "parsed": {},
                  "error": iana_raw}
        cache_set(cache_key, result)
        return result

    m = _REFER_RE.search(iana_raw)
    if not m:
        result = {"raw": iana_raw, "servers": [_IANA],
                  "parsed": _parse(iana_raw),
                  "warning": "no RIR referral; IANA reply only"}
        cache_set(cache_key, result)
        return result

    rir_server = m.group(1).strip().lower()
    rir_raw = await _query(rir_server, value)
    raw = iana_raw + "\n\n--- next server ---\n\n" + rir_raw
    result = {
        "raw": raw,
        "servers": [_IANA, rir_server],
        "parsed": _parse(raw),
    }
    cache_set(cache_key, result)
    return result
