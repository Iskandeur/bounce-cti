"""GLEIF / LEI — company identity & corporate hierarchy (Due Diligence pool).

GLEIF publishes the Global LEI Index (2M+ legal entities) under **CC0** (public
domain — commercial use OK, no key, no registration; see THIRD_PARTY_LICENSES).
This resolves a company by **name or LEI** to its legal identity (name,
jurisdiction, status, address, registration) and its Level-2 "who owns whom"
relationships (direct / ultimate parent, direct children).

⚠️ **Legal framing (also baked into the DD prompt):** GLEIF Level-2 is corporate
ownership / consolidation data — **NOT authoritative beneficial ownership
(UBO/RBE)**; GLEIF says so itself. Anything derived here is *estimated / inferred*
ownership, never "the official beneficial owner".
"""
from __future__ import annotations

import re

from .http_client import get_json

_API = "https://api.gleif.org/api/v1"
_LEI_RE = re.compile(r"^[A-Z0-9]{18}[0-9]{2}$", re.I)  # ISO 17442 LEI (20 chars)
_TTL = 86400


def _name(ent: dict):
    ln = ent.get("legalName")
    return ln.get("name") if isinstance(ln, dict) else ln


def _parse_record(rec: dict) -> dict:
    """Shape a GLEIF lei-record into a compact entity. Pure (unit-tested)."""
    if not isinstance(rec, dict):
        return {}
    a = rec.get("attributes", {}) or {}
    ent = a.get("entity", {}) or {}
    reg = a.get("registration", {}) or {}
    addr = ent.get("legalAddress", {}) or {}
    lf = ent.get("legalForm")
    addr_parts = [" ".join(addr.get("addressLines") or []), addr.get("city"),
                  addr.get("postalCode"), addr.get("country")]
    return {
        "lei": a.get("lei") or rec.get("id"),
        "name": _name(ent),
        "jurisdiction": ent.get("jurisdiction"),
        "status": ent.get("status"),
        "legal_form": lf.get("id") if isinstance(lf, dict) else lf,
        "country": addr.get("country"),
        "city": addr.get("city"),
        "address": ", ".join(p for p in addr_parts if p) or None,
        "registration_status": reg.get("status"),
        "last_update": reg.get("lastUpdateDate"),
    }


def _rel_stub(rec: dict) -> dict:
    p = _parse_record(rec)
    return {"lei": p.get("lei"), "name": p.get("name")}


async def _relationships(lei: str) -> dict:
    """Fetch Level-2 'who owns whom' relationships for an LEI."""
    out: dict = {}
    for endpoint, key in (("direct-parent", "direct_parent"),
                          ("ultimate-parent", "ultimate_parent")):
        r = await get_json(f"{_API}/lei-records/{lei}/{endpoint}", ttl=_TTL,
                           cache_key=f"gleif|{endpoint}|{lei}")
        d = r.get("data") if isinstance(r, dict) else None
        if isinstance(d, dict):
            out[key] = _rel_stub(d)
    rc = await get_json(f"{_API}/lei-records/{lei}/direct-children",
                        params={"page[size]": "20"}, ttl=_TTL,
                        cache_key=f"gleif|children|{lei}")
    dc = rc.get("data") if isinstance(rc, dict) else None
    if isinstance(dc, list) and dc:
        out["direct_children"] = [_rel_stub(c) for c in dc]
    return out


async def lookup(query: str) -> dict:
    """Resolve a company by LEI (exact) or legal name (search) via GLEIF."""
    q = (query or "").strip()
    if not q:
        return {"query": query, "found": False, "error": "empty query"}
    if _LEI_RE.match(q):
        rec = await get_json(f"{_API}/lei-records/{q.upper()}", ttl=_TTL,
                             cache_key=f"gleif|lei|{q.upper()}")
        data = rec.get("data") if isinstance(rec, dict) else None
        if not isinstance(data, dict):
            return {"query": q, "found": False, "source": "gleif (CC0)"}
        out = _parse_record(data)
        out["found"] = True
        out["relationships"] = await _relationships(out["lei"] or q.upper())
        out["source"] = "gleif (CC0)"
        out["ubo_disclaimer"] = ("Level-2 is corporate ownership, NOT "
                                 "authoritative beneficial ownership (UBO/RBE).")
        return out
    res = await get_json(f"{_API}/lei-records",
                         params={"filter[entity.legalName]": q, "page[size]": "10"},
                         ttl=_TTL, cache_key=f"gleif|name|{q.lower()}")
    data = res.get("data") if isinstance(res, dict) else None
    matches = [_parse_record(r) for r in data] if isinstance(data, list) else []
    return {"query": q, "found": bool(matches), "match_count": len(matches),
            "matches": matches, "source": "gleif (CC0)"}
