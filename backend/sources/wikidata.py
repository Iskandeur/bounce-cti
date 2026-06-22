"""Wikidata identity anchor (free, no key).

For an OSINT subject that is plausibly public (a notable developer, org, person),
Wikidata gives an authoritative, citable anchor in one or two calls: the entity
QID + description, official website, and self-declared social handles
(Twitter/X, GitHub, Mastodon, Facebook, Instagram). High-precision identity
attribution that gates the rest of a username/person investigation — and unlike
the social-media sweep it carries a stable citation (the QID URL).

No API key; the public ``wikidata.org/w/api.php`` endpoint just wants a
User-Agent (set by http_client). `found=False` simply means no notable entity by
that name — most private individuals won't be in Wikidata, which is itself a
useful signal (not a public figure).
"""
from __future__ import annotations

from .http_client import get_json

_API = "https://www.wikidata.org/w/api.php"
_TTL = 86400

# Wikidata property → output field for the social/identity claims we surface.
_CLAIM_PROPS = {
    "P856": "official_website",
    "P2002": "twitter",
    "P2037": "github",
    "P4033": "mastodon",
    "P2013": "facebook",
    "P2003": "instagram",
    "P2397": "youtube_channel",
    "P345": "imdb",
    "P1960": "google_scholar",
    "P571": "inception",          # orgs
    "P1448": "official_name",
}


def _claim_value(claims: dict, prop: str):
    """Extract the first claim value for a property (string/url/time/quantity).
    Returns None for QID-valued or absent claims (we only surface scalars)."""
    arr = (claims or {}).get(prop)
    if not arr:
        return None
    snak = (arr[0] or {}).get("mainsnak", {})
    dv = snak.get("datavalue", {})
    val = dv.get("value")
    if isinstance(val, str):
        return val
    if isinstance(val, dict):
        # time values → the ISO-ish timestamp; entity refs are skipped (QID only)
        if "time" in val:
            return val["time"].lstrip("+")
        return None
    return None


def _parse_entity(qid: str, ent: dict) -> dict:
    """Shape a wbgetentities entity into an identity card. Pure (unit-tested)."""
    labels = ent.get("labels", {}) or {}
    descs = ent.get("descriptions", {}) or {}
    claims = ent.get("claims", {}) or {}
    out = {
        "qid": qid,
        "url": f"https://www.wikidata.org/wiki/{qid}",
        "label": (labels.get("en") or {}).get("value")
                 or (next(iter(labels.values()), {}) or {}).get("value"),
        "description": (descs.get("en") or {}).get("value"),
    }
    for prop, field in _CLAIM_PROPS.items():
        v = _claim_value(claims, prop)
        if v:
            out[field] = v
    return out


def _parse_search(data: dict) -> list[dict]:
    out = []
    for r in (data.get("search") or []):
        out.append({"qid": r.get("id"), "label": r.get("label"),
                    "description": r.get("description")})
    return out


async def lookup(query: str) -> dict:
    """Resolve a name to its Wikidata identity card (best match) + alternates."""
    q = (query or "").strip().lstrip("@").strip()
    if not q:
        return {"query": query, "found": False, "error": "empty query"}
    res = await get_json(_API, params={
        "action": "wbsearchentities", "search": q, "language": "en",
        "format": "json", "limit": "5"}, ttl=_TTL,
        cache_key=f"wikidata|search|{q.lower()}")
    matches = _parse_search(res) if isinstance(res, dict) else []
    if not matches:
        return {"query": q, "found": False, "source": "wikidata"}
    top = matches[0]["qid"]
    ent_res = await get_json(_API, params={
        "action": "wbgetentities", "ids": top, "format": "json",
        "props": "labels|descriptions|claims"}, ttl=_TTL,
        cache_key=f"wikidata|ent|{top}")
    ent = ((ent_res or {}).get("entities") or {}).get(top, {}) if isinstance(ent_res, dict) else {}
    card = _parse_entity(top, ent) if ent else {"qid": top, "label": matches[0]["label"]}
    card["found"] = True
    card["match_count"] = len(matches)
    card["alternates"] = matches[1:]
    card["source"] = "wikidata (CC0)"
    return card
