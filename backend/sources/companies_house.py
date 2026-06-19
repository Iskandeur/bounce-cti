"""UK Companies House — company profile, officers & PSC (DD pool).

Free API (a free key is required; HTTP Basic with the key as username). Data is
under the **Open Government Licence v3.0** — commercial use incl. redistribution
is permitted; the personal data of officers/PSC carries GDPR obligations, so the
DD prompt keeps usage factual (no adverse-media / criminal inference).

Resolves a company by **name or company number** to its profile, its officers
(directors / secretaries) and its persons with significant control (PSC). The
officers and PSC become `person` nodes the agent then sanctions-screens — closing
the KYB loop company → directors → sanctions. Degrades gracefully (``available:
False``) when no ``COMPANIES_HOUSE_API_KEY`` is configured.
"""
from __future__ import annotations

import base64
import re

from .. import key_pool
from .http_client import get_json

_API = "https://api.company-information.service.gov.uk"
_TTL = 86400
# CH company numbers: 8 digits, or a 2-letter prefix (SC/NI/OC/…) + 6 digits.
_NUM_RE = re.compile(r"^(?:\d{8}|[A-Z]{2}\d{6})$")


def _auth_header():
    key = key_pool.acquire("companies_house")
    if not key:
        return None
    token = base64.b64encode(f"{key}:".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def _addr(a: dict) -> str | None:
    if not isinstance(a, dict):
        return None
    parts = [a.get("premises"), a.get("address_line_1"), a.get("address_line_2"),
             a.get("locality"), a.get("region"), a.get("postal_code"), a.get("country")]
    return ", ".join(p for p in parts if p) or None


def _dob(d: dict) -> str | None:
    if isinstance(d, dict) and d.get("year"):
        return f"{d['year']}-{int(d.get('month') or 0):02d}"  # month/year only (GDPR)
    return None


def _parse_profile(p: dict) -> dict:
    return {
        "company_number": p.get("company_number"),
        "name": p.get("company_name"),
        "status": p.get("company_status"),
        "type": p.get("type"),
        "jurisdiction": p.get("jurisdiction"),
        "incorporated": p.get("date_of_creation"),
        "address": _addr(p.get("registered_office_address")),
        "sic_codes": p.get("sic_codes") or [],
    }


def _parse_search_item(i: dict) -> dict:
    return {
        "company_number": i.get("company_number"),
        "name": i.get("title"),
        "status": i.get("company_status"),
        "address": i.get("address_snippet"),
    }


def _parse_officer(o: dict) -> dict:
    return {
        "name": o.get("name"),
        "role": o.get("officer_role"),
        "appointed": o.get("appointed_on"),
        "resigned": o.get("resigned_on"),
        "nationality": o.get("nationality"),
        "occupation": o.get("occupation"),
        "dob": _dob(o.get("date_of_birth")),
    }


def _parse_psc(p: dict) -> dict:
    return {
        "name": p.get("name"),
        "kind": p.get("kind"),
        "nationality": p.get("nationality"),
        "natures_of_control": p.get("natures_of_control") or [],
        "dob": _dob(p.get("date_of_birth")),
    }


async def _get_company(number: str, headers: dict) -> dict:
    prof = await get_json(f"{_API}/company/{number}", headers=headers, ttl=_TTL,
                          cache_key=f"ch|co|{number}")
    if not isinstance(prof, dict) or prof.get("_status") or not prof.get("company_number"):
        return {"company_number": number, "found": False, "source": "companies_house (OGL v3.0)"}
    out = _parse_profile(prof)
    out["found"] = True
    off = await get_json(f"{_API}/company/{number}/officers",
                         params={"items_per_page": "35"}, headers=headers, ttl=_TTL,
                         cache_key=f"ch|off|{number}")
    out["officers"] = ([_parse_officer(o) for o in (off.get("items") or [])]
                       if isinstance(off, dict) else [])
    psc = await get_json(f"{_API}/company/{number}/persons-with-significant-control",
                         params={"items_per_page": "25"}, headers=headers, ttl=_TTL,
                         cache_key=f"ch|psc|{number}")
    out["psc"] = ([_parse_psc(p) for p in (psc.get("items") or [])]
                  if isinstance(psc, dict) else [])
    out["source"] = "companies_house (OGL v3.0)"
    return out


async def lookup(query: str) -> dict:
    """Resolve a UK company by number (exact, + officers/PSC) or name (search)."""
    q = (query or "").strip()
    if not q:
        return {"query": query, "found": False, "error": "empty query"}
    headers = _auth_header()
    if not headers:
        return {"query": q, "available": False,
                "reason": "no COMPANIES_HOUSE_API_KEY configured (free key at "
                          "developer.company-information.service.gov.uk)"}
    num = q.upper().replace(" ", "")
    if _NUM_RE.match(num):
        return await _get_company(num, headers)
    res = await get_json(f"{_API}/search/companies",
                         params={"q": q, "items_per_page": "10"}, headers=headers,
                         ttl=_TTL, cache_key=f"ch|search|{q.lower()}")
    items = res.get("items") if isinstance(res, dict) else None
    matches = [_parse_search_item(i) for i in items] if isinstance(items, list) else []
    return {"query": q, "found": bool(matches), "match_count": len(matches),
            "matches": matches, "source": "companies_house (OGL v3.0)"}
