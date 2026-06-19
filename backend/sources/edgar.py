"""SEC EDGAR — US-listed company identity & filings (DD pool).

EDGAR filings are US-government-disseminated public information — *free to access
and reuse* incl. commercially (see THIRD_PARTY_LICENSES). No API key, but SEC
requires a descriptive ``User-Agent`` (a bare/empty UA gets a 403) and a fair-use
rate of ≤10 req/s.

Resolves a company by **name, ticker, or CIK** to its EDGAR identity: official
name, CIK, tickers + exchanges, SIC (industry), state/country of incorporation,
business address, former names (aliases), and a snapshot of recent filing types.
Officer/insider extraction (Forms 3/4/5) is intentionally deferred to a later
slice — this covers the company-identity layer for US issuers.
"""
from __future__ import annotations

import re

from .http_client import get_json

# SEC asks for a descriptive UA with contact info; an empty one is rejected (403).
_HEADERS = {"User-Agent": "bounce-cti due-diligence research (contact: abuse@bounce.invalid)"}
_TICKERS_URL = "https://www.sec.gov/files/company_tickers.json"
_SUBMISSIONS = "https://data.sec.gov/submissions/CIK{cik:010d}.json"
_TTL = 86400
_CIK_RE = re.compile(r"^(?:cik)?0*(\d{1,10})$", re.I)
_WS_RE = re.compile(r"[^\w\s]", re.UNICODE)
_SUFFIXES = {"inc", "incorporated", "corp", "corporation", "co", "company", "ltd",
             "llc", "plc", "lp", "the", "sa", "ag", "nv", "holdings", "group"}


def _norm(s: str) -> str:
    s = _WS_RE.sub(" ", (s or "").lower())
    return " ".join(t for t in s.split() if t and t not in _SUFFIXES)


def _resolve(query: str, tickers: dict) -> list[dict]:
    """Match a name/ticker against the parsed company_tickers.json. Pure."""
    q = (query or "").strip()
    ql = q.lower()
    nq = _norm(q)
    qtok = set(nq.split())
    out = []
    for row in (tickers or {}).values():
        if not isinstance(row, dict):
            continue
        title = row.get("title") or ""
        ticker = (row.get("ticker") or "")
        score = 0
        if ticker and ticker.lower() == ql:
            score = 100
        else:
            nt = _norm(title)
            ttok = set(nt.split())
            if nt == nq and nq:
                score = 100
            elif qtok and (qtok <= ttok or ttok <= qtok):
                score = 95
            elif qtok and ttok:
                inter = len(qtok & ttok)
                score = int(round(inter / len(qtok | ttok) * 100)) if inter else 0
        if score >= 80:
            out.append({"cik": row.get("cik_str"), "ticker": ticker,
                        "name": title, "score": score})
    out.sort(key=lambda d: d["score"], reverse=True)
    return out[:10]


def _parse_submissions(d: dict) -> dict:
    """Shape data.sec.gov submissions JSON into a company identity. Pure."""
    if not isinstance(d, dict) or not d.get("cik"):
        return {}
    addr = ((d.get("addresses") or {}).get("business") or {})
    addr_str = ", ".join(p for p in [addr.get("street1"), addr.get("city"),
                                     addr.get("stateOrCountry"), addr.get("zipCode")] if p)
    former = [f.get("name") for f in (d.get("formerNames") or []) if f.get("name")]
    forms = []
    recent = ((d.get("filings") or {}).get("recent") or {}).get("form") or []
    for f in recent:
        if f not in forms:
            forms.append(f)
        if len(forms) >= 12:
            break
    return {
        "cik": int(d["cik"]) if str(d.get("cik")).isdigit() else d.get("cik"),
        "name": d.get("name"),
        "tickers": d.get("tickers") or [],
        "exchanges": d.get("exchanges") or [],
        "sic": d.get("sic"),
        "sic_description": d.get("sicDescription"),
        "incorporated_in": d.get("stateOfIncorporation"),
        "address": addr_str or None,
        "former_names": former,
        "recent_form_types": forms,
        "entity_type": d.get("entityType"),
    }


async def _submissions(cik: int) -> dict:
    raw = await get_json(_SUBMISSIONS.format(cik=cik), headers=_HEADERS, ttl=_TTL,
                         cache_key=f"edgar|sub|{cik:010d}")
    if not isinstance(raw, dict) or raw.get("_status"):
        return {"cik": cik, "found": False, "source": "sec edgar"}
    out = _parse_submissions(raw)
    if not out:
        return {"cik": cik, "found": False, "source": "sec edgar"}
    out["found"] = True
    out["source"] = "sec edgar (public domain)"
    return out


async def lookup(query: str) -> dict:
    """Resolve a US issuer by CIK (exact), or by name/ticker (search)."""
    q = (query or "").strip()
    if not q:
        return {"query": query, "found": False, "error": "empty query"}
    m = _CIK_RE.match(q.replace(" ", ""))
    # Treat as a CIK only if it's clearly numeric (avoid matching short names).
    if m and (q.lower().startswith("cik") or q.replace(" ", "").isdigit()):
        return await _submissions(int(m.group(1)))
    tickers = await get_json(_TICKERS_URL, headers=_HEADERS, ttl=_TTL,
                             cache_key="edgar|tickers")
    if not isinstance(tickers, dict) or tickers.get("_status"):
        return {"query": q, "found": False, "source": "sec edgar",
                "error": "ticker index unavailable"}
    matches = _resolve(q, tickers)
    if not matches:
        return {"query": q, "found": False, "match_count": 0, "matches": [],
                "source": "sec edgar (public domain)"}
    # Enrich the best match with its full submissions record.
    best = await _submissions(int(matches[0]["cik"]))
    return {"query": q, "found": True, "match_count": len(matches),
            "matches": matches, "best": best, "source": "sec edgar (public domain)"}
