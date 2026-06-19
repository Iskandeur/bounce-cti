"""Sanctions screening — OFAC + EU FSF + UK UKSL consolidated lists (DD pool).

Screens a name (company or person) against the three consolidated sanctions
lists that the DD research cleared for **commercial redistribution**:

  * **OFAC** SDN list — US Treasury, public domain (17 U.S.C. §105).
  * **EU FSF** — DG FISMA consolidated financial-sanctions list, Commission
    Decision 2011/833/EU (commercial reuse OK).
  * **UK UKSL** — FCDO UK Sanctions List, Open Government Licence v3.0.

(UN SC and World Bank are deliberately excluded — their terms forbid commercial
redistribution without written permission; see the DD research.)

Design: the lists are large (~10-50 MB), so they're fetched with a dedicated
raw client (``http_client.get_text`` caps bodies at 8 KB) and the *parsed*
entries are memoised in-process with a TTL. Parsers are header-name-tolerant
(the official CSV layouts drift) and unit-tested on fixtures; the matcher is a
conservative normalised comparison (exact / token-subset / Jaccard) — no fuzzy
dependency yet (RapidFuzz lands with the Phase-3 matching slice). A hit is a
*candidate* for human review, never an automated determination.
"""
from __future__ import annotations

import csv
import io
import re
import time
import unicodedata

import httpx

from .http_client import UA

# ── List sources (all commercial-OK per DD research) ───────────────────────
_URLS = {
    "OFAC": ("https://www.treasury.gov/ofac/downloads/sdn.csv", None),
    "EU": ("https://webgate.ec.europa.eu/fsd/fsf/public/files/"
           "csvFullSanctionsList_1_1/content?token=dG9rZW4tMjAxNw", None),
    "UK": ("https://sanctionslist.fcdo.gov.uk/docs/UK-Sanctions-List.csv", None),
}
_LIST_TTL = 6 * 3600
_FETCH_TIMEOUT = 60
_SCORE_THRESHOLD = 85
_MAX_HITS = 50

# Corporate suffixes stripped during normalisation so "Acme Ltd" ~ "Acme".
_SUFFIXES = {
    "ltd", "limited", "inc", "incorporated", "llc", "llp", "plc", "corp",
    "corporation", "co", "company", "sa", "sas", "sarl", "gmbh", "ag", "se",
    "bv", "nv", "spa", "srl", "oyj", "ab", "as", "pte", "pty", "kg", "ohg",
}
_PUNCT_RE = re.compile(r"[^\w\s]", re.UNICODE)
_WS_RE = re.compile(r"\s+")


def _normalize(name: str) -> str:
    """Lowercase, strip diacritics + punctuation, drop corporate suffixes."""
    s = unicodedata.normalize("NFKD", name or "")
    s = "".join(c for c in s if not unicodedata.combining(c))
    s = _PUNCT_RE.sub(" ", s.lower())
    toks = [t for t in _WS_RE.sub(" ", s).split() if t and t not in _SUFFIXES]
    return " ".join(toks)


def _score(nq: str, qtok: set, cand: str):
    """Conservative match score 0-100 between a normalised query and candidate."""
    nc = _normalize(cand)
    if not nc or not nq:
        return 0
    if nc == nq:
        return 100
    ctok = set(nc.split())
    if not ctok:
        return 0
    # Token-subset (one name fully contained in the other) — strong signal,
    # but require ≥2 query tokens so single common words don't over-match.
    if len(qtok) >= 2 and (qtok <= ctok or ctok <= qtok):
        return 95
    inter = len(qtok & ctok)
    if not inter:
        return 0
    jacc = inter / len(qtok | ctok)
    return int(round(jacc * 100))


# ── Per-list parsers (header-tolerant; return list of entry dicts) ──────────

def _entry(name, aliases, etype, programs, ref, source):
    return {"name": name, "aliases": [a for a in (aliases or []) if a],
            "type": etype, "programs": [p for p in (programs or []) if p],
            "ref": ref, "list": source}


def _parse_ofac(text: str) -> list[dict]:
    """OFAC SDN.CSV — positional, no header. Columns: ent_num, name, type,
    program, title, … ; empty fields are ``-0-``."""
    out = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 4:
            continue
        name = (row[1] or "").strip()
        if not name or name == "-0-":
            continue
        raw_type = (row[2] or "").strip().lower()
        etype = "person" if raw_type == "individual" else (
            raw_type if raw_type in ("vessel", "aircraft") else "entity")
        prog = (row[3] or "").strip()
        out.append(_entry(name, [], etype, [prog] if prog and prog != "-0-" else [],
                          (row[0] or "").strip(), "OFAC"))
    return out


def _col(header: list[str], *needles: str):
    """Index of the first header column whose name contains any needle (ci)."""
    low = [(h or "").lower() for h in header]
    for i, h in enumerate(low):
        if any(n in h for n in needles):
            return i
    return None


def _parse_eu(text: str) -> list[dict]:
    """EU FSF CSV (semicolon-delimited). One row per name/alias; grouped by the
    EU reference number. Columns are matched by name to tolerate layout drift."""
    reader = csv.reader(io.StringIO(text), delimiter=";")
    rows = list(reader)
    if not rows:
        return []
    header = rows[0]
    i_name = _col(header, "wholename", "name_wholename", "namealias_wholename")
    i_ref = _col(header, "referencenumber", "logicalid", "entity_logical")
    i_type = _col(header, "subjecttype", "type")
    i_prog = _col(header, "regulation", "programme", "program")
    if i_name is None:
        return []
    grouped: dict[str, dict] = {}
    for r in rows[1:]:
        if i_name >= len(r):
            continue
        nm = (r[i_name] or "").strip()
        if not nm:
            continue
        ref = (r[i_ref].strip() if i_ref is not None and i_ref < len(r) else "") or nm
        g = grouped.get(ref)
        if g is None:
            etype = (r[i_type].strip().lower() if i_type is not None and i_type < len(r) else "")
            etype = "person" if etype.startswith("person") else ("entity" if etype else "")
            prog = (r[i_prog].strip() if i_prog is not None and i_prog < len(r) else "")
            grouped[ref] = _entry(nm, [], etype, [prog] if prog else [], ref, "EU")
        else:
            g["aliases"].append(nm)
    return list(grouped.values())


def _parse_uk(text: str) -> list[dict]:
    """UK UKSL CSV. A title line may precede the header. The full name is split
    across ``Name 1``…``Name 6`` columns; rows share a Group ID for aliases."""
    rows = list(csv.reader(io.StringIO(text)))
    # Find the header row (the one mentioning a Name column or Group Type).
    hidx = next((i for i, r in enumerate(rows)
                 if any("name 1" in (c or "").lower() or "group type" in (c or "").lower()
                        or "individual, entity" in (c or "").lower() for c in r)), None)
    if hidx is None:
        return []
    header = rows[hidx]
    name_cols = [i for i, h in enumerate(header)
                 if re.match(r"\s*name\s*[1-6]\s*$", (h or "").lower())]
    i_group = _col(header, "group id", "groupid")
    i_type = _col(header, "group type", "individual, entity", "entity, ship")
    i_regime = _col(header, "regime", "programme")
    if not name_cols:
        return []
    grouped: dict[str, dict] = {}
    for r in rows[hidx + 1:]:
        parts = [(r[i].strip() if i < len(r) else "") for i in name_cols]
        nm = " ".join(p for p in parts if p).strip()
        if not nm:
            continue
        gid = (r[i_group].strip() if i_group is not None and i_group < len(r) else "") or nm
        g = grouped.get(gid)
        if g is None:
            t = (r[i_type].strip().lower() if i_type is not None and i_type < len(r) else "")
            etype = "person" if t.startswith("individual") else ("entity" if t else "")
            reg = (r[i_regime].strip() if i_regime is not None and i_regime < len(r) else "")
            grouped[gid] = _entry(nm, [], etype, [reg] if reg else [], gid, "UK")
        else:
            g["aliases"].append(nm)
    return list(grouped.values())


_PARSERS = {"OFAC": _parse_ofac, "EU": _parse_eu, "UK": _parse_uk}

# ── Fetch + in-process parsed-list cache ───────────────────────────────────
_LIST_CACHE: dict[str, tuple[float, list[dict]]] = {}


async def _fetch_text(url: str, headers=None) -> str:
    h = {"User-Agent": UA}  # OFAC rejects an empty UA with 403
    if headers:
        h.update(headers)
    try:
        async with httpx.AsyncClient(timeout=_FETCH_TIMEOUT, follow_redirects=True) as c:
            r = await c.get(url, headers=h)
            return r.text if r.status_code == 200 else ""
    except Exception:
        return ""


async def _entries(list_name: str) -> list[dict]:
    now = time.time()
    cached = _LIST_CACHE.get(list_name)
    if cached and now - cached[0] < _LIST_TTL:
        return cached[1]
    url, headers = _URLS[list_name]
    text = await _fetch_text(url, headers)
    entries = _PARSERS[list_name](text) if text else []
    if entries:  # don't cache an empty (failed) fetch
        _LIST_CACHE[list_name] = (now, entries)
    return entries


def _match_entry(nq: str, qtok: set, e: dict):
    """Best score across the entry's primary name + aliases, with what matched."""
    best, matched = _score(nq, qtok, e["name"]), e["name"]
    for a in e["aliases"]:
        s = _score(nq, qtok, a)
        if s > best:
            best, matched = s, a
    return best, matched


async def screen(query: str, lists: list[str] | None = None) -> dict:
    """Screen a name against the consolidated sanctions lists. Returns scored
    candidate hits for human review — not an automated determination."""
    q = (query or "").strip()
    if not q:
        return {"query": query, "error": "empty query", "hits": [], "hit_count": 0}
    targets = [l for l in (lists or ["OFAC", "EU", "UK"]) if l in _PARSERS]
    nq = _normalize(q)
    qtok = set(nq.split())
    if not qtok:
        return {"query": q, "hits": [], "hit_count": 0, "lists_checked": [],
                "note": "query normalised to empty (only punctuation/suffixes)"}
    hits, checked, counts, errors = [], [], {}, []
    for ln in targets:
        ents = await _entries(ln)
        checked.append(ln)
        counts[ln] = len(ents)
        if not ents:
            errors.append(ln)
            continue
        for e in ents:
            score, matched = _match_entry(nq, qtok, e)
            if score >= _SCORE_THRESHOLD:
                hits.append({"name": e["name"], "matched_on": matched,
                             "list": e["list"], "type": e["type"],
                             "programs": e["programs"], "ref": e["ref"],
                             "score": score})
    hits.sort(key=lambda h: h["score"], reverse=True)
    out = {"query": q, "hits": hits[:_MAX_HITS], "hit_count": len(hits),
           "lists_checked": checked, "list_sizes": counts,
           "sanctioned": bool(hits),
           "disclaimer": ("Candidate matches for human review — verify against "
                          "the official list; not an automated determination.")}
    if errors:
        out["lists_unavailable"] = errors
    return out


async def screen_batch(names: list[str], lists: list[str] | None = None) -> dict:
    """Screen many names in one call (the lists are fetched/parsed once and
    reused from the in-process cache across all names). Returns per-name results
    + a flagged shortlist. Avoids the 1-call-per-node fan-out that blew the DD
    budget (2026-06-19 retro: 51 single sanctions_screen pivots)."""
    uniq = list(dict.fromkeys((n or "").strip() for n in (names or [])))
    uniq = [n for n in uniq if n][:200]
    if not uniq:
        return {"queries": 0, "results": [], "flagged": [], "any_hit": False,
                "error": "no names"}
    results = []
    for nm in uniq:
        r = await screen(nm, lists)
        results.append({"name": nm, "hits": r.get("hits", []),
                        "hit_count": r.get("hit_count", 0)})
    flagged = [r["name"] for r in results if r["hit_count"]]
    return {
        "queries": len(uniq),
        "any_hit": bool(flagged),
        "flagged": flagged,
        "results": results,
        "disclaimer": ("Candidate matches for human review — verify against the "
                       "official list; not an automated determination."),
    }
