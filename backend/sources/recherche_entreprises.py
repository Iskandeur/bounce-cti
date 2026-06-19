"""French company registry — API Recherche d'entreprises (DD pool).

DINUM/Etalab's "Recherche d'entreprises" API aggregates INSEE Sirene + INPI RNE.
**Free, no key, no auth**, data under the **Licence Ouverte 2.0** (commercial use
+ redistribution OK; attribution: source INSEE/INPI + update date). Non-diffusible
companies are already excluded by the API; `statut_diffusion = "P"` marks partial
diffusion — we pass through whatever the API returns and never re-complete masked
fields.

Resolves a French company by **name or SIREN** to its identity (SIREN, legal
name, status, legal form, activity, creation date, registered address) and its
**dirigeants** (officers) — which become `person` nodes the agent sanctions-
screens, closing the KYB loop for FR like Companies House does for the UK.

⚠️ Officer personal data is still GDPR-regulated (the DD prompt keeps usage
factual, no adverse-media); ownership stays ESTIMATED, never authoritative UBO.
"""
from __future__ import annotations

import re

from .http_client import get_json

_API = "https://recherche-entreprises.api.gouv.fr/search"
_TTL = 86400
_SIREN_RE = re.compile(r"^\d{9}$")
_SIRET_RE = re.compile(r"^\d{14}$")


def _addr(siege: dict) -> str | None:
    if not isinstance(siege, dict):
        return None
    geo = siege.get("geo_adresse") or siege.get("adresse")
    if geo:
        return geo
    parts = [siege.get("numero_voie"), siege.get("type_voie"), siege.get("libelle_voie"),
             siege.get("code_postal"), siege.get("libelle_commune")]
    return " ".join(str(p) for p in parts if p) or None


def _parse_dirigeant(d: dict) -> dict:
    """A dirigeant may be a natural person or a legal entity (personne morale)."""
    if not isinstance(d, dict):
        return {}
    is_person = (d.get("type_dirigeant") or "").lower().startswith("personne phys") \
        or bool(d.get("nom") or d.get("prenoms"))
    if is_person:
        name = " ".join(p for p in [d.get("prenoms"), d.get("nom")] if p).strip()
    else:
        name = d.get("denomination") or d.get("nom") or ""
    dob = d.get("date_de_naissance") or d.get("annee_de_naissance")
    return {
        "name": name,
        "kind": "person" if is_person else "company",
        "role": d.get("qualite"),
        "nationality": d.get("nationalite"),
        "dob": dob,  # API exposes month/year (or year) only
    }


def _parse_company(r: dict) -> dict:
    siege = r.get("siege") or {}
    dirs = [_parse_dirigeant(d) for d in (r.get("dirigeants") or [])]
    return {
        "siren": r.get("siren"),
        "name": r.get("nom_complet") or r.get("nom_raison_sociale"),
        "status": r.get("etat_administratif"),
        "legal_form": r.get("nature_juridique"),
        "activity": r.get("activite_principale"),
        "created": r.get("date_creation"),
        "employees": r.get("tranche_effectif_salarie"),
        "diffusion_status": r.get("statut_diffusion"),
        "address": _addr(siege),
        "dirigeants": [d for d in dirs if d.get("name")][:25],
    }


async def lookup(query: str) -> dict:
    """Resolve a French company by name or SIREN via Recherche d'entreprises."""
    q = (query or "").strip()
    if not q:
        return {"query": query, "found": False, "error": "empty query"}
    term = q.replace(" ", "") if (_SIREN_RE.match(q.replace(" ", ""))
                                  or _SIRET_RE.match(q.replace(" ", ""))) else q
    res = await get_json(_API, params={"q": term, "per_page": "10"}, ttl=_TTL,
                         cache_key=f"recherche_entreprises|{term.lower()}")
    if not isinstance(res, dict) or res.get("_status"):
        return {"query": q, "found": False, "source": "recherche_entreprises",
                "error": "API unavailable"}
    results = res.get("results") or []
    matches = [_parse_company(r) for r in results]
    return {"query": q, "found": bool(matches),
            "match_count": res.get("total_results", len(matches)),
            "matches": matches,
            "source": "recherche_entreprises (Licence Ouverte 2.0; INSEE/INPI)"}
