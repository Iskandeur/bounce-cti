"""CIRCL Luxembourg — two free, no-auth services we tap:

  - **hashlookup** (https://hashlookup.circl.lu/) — fast lookup of MD5 /
    SHA-1 / SHA-256 against the NIST NSRL + a few other "known-good"
    corpora. A hit means the file is a legitimate OS/vendor artefact and
    the hash node can be defused as ``nsrl_known`` (or as ``known_good``
    for non-NSRL sources).

  - **vulnerability-lookup** (https://vulnerability.circl.lu/) — CVE,
    CPE and product browser. Useful for translating a banner like
    ``Apache 2.4.49`` into an active CVE list when correlating with Shodan
    / Censys results.
"""
from __future__ import annotations

import re

from .http_client import get_json, post_json

_HASH_BASE = "https://hashlookup.circl.lu"
_VULN_BASE = "https://vulnerability.circl.lu/api"


def _hash_kind(value: str) -> str | None:
    v = value.strip().lower()
    if re.fullmatch(r"[0-9a-f]{32}", v):
        return "md5"
    if re.fullmatch(r"[0-9a-f]{40}", v):
        return "sha1"
    if re.fullmatch(r"[0-9a-f]{64}", v):
        return "sha256"
    return None


async def hash_lookup(value: str) -> dict:
    """Single-hash lookup. Auto-detects MD5/SHA-1/SHA-256. Returns the raw
    CIRCL record (which includes ``source`` and ``db`` — typically
    ``"NSRL"`` / ``"nsrl_modern_rds"`` for OS files), or ``{"found": false}``
    on a miss (CIRCL returns a 404 with a JSON body in that case)."""
    kind = _hash_kind(value)
    if not kind:
        return {"error": f"value is not an md5/sha1/sha256 hex digest: {value!r}"}
    cache_key = f"circl|hash|{kind}|{value.lower()}"
    data = await get_json(f"{_HASH_BASE}/lookup/{kind}/{value}",
                            headers={"Accept": "application/json"},
                            ttl=86400, cache_key=cache_key)
    # CIRCL signals "miss" via {"message": "Non existing ..."} 404 body.
    if isinstance(data, dict) and data.get("message", "").lower().startswith("non existing"):
        return {"found": False, "value": value, "kind": kind}
    if isinstance(data, dict):
        data.setdefault("found", True)
    return data


async def hash_lookup_bulk(values: list[str]) -> dict:
    """Bulk lookup. Splits by hash kind and posts one request per kind."""
    by_kind: dict[str, list[str]] = {"md5": [], "sha1": [], "sha256": []}
    bad: list[str] = []
    for v in values:
        k = _hash_kind(v)
        if k:
            by_kind[k].append(v.upper())
        else:
            bad.append(v)
    out: dict[str, list] = {"md5": [], "sha1": [], "sha256": [], "invalid": bad}
    for kind, hashes in by_kind.items():
        if not hashes:
            continue
        cache_key = f"circl|hash|bulk|{kind}|{','.join(sorted(hashes))[:200]}"
        data = await post_json(f"{_HASH_BASE}/bulk/{kind}",
                                 headers={"Accept": "application/json"},
                                 json_body={"hashes": hashes},
                                 ttl=86400, cache_key=cache_key)
        if isinstance(data, list):
            out[kind] = data
        else:
            out[kind] = [data]
    return out


async def cve(cve_id: str) -> dict:
    """Full CVE record (CIRCL aggregates NVD + CAPEC + CWE + CPE)."""
    cache_key = f"circl|cve|{cve_id.upper()}"
    return await get_json(f"{_VULN_BASE}/cve/{cve_id}", ttl=86400,
                           cache_key=cache_key)


async def vendor_product_search(vendor: str, product: str) -> dict:
    """All CVEs for a vendor/product combo (e.g. ``microsoft`` / ``office``)."""
    cache_key = f"circl|vp|{vendor}|{product}"
    return await get_json(f"{_VULN_BASE}/search/{vendor}/{product}",
                           ttl=86400, cache_key=cache_key)
