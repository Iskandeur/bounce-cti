"""OpenCTI — GraphQL client for community CTI knowledge graph.

Hits a single endpoint (`$OPENCTI_URL/graphql`) with a bearer token. Demo
instance at https://demo.opencti.io exposes curated OSINT: malware-family
labels, threat-actor / intrusion-set attribution, linked report titles,
YARA bodies, and MITRE ATT&CK relationships. Coverage is sparse — many
"normal" IOCs return empty — so we treat it as best-effort enrichment.

Three tools:
  - lookup_indicator(value)   exact-match IOC → relationships walk
  - search_intrusion_set(name) actor lookup (fuzzy)
  - search_report(name)        report context (fuzzy)

Auth: `Authorization: Bearer <token>`. Demo rate limit is a 10k sliding
window — we share the key_pool cooldown machinery anyway so a 429 or a
forbidden response parks the key for 60s instead of retrying in a hot loop.
"""
from __future__ import annotations

import httpx

from .. import key_pool
from ..config import OPENCTI_URL
from ..graph_store import cache_get, cache_set
from .http_client import UA


# ── Internal: one POST, key-pool aware, with caching ─────────────────────
async def _gql(query: str, variables: dict, cache_key: str, ttl: float = 3600) -> dict:
    """POST a GraphQL query. Cache on cache_key. Returns the response body
    (with `data` and optionally `errors`). On HTTP/auth failure returns
    `{"error": ...}` so callers can degrade gracefully."""
    cached = cache_get(cache_key, ttl=ttl)
    if cached is not None:
        return cached

    api_key = key_pool.acquire("opencti")
    if not api_key:
        return {"error": "no OpenCTI key configured or all keys exhausted"}

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "User-Agent": UA,
    }
    url = f"{OPENCTI_URL}/graphql"
    try:
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.post(url, headers=headers,
                              json={"query": query, "variables": variables})
    except httpx.HTTPError as e:
        return {"error": f"opencti transport error: {e.__class__.__name__}: {str(e)[:200]}"}

    # 429 / 5xx: park the key briefly and surface the failure so the agent
    # can move on instead of looping.
    if r.status_code == 429:
        key_pool.mark_rate_limited("opencti", api_key, cooldown_seconds=120)
        return {"error": "opencti rate-limited (HTTP 429)"}
    if r.status_code >= 500:
        key_pool.mark_rate_limited("opencti", api_key, cooldown_seconds=60)
        return {"error": f"opencti server error (HTTP {r.status_code})"}

    try:
        data = r.json()
    except Exception:
        return {"error": f"opencti non-JSON response (HTTP {r.status_code})"}

    # OpenCTI returns 200 + `errors[]` for auth failures (AUTH_REQUIRED, http_status=401).
    # Surface those instead of silently returning `null` data.
    errs = data.get("errors") if isinstance(data, dict) else None
    if errs:
        codes = [e.get("extensions", {}).get("code") for e in errs if isinstance(e, dict)]
        if "AUTH_REQUIRED" in codes or "FORBIDDEN" in codes:
            # Bad token — long cooldown so we don't burn the same call repeatedly.
            key_pool.mark_rate_limited("opencti", api_key, cooldown_seconds=600)
            # Cross-process: mark OpenCTI dead so graph_mcp skips
            # `opencti_lookup_indicator` at enqueue time on subsequent nodes
            # instead of re-discovering the auth failure per node.
            try:
                from .. import source_health
                source_health.mark_dead(
                    "opencti", "auth_required",
                    reason="GraphQL AUTH_REQUIRED — token expired/invalid; refresh OPENCTI_API_KEY",
                )
            except Exception:
                pass
            return {"error": "opencti auth failed (check OPENCTI_API_KEY)",
                    "errors": errs[:3]}
        # Other GraphQL errors are kept in-band so the caller can inspect.
        return {"error": "opencti graphql error", "errors": errs[:3]}

    cache_set(cache_key, data)
    return data


# ── Slimming: trim verbose GraphQL responses for the agent ───────────────
def _labels(node: dict) -> list[str]:
    """Pull `objectLabel[].value` out into a flat list. Filters UUID-shaped
    labels (some OpenCTI deployments emit those as side-effects of stub
    entities and they're never analyst-useful)."""
    raw = node.get("objectLabel") or []
    out: list[str] = []
    for lbl in raw:
        v = (lbl or {}).get("value") or ""
        if not v:
            continue
        # 36-char UUID with 4 hyphens — skip.
        if len(v) == 36 and v.count("-") == 4:
            continue
        out.append(v)
    return out


def _slim_relationships(rels: dict | None, limit: int = 20) -> list[dict]:
    """Walk `stixCoreRelationships.edges[].node` and surface only the
    attribution-bearing targets (Malware, IntrusionSet, ThreatActor,
    Campaign, AttackPattern, Tool, Vulnerability). Drop `based-on` to
    StixFile / Domain-Name / IPv4-Addr observables (those are just the
    pattern→observable link, not attribution)."""
    if not rels:
        return []
    out: list[dict] = []
    KEEP_TYPES = {"Malware", "Intrusion-Set", "Threat-Actor",
                  "Campaign", "Attack-Pattern", "Tool", "Vulnerability"}
    for edge in (rels.get("edges") or [])[:limit * 3]:
        n = (edge or {}).get("node") or {}
        to = n.get("to") or {}
        et = to.get("entity_type") or ""
        if et not in KEEP_TYPES:
            continue
        item = {
            "relation": n.get("relationship_type"),
            "entity_type": et,
            "name": to.get("name"),
        }
        # Aliases are useful for threat-actor name normalisation.
        aliases = to.get("aliases")
        if aliases:
            item["aliases"] = aliases[:8]
        mid = to.get("x_mitre_id")
        if mid:
            item["mitre_id"] = mid
        out.append(item)
        if len(out) >= limit:
            break
    return out


def _slim_reports(reports: dict | None, limit: int = 5) -> list[dict]:
    if not reports:
        return []
    out: list[dict] = []
    for edge in (reports.get("edges") or [])[:limit]:
        n = (edge or {}).get("node") or {}
        name = n.get("name")
        if not name:
            continue
        item = {"name": name}
        if n.get("published"):
            item["published"] = n["published"]
        out.append(item)
    return out


# ── Queries ───────────────────────────────────────────────────────────────
_Q_INDICATOR_LOOKUP = """
query($q: [Any!]!) {
  indicators(
    filters: {mode: and, filters: [{key: "name", values: $q, operator: eq, mode: or}], filterGroups: []},
    first: 3
  ) {
    edges { node {
      id name pattern pattern_type
      x_opencti_score confidence
      valid_from valid_until revoked
      objectLabel { value }
      createdBy { ... on Identity { name } }
      stixCoreRelationships(first: 30) {
        edges { node {
          relationship_type confidence start_time
          to {
            ... on BasicObject { id entity_type }
            ... on Malware { name aliases }
            ... on IntrusionSet { name aliases }
            ... on Campaign { name }
            ... on ThreatActor { name aliases }
            ... on AttackPattern { name x_mitre_id }
            ... on Tool { name }
            ... on Vulnerability { name }
          }
        } }
      }
      reports(first: 5) { edges { node { name published } } }
    } }
  }
}
"""

_Q_OBSERVABLE_LOOKUP = """
query($q: [Any!]!) {
  stixCyberObservables(
    filters: {mode: and, filters: [{key: "value", values: $q, operator: eq, mode: or}], filterGroups: []},
    first: 3
  ) {
    edges { node {
      id entity_type observable_value
      x_opencti_score
      objectLabel { value }
      indicators(first: 1) { edges { node { id name } } }
      reports(first: 5) { edges { node { name published } } }
    } }
  }
}
"""

_Q_INTRUSION_SET = """
query($q: String) {
  intrusionSets(search: $q, first: 5) {
    edges { node {
      id name aliases description
      first_seen last_seen
      objectLabel { value }
    } }
  }
}
"""

_Q_REPORT_SEARCH = """
query($q: String) {
  reports(search: $q, first: 5) {
    edges { node {
      id name published description
      objectLabel { value }
      externalReferences { edges { node { source_name url } } }
    } }
  }
}
"""


# ── Public source functions (called from cti_mcp.py) ─────────────────────
async def lookup_indicator(value: str) -> dict:
    """Exact-match indicator lookup + relationship walk.

    Returns:
      {"hit": bool, "indicators": [{name, pattern, score, labels,
                                    relationships:[{relation,entity_type,name,...}],
                                    reports:[{name,published}]}],
       "observable"?: {entity_type, value, score, labels, reports}}

    When the value is stored only as an observable (not yet promoted to an
    Indicator) we still surface the observable record so the caller sees
    labels + linked reports.
    """
    val = (value or "").strip()
    if not val:
        return {"error": "empty value"}
    ind_key = f"opencti|indicator|{val.lower()}"
    obs_key = f"opencti|observable|{val.lower()}"

    ind_resp = await _gql(_Q_INDICATOR_LOOKUP, {"q": [val]}, ind_key)
    if "error" in ind_resp and "data" not in ind_resp:
        return ind_resp

    indicators: list[dict] = []
    for edge in ((ind_resp.get("data") or {}).get("indicators") or {}).get("edges", []):
        n = (edge or {}).get("node") or {}
        if not n:
            continue
        indicators.append({
            "id": n.get("id"),
            "name": n.get("name"),
            "pattern": n.get("pattern"),
            "pattern_type": n.get("pattern_type"),
            "score": n.get("x_opencti_score"),
            "confidence": n.get("confidence"),
            "valid_from": n.get("valid_from"),
            "valid_until": n.get("valid_until"),
            "revoked": n.get("revoked"),
            "labels": _labels(n),
            "created_by": (n.get("createdBy") or {}).get("name"),
            "relationships": _slim_relationships(n.get("stixCoreRelationships")),
            "reports": _slim_reports(n.get("reports")),
        })

    out: dict = {"hit": bool(indicators), "indicators": indicators}

    # Always try the observable lookup too — useful when the value is stored
    # as a Domain-Name / IPv4-Addr / StixFile without a promoted Indicator,
    # AND complementary when both exist (observable score sometimes differs).
    obs_resp = await _gql(_Q_OBSERVABLE_LOOKUP, {"q": [val]}, obs_key)
    if isinstance(obs_resp, dict) and "data" in obs_resp:
        obs_edges = ((obs_resp.get("data") or {}).get("stixCyberObservables") or {}).get("edges", [])
        if obs_edges:
            n = (obs_edges[0] or {}).get("node") or {}
            if n:
                out["observable"] = {
                    "entity_type": n.get("entity_type"),
                    "value": n.get("observable_value"),
                    "score": n.get("x_opencti_score"),
                    "labels": _labels(n),
                    "reports": _slim_reports(n.get("reports")),
                }
                if not indicators:
                    out["hit"] = True

    return out


async def search_intrusion_set(name: str) -> dict:
    """Fuzzy actor / intrusion-set lookup. Use when a relationships walk
    surfaces a named actor and you want descriptions + alias list for
    cross-referencing."""
    q = (name or "").strip()
    if not q:
        return {"error": "empty name"}
    cache_key = f"opencti|intrusionset|{q.lower()}"
    resp = await _gql(_Q_INTRUSION_SET, {"q": q}, cache_key, ttl=86400)
    if "error" in resp and "data" not in resp:
        return resp
    out = []
    for edge in ((resp.get("data") or {}).get("intrusionSets") or {}).get("edges", []):
        n = (edge or {}).get("node") or {}
        if not n.get("name"):
            continue
        out.append({
            "name": n.get("name"),
            "aliases": (n.get("aliases") or [])[:12],
            "description": (n.get("description") or "")[:600],
            "first_seen": n.get("first_seen"),
            "last_seen": n.get("last_seen"),
            "labels": _labels(n),
        })
    return {"hit": bool(out), "intrusion_sets": out}


async def search_report(name: str) -> dict:
    """Fuzzy report lookup. Use when a relationships walk surfaces a report
    title (e.g. "OSINT - NSO related domains") and you want the description
    + external references for the underlying analysis."""
    q = (name or "").strip()
    if not q:
        return {"error": "empty name"}
    cache_key = f"opencti|report|{q.lower()}"
    resp = await _gql(_Q_REPORT_SEARCH, {"q": q}, cache_key, ttl=86400)
    if "error" in resp and "data" not in resp:
        return resp
    out = []
    for edge in ((resp.get("data") or {}).get("reports") or {}).get("edges", []):
        n = (edge or {}).get("node") or {}
        if not n.get("name"):
            continue
        refs = []
        for re_edge in ((n.get("externalReferences") or {}).get("edges") or [])[:5]:
            rn = (re_edge or {}).get("node") or {}
            url = rn.get("url")
            if url:
                refs.append({"source": rn.get("source_name"), "url": url})
        out.append({
            "name": n.get("name"),
            "published": n.get("published"),
            "description": (n.get("description") or "")[:600],
            "labels": _labels(n),
            "external_references": refs,
        })
    return {"hit": bool(out), "reports": out}
