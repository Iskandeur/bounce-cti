"""Shodan — free-first client with an explicit credit guard.

## Why this module is shaped the way it is

A Shodan **Membership** (one-time payment, `plan: "dev"` on `/api-info`) grants
**100 query credits and 100 scan credits per month**. They reset at the start of
the month and rollover is not documented, so treat them as a hard monthly
allowance shared by every investigation on the instance.

The important, counter-intuitive fact: **almost the whole useful API is free.**

| Endpoint                        | Credit cost | Exposed here                |
|---------------------------------|-------------|-----------------------------|
| `/shodan/host/{ip}`             | **0**       | ``host`` — full record      |
| `/shodan/host/count`            | **0**       | ``host_count`` — + facets   |
| `/dns/resolve`, `/dns/reverse`  | **0**       | ``dns_resolve``/``reverse`` |
| `/api-info`                     | **0**       | ``api_info``                |
| `/shodan/host/search`           | **1 / 100 results** | ``search`` — **guarded** |
| `/shodan/scan`                  | 1 scan credit/IP | **not exposed** (see below) |

`/shodan/host/search` bills 1 query credit per page of 100 results, and only
when the query carries a **filter** (`ssl.jarm:`, `asn:`, `http.favicon.hash:`…)
or you page past the first page. Every high-signal CTI pivot is filtered, so in
practice every useful search costs a credit.

Therefore the credit-consuming path is **off by default**: ``search`` refuses
before making any HTTP request and names the free alternatives. An operator
opts in with ``BOUNCE_SHODAN_ALLOW_CREDITS=1`` and can cap spend with
``BOUNCE_SHODAN_CREDIT_BUDGET=N``.

``/shodan/scan`` is deliberately **not implemented**: it spends scan credits and
*actively touches the target*, which would break the platform's passive-only
posture. Network Alerts are likewise out of scope — they mutate the account's
persistent monitoring state, which an autonomous investigation agent has no
business doing.

## Two upstream traps this module handles

1. **Rate-limit errors arrive as HTTP 200.** Shodan answers an over-rate request
   with ``{"error": "Rate limit reached..."}`` and a 200 status, so a naive
   caller caches an error as data and reads ``query_credits`` as ``None``.
   ``_unwrap`` detects the error-in-200 and never caches it.
2. **The 1 req/s limit bites for real.** Calls are serialised through an async
   limiter spacing them ~1.5s apart (per process).
"""
from __future__ import annotations

import asyncio
import re
import time

import httpx

from .. import key_pool, source_health
from ..config import shodan_credit_budget, shodan_credits_allowed
from ..graph_store import cache_get, cache_set
from .http_client import UA

_BASE = "https://api.shodan.io"
_TTL = 3600

# Shodan documents 1 request/second. Space a little wider — the limiter is
# per-process and the published limit is enforced strictly.
_MIN_INTERVAL = 1.5
_rate_lock = asyncio.Lock()
_last_call: float = 0.0

# Credits actually spent by this process (search calls only). Best-effort
# in-process accounting used to enforce BOUNCE_SHODAN_CREDIT_BUDGET.
_credits_spent = 0


# ── credit policy ──────────────────────────────────────────────────────────

# A Shodan search filter is `name:value`, where name is dotted/underscored and
# may be mixed-case (`ssl.cert.subject.CN:`). Anything matching means the query
# would be billed. Deliberately biased toward false positives: mis-reading a
# free query as billable only costs us a refusal, while the reverse spends a
# credit we were told not to spend.
_FILTER_RE = re.compile(r'(?:^|\s)(?!https?:)([A-Za-z][\w.]*):')


def query_is_filtered(query: str) -> bool:
    """True if this query would consume a query credit (it carries a filter).

    A keyword-only query on page 1 is free; anything with a `name:value` filter
    bills 1 credit per 100 results.
    """
    return bool(_FILTER_RE.search(query or ""))


def credit_policy() -> dict:
    """Current credit-spending policy, for surfacing to the agent/operator."""
    allowed, budget = shodan_credits_allowed(), shodan_credit_budget()
    remaining = max(0, budget - _credits_spent) if (allowed and budget > 0) else None
    return {
        "allow_credits": allowed,
        "budget": budget or None,
        "spent_this_process": _credits_spent,
        "budget_remaining": remaining,
    }


def _refuse(query: str, page: int, reason: str) -> dict:
    """Structured refusal for a credit-consuming call we will not make.

    Returned *instead of* an HTTP request, so no credit can be spent. Names the
    free replacements so the agent keeps working rather than stalling.
    """
    return {
        "error": "shodan_credits_disabled",
        "refused": True,
        "query": query,
        "page": page,
        "reason": reason,
        "policy": credit_policy(),
        "free_alternatives": [
            "shodan_host_count(query) — same query, returns the RESULT COUNT and "
            "FACET breakdown (top ASNs/countries/products/ports) for 0 credits. "
            "Enough to size a cluster and decide whether it is worth a credit.",
            "shodan_host(ip) — full per-IP record (ports, banners, vulns), 0 credits.",
            "internetdb_ip(ip) — ports/CPEs/CVEs/hostnames, 0 credits and no key.",
            "netlas_jarm / netlas_favicon / netlas_search — independent scanner DB.",
            "zoomeye_jarm / zoomeye_favicon — third scanner vantage.",
            "urlscan_search('hash:<jarm>') — free-tier JARM/favicon pivots.",
            "crtsh_serial / crtsh_query / certspotter_serial — free certificate pivots.",
        ],
        "_note": "Shodan query credits (100/month, shared across all investigations) "
                 "are reserved. Only /shodan/host/search bills; the free endpoints "
                 "above answer most cluster questions. An operator can enable "
                 "spending with BOUNCE_SHODAN_ALLOW_CREDITS=1.",
    }


# ── transport ──────────────────────────────────────────────────────────────

async def _throttle() -> None:
    """Serialise calls to respect Shodan's 1 req/s limit."""
    global _last_call
    async with _rate_lock:
        delta = time.monotonic() - _last_call
        if delta < _MIN_INTERVAL:
            await asyncio.sleep(_MIN_INTERVAL - delta)
        _last_call = time.monotonic()


def _unwrap(status: int, data) -> tuple[dict, str | None]:
    """Return ``(payload, health_status)``.

    Shodan reports rate limiting and auth failures as an ``error`` key — often
    with **HTTP 200** — so status code alone is not a reliable success signal.
    ``health_status`` is non-None when the failure is systemic enough to mark
    the source dead (so pivots needing it get parked instead of retried).
    """
    if not isinstance(data, dict):
        return {"error": f"unexpected response shape (HTTP {status})"}, None
    err = data.get("error")
    if err:
        low = str(err).lower()
        if "rate limit" in low:
            return {"error": str(err), "_retryable": True}, None
        if "invalid api key" in low or "no api key" in low or "unauthorized" in low:
            return {"error": str(err)}, "auth_required"
        if "membership" in low or "upgrade" in low or "not have permission" in low:
            return {"error": str(err)}, "tier_restricted"
        if "credit" in low:
            return {"error": str(err)}, "quota_exhausted"
        return {"error": str(err)}, None
    if status == 401 or status == 403:
        return {"error": f"HTTP {status}"}, "auth_required"
    if status == 429:
        return {"error": "HTTP 429 rate limited", "_retryable": True}, None
    if status >= 400:
        return {"error": f"HTTP {status}"}, None
    return data, None


async def _get(path: str, params: dict, *, ttl: float = _TTL,
               cache_key: str | None = None) -> dict:
    """Rate-limited, cached GET against the Shodan API.

    Only successful payloads are cached — an error (including a rate-limit
    error delivered as HTTP 200) must never poison the cache for the full TTL.
    """
    key = key_pool.acquire("shodan")
    if not key:
        return {"error": "no Shodan key configured"}

    ck = cache_key or f"shodan|{path}|{sorted(params.items())}"
    cached = cache_get(ck, ttl=ttl)
    if cached is not None:
        return cached

    await _throttle()
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True,
                                     headers={"User-Agent": UA}) as c:
            r = await c.get(f"{_BASE}{path}", params={**params, "key": key})
        try:
            raw = r.json()
        except Exception:
            raw = {"error": f"unparseable response (HTTP {r.status_code})"}
        payload, health = _unwrap(r.status_code, raw)
    except Exception as e:
        return {"error": f"request failed: {str(e)[:200]}"}

    if health:
        source_health.mark_dead("shodan", health, str(payload.get("error", ""))[:200])
    if payload.get("error"):
        if payload.get("_retryable"):
            key_pool.mark_rate_limited("shodan", key, cooldown_seconds=60)
        return payload
    cache_set(ck, payload)
    return payload


# ── free endpoints (0 query credits) ───────────────────────────────────────

async def shodan_host(ip: str) -> dict:
    """Full Shodan record for an IP: open ports, banners, products, vulns, org.

    **Costs 0 query credits** — host lookups are not billed. This is the
    banner-level view; ``internetdb_ip`` is the keyless, no-credit fallback
    when no Shodan key is configured.
    """
    out = await _get(f"/shodan/host/{(ip or '').strip()}", {})
    if isinstance(out, dict) and not out.get("error"):
        out["_cost"] = "free (host lookups do not consume query credits)"
    return out


async def shodan_host_count(query: str, facets: str = "") -> dict:
    """Result count + facet breakdown for a search query. **0 query credits.**

    This is the credit-free way to answer "how big is this cluster, and what is
    in it" — the same query you would pass to ``search``, but returning totals
    and facet aggregations instead of the matching records. Use it to size a
    cluster and decide whether the records themselves are worth a credit.

    ``facets`` is a comma-separated list, e.g. ``"asn,country,org,port"``.
    """
    q = (query or "").strip()
    if not q:
        return {"error": "empty query"}
    params: dict = {"query": q}
    if facets:
        params["facets"] = facets
    out = await _get("/shodan/host/count", params)
    if isinstance(out, dict) and not out.get("error"):
        out["_cost"] = "free (host/count does not consume query credits)"
        out["_note"] = ("Counts and facets only — no host records. If you need the "
                        "individual hosts, they cost 1 query credit per 100 results "
                        "via shodan_search (operator-gated).")
    return out


async def shodan_api_info() -> dict:
    """Plan name and remaining query/scan credits. **0 query credits.**

    Also reports this instance's local credit policy, so the agent can see both
    what the account has and what it is permitted to spend.
    """
    out = await _get("/api-info", {}, ttl=300)
    if isinstance(out, dict) and not out.get("error"):
        # Never trust these to be numbers — a rate-limited response can leave
        # them absent, which silently reads as `None` in arithmetic.
        for field in ("query_credits", "scan_credits"):
            if not isinstance(out.get(field), (int, float)):
                out[field] = None
        out["_cost"] = "free"
    out["local_policy"] = credit_policy()
    return out


async def shodan_dns_resolve(hostnames: str) -> dict:
    """Resolve hostnames to IPs via Shodan's DNS. **0 query credits.**

    ``hostnames`` is comma-separated (bulk in one call, up to ~100).
    """
    hn = (hostnames or "").strip()
    if not hn:
        return {"error": "no hostnames supplied"}
    return await _get("/dns/resolve", {"hostnames": hn})


async def shodan_reverse_dns(ips: str) -> dict:
    """Reverse-resolve IPs to hostnames via Shodan's DNS. **0 query credits.**

    ``ips`` is comma-separated (bulk in one call).
    """
    v = (ips or "").strip()
    if not v:
        return {"error": "no IPs supplied"}
    return await _get("/dns/reverse", {"ips": v})


# ── metered endpoint (query credits) ───────────────────────────────────────

async def shodan_search(query: str, page: int = 1) -> dict:
    """Shodan search. **Consumes 1 query credit per 100 results** when the query
    carries a filter or pages past page 1 — so it is **disabled by default.**

    With credits disabled (the default) this returns a structured refusal
    naming the free alternatives, **without making any HTTP request**, so no
    credit can be spent. Free keyword-only page-1 queries are still executed.
    """
    global _credits_spent
    q = (query or "").strip()
    if not q:
        return {"error": "empty query"}

    billable = query_is_filtered(q) or page > 1
    if billable:
        budget = shodan_credit_budget()
        if not shodan_credits_allowed():
            return _refuse(q, page, "credit spending is disabled "
                                    "(BOUNCE_SHODAN_ALLOW_CREDITS is not set)")
        if budget > 0 and _credits_spent >= budget:
            return _refuse(q, page, f"per-process credit budget exhausted "
                                    f"({_credits_spent}/{budget} spent)")

    params: dict = {"query": q}
    if page > 1:
        params["page"] = page
    out = await _get("/shodan/host/search", params)

    if billable and isinstance(out, dict) and not out.get("error"):
        _credits_spent += 1
        out["_cost"] = f"1 query credit (spent {_credits_spent} this process)"
        out["policy"] = credit_policy()
    elif isinstance(out, dict) and not out.get("error"):
        out["_cost"] = "free (keyword-only query, first page)"
    return out


def reset_for_tests() -> None:
    """Clear in-process credit accounting and rate-limiter state. Test-only."""
    global _credits_spent, _last_call
    _credits_spent = 0
    _last_call = 0.0
