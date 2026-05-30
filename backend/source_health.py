"""Source-health cache: short-lived flags marking a CTI source as
non-functional for this run.

Some sources return *systemic* failures that won't change on retry inside
this investigation window — an expired/invalid API token, a "Zero Account
Balance" wallet, a daily quota exhausted on a free tier. Per-call rediscovery
of these costs the agent real budget on every node and pollutes
``gaps_report`` with noise.

This module lets a source mark itself dead once, persisted in the existing
``cache`` table (so both the cti_mcp and graph_mcp processes see it), with a
short TTL (default 1h) so the cache self-heals after the operator fixes the
key without requiring a restart. Auto-enqueue checks the cache and parks
pivots needing a dead source as ``skipped(skip_reason='source_dead:<status>')``
instead of pending — visible in ``gaps_report`` rather than silently failing
per-node.
"""
from __future__ import annotations

import time
from typing import Optional

from . import graph_store as gs

# Per-status TTL (seconds). Keep short — operator may fix the key any moment.
_TTL = {
    "auth_required": 3600,        # 1h: token reset/expired/invalid
    "tier_restricted": 1800,      # 30 min: paid-feature gated free key
    "quota_exhausted": 14400,     # 4h: daily/monthly limit blown
    "zero_balance": 7200,         # 2h: prepaid wallet drained
    "default": 1800,
}


def _key(source: str) -> str:
    return f"source_health|{source}"


def mark_dead(source: str, status: str, reason: str = "") -> None:
    """Record that ``source`` is non-functional for this run with ``status``
    (e.g. 'auth_required'). Idempotent — overwrites the previous mark."""
    gs.cache_set(_key(source), {
        "source": source,
        "status": status,
        "reason": (reason or "")[:300],
        "since": time.time(),
    })


def is_dead(source: str) -> Optional[dict]:
    """Return the dead-status dict if the source is currently marked dead,
    else None. TTL is enforced via the per-status table above."""
    ttl = _TTL.get("default", 1800)
    # Try each status's TTL, longest first — cache_get returns None if expired.
    # We don't know the status until we read, so use the longest TTL as the
    # outer bound; the recorded status's TTL is checked after.
    rec = gs.cache_get(_key(source), ttl=max(_TTL.values()))
    if not rec:
        return None
    status = rec.get("status")
    age = time.time() - float(rec.get("since") or 0)
    if age > _TTL.get(status, ttl):
        return None
    return rec


def clear(source: str) -> None:
    """Wipe a source's dead flag (e.g. after a manual key refresh)."""
    gs.cache_set(_key(source), None)


def snapshot() -> dict:
    """Return {source: dead_status_dict} for every currently-dead source.
    Used by next_pivot to expose state to the agent. Iterates known sources
    rather than scanning the cache table."""
    out: dict = {}
    for src in ("opencti", "shodan", "whoxy", "criminalip", "emailrep",
                "censys", "netlas", "zoomeye", "abuseipdb", "certspotter",
                "vt", "otx", "onyphe", "pulsedive", "leakix", "dnsdumpster",
                "abusech"):
        d = is_dead(src)
        if d:
            out[src] = d
    return out
