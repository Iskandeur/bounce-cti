"""Pulsedive — risk-scored IOC enrichment.

Free tier: 500 requests / month (plus 100 bulk-scans + 100 submissions).
Authoritative URL: https://pulsedive.com/api/. We use three endpoints:

  - ``/api/info.php?indicator=<value>``   — look up an existing indicator
  - ``/api/analyze.php?value=<value>``    — on-demand scan (does NOT persist
                                            in the public DB if `probe=0`)
  - ``/api/explore.php?q=<lucene>``       — broad search (uses the most
                                            credit; reserve for actor pivots)

The risk score (``risk: high|medium|low|unknown``) is a useful "second
opinion" alongside VT/OTX, and the ``threats`` array surfaces malware-family
labels with attribution context."""
from __future__ import annotations

from .. import key_pool
from .http_client import get_json

_BASE = "https://pulsedive.com/api"


def _key_or_error() -> tuple[str | None, dict]:
    key = key_pool.acquire("pulsedive")
    if not key:
        return None, {"error": "no Pulsedive key configured or all keys exhausted"}
    return key, {}


async def indicator(value: str) -> dict:
    """Pre-existing indicator record (no scan triggered)."""
    key, err = _key_or_error()
    if err:
        return err
    params = {"indicator": value, "pretty": "1", "key": key}
    cache_key = f"pulsedive|info|{value}"
    return await get_json(f"{_BASE}/info.php", params=params,
                           ttl=3600, cache_key=cache_key)


async def analyze(value: str, probe: bool = False) -> dict:
    """On-demand scan. ``probe=False`` returns a cached/quick verdict and
    costs 1 request; ``probe=True`` schedules an active scan (costs a bulk
    credit). Defaults to ``probe=False`` to preserve quota."""
    key, err = _key_or_error()
    if err:
        return err
    params = {"value": value, "probe": "1" if probe else "0", "pretty": "1",
                "key": key}
    cache_key = f"pulsedive|analyze|{probe}|{value}"
    return await get_json(f"{_BASE}/analyze.php", params=params,
                           ttl=1800, cache_key=cache_key)


async def explore(query: str, limit: int = 25) -> dict:
    """Lucene-style search across the Pulsedive index. Use sparingly —
    consumes one request per page. Useful for pivoting on a threat name
    (``threat=mintsloader``) or a registrant org (``registrant.org=Acme``)."""
    key, err = _key_or_error()
    if err:
        return err
    params = {"q": query, "limit": str(limit), "pretty": "1", "key": key}
    cache_key = f"pulsedive|explore|{limit}|{query}"
    return await get_json(f"{_BASE}/explore.php", params=params,
                           ttl=3600, cache_key=cache_key)


async def threat(name: str) -> dict:
    """Look up a known threat (malware family / actor / campaign) by name.
    Returns the threat profile + linked indicators."""
    key, err = _key_or_error()
    if err:
        return err
    params = {"threat": name, "pretty": "1", "key": key}
    cache_key = f"pulsedive|threat|{name}"
    return await get_json(f"{_BASE}/threat.php", params=params,
                           ttl=86400, cache_key=cache_key)
