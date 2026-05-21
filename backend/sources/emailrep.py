"""EmailRep.io — reputation for an email address.

Free tier: 10/day (unauthenticated) or 250/month with a key (the key has a
hard cap of 10/day even on paid free). Sourced from breach corpora, mail
hygiene, social media presence.

Useful for grading a registrant email surfaced via RDAP/Whoxy:
``reputation`` (none|low|medium|high), ``suspicious`` (bool), ``details``
flags (deliverable, in breach, free provider, disposable, days_known)."""
from __future__ import annotations

from .. import key_pool
from .http_client import get_json

_BASE = "https://emailrep.io"


async def check(email: str) -> dict:
    key = key_pool.acquire("emailrep")
    headers = {"User-Agent": "bounce-cti", "Accept": "application/json"}
    if key:
        headers["Key"] = key
    cache_key = f"emailrep|{email.lower()}"
    return await get_json(f"{_BASE}/{email}", headers=headers,
                           ttl=86400, cache_key=cache_key)
