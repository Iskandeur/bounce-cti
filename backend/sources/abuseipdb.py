"""AbuseIPDB — IP reputation. Free tier: 1000 req/day."""
from __future__ import annotations

from .. import key_pool
from .http_client import get_json

_BASE = "https://api.abuseipdb.com/api/v2"


async def check_ip(ip: str, max_age_days: int = 90) -> dict:
    """Return AbuseIPDB report for an IP: confidence score, country, ISP,
    total reports, last report date, categories."""
    key = key_pool.acquire("abuseipdb")
    if not key:
        return {"error": "no AbuseIPDB key configured or all keys exhausted"}
    headers = {"Key": key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": str(max_age_days), "verbose": ""}
    cache_key = f"abuseipdb|check|{ip}|{max_age_days}"
    return await get_json(f"{_BASE}/check", headers=headers, params=params,
                           ttl=3600, cache_key=cache_key)
