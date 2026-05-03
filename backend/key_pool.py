"""
Key pool with rotation, cooldown, and per-day quota tracking.

Reads API keys from the environment in two formats per source:
  - ``<PREFIX>_API_KEYS=k1,k2,k3``  (multi-key, takes precedence)
  - ``<PREFIX>_API_KEY=k1``         (single-key, legacy/back-compat)

Sources register via a canonical short name (``"vt"``, ``"netlas"``, ...) which
maps to an env var prefix (``"VIRUSTOTAL"``, ``"NETLAS"``, ...). All state is
held in process memory: cooldowns reset on restart (the API will simply re-tell
us if we hit a rate limit), and quota counters are best-effort (we may
under-count if a quota was used by a previous process; the API will 429 us
back to reality).

Public API:
  - ``acquire(source)``               -> str | None  (round-robin, skips cooldown)
  - ``mark_rate_limited(source, key, cooldown_seconds=60)``
  - ``mark_quota_exhausted(source, key)``  (cooldown until next UTC midnight)
  - ``status(source)``                -> dict
  - ``status_all()``                  -> dict[source, dict]
"""
from __future__ import annotations

import hashlib
import os
import threading
import time
from typing import Optional

_ENV_PREFIX = {
    "vt": "VIRUSTOTAL",
    "urlscan": "URLSCAN",
    "onyphe": "ONYPHE",
    "shodan": "SHODAN",
    "otx": "OTX",
    "abusech": "ABUSECH",
    "abuseipdb": "ABUSEIPDB",
    "certspotter": "CERTSPOTTER",
    "netlas": "NETLAS",
    "whoxy": "WHOXY",
    "zoomeye": "ZOOMEYE",
    "criminalip": "CRIMINALIP",
}

_lock = threading.Lock()
_state: dict = {}


def _key_hash(key: str) -> str:
    return hashlib.sha1(key.encode()).hexdigest()[:12]


def _today_utc() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())


def _load_keys(source: str) -> list[str]:
    prefix = _ENV_PREFIX.get(source)
    if not prefix:
        return []
    multi = os.environ.get(f"{prefix}_API_KEYS", "") or os.environ.get(f"{prefix}_KEYS", "")
    if multi.strip():
        return [k.strip() for k in multi.split(",") if k.strip()]
    single = os.environ.get(f"{prefix}_API_KEY", "") or os.environ.get(f"{prefix}_KEY", "")
    if single.strip():
        return [single.strip()]
    # abuse.ch legacy var name
    if source == "abusech":
        legacy = os.environ.get("ABUSECH_AUTH_KEY", "")
        if legacy.strip():
            return [legacy.strip()]
    return []


def _ensure_state(source: str) -> dict:
    s = _state.get(source)
    if s is not None:
        return s
    s = {
        "keys": _load_keys(source),
        "next_idx": 0,
        "cooldowns": {},
        "quota": {},
    }
    _state[source] = s
    return s


def _is_available(s: dict, key: str, now: float) -> bool:
    return now >= s["cooldowns"].get(key, 0)


def acquire(source: str) -> Optional[str]:
    """Return the next available key for ``source``, or None if all in cooldown."""
    with _lock:
        s = _ensure_state(source)
        if not s["keys"]:
            return None
        now = time.time()
        n = len(s["keys"])
        for _ in range(n):
            idx = s["next_idx"] % n
            key = s["keys"][idx]
            s["next_idx"] = (idx + 1) % n
            if _is_available(s, key, now):
                today = _today_utc()
                q = s["quota"].get(key)
                if q is None or q["date"] != today:
                    s["quota"][key] = {"date": today, "used": 1}
                else:
                    q["used"] += 1
                return key
        return None


def mark_rate_limited(source: str, key: str, cooldown_seconds: int = 60) -> None:
    with _lock:
        s = _ensure_state(source)
        s["cooldowns"][key] = time.time() + max(1, cooldown_seconds)


def mark_quota_exhausted(source: str, key: str) -> None:
    """Cooldown until next UTC midnight."""
    with _lock:
        s = _ensure_state(source)
        now = time.time()
        next_midnight = (int(now // 86400) + 1) * 86400
        s["cooldowns"][key] = next_midnight


def has_any_key(source: str) -> bool:
    """Return True if at least one key is configured for ``source`` (regardless
    of cooldown). Used by the pivot mapper to decide whether a pivot should be
    enqueued as 'pending' or 'skipped' with reason='no_api_key'."""
    with _lock:
        return len(_ensure_state(source)["keys"]) > 0


def status(source: str) -> dict:
    with _lock:
        s = _ensure_state(source)
        now = time.time()
        avail = sum(1 for k in s["keys"] if _is_available(s, k, now))
        used_today = {_key_hash(k): s["quota"].get(k, {}).get("used", 0) for k in s["keys"]}
        return {
            "source": source,
            "keys_total": len(s["keys"]),
            "keys_available": avail,
            "keys_cooldown": len(s["keys"]) - avail,
            "used_today_per_key": used_today,
        }


def status_all() -> dict:
    out = {}
    for src in _ENV_PREFIX.keys():
        st = status(src)
        if st["keys_total"] > 0:
            out[src] = st
    return out


def reset_for_tests() -> None:
    """Clear all in-memory state. Test-only; not called by production code."""
    with _lock:
        _state.clear()
