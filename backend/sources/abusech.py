"""abuse.ch URLhaus + MalwareBazaar.
Both APIs share a single Auth-Key (free at https://auth.abuse.ch/).
URLhaus = malicious URL database (host-based pivots).
MalwareBazaar = malware sample database (hash-based pivots).
"""
from .http_client import post_form, post_json
from ..config import ABUSECH_KEY


def _h() -> dict:
    return {"Auth-Key": ABUSECH_KEY} if ABUSECH_KEY else {}


# ── URLhaus (form-encoded) ──────────────────────────────────────────────
async def urlhaus_host(host: str) -> dict:
    """Look up all malicious URLs ever observed on a host (domain or IP)."""
    return await post_form("https://urlhaus-api.abuse.ch/v1/host/",
                           headers=_h(), form_data={"host": host}, ttl=3600)


async def urlhaus_url(url: str) -> dict:
    """Look up a specific URL in URLhaus."""
    return await post_form("https://urlhaus-api.abuse.ch/v1/url/",
                           headers=_h(), form_data={"url": url}, ttl=3600)


# ── MalwareBazaar (form-encoded) ────────────────────────────────────────
async def mb_hash(h: str) -> dict:
    """Look up a sample by md5/sha1/sha256 in MalwareBazaar."""
    return await post_form("https://mb-api.abuse.ch/api/v1/",
                           headers=_h(),
                           form_data={"query": "get_info", "hash": h},
                           ttl=86400)


_MB_KEEP = (
    "sha256_hash", "sha1_hash", "md5_hash",
    "file_name", "file_type", "file_size",
    "signature", "first_seen", "last_seen",
    "reporter", "tags",
)


def _slim_mb_sample(s: dict) -> dict:
    return {k: s.get(k) for k in _MB_KEEP if s.get(k) is not None}


async def mb_signature(signature: str, limit: int = 10) -> dict:
    """List samples tagged with a malware family/signature (e.g. AgentTesla).

    Response is trimmed to hash-identifying fields only (no yara/cape/vendor_intel)
    to stay under MCP tool-result token limits.
    """
    raw = await post_form("https://mb-api.abuse.ch/api/v1/",
                          headers=_h(),
                          form_data={"query": "get_siginfo",
                                     "signature": signature, "limit": str(limit)},
                          ttl=3600)
    if isinstance(raw, dict) and isinstance(raw.get("data"), list):
        raw = dict(raw)
        raw["data"] = [_slim_mb_sample(s) for s in raw["data"]]
    return raw


async def mb_filename(filename: str, limit: int = 20) -> dict:
    """List samples seen on MalwareBazaar with this exact filename.

    Used as the primary pivot for `executable_name` seeds — the analyst only
    has the filename (no binary, no hash) and wants to know which samples
    were ever reported under that name, then run the standard hash workflow
    on the top hits for family attribution.
    Response is trimmed per-sample like `mb_signature`.
    """
    raw = await post_form("https://mb-api.abuse.ch/api/v1/",
                          headers=_h(),
                          form_data={"query": "get_filename",
                                     "filename": filename, "limit": str(limit)},
                          ttl=3600)
    if isinstance(raw, dict) and isinstance(raw.get("data"), list):
        raw = dict(raw)
        raw["data"] = [_slim_mb_sample(s) for s in raw["data"]]
    return raw
