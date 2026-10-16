import httpx
from .. import fixtures
from ..graph_store import cache_get, cache_set

UA = "bounce-cti/0.1 (+research)"

# Paramètres de requête qui portent un secret : ils ne doivent jamais entrer dans une clé de cache
# (la table `cache` est copiée avec la base ; une clé qui tourne invaliderait aussi tout le cache).
_SECRET_PARAMS = frozenset({
    "key", "apikey", "api_key", "api-key", "token", "access_token", "auth", "secret",
    "password", "pass", "signature", "sig",
})


def cache_params(params: dict | None) -> dict | None:
    """`params` sans les paramètres d'authentification, pour fabriquer une clé de cache."""
    if not params:
        return params
    return {k: v for k, v in params.items() if str(k).lower() not in _SECRET_PARAMS}


def _replay_miss(key: str) -> None:
    """In fixture replay a cache miss is a question the captured run never
    asked. Fail it here, under its own name, the way a dead network fails —
    before any request, so the offline guard is the second wall, not the first."""
    if fixtures.replaying():
        raise httpx.ConnectError(
            f"{fixtures.REPLAY_MISS}: no recorded response for {fixtures.redact(key)}")


async def get_json(url: str, headers: dict | None = None, params: dict | None = None,
                   ttl: float = 86400, cache_key: str | None = None) -> dict:
    key = cache_key or f"GET|{url}|{cache_params(params)}"
    cached = cache_get(key, ttl=ttl)
    if cached is not None:
        return cached
    _replay_miss(key)
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as c:
        r = await c.get(url, headers=h, params=params)
        try:
            data = r.json()
        except Exception:
            data = {"_status": r.status_code, "_text": r.text[:2000]}
    cache_set(key, data)
    return data


async def post_json(url: str, headers: dict | None = None, json_body: dict | None = None,
                    ttl: float = 86400, cache_key: str | None = None) -> dict:
    key = cache_key or f"POST|{url}|{cache_params(json_body)}"
    cached = cache_get(key, ttl=ttl)
    if cached is not None:
        return cached
    _replay_miss(key)
    h = {"User-Agent": UA, "Content-Type": "application/json"}
    if headers:
        h.update(headers)
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.post(url, headers=h, json=json_body)
        try:
            data = r.json()
        except Exception:
            data = {"_status": r.status_code, "_text": r.text[:2000]}
    cache_set(key, data)
    return data


async def get_text(url: str, headers: dict | None = None, params: dict | None = None,
                   ttl: float = 86400, cache_key: str | None = None,
                   follow_redirects: bool = True) -> dict:
    """GET returning the raw response shape {status, final_url, text} rather than
    parsed JSON — needed by sources that probe HTML pages (e.g. username
    enumeration). Transient failures (status 0) are NOT cached so a network
    blip doesn't poison the cache for the full TTL."""
    key = cache_key or f"TXT|{url}|{cache_params(params)}"
    cached = cache_get(key, ttl=ttl)
    if cached is not None:
        return cached
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    try:
        _replay_miss(key)
        async with httpx.AsyncClient(timeout=15, follow_redirects=follow_redirects) as c:
            r = await c.get(url, headers=h, params=params)
            data = {"status": r.status_code, "final_url": str(r.url), "text": r.text[:8000]}
    except Exception as e:  # network error / timeout — surface, don't cache
        return {"status": 0, "final_url": url, "text": "", "error": str(e)[:200]}
    cache_set(key, data)
    return data


async def post_form(url: str, headers: dict | None = None, form_data: dict | None = None,
                    ttl: float = 86400, cache_key: str | None = None) -> dict:
    """POST with application/x-www-form-urlencoded body (needed by MalwareBazaar, URLhaus)."""
    key = cache_key or f"FORM|{url}|{cache_params(form_data)}"
    cached = cache_get(key, ttl=ttl)
    if cached is not None:
        return cached
    _replay_miss(key)
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.post(url, headers=h, data=form_data)
        try:
            data = r.json()
        except Exception:
            data = {"_status": r.status_code, "_text": r.text[:2000]}
    cache_set(key, data)
    return data
