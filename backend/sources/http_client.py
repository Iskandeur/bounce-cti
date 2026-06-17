import httpx
from ..graph_store import cache_get, cache_set

UA = "bounce-cti/0.1 (+research)"


async def get_json(url: str, headers: dict | None = None, params: dict | None = None,
                   ttl: float = 86400, cache_key: str | None = None) -> dict:
    key = cache_key or f"GET|{url}|{params}"
    cached = cache_get(key, ttl=ttl)
    if cached is not None:
        return cached
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
    key = cache_key or f"POST|{url}|{json_body}"
    cached = cache_get(key, ttl=ttl)
    if cached is not None:
        return cached
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
    key = cache_key or f"TXT|{url}|{params}"
    cached = cache_get(key, ttl=ttl)
    if cached is not None:
        return cached
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    try:
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
    key = cache_key or f"FORM|{url}|{form_data}"
    cached = cache_get(key, ttl=ttl)
    if cached is not None:
        return cached
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
