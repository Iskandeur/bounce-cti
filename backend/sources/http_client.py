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
