"""Subdomain-takeover heuristic checker.

For a given hostname, fetch the HTTP response from http(s)://host and
inspect the body for *fingerprint strings* that abandoned third-party
services emit when an unclaimed bucket / app is queried with the wrong
Host header. These fingerprints are well-documented (see EdOverflow's
can-i-take-over-xyz project) and we keep a compact, curated subset that
focuses on the cloud providers actually observed in current adversary
infrastructure.

Strictly passive: we only do an HTTP GET of the host's own root page. We
do not interact with the underlying cloud account.
"""
from __future__ import annotations

import httpx

from ..graph_store import cache_get, cache_set
from .http_client import UA

# (provider_name, fingerprint substring, status_code_hint_or_None)
# Sourced from https://github.com/EdOverflow/can-i-take-over-xyz — kept
# small on purpose; expand as TPs accumulate.
_FINGERPRINTS: list[tuple[str, str, int | None]] = [
    ("aws_s3",       "NoSuchBucket", 404),
    ("aws_s3",       "The specified bucket does not exist", 404),
    ("azure",        "404 Web Site not found", 404),
    ("github_pages", "There isn't a GitHub Pages site here.", 404),
    ("github_pages", "For root URLs (like http://example.com/) you must provide an index.html file", None),
    ("heroku",       "No such app", 404),
    ("netlify",      "Not Found - Request ID:", 404),
    ("fastly",       "Fastly error: unknown domain", None),
    ("readme",       "Project doesnt exist... yet!", None),
    ("shopify",      "Sorry, this shop is currently unavailable.", None),
    ("surge",        "project not found", None),
    ("tumblr",       "Whatever you were looking for doesn't currently exist at this address.", None),
    ("unbounce",     "The requested URL was not found on this server", None),
    ("zendesk",      "Help Center Closed", None),
    ("uservoice",    "This UserVoice subdomain is currently available!", None),
    ("teamwork",     "Oops - We didn't find your site.", None),
    ("bitbucket",    "Repository not found", 404),
    ("ghost",        "The thing you were looking for is no longer here, or never was", 404),
    ("wordpress",    "Do you want to register", None),
    ("worksites",    "Hello! Sorry, but this website is", None),
]


async def check_host(host: str) -> dict:
    """Return ``{vulnerable: bool, provider?: str, ...}``.

    Tries https first, then http on failure. Only flags the host as
    vulnerable when both the status code (when specified) AND the body
    fingerprint match. Caches the verdict for 1h."""
    cache_key = f"takeover|{host}"
    cached = cache_get(cache_key, ttl=3600)
    if cached is not None:
        return cached
    out: dict = {"vulnerable": False, "host": host, "checked": []}
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=False,
                                          headers={"User-Agent": UA}) as c:
                r = await c.get(url)
        except Exception as exc:  # noqa: BLE001
            out["checked"].append({"url": url, "error": str(exc)[:200]})
            continue
        body_sample = (r.text or "")[:8000]
        out["checked"].append({"url": url, "status": r.status_code})
        for provider, marker, status_hint in _FINGERPRINTS:
            if status_hint is not None and r.status_code != status_hint:
                continue
            if marker in body_sample:
                out["vulnerable"] = True
                out["provider"] = provider
                out["marker"] = marker
                out["status"] = r.status_code
                out["url"] = url
                cache_set(cache_key, out)
                return out
    cache_set(cache_key, out)
    return out
