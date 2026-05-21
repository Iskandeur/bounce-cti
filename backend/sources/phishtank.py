"""PhishTank — community phishing URL database (independent of OpenPhish).

The check endpoint accepts an application/x-www-form-urlencoded POST with
``url`` and ``format=json``. An API key is optional — anonymous use is
rate-limited but does not require registration. We hit the HTTPS endpoint
directly because the HTTP variant 301-redirects and drops the body."""
from __future__ import annotations

from .http_client import post_form

_URL = "https://checkurl.phishtank.com/checkurl/"


async def check_url(url: str) -> dict:
    """Return PhishTank's verdict for a URL.

    Response shape (success):
      {"meta": {...},
       "results": {"url": ..., "in_database": bool,
                    "verified": bool, "valid": bool,
                    "phish_id": int, "phish_detail_page": str, ...}}
    """
    form = {"url": url, "format": "json"}
    headers = {"User-Agent": "phishtank/bounce-cti"}
    cache_key = f"phishtank|{url}"
    return await post_form(_URL, headers=headers, form_data=form,
                            ttl=3600, cache_key=cache_key)
