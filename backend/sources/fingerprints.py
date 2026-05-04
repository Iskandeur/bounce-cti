"""DOM fingerprint extractor.

Extracts high-signal markers from a page's HTML / DOM that are notoriously
useful for clustering attacker infrastructure across hosting changes:

  - Favicon mmh3 hash (Shodan-compatible: ``http.favicon.hash``)
  - Page title SHA1
  - Marketing tracking IDs (GA, GA4, GTM, FB Pixel, Yandex, Hotjar,
    Adobe DTM, Microsoft Clarity, TikTok Pixel)
  - Form action URLs (often the phishing backend)
  - Inline-script SHA1 hashes
  - Crypto wallet addresses (BTC bech32, ETH, XMR — drainer kits)

All fetches go through the shared HTTPX client + cache; results re-use the
SQLite cache table so a re-extract of the same URL is free.
"""
from __future__ import annotations

import base64
import hashlib
import re
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import httpx
import mmh3

from ..graph_store import cache_get, cache_set
from .http_client import UA

# ── Regex patterns ────────────────────────────────────────────────────────

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_FAVICON_RE = re.compile(
    r"""<link[^>]+rel=['"]?(?:shortcut\s+icon|icon|apple-touch-icon)['"]?[^>]*>""",
    re.IGNORECASE,
)
_HREF_RE = re.compile(r"""href=['"]([^'"]+)['"]""", re.IGNORECASE)
_FORM_ACTION_RE = re.compile(r"""<form[^>]+action=['"]([^'"]+)['"]""", re.IGNORECASE)
_INLINE_SCRIPT_RE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>",
                                re.IGNORECASE | re.DOTALL)

_TRACKING_PATTERNS: list[tuple[str, str]] = [
    ("google_analytics_ua", r"\b(UA-\d{4,10}-\d{1,4})\b"),
    ("google_analytics_ga4", r"\b(G-[A-Z0-9]{8,12})\b"),
    ("google_tag_manager", r"\b(GTM-[A-Z0-9]{6,10})\b"),
    ("facebook_pixel", r"""fbq\(['"]init['"],\s*['"](\d{14,17})['"]"""),
    ("yandex_metrica", r"""ym\(\s*(\d{6,10})\s*[,)]"""),
    ("hotjar", r"""hjid\s*:\s*(\d{5,9})"""),
    ("microsoft_clarity", r"""clarity[/.]ms[/'"]([a-z0-9]{10,})"""),
    ("tiktok_pixel", r"""ttq\.load\(['"]([A-Z0-9]{15,25})['"]"""),
    ("adobe_dtm", r"""assets\.adobedtm\.com/([a-f0-9]{40})"""),
]
_TRACKING_RE = [(name, re.compile(pat, re.IGNORECASE)) for name, pat in _TRACKING_PATTERNS]

_WALLET_PATTERNS: list[tuple[str, str]] = [
    ("btc_bech32", r"\b(bc1[ac-hj-np-z02-9]{20,80})\b"),
    ("eth", r"\b(0x[a-fA-F0-9]{40})\b"),
    ("xmr", r"\b(4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b"),
]
_WALLET_RE = [(name, re.compile(pat)) for name, pat in _WALLET_PATTERNS]


# ── Extraction primitives ─────────────────────────────────────────────────

def _sha1(s: str | bytes) -> str:
    if isinstance(s, str):
        s = s.encode()
    return hashlib.sha1(s).hexdigest()


def _shodan_favicon_hash(raw: bytes) -> int:
    """Replicate Shodan's favicon hash: base64-encode (with 76-char wrap +
    trailing newline as per Python's stdlib) then mmh3.hash() as signed int32.
    """
    b64 = base64.encodebytes(raw)
    return mmh3.hash(b64.decode("ascii"))


def _extract_favicon_url(html: str, base_url: Optional[str]) -> Optional[str]:
    """Return the absolute URL of the page's favicon, or None."""
    for tag in _FAVICON_RE.findall(html):
        m = _HREF_RE.search(tag)
        if m:
            href = m.group(1).strip()
            if base_url:
                return urljoin(base_url, href)
            return href
    if base_url:
        # Default fallback per RFC
        p = urlparse(base_url)
        return f"{p.scheme}://{p.netloc}/favicon.ico"
    return None


def _extract_title(html: str) -> Optional[str]:
    m = _TITLE_RE.search(html)
    if not m:
        return None
    title = re.sub(r"\s+", " ", m.group(1)).strip()
    return title or None


def _extract_form_actions(html: str, base_url: Optional[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for action in _FORM_ACTION_RE.findall(html):
        action = action.strip()
        if not action or action in ("#", "javascript:void(0)"):
            continue
        full = urljoin(base_url, action) if base_url else action
        if full not in seen:
            seen.add(full)
            out.append(full)
    return out


def _extract_tracking_ids(html: str) -> list[dict]:
    out: list[dict] = []
    seen: set[tuple] = set()
    for name, regex in _TRACKING_RE:
        for m in regex.finditer(html):
            val = m.group(1)
            key = (name, val)
            if key in seen:
                continue
            seen.add(key)
            out.append({"type": name, "value": val})
    return out


def _extract_inline_script_hashes(html: str, max_n: int = 10) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for body in _INLINE_SCRIPT_RE.findall(html):
        body = body.strip()
        if len(body) < 64:  # skip trivially-short snippets
            continue
        h = _sha1(body)
        if h in seen:
            continue
        seen.add(h)
        out.append(h)
        if len(out) >= max_n:
            break
    return out


def _extract_wallets(html: str) -> list[dict]:
    out: list[dict] = []
    seen: set[tuple] = set()
    for name, regex in _WALLET_RE:
        for m in regex.finditer(html):
            val = m.group(1)
            key = (name, val.lower())
            if key in seen:
                continue
            seen.add(key)
            out.append({"chain": name, "value": val})
    return out


# ── Public API ────────────────────────────────────────────────────────────

def extract_from_html(html: str, base_url: Optional[str] = None,
                       favicon_bytes: Optional[bytes] = None) -> dict:
    """Extract all fingerprints from a raw HTML string. ``favicon_bytes`` is
    optional; if provided, it's mmh3-hashed Shodan-style. Otherwise the
    favicon URL is identified but not hashed."""
    title = _extract_title(html)
    fav_url = _extract_favicon_url(html, base_url)
    fav_hash = _shodan_favicon_hash(favicon_bytes) if favicon_bytes else None
    return {
        "title": title,
        "title_hash": _sha1(title) if title else None,
        "favicon_url": fav_url,
        "favicon_hash": fav_hash,
        "tracking_ids": _extract_tracking_ids(html),
        "form_actions": _extract_form_actions(html, base_url),
        "inline_script_hashes": _extract_inline_script_hashes(html),
        "wallet_addresses": _extract_wallets(html),
    }


async def fetch_html_and_favicon(url: str, timeout: float = 20.0) -> tuple[str, Optional[bytes], Optional[str]]:
    """Fetch the page HTML and (best-effort) the favicon bytes. Returns
    (html, favicon_bytes_or_None, final_url_after_redirects)."""
    headers = {"User-Agent": UA}
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                  headers=headers, verify=False) as c:
        r = await c.get(url)
        html = r.text
        final_url = str(r.url)
        fav_url = _extract_favicon_url(html, final_url)
        fav_bytes: Optional[bytes] = None
        if fav_url:
            try:
                rf = await c.get(fav_url)
                if rf.status_code == 200 and rf.content:
                    fav_bytes = rf.content
            except Exception:
                pass
    return html, fav_bytes, final_url


async def extract_from_url(url: str, ttl: float = 86400) -> dict:
    """Fetch URL + favicon, then extract all fingerprints. Cached by URL."""
    cache_key = f"FP|{url}"
    cached = cache_get(cache_key, ttl=ttl)
    if cached is not None:
        return cached
    try:
        html, fav_bytes, final_url = await fetch_html_and_favicon(url)
    except Exception as e:
        return {"error": f"fetch failed: {type(e).__name__}: {e}"[:200], "url": url}
    out = extract_from_html(html, base_url=final_url, favicon_bytes=fav_bytes)
    out["url"] = url
    out["final_url"] = final_url
    cache_set(cache_key, out)
    return out


async def extract_from_urlscan(uuid: str, ttl: float = 86400) -> dict:
    """Use urlscan's public DOM endpoint to fetch the rendered HTML, then
    extract fingerprints. Note: urlscan's DOM endpoint requires the scan to
    have been visible; private scans return 401."""
    cache_key = f"FP|urlscan|{uuid}"
    cached = cache_get(cache_key, ttl=ttl)
    if cached is not None:
        return cached
    dom_url = f"https://urlscan.io/dom/{uuid}/"
    headers = {"User-Agent": UA}
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True,
                                      headers=headers) as c:
            r = await c.get(dom_url)
            if r.status_code != 200:
                return {"error": f"urlscan DOM fetch returned {r.status_code}", "uuid": uuid}
            html = r.text
    except Exception as e:
        return {"error": f"fetch failed: {type(e).__name__}: {e}"[:200], "uuid": uuid}
    out = extract_from_html(html)
    out["urlscan_uuid"] = uuid
    cache_set(cache_key, out)
    return out
