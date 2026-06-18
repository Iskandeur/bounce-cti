"""Website content extraction — outbound links, domains, emails, social profiles.

Concept ported from flowsint's ``website`` enrichers (``to_text`` / ``to_links``,
Apache-2.0 — see THIRD_PARTY_LICENSES). flowsint relies on BeautifulSoup + its
own crawler libs (``reconspread``); we reimplement the extraction with stdlib
regex over the fetched HTML — no new dependency, our async ``http_client`` +
cache. Given a URL this surfaces the page's title, a text excerpt, its outbound
links (internal vs external), the external domains it references, any emails,
and links to known social platforms — the core "footprint a site / profile
page" OSINT move that turns one URL into a graph of connected identities and
infrastructure. No API key.
"""
from __future__ import annotations

import html as _html
import re
from urllib.parse import urljoin, urlparse

from .http_client import get_text

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_HREF_RE = re.compile(r"""<a\b[^>]*?\bhref\s*=\s*['"]([^'"<>]+)['"]""", re.I)
_SCRIPT_STYLE_RE = re.compile(r"<(script|style)\b.*?</\1>", re.I | re.S)
_ANYTAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
# Email domains that are really asset filenames (foo@2x.png) — drop them.
_ASSET_TLDS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "css", "js", "ico"}

# Known social platforms → handle extraction (anchored, to avoid false positives).
_SOCIAL = [
    ("github", re.compile(r"^https?://(?:www\.)?github\.com/([A-Za-z0-9_-]{1,39})/?$", re.I)),
    ("twitter", re.compile(r"^https?://(?:www\.)?(?:twitter|x)\.com/([A-Za-z0-9_]{1,15})/?$", re.I)),
    ("telegram", re.compile(r"^https?://(?:www\.)?t\.me/([A-Za-z0-9_]{3,32})/?$", re.I)),
    ("linkedin", re.compile(r"^https?://(?:www\.)?linkedin\.com/(?:in|company)/([A-Za-z0-9_-]+)/?$", re.I)),
    ("instagram", re.compile(r"^https?://(?:www\.)?instagram\.com/([A-Za-z0-9_.]{1,30})/?$", re.I)),
    ("youtube", re.compile(r"^https?://(?:www\.)?youtube\.com/(@[A-Za-z0-9_.\-]+|channel/[A-Za-z0-9_-]+|c/[A-Za-z0-9_-]+)/?$", re.I)),
    ("tiktok", re.compile(r"^https?://(?:www\.)?tiktok\.com/(@[A-Za-z0-9_.]+)/?$", re.I)),
    ("facebook", re.compile(r"^https?://(?:www\.)?facebook\.com/([A-Za-z0-9.]{3,})/?$", re.I)),
]


def _norm_host(netloc: str) -> str:
    h = (netloc or "").lower()
    return h[4:] if h.startswith("www.") else h


def _text_excerpt(html_text: str, cap: int = 1500) -> str:
    stripped = _SCRIPT_STYLE_RE.sub(" ", html_text)
    stripped = _ANYTAG_RE.sub(" ", stripped)
    text = _WS_RE.sub(" ", _html.unescape(stripped)).strip()
    return text[:cap]


def _extract(html_text: str, base_url: str) -> dict:
    """Pure HTML extraction → links / domains / emails / socials. Unit-tested."""
    base_host = _norm_host(urlparse(base_url).netloc)
    title_m = _TITLE_RE.search(html_text)
    title = _WS_RE.sub(" ", _html.unescape(title_m.group(1))).strip() if title_m else None

    internal, external, ext_domains, socials = [], [], set(), []
    seen_links, seen_social = set(), set()
    for raw in _HREF_RE.findall(html_text):
        u = urljoin(base_url, _html.unescape(raw.strip()))
        p = urlparse(u)
        if p.scheme not in ("http", "https") or u in seen_links:
            continue
        seen_links.add(u)
        host = _norm_host(p.netloc)
        if not host or host == base_host:
            internal.append(u)
            continue
        external.append(u)
        ext_domains.add(host)
        for name, rx in _SOCIAL:
            m = rx.match(u)
            if m and u not in seen_social:
                seen_social.add(u)
                socials.append({"platform": name, "url": u, "handle": m.group(1)})
                break

    emails = []
    seen_email = set()
    for e in _EMAIL_RE.findall(html_text):
        el = e.lower()
        if el in seen_email or el.rsplit(".", 1)[-1] in _ASSET_TLDS:
            continue
        seen_email.add(el)
        emails.append(el)

    return {
        "title": title,
        "text_excerpt": _text_excerpt(html_text),
        "internal_links": internal[:50],
        "external_links": external[:50],
        "external_domains": sorted(ext_domains)[:50],
        "emails": emails[:30],
        "social_profiles": socials[:30],
        "link_count": len(seen_links),
    }


async def extract(url: str) -> dict:
    """Fetch a URL and extract its links / domains / emails / social profiles."""
    u = (url or "").strip()
    if not u:
        return {"url": url, "fetched": False, "error": "empty url"}
    if not re.match(r"^https?://", u, re.I):
        u = "http://" + u
    resp = await get_text(u, ttl=21600, cache_key=f"website|{u}")
    if resp.get("status", 0) <= 0 or not resp.get("text"):
        return {"url": u, "fetched": False, "status": resp.get("status", 0),
                "error": resp.get("error") or "no content"}
    out = _extract(resp["text"], resp.get("final_url") or u)
    out.update({"url": u, "final_url": resp.get("final_url"), "status": resp["status"],
                "fetched": True, "source": "website (HTML extraction)"})
    return out
