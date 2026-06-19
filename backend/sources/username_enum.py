"""Username enumeration across public platforms (free, no API key).

Sherlock-style: probe a curated manifest of well-known sites for the existence
of a *public* profile at ``/{username}``. Each site declares a detection rule
(expected status / expected body marker / "missing" body marker for soft-404
sites that answer 200 for everyone). Benign OSINT — this only checks whether a
public profile page exists; it fetches no private data and submits no forms.

Feeds the OSINT vertical's identity-footprint correlation and the CTI vertical's
actor-handle pivots (a forum/Telegram handle surfaced during an investigation).

Attribution / licensing
------------------------
The site manifest and the ``e_code``/``e_string``/``m_string`` detection model
are adapted (COPY-DATA, with attribution) from the public, MIT-licensed
username-OSINT projects **blackbird** (p1ngul1n0/blackbird) and **Sherlock**
(sherlock-project/sherlock). Only the publicly published site-detection metadata
is reused; no project code is copied. See ``THIRD_PARTY_LICENSES.md``.
"""
from __future__ import annotations

import asyncio
import os
import re

from .http_client import get_text

# Cache existence verdicts for 6h — profiles appear/disappear, so a shorter TTL
# than the default keeps results reasonably fresh without re-probing every run.
_TTL = 21600
_MAX_CONCURRENCY = 10
_VALID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

# ── Apify seam (paid scraping backend, NOT enabled) ─────────────────────────
# Platforms that block direct HTTP probing (anti-bot / JS-only) and so can't be
# checked for free. They're declared here so the capability gap is *visible*
# (surfaced as `deferred` in the result) rather than silently absent. Wiring a
# scraping backend later — Apify is the intended one — means: set an APIFY token,
# add a per-platform actor id below, and route these through that adapter in
# enumerate_username(). No dead code now; this is the documented extension point
# for the paid OSINT source tier (mirrors the DD "premium source slot").
_APIFY_PLATFORMS: list[dict] = [
    {"app": "Instagram", "cat": "social"},
    {"app": "TikTok", "cat": "social"},
    {"app": "X", "cat": "social"},
    {"app": "LinkedIn", "cat": "professional"},
    {"app": "Facebook", "cat": "social"},
]


def _apify_enabled() -> bool:
    """Whether a paid scraping backend is wired. False until the Apify adapter
    + token land — the `deferred` platforms stay unprobed but visible."""
    return bool(os.getenv("APIFY_API_TOKEN"))


# Site manifest. Each entry:
#   app       display name
#   cat       category (dev / social / forum / blog / gaming / creator / misc)
#   url       profile URL, "{u}" is replaced by the username
#   e_code    HTTP status that an *existing* profile returns (usually 200)
#   e_string  substring that must be present for an existing profile (or None)
#   m_string  substring that, if present in a 200 body, means "missing"
#             (for soft-404 sites that answer 200 for everyone)
# Detection precedence is implemented in _classify(); a clean 404-on-missing
# site needs only e_code (most robust over time — body markers drift).
_SITES: list[dict] = [
    # — developer / code —
    {"app": "GitHub", "cat": "dev", "url": "https://github.com/{u}", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "GitLab", "cat": "dev", "url": "https://gitlab.com/{u}", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "Bitbucket", "cat": "dev", "url": "https://bitbucket.org/{u}/", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "PyPI", "cat": "dev", "url": "https://pypi.org/user/{u}/", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "npm", "cat": "dev", "url": "https://www.npmjs.com/~{u}", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "DockerHub", "cat": "dev", "url": "https://hub.docker.com/u/{u}", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "Keybase", "cat": "dev", "url": "https://keybase.io/{u}", "e_code": 200, "e_string": None, "m_string": None},
    # — forums / aggregators —
    {"app": "Reddit", "cat": "forum", "url": "https://old.reddit.com/user/{u}", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "HackerNews", "cat": "forum", "url": "https://news.ycombinator.com/user?id={u}", "e_code": 200, "e_string": None, "m_string": "No such user."},
    {"app": "Pastebin", "cat": "forum", "url": "https://pastebin.com/u/{u}", "e_code": 200, "e_string": None, "m_string": None},
    # — blogging / writing —
    {"app": "Medium", "cat": "blog", "url": "https://medium.com/@{u}", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "DevTo", "cat": "blog", "url": "https://dev.to/{u}", "e_code": 200, "e_string": None, "m_string": None},
    # — creator / portfolio —
    {"app": "Patreon", "cat": "creator", "url": "https://www.patreon.com/{u}", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "AboutMe", "cat": "creator", "url": "https://about.me/{u}", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "Gravatar", "cat": "creator", "url": "https://en.gravatar.com/{u}", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "Vimeo", "cat": "creator", "url": "https://vimeo.com/{u}", "e_code": 200, "e_string": None, "m_string": None},
    # — social / messaging —
    {"app": "Telegram", "cat": "social", "url": "https://t.me/{u}", "e_code": 200, "e_string": "tgme_page_title", "m_string": None},
    # — gaming —
    {"app": "Steam", "cat": "gaming", "url": "https://steamcommunity.com/id/{u}", "e_code": 200, "e_string": None, "m_string": "The specified profile could not be found"},
    {"app": "ChessCom", "cat": "gaming", "url": "https://www.chess.com/member/{u}", "e_code": 200, "e_string": None, "m_string": None},
    # — music —
    {"app": "LastFm", "cat": "misc", "url": "https://www.last.fm/user/{u}", "e_code": 200, "e_string": None, "m_string": None},
    # — design / portfolio (404-clean) —
    {"app": "Behance", "cat": "creator", "url": "https://www.behance.net/{u}", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "Dribbble", "cat": "creator", "url": "https://dribbble.com/{u}", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "Linktree", "cat": "creator", "url": "https://linktr.ee/{u}", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "ProductHunt", "cat": "creator", "url": "https://www.producthunt.com/@{u}", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "ItchIo", "cat": "gaming", "url": "https://{u}.itch.io/", "e_code": 200, "e_string": None, "m_string": None},
    # — data / security community (404-clean) —
    {"app": "Kaggle", "cat": "dev", "url": "https://www.kaggle.com/{u}", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "HackerOne", "cat": "dev", "url": "https://hackerone.com/{u}", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "GitHubGist", "cat": "dev", "url": "https://gist.github.com/{u}", "e_code": 200, "e_string": None, "m_string": None},
    # — extended manifest (Sherlock / Maigret COPY-DATA, 2026-06; 404-clean) —
    # dev / code
    {"app": "Codeberg", "cat": "dev", "url": "https://codeberg.org/{u}", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "SourceForge", "cat": "dev", "url": "https://sourceforge.net/u/{u}/profile", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "Launchpad", "cat": "dev", "url": "https://launchpad.net/~{u}", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "CodePen", "cat": "dev", "url": "https://codepen.io/{u}", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "Hackaday", "cat": "dev", "url": "https://hackaday.io/{u}", "e_code": 200, "e_string": None, "m_string": None},
    # forum / social
    {"app": "Disqus", "cat": "forum", "url": "https://disqus.com/by/{u}/", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "Imgur", "cat": "social", "url": "https://imgur.com/user/{u}", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "Flickr", "cat": "social", "url": "https://www.flickr.com/people/{u}", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "Trello", "cat": "social", "url": "https://trello.com/{u}", "e_code": 200, "e_string": None, "m_string": None},
    # creator
    {"app": "KoFi", "cat": "creator", "url": "https://ko-fi.com/{u}", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "BuyMeACoffee", "cat": "creator", "url": "https://www.buymeacoffee.com/{u}", "e_code": 200, "e_string": None, "m_string": None},
    # music
    {"app": "Mixcloud", "cat": "misc", "url": "https://www.mixcloud.com/{u}/", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "SoundCloud", "cat": "misc", "url": "https://soundcloud.com/{u}", "e_code": 200, "e_string": None, "m_string": None},
    # blog / writing
    {"app": "Blogger", "cat": "blog", "url": "https://{u}.blogspot.com", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "Substack", "cat": "blog", "url": "https://{u}.substack.com", "e_code": 200, "e_string": None, "m_string": None},
    # art / photo
    {"app": "DeviantArt", "cat": "creator", "url": "https://www.deviantart.com/{u}", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "ArtStation", "cat": "creator", "url": "https://www.artstation.com/{u}", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "Unsplash", "cat": "creator", "url": "https://unsplash.com/@{u}", "e_code": 200, "e_string": None, "m_string": None},
    # gaming / media
    {"app": "Lichess", "cat": "gaming", "url": "https://lichess.org/@/{u}", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "MyAnimeList", "cat": "gaming", "url": "https://myanimelist.net/profile/{u}", "e_code": 200, "e_string": None, "m_string": None},
    {"app": "Letterboxd", "cat": "misc", "url": "https://letterboxd.com/{u}/", "e_code": 200, "e_string": None, "m_string": None},
]


def _classify(site: dict, status: int, text: str) -> str:
    """Decide existence from a probe result. Pure function (unit-tested).

    Returns "found", "not_found", or "unknown" (blocked / network error / an
    unexpected status we can't interpret). Body-marker checks only apply when
    the status already matches e_code — a soft-404 site answers e_code for
    everyone, so the m_string/e_string markers are what disambiguate."""
    e_code = site.get("e_code", 200)
    e_string = site.get("e_string")
    m_string = site.get("m_string")
    if status == 404:
        return "not_found"
    if status == e_code:
        if m_string and m_string in text:
            return "not_found"
        if e_string and e_string not in text:
            return "not_found"
        return "found"
    return "unknown"


async def _probe(site: dict, username: str, sem: asyncio.Semaphore) -> tuple[dict, str, int]:
    url = site["url"].replace("{u}", username)
    cache_key = f"uenum|{site['app']}|{username.lower()}"
    async with sem:
        resp = await get_text(url, ttl=_TTL, cache_key=cache_key)
    status = int(resp.get("status") or 0)
    verdict = "unknown" if status == 0 else _classify(site, status, resp.get("text") or "")
    return site, verdict, status


async def enumerate_username(username: str) -> dict:
    """Probe the site manifest for a public profile under ``username``.

    Returns {username, checked, found:[{app,category,url}], found_count,
    not_found_count, unknown:[{app,status}], source}. ``unknown`` entries are
    sites that blocked the probe or errored — surfaced for transparency rather
    than silently dropped (absence of evidence ≠ evidence of absence)."""
    u = (username or "").strip().lstrip("@").strip()
    if not _VALID_RE.match(u):
        return {"username": username, "error": "invalid username (expected 1-64 chars [A-Za-z0-9._-])",
                "found": [], "found_count": 0, "checked": 0}
    sem = asyncio.Semaphore(_MAX_CONCURRENCY)
    results = await asyncio.gather(*[_probe(s, u, sem) for s in _SITES])
    found, unknown = [], []
    not_found = 0
    for site, verdict, status in results:
        if verdict == "found":
            found.append({"app": site["app"], "category": site["cat"],
                          "url": site["url"].replace("{u}", u)})
        elif verdict == "not_found":
            not_found += 1
        else:
            unknown.append({"app": site["app"], "status": status})
    found.sort(key=lambda d: d["app"].lower())
    # Anti-bot platforms we can't probe for free — visible, not silently absent.
    deferred = [] if _apify_enabled() else [
        {"app": p["app"], "category": p["cat"],
         "reason": "needs a scraping backend (Apify; paid, not enabled)"}
        for p in _APIFY_PLATFORMS
    ]
    return {
        "username": u,
        "checked": len(_SITES),
        "found": found,
        "found_count": len(found),
        "not_found_count": not_found,
        "unknown": unknown,
        "deferred": deferred,
        "source": "username_enum (site manifest adapted from Sherlock / blackbird, MIT)",
    }
