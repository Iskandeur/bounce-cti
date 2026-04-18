"""Onyphe CTI source. Summary endpoints (domain/ip) plus Griffin View+
expansion endpoints: datascan, threatlist, resolver (fwd/rev), ctl,
pastries, geoloc.

All endpoints degrade gracefully when no key is set.

The `summary/domain` and `summary/ip` endpoints are aggregates across all
Onyphe categories (datascan, resolver, ctl, threatlist, pastries, geoloc).
They work on the community tier. We post-process their raw response into
a flat `digest` with pivot-ready fields (ips, jarms, subdomains, ports,
asns, tls_issuers, threat_feeds), so the agent can graph each item
directly without having to parse Onyphe's `results[].@category` JSON shape.

The `simple/<category>/…` endpoints return one category at a time and
require a Griffin-tier key. On community-tier keys they return
`{'error': <nonzero>, 'text': 'Access denied'}` — we surface that with a
`tier_restricted: true` flag so the agent knows to skip follow-up pivots
on the same call rather than retrying.
"""
from collections import defaultdict
from typing import Any

from .http_client import get_json
from ..config import ONYPHE_KEY


def _auth() -> dict:
    return {"Authorization": f"bearer {ONYPHE_KEY}"}


def _missing_key() -> dict:
    return {"error": "no Onyphe key", "results": [], "digest": _empty_digest()}


def _empty_digest() -> dict:
    return {
        "ips": [], "jarms": [], "subdomains": [], "ports": [],
        "asns": [], "countries": [], "organizations": [],
        "tls_issuers": [], "tls_subjects": [], "favicon_hashes": [],
        "http_titles": [], "products": [], "threat_feeds": [],
        "certs_seen": 0, "categories": {}, "records": 0,
    }


def _as_list(v: Any) -> list:
    if v is None: return []
    if isinstance(v, list): return v
    return [v]


def _digest_summary(raw: dict) -> dict:
    """Flatten a summary/* response (or simple/*) into pivot-ready fields.

    Accepts either raw summary JSON `{results: [...], error: 0, ...}` or a
    simple response with the same shape. Unknown fields are ignored.
    """
    d = _empty_digest()
    if not isinstance(raw, dict):
        return d
    results = raw.get("results") or []
    if not isinstance(results, list):
        return d
    d["records"] = len(results)
    ips = set(); jarms = set(); subs = set(); ports = set()
    asns = set(); cc = set(); orgs = set()
    issuers = set(); subjects = set(); favs = set()
    titles = set(); prods = set(); feeds = set()
    cats = defaultdict(int)
    cert_count = 0
    for rec in results:
        if not isinstance(rec, dict):
            continue
        cat = rec.get("@category") or "unknown"
        cats[cat] += 1
        for ip_key in ("ip", "ipaddr", "destip", "srcip"):
            v = rec.get(ip_key)
            if isinstance(v, str) and v:
                ips.add(v)
        j = rec.get("jarm") or rec.get("tls_jarm")
        if isinstance(j, str) and len(j) >= 30:
            jarms.add(j)
        for h in _as_list(rec.get("hostname")) + _as_list(rec.get("subdomains")) + _as_list(rec.get("domain")) + _as_list(rec.get("subdomain")):
            if isinstance(h, str) and "." in h:
                subs.add(h.lower().strip("."))
        p = rec.get("port")
        if isinstance(p, int):
            ports.add(p)
        elif isinstance(p, str) and p.isdigit():
            ports.add(int(p))
        a = rec.get("asn") or rec.get("asnum")
        if isinstance(a, str) and a:
            # normalize "AS13335" form
            an = a.upper()
            if not an.startswith("AS"):
                an = "AS" + an.lstrip("AS")
            asns.add(an)
        c = rec.get("country") or rec.get("countrycode")
        if isinstance(c, str) and c:
            cc.add(c.upper())
        o = rec.get("organization") or rec.get("organisation") or rec.get("org")
        if isinstance(o, str) and o:
            orgs.add(o)
        iss = rec.get("issuer") or {}
        if isinstance(iss, dict):
            cn = iss.get("commonname") or iss.get("cn")
            if isinstance(cn, str) and cn:
                issuers.add(cn)
        elif isinstance(iss, str) and iss:
            issuers.add(iss)
        sub = rec.get("subject") or {}
        if isinstance(sub, dict):
            cn = sub.get("commonname") or sub.get("cn")
            if isinstance(cn, str) and cn:
                subjects.add(cn)
        fh = rec.get("favicon") or {}
        if isinstance(fh, dict):
            mm = fh.get("murmur") or fh.get("hash")
            if isinstance(mm, (str, int)):
                favs.add(str(mm))
        elif isinstance(fh, (str, int)):
            favs.add(str(fh))
        t = rec.get("title") or rec.get("http_title")
        if isinstance(t, str) and t.strip():
            titles.add(t.strip()[:120])
        pr = rec.get("product") or rec.get("productname")
        if isinstance(pr, str) and pr:
            prods.add(pr)
        tl = rec.get("threatlist") or rec.get("feed") or rec.get("category")
        if cat == "threatlist" and isinstance(tl, str) and tl:
            feeds.add(tl)
        if cat == "ctl":
            cert_count += 1
    d["ips"] = sorted(ips)
    d["jarms"] = sorted(jarms)
    d["subdomains"] = sorted(subs)
    d["ports"] = sorted(ports)
    d["asns"] = sorted(asns)
    d["countries"] = sorted(cc)
    d["organizations"] = sorted(orgs)[:20]
    d["tls_issuers"] = sorted(issuers)[:20]
    d["tls_subjects"] = sorted(subjects)[:20]
    d["favicon_hashes"] = sorted(favs)
    d["http_titles"] = sorted(titles)[:20]
    d["products"] = sorted(prods)[:20]
    d["threat_feeds"] = sorted(feeds)
    d["certs_seen"] = cert_count
    d["categories"] = dict(cats)
    return d


def _wrap(raw: dict, max_records: int = 30) -> dict:
    """Return {digest, error?, tier_restricted?, results: capped, raw fields}.

    Callers (agent) should consume `digest` for graphing and `results` for
    details. The `tier_restricted` flag is set when Onyphe returns an error
    indicating Griffin-tier membership is required.
    """
    if not isinstance(raw, dict):
        return {"digest": _empty_digest(), "results": [], "_raw_type": type(raw).__name__}
    err = raw.get("error") or 0
    text = (raw.get("text") or "").lower()
    tier_restricted = False
    if err and ("tier" in text or "griffin" in text or "subscription" in text
                or "forbidden" in text or "access denied" in text or "upgrade" in text):
        tier_restricted = True
    out = {
        "digest": _digest_summary(raw),
        "count": raw.get("count"),
        "error": err,
        "tier_restricted": tier_restricted,
        "results": (raw.get("results") or [])[:max_records],
    }
    if text:
        out["text"] = raw.get("text")
    return out


async def onyphe_summary_domain(domain: str) -> dict:
    if not ONYPHE_KEY:
        return _missing_key()
    raw = await get_json(f"https://www.onyphe.io/api/v2/summary/domain/{domain}",
                         headers=_auth(), ttl=3600)
    return _wrap(raw)


async def onyphe_summary_ip(ip: str) -> dict:
    if not ONYPHE_KEY:
        return _missing_key()
    raw = await get_json(f"https://www.onyphe.io/api/v2/summary/ip/{ip}",
                         headers=_auth(), ttl=3600)
    return _wrap(raw)


# ── Griffin View+ endpoints (require a Griffin-tier key) ──────────────────
async def onyphe_datascan(query: str) -> dict:
    """Onyphe datascan — banners/HTTP/TLS across the internet. `query` is a
    raw Onyphe query (e.g. `ip:1.2.3.4`, `jarm:<jarm>`, `product:nginx`)."""
    if not ONYPHE_KEY:
        return _missing_key()
    raw = await get_json(f"https://www.onyphe.io/api/v2/simple/datascan/{query}",
                         headers=_auth(), ttl=3600)
    return _wrap(raw)


async def onyphe_threatlist(ip: str) -> dict:
    """Onyphe threatlist — known-malicious IP hits from curated feeds."""
    if not ONYPHE_KEY:
        return _missing_key()
    raw = await get_json(f"https://www.onyphe.io/api/v2/simple/threatlist/{ip}",
                         headers=_auth(), ttl=3600)
    return _wrap(raw)


async def onyphe_resolver_forward(domain: str) -> dict:
    """Onyphe forward DNS resolution history for a domain."""
    if not ONYPHE_KEY:
        return _missing_key()
    raw = await get_json(f"https://www.onyphe.io/api/v2/simple/resolver/forward/{domain}",
                         headers=_auth(), ttl=3600)
    return _wrap(raw)


async def onyphe_resolver_reverse(ip: str) -> dict:
    """Onyphe reverse DNS resolution history for an IP (pDNS)."""
    if not ONYPHE_KEY:
        return _missing_key()
    raw = await get_json(f"https://www.onyphe.io/api/v2/simple/resolver/reverse/{ip}",
                         headers=_auth(), ttl=3600)
    return _wrap(raw)


async def onyphe_ctl(domain: str) -> dict:
    """Onyphe Certificate Transparency Logs — SAN pivots for a domain."""
    if not ONYPHE_KEY:
        return _missing_key()
    raw = await get_json(f"https://www.onyphe.io/api/v2/simple/ctl/{domain}",
                         headers=_auth(), ttl=3600)
    return _wrap(raw)


async def onyphe_pastries(query: str) -> dict:
    """Onyphe pastries — mentions of an IOC in pastebin-like dumps."""
    if not ONYPHE_KEY:
        return _missing_key()
    raw = await get_json(f"https://www.onyphe.io/api/v2/simple/pastries/{query}",
                         headers=_auth(), ttl=3600)
    return _wrap(raw)


async def onyphe_geoloc(ip: str) -> dict:
    """Onyphe geolocation — authoritative country/city per their dataset."""
    if not ONYPHE_KEY:
        return _missing_key()
    raw = await get_json(f"https://www.onyphe.io/api/v2/simple/geoloc/{ip}",
                         headers=_auth(), ttl=3600)
    return _wrap(raw)
