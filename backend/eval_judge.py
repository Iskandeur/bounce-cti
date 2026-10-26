"""Prospective cases, the server side (EVAL_PROTOCOL §4.E): fresh seeds and judge v2.

Two things a prospective batch needs that only the server can do, because the
feed keys live in its own ``.env`` (as ``demo_snapshot`` checks secrets there):

* :func:`fresh_iocs`: the indicators ThreatFox listed in the last days, each
  with the reasons it may or may not be a seed under the §4.E rules
  (``GET /api/admin/eval/fresh_iocs``). The keyless abuse.ch feeds were closed
  on 2026-10-25 (exports 410, ThreatFox ``browse`` 307, URLhaus 403).
* :func:`judge`: judge v2 (``otx+abusech/2``), every claim asked of OTX (with
  the server's key, the rate limit then holds a batch) and of abuse.ch
  (ThreatFox, URLhaus, MalwareBazaar) (``POST /api/admin/eval/judge``). Each
  section keeps, per listing, its id, creation date and author: who confirmed
  a claim, and how long after the seal, is part of the result (a mirror that
  copies a feed on day 1 is not an analyst a month later).

Never through the cache. ``graph_store.cache_get`` would answer a check with
what it stored at T, and the check would confirm nothing. Every request here
goes out, with ``urllib``.

Exact match only. ThreatFox ``search_ioc`` is a substring search: measured on
production's cache (2026-10-26), a domain also returns other domains that
contain it, and a bare IP returns ``ip:port`` entries next to URLs that contain
the IP. A claim is listed by an entry whose indicator is the claim itself.

Merge rule, as in judge v1: listed in any section is listed; "in no listing"
needs every section that can express the value to have answered; a section
that cannot express it (an imphash for MalwareBazaar) is ``n/a``; a value no
section can express is unjudgeable. Only OTX whitelists (``validation`` /
``false_positive``).

Stdlib only (plus ``defuse_lists`` and ``pivot_mapping`` for the shared
platforms). Network calls go through an injectable ``opener``.
"""
from __future__ import annotations

import ipaddress
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

JUDGE_V2 = "otx+abusech/2"
OTX_BASE = "https://otx.alienvault.com/api/v1/indicators"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_HOST = "https://urlhaus-api.abuse.ch/v1/host/"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"
MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
SECTIONS = {
    "ip": ("otx", "threatfox", "urlhaus"),
    "domain": ("otx", "threatfox", "urlhaus"),
    "url": ("otx", "threatfox", "urlhaus"),
    "hash": ("otx", "threatfox", "malwarebazaar"),
}
UNJUDGEABLE = "no exact lookup"
MAX_CLAIMS_PER_REQUEST = 20
# Between two requests of judge v2. Keyed, OTX allows 10,000 requests an hour;
# abuse.ch asks for fair use. A quarter second keeps a 20-claim chunk near a minute.
PAUSE_KEYED_S = 0.25
_RETRY_STATUS = {429, 500, 502, 503, 504}
_FILE_HASH_RE = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")
_UA = "bounce-cti-eval/judge-v2"


def _error(msg: str) -> dict:
    return {"state": "error", "error": msg}


def _na() -> dict:
    return {"state": "n/a"}


def is_unjudgeable(r: dict) -> bool:
    """An error that says the value cannot be asked, not that the judge failed."""
    return r.get("state") == "error" and UNJUDGEABLE in str(r.get("error") or "")


def _utc(s) -> str | None:
    """The feeds' dates, one form: ``2026-10-25T14:03:11Z`` (None when absent).
    ThreatFox and URLhaus write ``2026-10-25 14:03:11 UTC``, MalwareBazaar
    ``2026-10-25 14:03:11``, OTX ``2026-10-25T14:03:11.917000``."""
    if not s or not isinstance(s, str):
        return None
    t = s.strip().removesuffix(" UTC").removesuffix("Z").replace("T", " ")
    t = t.split(".")[0]
    try:
        return datetime.strptime(t, "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None


def _request(req: urllib.request.Request, *, opener, retries: int, backoff_s: float, sleep):
    """``(body, None)`` or ``(None, error)``. 429 and 5xx are retried; a
    ``Retry-After`` header, when given, wins over the backoff."""
    opener = opener or urllib.request.urlopen
    last = "no attempt"
    wait = 0.0
    for attempt in range(retries + 1):
        if attempt:
            sleep(wait or backoff_s * attempt)
        wait = 0.0
        try:
            with opener(req, timeout=60) as r:
                return json.loads(r.read()), None
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}"
            if e.code in _RETRY_STATUS:
                retry_after = e.headers.get("Retry-After") if e.headers else None
                if retry_after and str(retry_after).isdigit():
                    wait = min(float(retry_after), 300.0)
                continue
            return None, last
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last = f"network: {e}"
            continue
        except ValueError:
            return None, "answer is not JSON"
    return None, last


# ── OTX ────────────────────────────────────────────────────────────────────

def otx_paths(ntype: str, value: str) -> list[str]:
    """The OTX indicator paths for a claim, empty when OTX has no exact lookup
    for that value (an imphash typed ``hash``, an unknown type).

    A domain gets two: OTX files a registrable domain under ``domain`` and a
    subdomain under ``hostname``, and the other section answers a clean zero
    (2026-10-25: ``moonzonet.com``, a C2 of case 2, is in 46 pulses under
    ``domain`` and in none under ``hostname``; ``cdn.jsdelivr.net`` the other
    way round). Telling the two apart needs the public suffix list, so both
    are asked."""
    if ntype == "ip":
        sections = ["IPv6" if ":" in value else "IPv4"]
    elif ntype == "domain":
        sections = ["hostname", "domain"]
    elif ntype == "url":
        sections = ["url"]
    elif ntype == "hash" and _FILE_HASH_RE.match(value):
        sections = ["file"]
    else:
        return []
    # OTX takes the raw URL in the path (its own documented form); only what
    # would end the path early or break the request line is escaped.
    quoted = urllib.parse.quote(value, safe=":/@!$&'()*+,;=-._~") if ntype == "url" else value
    return [f"{OTX_BASE}/{s}/{quoted}/general" for s in sections]


def _otx_get(url: str, *, key, opener, retries, backoff_s, sleep) -> dict:
    """One OTX section. An answer without ``pulse_info`` is an error, never "in
    no pulse": a reader that cannot see is not a negative."""
    headers = {"User-Agent": "bounce-cti-eval/prospective", "Accept": "application/json"}
    if key:
        headers["X-OTX-API-KEY"] = key
    body, err = _request(urllib.request.Request(url, headers=headers), opener=opener,
                         retries=retries, backoff_s=backoff_s, sleep=sleep)
    if err:
        return _error(err)
    pi = body.get("pulse_info") if isinstance(body, dict) else None
    if not isinstance(pi, dict) or not isinstance(pi.get("pulses"), list):
        return _error("answer has no pulse_info")
    raw = [p for p in pi["pulses"] if isinstance(p, dict) and p.get("id")]
    pulses = sorted({str(p.get("id")) for p in raw})
    count = pi.get("count") if isinstance(pi.get("count"), int) else len(pulses)
    flags = [v for f in ("validation", "false_positive")
             for v in (body.get(f) if isinstance(body.get(f), list) else [])]
    whitelist = sorted({str(v.get("source") or v.get("name") or "?") for v in flags
                        if isinstance(v, dict)})
    entries = sorted(({"id": str(p["id"]), "created": _utc(p.get("created")),
                       "author": (p.get("author") or {}).get("username")
                       if isinstance(p.get("author"), dict) else None} for p in raw),
                     key=lambda e: e["id"])
    return {"state": "listed" if (count or pulses) else "unlisted", "count": max(count, len(pulses)),
            "pulses": pulses, "entries": entries, "whitelist": whitelist}


def otx_lookup(ntype: str, value: str, *, key: str | None = None, opener=None,
               retries: int = 3, backoff_s: float = 15.0, sleep=time.sleep) -> dict:
    """``{"state": "listed"|"unlisted", "count", "pulses", "entries", "whitelist"}``,
    or ``{"state": "error", "error"}``. Listed in any section is listed;
    otherwise one failed section makes the whole answer an error: "in no
    pulse" needs every section to have answered."""
    paths = otx_paths(ntype, value)
    if not paths:
        return _error(f"{UNJUDGEABLE} in OTX for this {ntype}")
    answers = [_otx_get(p, key=key, opener=opener, retries=retries, backoff_s=backoff_s, sleep=sleep)
               for p in paths]
    ok = [a for a in answers if a["state"] != "error"]
    pulses = sorted({p for a in ok for p in a["pulses"]})
    entries = sorted({e["id"]: e for a in ok for e in a["entries"]}.values(), key=lambda e: e["id"])
    merged = {"state": "listed" if any(a["state"] == "listed" for a in ok) else "unlisted",
              "count": max([len(pulses)] + [a["count"] for a in ok]),
              "pulses": pulses, "entries": entries,
              "whitelist": sorted({w for a in ok for w in a["whitelist"]})}
    if merged["state"] == "unlisted" and len(ok) < len(answers):
        return _error("; ".join(a["error"] for a in answers if a["state"] == "error"))
    return merged


# ── abuse.ch ───────────────────────────────────────────────────────────────

def _abusech(url: str, *, key: str, json_body=None, form=None, opener, retries, backoff_s, sleep):
    headers = {"User-Agent": _UA, "Accept": "application/json", "Auth-Key": key}
    if json_body is not None:
        data = json.dumps(json_body).encode()
        headers["Content-Type"] = "application/json"
    else:
        data = urllib.parse.urlencode(form or {}).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    return _request(urllib.request.Request(url, data=data, headers=headers, method="POST"),
                    opener=opener, retries=retries, backoff_s=backoff_s, sleep=sleep)


def _listed(entries: list[dict]) -> dict:
    entries = sorted(entries, key=lambda e: (e.get("created") or "", e["id"]))
    return {"state": "listed" if entries else "unlisted", "count": len(entries),
            "entries": entries, "whitelist": []}


def threatfox_matches(ntype: str, value: str, entries) -> list[dict]:
    """The ThreatFox entries whose indicator IS the claim (``search_ioc`` is a
    substring search). An ``ip`` claim matches ``ip:port`` entries on that
    host; ``domain``, ``url`` and ``hash`` match their own type, value equal."""
    out = []
    v = value.strip()
    for d in entries if isinstance(entries, list) else []:
        if not isinstance(d, dict):
            continue
        ioc, itype = str(d.get("ioc") or "").strip(), str(d.get("ioc_type") or "")
        if ntype == "ip":
            hit = itype == "ip:port" and ioc.rsplit(":", 1)[0].strip("[]").lower() == v.lower()
        elif ntype == "domain":
            hit = itype == "domain" and ioc.lower().rstrip(".") == v.lower().rstrip(".")
        elif ntype == "url":
            hit = itype == "url" and ioc == v
        else:
            hit = itype.endswith("_hash") and ioc.lower() == v.lower()
        if hit:
            out.append({"id": str(d.get("id")), "created": _utc(d.get("first_seen")),
                        "author": d.get("reporter"), "family": d.get("malware"),
                        "compromised": bool(d.get("is_compromised"))})
    return out


def threatfox_lookup(ntype: str, value: str, *, key: str, opener=None, retries: int = 3,
                     backoff_s: float = 15.0, sleep=time.sleep) -> dict:
    if ntype == "hash" and not _FILE_HASH_RE.match(value.lower()):
        return _na()
    body, err = _abusech(THREATFOX_API, key=key, json_body={"query": "search_ioc", "search_term": value},
                         opener=opener, retries=retries, backoff_s=backoff_s, sleep=sleep)
    if err:
        return _error(f"{err}")
    status = body.get("query_status") if isinstance(body, dict) else None
    if status == "no_result":
        return _listed([])
    if status != "ok":
        return _error(f"query_status {status!r}")
    return _listed(threatfox_matches(ntype, value, body.get("data")))


def urlhaus_lookup(ntype: str, value: str, *, key: str, opener=None, retries: int = 3,
                   backoff_s: float = 15.0, sleep=time.sleep) -> dict:
    """URLhaus by host (an ip or a domain: the URLs it ever served) or by URL."""
    if ntype in ("ip", "domain"):
        url, form = URLHAUS_HOST, {"host": value}
    elif ntype == "url":
        url, form = URLHAUS_URL, {"url": value}
    else:
        return _na()
    body, err = _abusech(url, key=key, form=form, opener=opener, retries=retries,
                         backoff_s=backoff_s, sleep=sleep)
    if err:
        return _error(f"{err}")
    status = body.get("query_status") if isinstance(body, dict) else None
    if status == "no_results":
        return _listed([])
    if status != "ok":
        return _error(f"query_status {status!r}")
    if ntype == "url":
        if str(body.get("url") or "") != value:
            return _listed([])
        return _listed([{"id": str(body.get("id")), "created": _utc(body.get("date_added")),
                         "author": body.get("reporter")}])
    host = str(body.get("host") or "").lower().rstrip(".")
    if host and host != value.lower().rstrip("."):
        return _listed([])
    urls = body.get("urls") if isinstance(body.get("urls"), list) else []
    return _listed([{"id": str(u.get("id")), "created": _utc(u.get("date_added")),
                     "author": u.get("reporter")} for u in urls if isinstance(u, dict)])


def malwarebazaar_lookup(ntype: str, value: str, *, key: str, opener=None, retries: int = 3,
                         backoff_s: float = 15.0, sleep=time.sleep) -> dict:
    if ntype != "hash" or not _FILE_HASH_RE.match(value.lower()):
        return _na()
    body, err = _abusech(MALWAREBAZAAR_API, key=key, form={"query": "get_info", "hash": value},
                         opener=opener, retries=retries, backoff_s=backoff_s, sleep=sleep)
    if err:
        return _error(f"{err}")
    status = body.get("query_status") if isinstance(body, dict) else None
    if status == "hash_not_found":
        return _listed([])
    if status != "ok":
        return _error(f"query_status {status!r}")
    v = value.lower()
    data = body.get("data") if isinstance(body.get("data"), list) else []
    return _listed([{"id": str(s.get("sha256_hash")), "created": _utc(s.get("first_seen")),
                     "author": s.get("reporter")}
                    for s in data if isinstance(s, dict)
                    and v in {str(s.get(k) or "").lower() for k in ("md5_hash", "sha1_hash", "sha256_hash")}])


def merge(sections: dict[str, dict]) -> dict:
    """One answer from the sections' (judge v2's rule, the same as v1's
    between OTX's own two sections)."""
    asked = {s: a for s, a in sections.items() if a.get("state") != "n/a"}
    if not asked:
        return _error(f"{UNJUDGEABLE} in any section") | {"sections": sections}
    ok = [a for a in asked.values() if a["state"] != "error"]
    listed = any(a["state"] == "listed" for a in ok)
    whitelist = sorted({w for a in ok for w in a.get("whitelist") or []})
    if not listed and len(ok) < len(asked):
        return _error("; ".join(f"{s}: {a['error']}" for s, a in sorted(asked.items())
                                if a["state"] == "error")) | {"whitelist": whitelist, "sections": sections}
    return {"state": "listed" if listed else "unlisted",
            "count": sum(a.get("count") or 0 for a in ok),
            "whitelist": whitelist, "sections": sections}


def judge_one(ntype: str, value: str, *, otx_key: str | None, abusech_key: str, opener=None,
              pause_s: float = PAUSE_KEYED_S, sleep=time.sleep, retries: int = 3,
              backoff_s: float = 15.0) -> dict:
    lookups = {"otx": lambda: otx_lookup(ntype, value, key=otx_key, opener=opener, retries=retries,
                                         backoff_s=backoff_s, sleep=sleep),
               "threatfox": lambda: threatfox_lookup(ntype, value, key=abusech_key, opener=opener,
                                                     retries=retries, backoff_s=backoff_s, sleep=sleep),
               "urlhaus": lambda: urlhaus_lookup(ntype, value, key=abusech_key, opener=opener,
                                                 retries=retries, backoff_s=backoff_s, sleep=sleep),
               "malwarebazaar": lambda: malwarebazaar_lookup(ntype, value, key=abusech_key, opener=opener,
                                                             retries=retries, backoff_s=backoff_s, sleep=sleep)}
    sections: dict[str, dict] = {}
    for i, name in enumerate(SECTIONS.get(ntype, ())):
        if i and pause_s:
            sleep(pause_s)
        r = lookups[name]()
        if name == "otx" and is_unjudgeable(r):
            r = _na()
        sections[name] = r
    return merge(sections)


def judge(claims: list[dict], *, otx_key: str | None, abusech_key: str, opener=None,
          pause_s: float = PAUSE_KEYED_S, sleep=time.sleep) -> dict:
    """``{"judge": JUDGE_V2, "lookups": {"type|value": answer}}`` for each claim."""
    out: dict[str, dict] = {}
    for i, c in enumerate(claims):
        ntype, value = str(c.get("type") or ""), str(c.get("value") or "").strip()
        k = f"{ntype}|{value}"
        if k in out:
            continue
        if i and pause_s:
            sleep(pause_s)
        out[k] = judge_one(ntype, value, otx_key=otx_key, abusech_key=abusech_key, opener=opener,
                           pause_s=pause_s, sleep=sleep)
    return {"judge": JUDGE_V2, "lookups": out}


# ── fresh seeds ────────────────────────────────────────────────────────────

MAX_AGE_HOURS = 48
MIN_CONFIDENCE = 50
# Shared platforms a fresh seed may not sit on (§4.E rule 1), beyond the CDN /
# dyndns / cloud-platform lists the agent already uses: URL shorteners, file
# and code hosting, paste sites, tunnels. A seed there is the platform's abuse,
# not an actor's infrastructure (the N2 failure mode).
SHARED_HOSTS = (
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "goo.gl", "ow.ly", "buff.ly",
    "shorturl.at", "rebrand.ly", "t.ly", "tiny.cc",
    "github.com", "raw.githubusercontent.com", "objects.githubusercontent.com", "gist.github.com",
    "gitlab.com", "bitbucket.org", "codeberg.org",
    "drive.google.com", "docs.google.com", "storage.googleapis.com", "dropbox.com",
    "dl.dropboxusercontent.com", "onedrive.live.com", "1drv.ms", "sharepoint.com",
    "mediafire.com", "mega.nz", "we.tl", "wetransfer.com", "transfer.sh", "filebin.net",
    "cdn.discordapp.com", "discord.com", "media.discordapp.net", "telegra.ph", "t.me",
    "pastebin.com", "paste.ee", "rentry.co", "hastebin.com",
    "trycloudflare.com", "ngrok.io", "ngrok-free.app", "ngrok.app", "serveo.net", "loca.lt",
    "duckdns.org", "no-ip.com", "ddns.net",
)
_TF_TYPES = {"ip:port": "ip", "domain": "domain", "url": "url",
             "md5_hash": "hash", "sha1_hash": "hash", "sha256_hash": "hash"}


def _host_of(seed_type: str, value: str) -> str | None:
    if seed_type == "domain":
        return value.lower().rstrip(".")
    if seed_type == "url":
        try:
            return (urllib.parse.urlsplit(value).hostname or "").lower().rstrip(".") or None
        except ValueError:
            return None
    return None


def _on_shared_host(host: str) -> bool:
    return any(host == h or host.endswith("." + h) for h in SHARED_HOSTS)


def _no_family(d: dict) -> bool:
    m = str(d.get("malware") or "").strip().lower()
    p = str(d.get("malware_printable") or "").strip().lower()
    return not m or m == "unknown" or m.endswith(".unknown") or p in ("", "unknown", "unknown malware")


def candidate(d: dict, now: datetime) -> dict | None:
    """One ThreatFox entry as a candidate seed, with ``excluded_by``: the §4.E
    rules it breaks (empty = eligible). None for a type Bounce-CTI cannot seed."""
    from .defuse_lists import defuse_check, is_dyndns_domain
    from .pivot_mapping import cloud_platform_domain

    seed_type = _TF_TYPES.get(str(d.get("ioc_type") or ""))
    ioc = str(d.get("ioc") or "").strip()
    if not seed_type or not ioc:
        return None
    value = ioc.rsplit(":", 1)[0].strip("[]") if seed_type == "ip" else ioc
    if seed_type in ("domain", "hash"):
        value = value.lower().rstrip(".")
    first_seen = _utc(d.get("first_seen"))
    excluded: list[str] = []
    if first_seen is None:
        excluded.append("no first_seen")
    else:
        age_h = (now - datetime.strptime(first_seen, "%Y-%m-%dT%H:%M:%SZ")
                 .replace(tzinfo=timezone.utc)).total_seconds() / 3600
        if age_h > MAX_AGE_HOURS:
            excluded.append(f"first listed {age_h:.0f} h ago (> {MAX_AGE_HOURS} h)")
    if _no_family(d):
        excluded.append("no family tag")
    conf = d.get("confidence_level")
    if not isinstance(conf, int) or conf < MIN_CONFIDENCE:
        excluded.append(f"confidence {conf} (< {MIN_CONFIDENCE})")
    if d.get("is_compromised"):
        excluded.append("compromised site (a victim, not the actor's)")
    if seed_type == "ip":
        try:
            if not ipaddress.ip_address(value).is_global:
                excluded.append("not a public address")
        except ValueError:
            excluded.append("not an IP address")
        else:
            tags = defuse_check("ip", value)["tags"]
            if tags:
                excluded.append("shared platform: " + ", ".join(tags))
    host = _host_of(seed_type, value)
    if seed_type in ("domain", "url"):
        if not host:
            excluded.append("no host")
        elif cloud_platform_domain(host) or is_dyndns_domain(host) or _on_shared_host(host):
            excluded.append(f"shared platform: {host}")
    return {"seed_type": seed_type, "seed_value": value, "first_seen": first_seen,
            "family": str(d.get("malware") or "") or None, "family_name": d.get("malware_printable"),
            "threat_type": d.get("threat_type"), "confidence": conf, "reporter": d.get("reporter"),
            "tags": list(d.get("tags") or []) if isinstance(d.get("tags"), list) else [],
            "source": f"threatfox:{d.get('id')}", "excluded_by": excluded}


def fresh_iocs(*, abusech_key: str, days: int = 2, now: datetime | None = None, opener=None,
               sleep=time.sleep) -> dict:
    """ThreatFox ``get_iocs`` for the last ``days`` (1 to 7), as candidates."""
    now = now or datetime.now(timezone.utc)
    days = max(1, min(int(days), 7))
    body, err = _abusech(THREATFOX_API, key=abusech_key, json_body={"query": "get_iocs", "days": days},
                         opener=opener, retries=3, backoff_s=15.0, sleep=sleep)
    if err:
        raise RuntimeError(f"threatfox get_iocs: {err}")
    status = body.get("query_status") if isinstance(body, dict) else None
    if status == "no_result":
        data = []
    elif status == "ok" and isinstance(body.get("data"), list):
        data = body["data"]
    else:
        raise RuntimeError(f"threatfox get_iocs: query_status {status!r}")
    cands = [c for c in (candidate(d, now) for d in data if isinstance(d, dict)) if c]
    cands.sort(key=lambda c: (c["first_seen"] or "", c["seed_value"]), reverse=True)
    return {"source": "threatfox get_iocs", "days": days,
            "fetched_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "rules": {
                "max_age_hours": MAX_AGE_HOURS, "min_confidence": MIN_CONFIDENCE,
                "family": "required", "shared_platforms": "excluded", "compromised": "excluded"},
            "count": len(cands), "eligible": sum(1 for c in cands if not c["excluded_by"]),
            "candidates": cands}
