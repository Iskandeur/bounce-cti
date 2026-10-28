"""Prospective cases: seeds investigated before anyone has written them up, judged
later by what an independent feed confirms (EVAL_PROTOCOL §4.E).

Every case in cases.py takes its ground truth from a public write-up. The J4
baseline (§4.D) showed what that costs: the bare model with web search read the
write-up of its own case on 3 of the 5 fresh cases, so those cases measure who
reads the answer key, not who investigates. A prospective case takes the answer
key out of the world at run time: the seed is fresh (listed hours ago, nothing
written about it yet), every arm runs on it at the same time, and the judgement
waits until a fixed horizon has passed.

The judge is an independent feed, queried for every claim twice: when the batch
is sealed (T) and after the horizon. Judge v1 is AlienVault OTX pulses, exact
indicator match (keyless; ``OTX_API_KEY`` is sent when set, for the rate limit
only). Judge v2 (``--server``) adds ThreatFox, URLhaus and MalwareBazaar, asked
through the server, which holds the keys (backend/eval_judge.py). A claim is
what an arm would hand a defender: the domain, ip, url and hash nodes
backend.action_exports would put in a blocklist or a detection rule (no lead,
no unverified or defused node), minus the seed. Each claim lands in one class:

- ``known``: already in a pulse at T. The arm could have read it there. Under
  judge v2, also a claim the check finds in an abuse.ch entry dated before T
  (``known_late``): the feed had it, its search did not return it yet.
- ``ahead``: in no pulse at T, in one at the check. Found before the feed had it.
- ``unconfirmed``: in no pulse either time. Not shown wrong, not shown right.
- ``benign``: OTX whitelists it (``validation`` / ``false_positive``) at either
  time. Shared infrastructure, the N2 failure mode.
- ``undetermined``: a lookup failed either time, or the judge cannot express the
  value. Never counted as "in no pulse".

Per arm: the counts, ``ahead_share`` = ahead / (ahead + unconfirmed), and
``pooled_recall`` = ahead / the union of every arm's ahead claims on the same
seed (pooling as in TREC: the pool is what the systems found, the feed judges it).

Pre-registration. ``seal`` freezes the claims of every arm, the judge's answer at
T, the horizon and the judge version in ``manifest.json``, then writes
``commitment.json``: the manifest's sha256 and counts, no indicator value. Commit
the commitment at T: its commit date proves the claims were fixed before the
judge spoke. ``check`` and ``score`` refuse a manifest whose hash is not the
committed one, and ``check`` refuses to run before the horizon unless ``--early``
(every score from an early check says provisional).

    S="--server https://cti.alexandre-pinoteau.fr --cookies <admin cookie jar>"
    python3 eval/prospective.py seeds --batch <dir> $S [--n 6] [--avoid <lot1>/seeds.json]
    python3 eval/prospective.py preflight --batch <dir> $S
    python3 eval/prospective.py pivot --batch <dir> --out <pivot-dir> $S
    python3 eval/prospective.py seal --batch <dir> --arm bounce=<dir> --arm web=<dir> --arm pivot-1=<pivot-dir> $S \\
        [--horizon-days 14] [--secondary-horizon-days 30]
    python3 eval/prospective.py check --batch <dir> $S [--early] [--secondary]
    python3 eval/prospective.py score --batch <dir> [--check <file>] [--write]

``pivot`` fills the mechanical arm ``pivot-1`` (§4.E rule 1, the base rate): the server runs
each seed's mandatory tools on the seed alone, no model (POST /api/admin/eval/pivot), under one
timestamp. ``seal`` refuses ``--arm pivot-1=`` filled for other seeds or not within the hour
before the seal: run it in the same hour as the other arms.

``seeds`` picks the batch from the server's fresh ThreatFox entries by a fixed
rule (pick/1), once. Judge v2 has a positive control: a seed picked from a feed
must be listed in that section at T, or nothing is sealed (``preflight`` tells
before the arms run). A seed the search does not return is then read by its id:
an entry still in the feed is ``late`` (the search lags; the batch can be sealed
as long as the search returns at least one other seed of that feed), a gone
entry or one read with another value is a refusal. At the check the control is
strict: every seed must be returned by its feed's search, or the batch is not
scored (a seed its feed withdrew is reported). Every batch pre-registers a
secondary horizon (30 days).

``<batch>/seeds.json`` lists the batch: ``[{"label": "P1", "seed_type": "ip",
"seed_value": "…", "first_seen": "<UTC>", "source": "<where it was picked>"}]``.
An arm directory holds one ``<label>/graph.json`` per seed (the layout fetch.py
writes, and ``baseline.py run --seeds``). The manifest, the checks and the arms'
graphs stay out of the repository: claims can name victims and other third
parties. ``commitment.json`` and ``results.json`` / ``results.md`` (counts only)
are the parts meant to be committed.

Exit codes: 0 done; 1 the manifest is not the committed one; 2 usage or input
error; 3 the check is not due yet (``--early`` to run it anyway); 4 lookups
failed at T, nothing sealed (seal again later, or with ``OTX_API_KEY``), or
judge v2 does not see a seed in its own feed (at ``preflight`` and ``seal``;
at ``check``, and then ``score`` refuses that check).

Stdlib only, plus backend.action_exports for the definition of a claim and
backend.eval_judge for the OTX lookup and judge v2's name.
"""
from __future__ import annotations

import argparse
import hashlib
import http.cookiejar
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
# The definition of "what an arm would hand a defender" lives with the exports
# themselves: change what a blocklist leaves out, and the claims follow.
from backend.action_exports import _HASH_TYPES, _NETWORK_TYPES, _iter_actionable  # noqa: E402
from backend.eval_judge import (  # noqa: E402,F401  (otx_* re-exported: judge v1 lives here)
    JUDGE_V2, MAX_CLAIMS_PER_REQUEST, MAX_ENTRIES_PER_REQUEST, is_unjudgeable, otx_lookup, otx_paths,
)

JUDGE = "otx-pulses/1"
JUDGES = (JUDGE, JUDGE_V2)
CLAIM_TYPES = frozenset(_NETWORK_TYPES | _HASH_TYPES)
CLASSES = ("known", "ahead", "unconfirmed", "benign", "undetermined")
BAD_TAGS = {"malicious", "c2", "phishing", "malware", "attacker"}  # as eval/scorer.score_negative
# Between requests: the keyless OTX API answered 429 after ~60 calls in 3 minutes
# (measured 2026-10-25, EVAL_PROTOCOL §4.E).
PAUSE_S = 3.0
LABEL_RE = re.compile(r"[A-Za-z0-9_-]+")
COMMITTED_DIR = ROOT / "eval" / "prospective"
EXIT_TAMPERED, EXIT_USAGE, EXIT_NOT_DUE, EXIT_JUDGE = 1, 2, 3, 4


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


# ── claims ─────────────────────────────────────────────────────────────────

def normalise(ntype: str, value) -> str:
    v = str(value or "").strip()
    if ntype == "url":
        return v
    v = v.lower()
    return v.rstrip(".") if ntype == "domain" else v


def claims_of(graph: dict, seed_value: str) -> list[dict]:
    """The nodes an arm would hand a defender, minus the seed, one per value."""
    seed = str(seed_value or "").strip().lower()
    out: dict[str, dict] = {}
    for n in _iter_actionable(graph.get("nodes") or [], CLAIM_TYPES):
        ntype = n.get("type")
        value = normalise(ntype, n.get("value"))
        tags = set(n.get("tags") or [])
        if not value or "seed" in tags or value.lower() == seed:
            continue
        c = out.setdefault(f"{ntype}|{value}", {"type": ntype, "value": value, "malicious": False})
        c["malicious"] = c["malicious"] or bool(tags & BAD_TAGS)
    return [out[k] for k in sorted(out)]


# ── the judge ──────────────────────────────────────────────────────────────
# Judge v1 is OTX, asked from here (keyless, or with OTX_API_KEY). Judge v2 is
# OTX + abuse.ch, asked through the server, which holds the keys
# (POST /api/admin/eval/judge, backend/eval_judge.py). Both share the OTX code.

def _unjudgeable(r: dict) -> bool:
    return is_unjudgeable(r)


# Judge v2 sections whose entry IS the indicator, dated when the feed listed it.
# An OTX pulse is not: an indicator can be added to a pulse created long before.
DATED_SECTIONS = ("threatfox", "urlhaus", "malwarebazaar")


def listed_before(answer, t: datetime) -> bool:
    """Judge v2: an abuse.ch entry of ``answer`` was created before ``t``."""
    secs = (answer or {}).get("sections") if isinstance(answer, dict) else None
    for name in DATED_SECTIONS:
        a = (secs or {}).get(name)
        if isinstance(a, dict) and a.get("state") == "listed":
            for e in a.get("entries") or []:
                created = e.get("created") if isinstance(e, dict) else None
                if created and _parse_iso(created) < t:
                    return True
    return False


def classify(at_t: dict | None, at_check: dict | None, sealed_at: datetime | None = None) -> str:
    """``sealed_at`` (judge v2): a claim the check finds in an abuse.ch entry
    dated before the seal was in the feed at T, whatever its search answered
    then (the 2026-10-27 canary: ThreatFox's search did not return 3 of 6
    entries an hour old). It is ``known``, not ``ahead``."""
    if not at_t or not at_check or "error" in (at_t.get("state"), at_check.get("state")):
        return "undetermined"
    if at_t.get("whitelist") or at_check.get("whitelist"):
        return "benign"
    if at_t.get("state") == "listed":
        return "known"
    if at_check.get("state") != "listed":
        return "unconfirmed"
    return "known" if sealed_at is not None and listed_before(at_check, sealed_at) else "ahead"


def _lookup_all(keys, lookup, pause_s: float, sleep) -> dict:
    """One lookup per distinct ``type|value``, paced for a keyless API: the pause
    after a lookup counts the requests it made (two for a domain)."""
    out: dict[str, dict] = {}
    requests_before = 0
    for k in sorted(set(keys)):
        if requests_before and pause_s:
            sleep(pause_s * requests_before)
        ntype, value = k.split("|", 1)
        out[k] = lookup(ntype, value)
        requests_before = max(1, len(otx_paths(ntype, value)))
    return out


# ── files ──────────────────────────────────────────────────────────────────

def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _dump(path: Path, doc) -> None:
    path.write_text(json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                    encoding="utf-8")


def load_seeds(batch: Path) -> list[dict]:
    seeds = json.loads((batch / "seeds.json").read_text(encoding="utf-8"))
    labels = set()
    for s in seeds:
        missing = [k for k in ("label", "seed_type", "seed_value", "first_seen", "source") if not s.get(k)]
        if missing:
            raise ValueError(f"seed {s.get('label') or '?'}: missing {', '.join(missing)}")
        if not LABEL_RE.fullmatch(str(s["label"])):
            # The label names a directory under every arm: "../x" would leave it.
            raise ValueError(f"seed label {s['label']!r}: letters, digits, '_' and '-' only")
        if s["label"] in labels:
            raise ValueError(f"seed label {s['label']} appears twice")
        labels.add(s["label"])
    return seeds


def committed_copy(batch: Path) -> Path:
    """Where the pre-registration lives once committed: the repo, not the batch."""
    return COMMITTED_DIR / batch.name / "commitment.json"


def load_manifest(batch: Path) -> dict:
    """The manifest, if and only if it is the one the commitment names, and the
    one the committed copy names when the repo has it. The batch's own
    commitment.json is written by whoever sealed the batch: only the copy in
    git, dated by its commit, proves the claims were fixed at T."""
    commitment = json.loads((batch / "commitment.json").read_text(encoding="utf-8"))
    digest = _sha256(batch / "manifest.json")
    if digest != commitment.get("manifest_sha256"):
        raise PermissionError(f"manifest.json is not the sealed one (sha256 {digest[:12]}, "
                              f"committed {str(commitment.get('manifest_sha256'))[:12]})")
    copy = committed_copy(batch)
    if copy.is_file():
        pinned = json.loads(copy.read_text(encoding="utf-8")).get("manifest_sha256")
        if digest != pinned:
            raise PermissionError(f"manifest.json is not the one {copy} names "
                                  f"(sha256 {digest[:12]}, committed {str(pinned)[:12]})")
    return json.loads((batch / "manifest.json").read_text(encoding="utf-8"))


# ── the server (judge v2, fresh seeds) ─────────────────────────────────────

def server_opener(cookies: Path):
    """An opener that sends the admin session of a cookie jar (Netscape format,
    as ``curl -c`` writes it, the one ``fetch.py`` reads)."""
    jar = http.cookiejar.MozillaCookieJar(str(cookies))
    jar.load(ignore_discard=True, ignore_expires=True)
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar)).open


def server_call(base: str, path: str, *, opener, body=None, timeout: float = 600) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Accept": "application/json", "User-Agent": "bounce-cti-eval/prospective"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base.rstrip("/") + path, data=data, headers=headers,
                                 method="POST" if data is not None else "GET")
    with opener(req, timeout=timeout) as r:
        return json.loads(r.read())


def server_lookup_all(keys, *, base: str, opener, chunk: int = MAX_CLAIMS_PER_REQUEST) -> dict:
    """Judge v2 through ``POST /api/admin/eval/judge``, ``chunk`` claims a
    request. A request that fails leaves its claims in error (the server's
    status in the message), never "in no listing"."""
    out: dict[str, dict] = {}
    keys = sorted(set(keys))
    for i in range(0, len(keys), chunk):
        part = keys[i:i + chunk]
        claims = [dict(zip(("type", "value"), k.split("|", 1))) for k in part]
        try:
            doc = server_call(base, "/api/admin/eval/judge", opener=opener, body={"claims": claims})
        except urllib.error.HTTPError as e:
            out.update({k: {"state": "error", "error": f"server: HTTP {e.code}"} for k in part})
            continue
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            out.update({k: {"state": "error", "error": f"server: {e}"} for k in part})
            continue
        if doc.get("judge") != JUDGE_V2:
            raise ValueError(f"the server judged as {doc.get('judge')!r}, expected {JUDGE_V2!r}")
        lookups = doc.get("lookups") if isinstance(doc.get("lookups"), dict) else {}
        for k in part:
            out[k] = lookups.get(k) or {"state": "error", "error": "server: no answer for this claim"}
    return out


def server_entries(refs, *, base: str, opener) -> dict:
    """Seed sources (``threatfox:<id>``) read by id through the judge route's
    ``entries``. A failed request leaves every entry in error."""
    refs = sorted(set(refs))
    out: dict[str, dict] = {}
    for i in range(0, len(refs), MAX_ENTRIES_PER_REQUEST):
        part = refs[i:i + MAX_ENTRIES_PER_REQUEST]
        try:
            doc = server_call(base, "/api/admin/eval/judge", opener=opener,
                              body={"claims": [], "entries": part})
        except urllib.error.HTTPError as e:
            out.update({r: {"state": "error", "error": f"server: HTTP {e.code}"} for r in part})
            continue
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            out.update({r: {"state": "error", "error": f"server: {e}"} for r in part})
            continue
        got = doc.get("entries") if isinstance(doc.get("entries"), dict) else {}
        for r in part:
            # A server older than the entries field answers without it.
            out[r] = got.get(r) or {"state": "error", "error": "server: no entry lookup (an older server?)"}
    return out


_FEED_SECTIONS = ("otx", "threatfox", "urlhaus", "malwarebazaar")


def seed_feed(seed: dict) -> str | None:
    """The judge section a seed was picked from (``threatfox:<id>`` → threatfox)."""
    feed = str(seed.get("source") or "").split(":", 1)[0].strip().lower()
    return feed if feed in _FEED_SECTIONS else None


def _seed_key(s: dict) -> str:
    return f"{s['seed_type']}|{normalise(s['seed_type'], s['seed_value'])}"


def _feed_state(s: dict, answers: dict) -> str | None:
    a = answers.get(_seed_key(s)) or {}
    return ((a.get("sections") or {}).get(seed_feed(s)) or {}).get("state")


def _entry_is_seed(entry: dict, s: dict) -> bool:
    """The entry read by id holds the seed as it was picked (fresh_iocs takes the
    host of an ``ip:port`` entry)."""
    ioc, itype = str(entry.get("ioc") or ""), str(entry.get("ioc_type") or "")
    if s["seed_type"] == "ip":
        return itype == "ip:port" and ioc.rsplit(":", 1)[0].strip("[]").lower() == \
            normalise("ip", s["seed_value"])
    return normalise(s["seed_type"], ioc) == normalise(s["seed_type"], s["seed_value"])


def _unseen(seeds: list[dict], answers: dict) -> list[dict]:
    return [s for s in seeds if seed_feed(s) and _feed_state(s, answers) != "listed"]


def control(seeds: list[dict], answers: dict, entries: dict | None = None, *, strict: bool = False) -> dict:
    """Judge v2's positive control. A seed picked from a feed is listed there by
    construction: if the judge's section for that feed does not list it, the
    section may be blind (a renamed field, a changed match rule, a key that no
    longer works) and every "in no listing" it gives is worthless. A judge of
    absence is fired at a known presence first.

    The search alone cannot say why a seed is missing: on 2026-10-27, 3 of 6
    seeds an hour old were not returned by ThreatFox's search while their
    neighbours were. ``entries`` (each unseen seed read by its id) tells:

    * still in the feed, same value: ``late``. At T this is accepted, because
      a claim the check finds in an abuse.ch entry dated before T is scored
      ``known`` (:func:`classify`), so a lagging search cannot turn the feed's
      own knowledge into "ahead". Not when the search returns no seed of that
      feed at all: then the search path itself is suspect.
    * gone, read with another value, or unreadable: a refusal.

    ``strict`` (the check, a horizon later): every seed must be returned by its
    feed's search; a present entry the search still misses is a blind search.
    A seed whose entry is gone is ``withdrawn``: the feed retracted it, which
    is reported, not a judge failure.

    Returns ``{"blind": [reason, …], "late": {label: {...}}, "withdrawn": [label, …]}``."""
    blind: list[str] = []
    late: dict[str, dict] = {}
    withdrawn: list[str] = []
    returned: dict[str, int] = {}
    for s in seeds:
        feed = seed_feed(s)
        if not feed:
            continue
        state = _feed_state(s, answers)
        if state == "listed":
            returned[feed] = returned.get(feed, 0) + 1
            continue
        why = f"{s['label']}: picked from {feed}, which answers {state or 'nothing'}"
        e = (entries or {}).get(str(s.get("source") or "").strip())
        if e is None:
            blind.append(why)
            continue
        eid = e.get("id") or str(s.get("source")).partition(":")[2]
        if e.get("state") == "present" and _entry_is_seed(e, s):
            search = e.get("search") or {}
            seen = f"search wildcard {search.get('wildcard')}, exact {search.get('exact')}"
            if strict:
                blind.append(f"{why}; its entry {eid} is still in the feed ({seen}): the search is blind")
            else:
                late[s["label"]] = {"entry": eid, "first_seen": e.get("first_seen"), "search": search}
        elif e.get("state") == "present":
            blind.append(f"{why}; its entry {eid} holds another value than the seed as picked")
        elif e.get("state") == "not_present":
            if strict:
                withdrawn.append(s["label"])
            else:
                blind.append(f"{why}; its entry {eid} is no longer in the feed (query_status "
                             f"{e.get('status')!r}): this batch cannot be sealed as picked, start "
                             "another one (--avoid this one)")
        else:
            blind.append(f"{why}; its entry {eid} could not be read ({e.get('error')})")
    for feed in sorted({seed_feed(s) for s in seeds if s["label"] in late}):
        if not returned.get(feed):
            blind.append(f"{feed}: its search returns none of the seeds picked from it, so its "
                         "silence proves nothing yet; run preflight again in an hour")
    return {"blind": blind, "late": late, "withdrawn": withdrawn}


def control_failures(seeds: list[dict], at_t: dict, entries: dict | None = None) -> list[str]:
    return control(seeds, at_t, entries)["blind"]


def _control_at(seeds: list[dict], answers: dict, lookup_entries, *, strict: bool = False) -> dict:
    """:func:`control`, reading by id only the seeds the search did not return."""
    unseen = _unseen(seeds, answers)
    entries = lookup_entries([s["source"] for s in unseen]) if (unseen and lookup_entries) else None
    return control(seeds, answers, entries, strict=strict)


class JudgeUnavailable(Exception):
    pass


def preflight(batch: Path, *, lookup_all, lookup_entries=None) -> dict:
    """Judge v2 on the seeds alone, before any arm runs: the control of
    :func:`control`, at the cost of a few lookups instead of a batch."""
    seeds = load_seeds(batch)
    keys = [_seed_key(s) for s in seeds]
    at = lookup_all(keys)
    ctl = _control_at(seeds, at, lookup_entries)
    failed = sorted(k for k, r in at.items() if r.get("state") == "error" and not _unjudgeable(r))
    rows = {s["label"]: {name: a.get("state") for name, a in
                         (at.get(k, {}).get("sections") or {}).items()}
            for s, k in zip(seeds, keys)}
    return {"seeds": rows, "blind": ctl["blind"], "late": ctl["late"], "failed": len(failed)}


def pick(fresh: dict, n: int, avoid_families=()) -> list[dict]:
    """§4.E rule 1, applied by the code and not by the operator: eligible
    candidates only (``excluded_by`` empty, as the server judged them), one per
    family, the family's newest entry, families taken newest first, families of
    an earlier lot left out. Same fresh_iocs answer, same seeds."""
    avoid = set(avoid_families)
    ranked = sorted((c for c in fresh.get("candidates") or []
                     if not c.get("excluded_by") and c.get("family") and c.get("first_seen")),
                    key=lambda c: (c["first_seen"], c["family"], c["seed_value"]), reverse=True)
    chosen: dict[str, dict] = {}
    for c in ranked:
        if c["family"] not in avoid and c["family"] not in chosen:
            chosen[c["family"]] = c
    seeds = []
    for i, c in enumerate(list(chosen.values())[:n], start=1):
        seeds.append({"label": f"P{i}", "seed_type": c["seed_type"], "seed_value": c["seed_value"],
                      "first_seen": c["first_seen"], "source": c["source"], "family": c["family"],
                      "reporter": c.get("reporter"),
                      "picked": f"pick/1 from fresh_iocs fetched {fresh.get('fetched_at')}"})
    return seeds


def families_of(paths) -> set[str]:
    out = set()
    for p in paths:
        out |= {s.get("family") for s in json.loads(Path(p).read_text(encoding="utf-8")) if s.get("family")}
    return out


# ── seal / check / score ───────────────────────────────────────────────────

SECONDARY_HORIZON_DAYS = 30


PIVOT_ARM = "pivot-1"
PIVOT_STAMP = "pivot-1.json"
PIVOT_SAME_HOUR_S = 3600


def fill_pivot(batch: Path, out: Path, *, call, now=None) -> dict:
    """Fill the mechanical arm ``pivot-1`` for a batch: one ``<label>/graph.json``
    per seed, from the server's pivot route (no model), all under ONE timestamp
    (``pivot-1.json``), taken once for the lot. ``seal`` refuses the arm when that
    stamp is not within the hour of the seal, as the other arms run: a base rate
    read a day apart from the arms it is compared to is not a base rate."""
    if (out / PIVOT_STAMP).exists():
        raise FileExistsError(f"{out / PIVOT_STAMP} exists: the arm is filled once per batch")
    seeds = load_seeds(batch)
    stamp = _iso((now or utcnow)())
    failed: dict[str, list[str]] = {}
    for s in seeds:
        graph = call({"type": s["seed_type"], "value": s["seed_value"]})
        (out / s["label"]).mkdir(parents=True, exist_ok=True)
        _dump(out / s["label"] / "graph.json", graph)
        bad = [t["tool"] for t in (graph.get("metadata") or {}).get("tools", []) if t.get("status") != "ok"]
        if bad:
            failed[s["label"]] = bad
    doc = {"arm": PIVOT_ARM, "fetched_at": stamp, "seeds_sha256": _sha256(batch / "seeds.json"),
           "seeds": [s["label"] for s in seeds], "tools_failed": failed}
    out.mkdir(parents=True, exist_ok=True)
    _dump(out / PIVOT_STAMP, doc)
    return doc


def pivot_stamp_check(batch: Path, d: Path, seeds: list[dict], sealed_at: datetime) -> None:
    path = d / PIVOT_STAMP
    if not path.is_file():
        raise ValueError(f"arm {PIVOT_ARM} has no {PIVOT_STAMP} in {d}: fill it with the pivot command")
    stamp = json.loads(path.read_text(encoding="utf-8"))
    if stamp.get("seeds_sha256") != _sha256(batch / "seeds.json"):
        raise ValueError(f"arm {PIVOT_ARM} was filled for other seeds than this batch's")
    age = (sealed_at - _parse_iso(stamp["fetched_at"])).total_seconds()
    if not 0 <= age <= PIVOT_SAME_HOUR_S:
        raise ValueError(f"arm {PIVOT_ARM} was filled {stamp['fetched_at']}, not within the hour before the "
                         f"seal: refill it in the same hour as the other arms (new batch dir)")


def seal(batch: Path, arms: dict[str, Path], horizon_days: int, *, lookup=otx_lookup,
         lookup_all=None, lookup_entries=None, judge: str = JUDGE,
         secondary_days: int = SECONDARY_HORIZON_DAYS, now=None, pause_s: float = PAUSE_S,
         sleep=time.sleep, max_failed: int = 0) -> dict:
    """``lookup`` asks one claim (judge v1, from here); ``lookup_all`` asks a
    list (judge v2, through the server) and wins when given; ``lookup_entries``
    reads seeds by id for the positive control (judge v2)."""
    if (batch / "manifest.json").exists():
        raise FileExistsError(f"{batch / 'manifest.json'} exists: a batch is sealed once")
    if horizon_days < 1:
        raise ValueError("the horizon is at least one day")
    if secondary_days and secondary_days <= horizon_days:
        raise ValueError("the secondary horizon comes after the primary one (0: none)")
    if judge not in JUDGES:
        raise ValueError(f"unknown judge {judge!r}")
    seeds = load_seeds(batch)
    graphs: dict[str, dict] = {}
    claims: dict[str, dict[str, dict]] = {s["label"]: {} for s in seeds}
    for arm, d in sorted(arms.items()):
        graphs[arm] = {}
        for s in seeds:
            path = d / s["label"] / "graph.json"
            if not path.is_file():
                raise FileNotFoundError(f"arm {arm} has no graph for {s['label']} ({path}): "
                                        "re-run it, or seal without that arm")
            graph = json.loads(path.read_text(encoding="utf-8"))
            graphs[arm][s["label"]] = {"sha256": _sha256(path), "nodes": len(graph.get("nodes") or [])}
            for c in claims_of(graph, s["seed_value"]):
                entry = claims[s["label"]].setdefault(f"{c['type']}|{c['value']}",
                                                      {"type": c["type"], "value": c["value"],
                                                       "arms": [], "malicious": {}})
                entry["arms"].append(arm)
                entry["malicious"][arm] = c["malicious"]
    sealed_at = (now or utcnow)()
    if PIVOT_ARM in arms:
        pivot_stamp_check(batch, arms[PIVOT_ARM], seeds, sealed_at)
    keys = [k for per in claims.values() for k in per]
    keys += [f"{s['seed_type']}|{normalise(s['seed_type'], s['seed_value'])}" for s in seeds]
    at_t = lookup_all(keys) if lookup_all else _lookup_all(keys, lookup, pause_s, sleep)
    failed = sorted(k for k, r in at_t.items() if r.get("state") == "error" and not _unjudgeable(r))
    if len(failed) > max_failed:
        # A lookup that fails at T can never be redone at T: sealing now would
        # freeze those claims as undetermined for good. Nothing is written, so
        # the batch can be sealed again once the judge answers.
        raise JudgeUnavailable(f"{len(failed)} of {len(at_t)} lookups failed at T "
                               f"({at_t[failed[0]].get('error')}, …): nothing sealed. Seal again later "
                               f"or with OTX_API_KEY set (--max-failed N accepts N failures)")
    ctl = _control_at(seeds, at_t, lookup_entries) if judge == JUDGE_V2 else {"blind": [], "late": {}}
    if ctl["blind"]:
        raise JudgeUnavailable("the judge does not see a seed in the feed it was picked from, so its "
                               "silence proves nothing: " + "; ".join(ctl["blind"]) + ". Nothing sealed.")
    secondary_due = _iso(sealed_at + timedelta(days=secondary_days)) if secondary_days else None
    manifest = {
        "version": 1, "judge": judge, "batch": batch.name,
        "sealed_at": _iso(sealed_at), "horizon_days": horizon_days,
        "due_at": _iso(sealed_at + timedelta(days=horizon_days)),
        "secondary_horizon_days": secondary_days or None, "secondary_due_at": secondary_due,
        "seeds": seeds, "arms": {a: {"source": str(d), "graphs": graphs[a]} for a, d in sorted(arms.items())},
        "claims": {lab: [per[k] for k in sorted(per)] for lab, per in claims.items()},
        "at_t": at_t,
    }
    if judge == JUDGE_V2:
        # Seeds in their feed that its search did not return at T (read by id).
        manifest["control_at_t"] = {"late": ctl["late"]}
    _dump(batch / "manifest.json", manifest)
    commitment = {
        "version": 1, "judge": judge, "batch": batch.name,
        "sealed_at": manifest["sealed_at"], "due_at": manifest["due_at"], "horizon_days": horizon_days,
        "secondary_horizon_days": manifest["secondary_horizon_days"], "secondary_due_at": secondary_due,
        "manifest_sha256": _sha256(batch / "manifest.json"),
        "seeds": len(seeds),
        "claims_per_arm": {a: sum(1 for per in claims.values() for c in per.values() if a in c["arms"])
                           for a in sorted(arms)},
        "max_failed_accepted": max_failed,
        "seeds_late_at_t": len(ctl["late"]),
        "lookups_failed_at_t": sum(1 for r in at_t.values()
                                   if r.get("state") == "error" and not _unjudgeable(r)),
        "unjudgeable": sum(1 for r in at_t.values() if _unjudgeable(r)),
    }
    _dump(batch / "commitment.json", commitment)
    return commitment


class NotDue(Exception):
    pass


def horizon_reached(manifest: dict, t: datetime) -> str | None:
    """``secondary``, ``primary``, or None (before the primary horizon)."""
    if manifest.get("secondary_due_at") and t >= _parse_iso(manifest["secondary_due_at"]):
        return "secondary"
    return "primary" if t >= _parse_iso(manifest["due_at"]) else None


def check(batch: Path, *, early: bool = False, secondary: bool = False, lookup=otx_lookup,
          lookup_all=None, lookup_entries=None, judge: str = JUDGE, now=None, pause_s: float = PAUSE_S,
          sleep=time.sleep) -> Path:
    """Judge v2: the check carries the strict positive control (``control``):
    :func:`score` refuses a check whose judge does not return every seed of
    its feed."""
    manifest = load_manifest(batch)
    if manifest.get("judge") != judge:
        raise ValueError(f"the batch was sealed under {manifest.get('judge')}, not {judge}: check it "
                         "with the same judge (--server for judge v2, none for v1)")
    if secondary and not manifest.get("secondary_due_at"):
        raise ValueError("no secondary horizon was sealed for this batch")
    t = (now or utcnow)()
    due = _parse_iso(manifest["due_at"])
    target = _parse_iso(manifest["secondary_due_at"]) if secondary else due
    if t < target and not early:
        which = manifest["secondary_due_at"] if secondary else manifest["due_at"]
        raise NotDue(f"not due until {which} (--early runs a provisional check)")
    keys = manifest["at_t"].keys()
    lookups = lookup_all(list(keys)) if lookup_all else _lookup_all(keys, lookup, pause_s, sleep)
    doc = {"version": 1, "judge": manifest["judge"], "checked_at": _iso(t), "early": t < due,
           "horizon": horizon_reached(manifest, t),
           "manifest_sha256": _sha256(batch / "manifest.json"), "lookups": lookups}
    if manifest["judge"] == JUDGE_V2:
        # Written even when blind: the lookups are a measurement, and the score refuses.
        doc["control"] = _control_at(manifest["seeds"], lookups, lookup_entries, strict=True)
    path = batch / f"check-{t.strftime('%Y%m%dT%H%M%SZ')}.json"
    _dump(path, doc)
    return path


def latest_check(batch: Path) -> Path | None:
    checks = sorted(batch.glob("check-*.json"))
    return checks[-1] if checks else None


def load_check(batch: Path, path: Path) -> dict:
    """A check, if and only if it judged this batch's sealed manifest."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("manifest_sha256") != _sha256(batch / "manifest.json"):
        raise PermissionError(f"{path.name} judged another manifest than this batch's")
    return doc


def _listings(answer) -> dict[str, list[dict]]:
    """Judge v2: the sections that list a claim, with their entries."""
    secs = (answer or {}).get("sections") if isinstance(answer, dict) else None
    return {s: a.get("entries") or [] for s, a in (secs or {}).items()
            if isinstance(a, dict) and a.get("state") == "listed"}


def _ahead_detail(answer, seed: dict, sealed_at: datetime) -> dict:
    """For an ``ahead`` claim under judge v2: the sections that confirmed it,
    whether one confirmation is independent of the seed (another feed than the
    seed's, an author other than the seed's reporter), and the days from the
    seal to the earliest dated confirmation (negative: a listing dated before
    the seal that the judge did not show at T, e.g. an indicator added to an
    older pulse)."""
    feed, reporter = seed_feed(seed), seed.get("reporter")
    listings = _listings(answer)
    independent = any(e.get("author") and e.get("author") != reporter
                      for s, entries in listings.items() if s != feed for e in entries)
    dates = sorted(e["created"] for entries in listings.values() for e in entries if e.get("created"))
    delay = round((_parse_iso(dates[0]) - sealed_at).total_seconds() / 86400, 1) if dates else None
    return {"sections": sorted(listings), "independent": independent, "delay_days": delay}


def score(manifest: dict, check_doc: dict) -> dict:
    if check_doc.get("judge") != manifest.get("judge"):
        raise ValueError(f"check judged by {check_doc.get('judge')}, manifest by {manifest.get('judge')}")
    v2 = manifest.get("judge") == JUDGE_V2
    sealed_at = _parse_iso(manifest["sealed_at"])
    arms = sorted(manifest["arms"])
    withdrawn: list[str] = []
    if v2:
        ctl = check_doc.get("control")
        if not isinstance(ctl, dict):
            raise ValueError("this judge v2 check carries no positive control: check again")
        if ctl.get("blind"):
            raise JudgeUnavailable("the judge did not see every seed in its own feed at the check, so "
                                   "its silence proves nothing: " + "; ".join(ctl["blind"])
                                   + ". Check again later.")
        withdrawn = sorted(ctl.get("withdrawn") or [])

    def blank():
        row = {c: 0 for c in CLASSES} | {"claims": 0, "ahead_malicious": 0}
        if v2:
            row |= {"known_late": 0, "ahead_independent": 0, "ahead_by_section": {}, "ahead_delays_days": []}
        return row

    per_seed: dict[str, dict] = {}
    totals = {a: blank() for a in arms}
    pool_total = 0
    for s in manifest["seeds"]:
        lab = s["label"]
        rows = {a: blank() for a in arms}
        pool = set()
        for c in manifest["claims"].get(lab, []):
            k = f"{c['type']}|{c['value']}"
            at_t, at_check = manifest["at_t"].get(k), check_doc["lookups"].get(k)
            cls = classify(at_t, at_check, sealed_at if v2 else None)
            late = v2 and cls == "known" and classify(at_t, at_check) == "ahead"
            detail = _ahead_detail(at_check, s, sealed_at) if v2 and cls == "ahead" else None
            if cls == "ahead":
                pool.add(k)
            for a in c["arms"]:
                rows[a]["claims"] += 1
                rows[a][cls] += 1
                if late:
                    rows[a]["known_late"] += 1
                if cls == "ahead" and c["malicious"].get(a):
                    rows[a]["ahead_malicious"] += 1
                if detail:
                    rows[a]["ahead_independent"] += int(detail["independent"])
                    for sec in detail["sections"]:
                        rows[a]["ahead_by_section"][sec] = rows[a]["ahead_by_section"].get(sec, 0) + 1
                    if detail["delay_days"] is not None:
                        rows[a]["ahead_delays_days"].append(detail["delay_days"])
        for a in arms:
            rows[a]["pooled_recall"] = round(100 * rows[a]["ahead"] / len(pool), 1) if pool else None
            for key in ("claims", "ahead_malicious", *CLASSES) + (("known_late", "ahead_independent") if v2 else ()):
                totals[a][key] += rows[a][key]
            if v2:
                for sec, n in rows[a]["ahead_by_section"].items():
                    totals[a]["ahead_by_section"][sec] = totals[a]["ahead_by_section"].get(sec, 0) + n
                totals[a]["ahead_delays_days"] += rows[a]["ahead_delays_days"]
        pool_total += len(pool)
        per_seed[lab] = {"pool": len(pool), "arms": rows}
    for a in arms:
        t = totals[a]
        judged = t["ahead"] + t["unconfirmed"]
        t["ahead_share"] = round(100 * t["ahead"] / judged, 1) if judged else None
        t["pooled_recall"] = round(100 * t["ahead"] / pool_total, 1) if pool_total else None
        if v2:
            t["ahead_delays_days"].sort()
            t["ahead_by_section"] = dict(sorted(t["ahead_by_section"].items()))
    checked_at = _parse_iso(check_doc["checked_at"])
    return {
        "batch": manifest["batch"], "judge": manifest["judge"], "sealed_at": manifest["sealed_at"],
        "due_at": manifest["due_at"], "checked_at": check_doc["checked_at"],
        "horizon_days": manifest["horizon_days"],
        "secondary_horizon_days": manifest.get("secondary_horizon_days"),
        "horizon_reached": horizon_reached(manifest, checked_at),
        "provisional": bool(check_doc.get("early")) or checked_at < _parse_iso(manifest["due_at"]),
        "pool": pool_total, "arms": totals, "seeds": per_seed,
    } | ({"seeds_withdrawn": withdrawn} if v2 else {})


def _fmt(x) -> str:
    return "n/a" if x is None else (f"{x:.1f}" if isinstance(x, float) else str(x))


def _median(xs: list[float]):
    if not xs:
        return None
    xs = sorted(xs)
    m = len(xs) // 2
    return float(xs[m]) if len(xs) % 2 else round((xs[m - 1] + xs[m]) / 2, 1)


def render_md(r: dict) -> str:
    cols = ("claims", *CLASSES, "ahead_share", "pooled_recall")
    head = "| arm | " + " | ".join(cols) + " |"
    reached = {"secondary": f" at the secondary horizon ({r.get('secondary_horizon_days')} days)",
               "primary": " at the primary horizon"}.get(r.get("horizon_reached") or "", "")
    lines = [f"# Prospective batch {r['batch']}", "",
             f"Sealed {r['sealed_at']}, checked {r['checked_at']}{reached} (horizon {r['horizon_days']} days, "
             f"due {r['due_at']}), judge `{r['judge']}`."
             + (" **Provisional: checked before the horizon.**" if r["provisional"] else ""), ""]
    if r.get("commitment_in_repo") is True:
        lines += [f"Manifest checked against the committed `eval/prospective/{r['batch']}/commitment.json`.", ""]
    elif r.get("commitment_in_repo") is False:
        lines += [f"**No committed `eval/prospective/{r['batch']}/commitment.json`: nothing here proves the "
                  "claims were fixed before the judge spoke.**", ""]
    lines += [head, "|" + "---|" * (len(cols) + 1)]
    for a, t in r["arms"].items():
        lines.append(f"| {a} | " + " | ".join(_fmt(t[c]) for c in cols) + " |")
    if r["judge"] == JUDGE_V2:
        lines += ["", "Who confirmed the ahead claims (judge v2):", "",
                  "| arm | ahead | independent of the seed | by section | median delay (days) |",
                  "|---|---|---|---|---|"]
        for a, t in r["arms"].items():
            by = ", ".join(f"{s} {n}" for s, n in t["ahead_by_section"].items()) or "none"
            lines.append(f"| {a} | {t['ahead']} | {t['ahead_independent']} | {by} | "
                         f"{_fmt(_median(t['ahead_delays_days']))} |")
        lines += ["", "*known* includes the claims found at the check in an abuse.ch entry dated before "
                  "the seal, which the feed's search did not return at T: "
                  + ", ".join(f"{a} {t['known_late']}" for a, t in r["arms"].items()) + "."]
        if r.get("seeds_withdrawn"):
            lines += ["", f"**Seeds their own feed withdrew after the seal: {', '.join(r['seeds_withdrawn'])}.** "
                      "Their claims are scored as the others; read them knowing the feed retracted the seed."]
    lines += ["", "Per seed (ahead / claims, pooled recall):", "",
              "| seed | pool | " + " | ".join(r["arms"]) + " |", "|" + "---|" * (len(r["arms"]) + 2)]
    for lab, s in r["seeds"].items():
        cells = [f"{s['arms'][a]['ahead']}/{s['arms'][a]['claims']} ({_fmt(s['arms'][a]['pooled_recall'])})"
                 for a in r["arms"]]
        lines.append(f"| {lab} | {s['pool']} | " + " | ".join(cells) + " |")
    lines += ["", "*ahead*: in no listing when the batch was sealed, in one at the check. "
              "*ahead_share* = ahead / (ahead + unconfirmed). *pooled_recall* = ahead / every arm's "
              "ahead claims on the same seed. A failed lookup is *undetermined*, never \"in no listing\". "
              "*independent*: confirmed in another feed than the seed's, by another author than the "
              "seed's reporter. Method: EVAL_PROTOCOL §4.E.", ""]
    return "\n".join(lines)


# ── CLI ────────────────────────────────────────────────────────────────────

def _arms(values: list[str]) -> dict[str, Path]:
    arms: dict[str, Path] = {}
    for v in values:
        name, sep, d = v.partition("=")
        if not sep or not name or not d:
            raise ValueError(f"--arm takes name=<dir>, got {v!r}")
        if name in arms:
            raise ValueError(f"arm {name} given twice")
        arms[name] = Path(d)
    return arms


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("seeds", help="pick a batch's seeds from the server's fresh_iocs (§4.E rule 1)")
    d.add_argument("--batch", type=Path, required=True)
    d.add_argument("--n", type=int, default=6)
    d.add_argument("--days", type=int, default=2)
    d.add_argument("--avoid", type=Path, action="append", default=[],
                   help="seeds.json of an earlier lot: its families are not picked again")
    f = sub.add_parser("preflight", help="judge v2 on the seeds alone, before the arms run")
    f.add_argument("--batch", type=Path, required=True)
    v = sub.add_parser("pivot", help="fill the mechanical arm pivot-1 from the server (no model); "
                                     "then seal with --arm pivot-1=<dir>")
    v.add_argument("--batch", type=Path, required=True)
    v.add_argument("--out", type=Path, required=True, help="the arm directory (<label>/graph.json)")
    s = sub.add_parser("seal")
    s.add_argument("--batch", type=Path, required=True)
    s.add_argument("--arm", action="append", required=True, help="name=<dir with <label>/graph.json>")
    s.add_argument("--horizon-days", type=int, default=14)
    s.add_argument("--secondary-horizon-days", type=int, default=SECONDARY_HORIZON_DAYS,
                   help=f"a second pre-registered horizon (default {SECONDARY_HORIZON_DAYS}; 0: none)")
    s.add_argument("--max-failed", type=int, default=0,
                   help="failed lookups at T accepted before sealing (default 0: none)")
    c = sub.add_parser("check")
    c.add_argument("--batch", type=Path, required=True)
    c.add_argument("--early", action="store_true", help="check before the horizon (provisional)")
    c.add_argument("--secondary", action="store_true", help="wait for the secondary horizon")
    for p in (s, c):
        p.add_argument("--pause", type=float, default=PAUSE_S,
                       help=f"seconds between lookups (default {PAUSE_S}: the keyless OTX limit)")
    for p in (d, f, v, s, c):
        p.add_argument("--server", help="the Bounce-CTI server (judge v2 and fresh seeds), "
                                        "e.g. https://cti.alexandre-pinoteau.fr")
        p.add_argument("--cookies", type=Path, help="cookie jar holding an admin session (curl -c)")
    r = sub.add_parser("score")
    r.add_argument("--batch", type=Path, required=True)
    r.add_argument("--check", type=Path, help="a check file (default: the latest in --batch)")
    r.add_argument("--write", action="store_true", help="write results.json and results.md in --batch")
    args = ap.parse_args(argv)
    key = os.environ.get("OTX_API_KEY") or None

    def lookup(ntype, value):
        return otx_lookup(ntype, value, key=key)

    try:
        server = None
        if args.cmd in ("seeds", "preflight", "pivot", "seal", "check"):
            if args.cmd in ("seeds", "preflight", "pivot") and not args.server:
                raise ValueError(f"{args.cmd} needs --server and --cookies")
            if args.server:
                if not args.cookies:
                    raise ValueError("--server needs --cookies (an admin session)")
                server = (args.server, server_opener(args.cookies))
        v2 = {} if server is None else {
            "judge": JUDGE_V2,
            "lookup_all": lambda ks: server_lookup_all(ks, base=server[0], opener=server[1]),
            "lookup_entries": lambda refs: server_entries(refs, base=server[0], opener=server[1])}
        if args.cmd == "seeds":
            if (args.batch / "seeds.json").exists():
                raise FileExistsError(f"{args.batch / 'seeds.json'} exists: seeds are picked once")
            fresh = server_call(server[0], f"/api/admin/eval/fresh_iocs?days={args.days}", opener=server[1])
            seeds = pick(fresh, args.n, families_of(args.avoid))
            if not seeds:
                # Nothing written: no seed was chosen, so a later attempt chooses nothing twice.
                raise ValueError(f"no eligible seed among {fresh.get('count')} candidates")
            args.batch.mkdir(parents=True, exist_ok=True)
            _dump(args.batch / "fresh_iocs.json", fresh)
            _dump(args.batch / "seeds.json", seeds)
            print(f"{len(seeds)} seeds of {fresh.get('eligible')} eligible / {fresh.get('count')} candidates "
                  f"→ {args.batch / 'seeds.json'}; next: preflight, then the arms in the same hour")
            return 0
        if args.cmd == "pivot":
            doc = fill_pivot(args.batch, args.out, call=lambda body: server_call(
                server[0], "/api/admin/eval/pivot", opener=server[1], body=body))
            print(f"{PIVOT_ARM}: {len(doc['seeds'])} seeds → {args.out} at {doc['fetched_at']}; "
                  f"seal within the hour with --arm {PIVOT_ARM}={args.out}")
            for lab, tools in doc["tools_failed"].items():
                print(f"{lab}: tools that failed: {', '.join(tools)}", file=sys.stderr)
            return 0
        if args.cmd == "preflight":
            res = preflight(args.batch, lookup_all=v2["lookup_all"], lookup_entries=v2["lookup_entries"])
            for lab, secs in res["seeds"].items():
                print(f"{lab}: " + ", ".join(f"{s} {st}" for s, st in sorted(secs.items())))
            for lab, e in res["late"].items():
                srch = e.get("search") or {}
                print(f"{lab}: entry {e.get('entry')} is in the feed, its search does not return it yet "
                      f"(wildcard {srch.get('wildcard')}, exact {srch.get('exact')})")
            if res["blind"] or res["failed"]:
                why = res["blind"] + ([f"{res['failed']} lookups failed"] if res["failed"] else [])
                print("refusing: " + "; ".join(why), file=sys.stderr)
                return EXIT_JUDGE
            print("judge v2 finds every seed in its own feed"
                  + (" (some by id only: scored known when dated before the seal)" if res["late"] else "")
                  + ": run the arms")
            return 0
        if args.cmd == "seal":
            commitment = seal(args.batch, _arms(args.arm), args.horizon_days, lookup=lookup,
                              secondary_days=args.secondary_horizon_days,
                              pause_s=args.pause, max_failed=args.max_failed, **v2)
            print(json.dumps(commitment, indent=2))
            if commitment["lookups_failed_at_t"]:
                print(f"warning: {commitment['lookups_failed_at_t']} lookups failed at T; those "
                      "claims stay undetermined for good", file=sys.stderr)
            print(f"commit {args.batch / 'commitment.json'} now: its date is the pre-registration")
            return 0
        if args.cmd == "check":
            path = check(args.batch, early=args.early, secondary=args.secondary, lookup=lookup,
                         pause_s=args.pause, **v2)
            doc = json.loads(path.read_text(encoding="utf-8"))
            failed = sum(1 for v in doc["lookups"].values() if v.get("state") == "error")
            print(f"{path}: {len(doc['lookups'])} lookups, {failed} failed"
                  + (" (early: provisional)" if doc["early"] else ""))
            ctl = doc.get("control") or {}
            if ctl.get("withdrawn"):
                print(f"seeds their feed withdrew: {', '.join(ctl['withdrawn'])}", file=sys.stderr)
            if ctl.get("blind"):
                print("the judge does not see every seed in its own feed, this check will not be scored: "
                      + "; ".join(ctl["blind"]), file=sys.stderr)
                return EXIT_JUDGE
            return 0
        manifest = load_manifest(args.batch)
        path = args.check or latest_check(args.batch)
        if path is None:
            raise FileNotFoundError(f"no check-*.json in {args.batch}: run check first")
        result = score(manifest, load_check(args.batch, path))
        result["commitment_in_repo"] = committed_copy(args.batch).is_file()
    except PermissionError as e:
        print(f"refusing: {e}", file=sys.stderr)
        return EXIT_TAMPERED
    except NotDue as e:
        print(str(e), file=sys.stderr)
        return EXIT_NOT_DUE
    except JudgeUnavailable as e:
        print(str(e), file=sys.stderr)
        return EXIT_JUDGE
    except urllib.error.HTTPError as e:
        print(f"error: the server answered HTTP {e.code} ({e.reason})", file=sys.stderr)
        return EXIT_USAGE
    except (ValueError, FileNotFoundError, FileExistsError, KeyError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_USAGE
    md = render_md(result)
    if args.write:
        _dump(args.batch / "results.json", result)
        (args.batch / "results.md").write_text(md, encoding="utf-8")
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
