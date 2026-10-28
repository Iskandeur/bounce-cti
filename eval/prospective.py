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
    python3 eval/prospective.py bounce --batch <dir> --out <bounce-dir> $S [--model opus-5]
    python3 eval/baseline.py run --arm web --model claude-opus-5 --out <web-out> --seeds <dir>/seeds.json P1 P2 …
    python3 eval/prospective.py pivot --batch <dir> --out <pivot-dir> $S
    python3 eval/prospective.py seal --batch <dir> --arm bounce=<bounce-dir> --arm web=<web-out>/web --arm pivot-1=<pivot-dir> $S \\
        [--horizon-days 14] [--secondary-horizon-days 30]
    python3 eval/prospective.py check --batch <dir> $S [--early] [--secondary]
    python3 eval/prospective.py score --batch <dir> [--check <file>] [--write]

``bounce`` fills the Bounce-CTI arm: one investigation per seed on the server (admin session),
ONE AT A TIME (the runs spend the operator's Claude subscription), each resumed at most twice
when a restart (``error: interrupted``) or the quota stopped it, and a graph written only for a run
that ended ``done``. ``<bounce-dir>/bounce.json`` records every run as it is submitted, so running
the command again picks the batch up where it stopped and never submits a seed twice.

``seal`` reads when each seed's run started (``bounce.json``, ``pivot-1.json``, or baseline.py's
``run.json``) and refuses a run that started more than 48 h after its seed was first listed
(rule 1 again, at run time: the arms can run days after the pick), a Bounce-CTI run that did not
end done, a web run that ended without an answer (its empty graph would seal as "found
nothing"), and an arm with no start times unless ``--allow-unstamped`` (listed in the
commitment). The start times go into the manifest; the commitment keeps the window.
``--drop LABEL=<reason>`` leaves a seed out at the seal (the contamination rule): never edit
``seeds.json``, whose sha256 ties every stamped arm to the batch.

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
at ``check``, and then ``score`` refuses that check); 5 a run of the arm ``bounce`` fills did not
end done, or is still going (run it again: it waits for that run, it starts no other).

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
EXIT_TAMPERED, EXIT_USAGE, EXIT_NOT_DUE, EXIT_JUDGE, EXIT_ARM = 1, 2, 3, 4, 5


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


# The Bounce-CTI arm (§4.E step 2): one investigation per seed on the server, ONE AT
# A TIME. The investigations spend the same Claude subscription as whoever drives the
# batch, and parallel runs exhaust it (the no-parallelism rule of sequential_runner.py).
# On production an opus-5 investigation took 28 min (median) to 44 min (max) over the
# 16 that ended done in the 30 days to 2026-10-28, so a batch of 6 takes about 3 hours.
BOUNCE_ARM = "bounce"
BOUNCE_STAMP = "bounce.json"
BOUNCE_MODEL = "opus-5"
# A service restart marks the runs in flight `error: interrupted` (graph_store.
# reconcile_orphaned_running): a deploy during the batch does it. Both statuses keep
# the graph, and POST /resume carries on from it.
BOUNCE_RESUMABLE = ("quota_exceeded", "error: interrupted")
BOUNCE_MAX_RESUMES = 2
# A run recorded before its POST is answered (`find` looks for it on the next call).
BOUNCE_SUBMITTING = "submitting"
# How far before the recorded submission a server's start time may be (clock skew).
BOUNCE_FIND_SKEW_S = 120
BOUNCE_POLL_S = 30.0
BOUNCE_MAX_WAIT_S = 150 * 60
# Rule 1: a seed was first listed in a feed at most 48 h before the runs. `seeds`
# applies it when it picks; `seal` applies it again to every run's start, since the
# arms can run days after the pick.
FRESH_MAX_S = 48 * 3600


class ArmIncomplete(Exception):
    """A run of the arm did not end done, or is still going: nothing to seal yet."""


_OUT_OF_REACH = object()


def _transient(e: OSError) -> bool:
    """A deploy restarts the server: connection refused, then the proxy's 5xx for a few
    seconds. A 4xx is not transient (401: the session expired; 404: no such run)."""
    if isinstance(e, urllib.error.HTTPError):
        return e.code >= 500
    return True


def _bounce_final(status: str) -> bool:
    return status in ("done", "failed", "stopped", "cleared") or status.startswith("error")


def _epoch_iso(x) -> str | None:
    if isinstance(x, (int, float)) and x > 0:
        return _iso(datetime.fromtimestamp(x, timezone.utc))
    return None


def fill_bounce(batch: Path, out: Path, *, start, row_of, resume, graph_of, model: str = BOUNCE_MODEL,
                context_pool: bool = False, stop=None, find=None, now=None, sleep=time.sleep,
                poll_s: float = BOUNCE_POLL_S, max_wait_s: float = BOUNCE_MAX_WAIT_S, log=print) -> dict:
    """Fill the Bounce-CTI arm: for each seed in order, start an investigation
    (``start(body)``, POST /api/investigations), wait until it ends (``row_of(id)``,
    its row in GET /api/investigations), resume it when a restart or the quota
    stopped it, and write ``<label>/graph.json`` (``graph_of(id)``) only for a run
    that ended done. ``bounce.json`` records each run as soon as it is submitted
    (server id, start time read from the server's row, status), so running the
    command again picks the batch up where it stopped and never submits a seed
    twice. The next seed starts only once the previous run has ended. A server
    out of reach for a while (a restart) is polled through (``_transient``)."""
    clock = now or utcnow
    seeds = load_seeds(batch)
    digest = _sha256(batch / "seeds.json")
    path = out / BOUNCE_STAMP
    if path.is_file():
        stamp = json.loads(path.read_text(encoding="utf-8"))
        if stamp.get("seeds_sha256") != digest:
            raise ValueError(f"{path} was filled for other seeds than this batch's")
        if (stamp.get("model"), bool(stamp.get("context_pool"))) != (model, context_pool):
            raise ValueError(f"{path} runs model {stamp.get('model')} with context_pool "
                             f"{bool(stamp.get('context_pool'))}: one arm, one setting (another --out)")
    else:
        stamp = {"arm": BOUNCE_ARM, "model": model, "context_pool": context_pool,
                 "seeds_sha256": digest, "runs": {}}
    out.mkdir(parents=True, exist_ok=True)

    def save():
        _dump(path, stamp)

    for s in seeds:
        lab = s["label"]
        run = stamp["runs"].get(lab)
        if run and run.get("status") == "done" and (out / lab / "graph.json").is_file():
            continue
        if run and _bounce_final(run.get("status") or "") and run.get("status") != "done" \
                and run.get("status") not in BOUNCE_RESUMABLE:
            log(f"{lab}: {run['inv_id']} ended {run['status']}; not run again")
            continue
        if run is not None and run.get("status") == BOUNCE_SUBMITTING:
            # The last call stopped between its POST and the answer (a lost response, a killed
            # process): the server may hold that run. Find it rather than submit the seed twice.
            if find is None:
                raise ArmIncomplete(f"{lab}: the submission of {run['submitted_at']} got no answer; look for "
                                    "it among the server's investigations before running this again")
            row = find(s, model, _parse_iso(run["submitted_at"]))
            if row is None:
                del stamp["runs"][lab]  # it never reached the server
                run = None
            elif context_pool and not row.get("context_pool"):
                if stop:
                    stop(row["id"])
                run.update(inv_id=row["id"], status="refused: the server did not mount the context pool")
                save()
                raise ValueError(f"{lab}: {run['status']}")
            else:
                run.update(inv_id=row["id"], status="submitted")
                save()
                log(f"{lab}: found {row['id']}, submitted {run['submitted_at']} with no answer")
        if run is None:
            body = {"seed_type": s["seed_type"], "seed_value": s["seed_value"], "model": model,
                    "vertical": "cti"}
            if context_pool:
                body["context_pool"] = True
            # Written BEFORE the POST: a call cut off after the server created the run finds it next time.
            run = {"status": BOUNCE_SUBMITTING, "submitted_at": _iso(clock()), "resumes": []}
            stamp["runs"][lab] = run
            save()
            doc = start(body)
            run.update(inv_id=doc["id"], status="submitted")
            save()
            if context_pool and not (doc.get("context_pool") and doc.get("context_pool_web")):
                # A run without the pool (or its web tools) would be scored as the arm with it.
                if stop:
                    stop(run["inv_id"])
                run["status"] = "refused: the server did not mount the context pool with its web tools"
                save()
                raise ValueError(f"{lab}: {run['status']}")
            log(f"{lab}: started {run['inv_id']} ({s['seed_type']} {model})")
        waited = 0.0
        while True:
            try:
                row = row_of(run["inv_id"])
            except OSError as e:
                if not _transient(e):
                    raise
                row = _OUT_OF_REACH
            if row is _OUT_OF_REACH:
                status = run.get("status") or ""
                log(f"{lab}: the server is out of reach, polling again")
            elif row is None:
                run["status"] = "missing: not in the session's investigations"
                save()
                raise ArmIncomplete(f"{lab}: {run['inv_id']} is not in this session's investigations")
            else:
                if not run.get("started_at"):
                    run["started_at"] = _epoch_iso(row.get("created_at"))
                run["model_run"] = row.get("model")
                status = str(row.get("status") or "")
                if status == "done":
                    try:
                        graph = graph_of(run["inv_id"])
                    except OSError as e:
                        if not _transient(e):
                            raise
                        log(f"{lab}: done, its graph is out of reach, asking again")
                    else:
                        (out / lab).mkdir(parents=True, exist_ok=True)
                        _dump(out / lab / "graph.json", graph)
                        run.update(status="done", finished_at=_iso(clock()), nodes=len(graph.get("nodes") or []))
                        save()
                        log(f"{lab}: done, {run['nodes']} nodes")
                        break
                elif status in BOUNCE_RESUMABLE:
                    if len(run["resumes"]) >= BOUNCE_MAX_RESUMES:
                        run["status"] = status
                        save()
                        log(f"{lab}: {status} again after {BOUNCE_MAX_RESUMES} resumes; left there")
                        break
                    try:
                        resume(run["inv_id"])
                    except OSError as e:
                        # 425: the quota cooldown is not over. Out of reach: a restart. Poll again.
                        if not (isinstance(e, urllib.error.HTTPError) and e.code == 425) and not _transient(e):
                            raise
                    else:
                        run["resumes"].append({"after": status, "at": _iso(clock())})
                        run["status"] = "running"
                        save()
                        log(f"{lab}: resumed after {status}")
                elif _bounce_final(status):
                    run.update(status=status, finished_at=_iso(clock()))
                    save()
                    log(f"{lab}: ended {status}, no graph written")
                    break
                elif run.get("status") != status:
                    run["status"] = status
                    save()
            if waited >= max_wait_s:
                raise ArmIncomplete(f"{lab}: {run['inv_id']} still {status} after {round(waited / 60)} min; "
                                    "run the command again later (it waits for this run, it starts no other)")
            sleep(poll_s)
            waited += poll_s
    missing = [lab for lab in (s["label"] for s in seeds) if stamp["runs"].get(lab, {}).get("status") != "done"]
    if missing:
        raise ArmIncomplete("runs not done: " + ", ".join(
            f"{lab} ({stamp['runs'].get(lab, {}).get('status')})" for lab in missing))
    return stamp


def find_submitted(rows, seed: dict, model: str, since: datetime) -> dict | None:
    """Among the session's investigations (GET /api/investigations), the newest one
    on this seed and model started no earlier than ``since`` (less the clock skew):
    the run of a submission whose answer was lost. None if there is none."""
    want = str(seed["seed_value"]).strip().lower()
    floor = since.timestamp() - BOUNCE_FIND_SKEW_S
    hits = [r for r in rows if isinstance(r, dict) and r.get("id")
            and str(r.get("seed_value") or "").strip().lower() == want
            and r.get("seed_type") == seed["seed_type"] and r.get("model") == model
            and isinstance(r.get("created_at"), (int, float)) and r["created_at"] >= floor]
    return max(hits, key=lambda r: r["created_at"]) if hits else None


def arm_runs(arm: str, d: Path, seeds: list[dict], batch: Path) -> dict[str, dict]:
    """When each seed's run of an arm started, read from what filled the arm:
    ``bounce.json`` (filled for this batch's seeds; the server's start time of each
    investigation, which must have ended done), ``pivot-1.json`` (one stamp for the lot), or each seed's
    ``run.json`` (baseline.py: ``started_at``, and the run must have produced an
    answer). A seed with none of them has ``started_at`` None."""
    runs: dict[str, dict] = {}
    labels = [s["label"] for s in seeds]
    if (d / BOUNCE_STAMP).is_file():
        stamp = json.loads((d / BOUNCE_STAMP).read_text(encoding="utf-8"))
        if stamp.get("seeds_sha256") != _sha256(batch / "seeds.json"):
            # Same labels (P1…P6) in every batch: another batch's runs would pass unseen.
            raise ValueError(f"arm {arm} was filled for other seeds than this batch's ({d / BOUNCE_STAMP})")
        for lab in labels:
            r = (stamp.get("runs") or {}).get(lab) or {}
            if r.get("status") != "done":
                raise ValueError(f"arm {arm}: the run of {lab} is {r.get('status') or 'missing'} in "
                                 f"{d / BOUNCE_STAMP}, not done: finish it, or seal without that arm")
            runs[lab] = {"started_at": r.get("started_at"), "model": r.get("model_run") or stamp.get("model"),
                         "inv_id": r.get("inv_id"), "resumes": len(r.get("resumes") or [])}
        return runs
    if (d / PIVOT_STAMP).is_file():
        at = json.loads((d / PIVOT_STAMP).read_text(encoding="utf-8")).get("fetched_at")
        return {lab: {"started_at": at, "model": None} for lab in labels}
    for lab in labels:
        p = d / lab / "run.json"
        if not p.is_file():
            runs[lab] = {"started_at": None, "model": None}
            continue
        r = json.loads(p.read_text(encoding="utf-8"))
        if r.get("timed_out") or r.get("is_error") or r.get("answer_parsed") is False:
            # An empty graph from a run that failed would seal as "found nothing".
            raise ValueError(f"arm {arm}: the run of {lab} did not end in an answer ({p}: timed_out "
                             f"{r.get('timed_out')}, is_error {r.get('is_error')}, answer_parsed "
                             f"{r.get('answer_parsed')}): run it again, or seal without that arm")
        runs[lab] = {"started_at": r.get("started_at"), "model": r.get("model")}
    return runs


def check_fresh(arm: str, runs: dict[str, dict], seeds: list[dict], sealed_at: datetime) -> list[float]:
    """Rule 1 at the seal: every run started after its seed was first listed, at
    most 48 h after, and before the seal. Returns the hours from first listing to
    each run's start."""
    hours = []
    for s in seeds:
        at = runs[s["label"]]["started_at"]
        if at is None:
            continue
        started, first = _parse_iso(at), _parse_iso(s["first_seen"])
        age = (started - first).total_seconds()
        if age < 0 or started > sealed_at:
            raise ValueError(f"arm {arm}: the run of {s['label']} started {at}, outside [first listed "
                             f"{s['first_seen']}, sealed {_iso(sealed_at)}]: its time is wrong")
        if age > FRESH_MAX_S:
            raise ValueError(f"arm {arm}: the run of {s['label']} started {round(age / 3600, 1)} h after its "
                             f"seed was first listed ({s['first_seen']}), over the 48 h of rule 1: "
                             "the seed was no longer fresh, start another batch")
        hours.append(age / 3600)
    return hours


def seal(batch: Path, arms: dict[str, Path], horizon_days: int, *, lookup=otx_lookup,
         lookup_all=None, lookup_entries=None, judge: str = JUDGE,
         secondary_days: int = SECONDARY_HORIZON_DAYS, now=None, pause_s: float = PAUSE_S,
         sleep=time.sleep, max_failed: int = 0, allow_unstamped: bool = False,
         drop: dict[str, str] | None = None) -> dict:
    """``lookup`` asks one claim (judge v1, from here); ``lookup_all`` asks a
    list (judge v2, through the server) and wins when given; ``lookup_entries``
    reads seeds by id for the positive control (judge v2). Every arm must say
    when each seed's run started (``arm_runs``), each start within 48 h of the
    seed's first listing (``check_fresh``), unless ``allow_unstamped``.
    ``drop`` (label → reason) leaves seeds out of the batch at the seal, the
    contamination rule's way: ``seeds.json`` is never edited, since its sha256 is
    what ties every stamped arm to the batch."""
    if (batch / "manifest.json").exists():
        raise FileExistsError(f"{batch / 'manifest.json'} exists: a batch is sealed once")
    if horizon_days < 1:
        raise ValueError("the horizon is at least one day")
    if secondary_days and secondary_days <= horizon_days:
        raise ValueError("the secondary horizon comes after the primary one (0: none)")
    if judge not in JUDGES:
        raise ValueError(f"unknown judge {judge!r}")
    seeds_all = load_seeds(batch)
    drop = dict(drop or {})
    unknown = sorted(set(drop) - {s["label"] for s in seeds_all})
    if unknown:
        raise ValueError(f"--drop names no seed of this batch: {', '.join(unknown)}")
    if any(not str(r).strip() for r in drop.values()):
        raise ValueError("--drop takes LABEL=<reason>: a seed leaves the batch with its reason written")
    dropped = [dict(s, dropped_because=drop[s["label"]].strip()) for s in seeds_all if s["label"] in drop]
    seeds = [s for s in seeds_all if s["label"] not in drop]
    if not seeds:
        raise ValueError("--drop leaves no seed to seal")
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
    # Before any lookup: when each arm ran is part of what is sealed (rule 1).
    runs: dict[str, dict[str, dict]] = {}
    hours: list[float] = []
    unstamped: list[str] = []
    for arm, d in sorted(arms.items()):
        runs[arm] = arm_runs(arm, d, seeds, batch)
        hours += check_fresh(arm, runs[arm], seeds, sealed_at)
        lacking = [lab for lab, r in runs[arm].items() if r["started_at"] is None]
        if lacking:
            if not allow_unstamped:
                raise ValueError(f"arm {arm}: no start time for {', '.join(lacking)} (no {BOUNCE_STAMP}, "
                                 f"{PIVOT_STAMP} or <label>/run.json with started_at), so rule 1 cannot be "
                                 "checked: fill the arm with prospective.py bounce / pivot or baseline.py, "
                                 "or seal with --allow-unstamped (recorded in the commitment)")
            unstamped.append(arm)
    starts = sorted(r["started_at"] for per in runs.values() for r in per.values() if r["started_at"])
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
        "seeds": seeds,
        # Left out at the seal (the contamination rule), with the reason: not judged, not scored.
        "dropped": dropped,
        "arms": {a: {"source": str(d), "graphs": graphs[a], "runs": runs[a]} for a, d in sorted(arms.items())},
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
        # Labels only (a reason can name a host): dropping after seeing would be choosing, so it is public.
        "seeds_dropped": [s["label"] for s in dropped],
        "claims_per_arm": {a: sum(1 for per in claims.values() for c in per.values() if a in c["arms"])
                           for a in sorted(arms)},
        "max_failed_accepted": max_failed,
        "seeds_late_at_t": len(ctl["late"]),
        "lookups_failed_at_t": sum(1 for r in at_t.values()
                                   if r.get("state") == "error" and not _unjudgeable(r)),
        "unjudgeable": sum(1 for r in at_t.values() if _unjudgeable(r)),
        # When the arms ran: the window the claims come from, and how fresh the
        # seeds still were (rule 1 refuses past 48 h). Times, no value.
        "runs": {"first_started_at": starts[0] if starts else None,
                 "last_started_at": starts[-1] if starts else None,
                 "max_hours_after_first_seen": round(max(hours), 1) if hours else None,
                 "unstamped_arms": unstamped},
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


def _drops(values: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for v in values:
        label, sep, reason = v.partition("=")
        if not sep or not label.strip():
            raise ValueError(f"--drop takes LABEL=<reason>, got {v!r}")
        if label.strip() in out:
            raise ValueError(f"seed {label.strip()} dropped twice")
        out[label.strip()] = reason
    return out


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
    b = sub.add_parser("bounce", help="fill the Bounce-CTI arm: one investigation per seed on the server, "
                                      "one at a time, graphs of the runs that ended done; run it again to "
                                      "pick up where it stopped")
    b.add_argument("--batch", type=Path, required=True)
    b.add_argument("--out", type=Path, required=True, help="the arm directory (<label>/graph.json + bounce.json)")
    b.add_argument("--model", default=BOUNCE_MODEL, help=f"server model alias (default {BOUNCE_MODEL})")
    b.add_argument("--context-pool", action="store_true",
                   help="the Bounce-CTI-with-web arm (context_pool: true; use another --out)")
    b.add_argument("--max-minutes", type=float, default=BOUNCE_MAX_WAIT_S / 60,
                   help="how long to wait for one run before giving the hand back (default 150)")
    s = sub.add_parser("seal")
    s.add_argument("--batch", type=Path, required=True)
    s.add_argument("--arm", action="append", required=True, help="name=<dir with <label>/graph.json>")
    s.add_argument("--horizon-days", type=int, default=14)
    s.add_argument("--secondary-horizon-days", type=int, default=SECONDARY_HORIZON_DAYS,
                   help=f"a second pre-registered horizon (default {SECONDARY_HORIZON_DAYS}; 0: none)")
    s.add_argument("--max-failed", type=int, default=0,
                   help="failed lookups at T accepted before sealing (default 0: none)")
    s.add_argument("--drop", action="append", default=[], metavar="LABEL=REASON",
                   help="leave a seed out at the seal (the contamination rule: its web run read a write-up "
                        "about it); seeds.json is never edited. Recorded in the manifest and the commitment")
    s.add_argument("--allow-unstamped", action="store_true",
                   help="seal an arm that does not say when its runs started (rule 1 unchecked for it; "
                        "listed in the commitment)")
    c = sub.add_parser("check")
    c.add_argument("--batch", type=Path, required=True)
    c.add_argument("--early", action="store_true", help="check before the horizon (provisional)")
    c.add_argument("--secondary", action="store_true", help="wait for the secondary horizon")
    for p in (s, c):
        p.add_argument("--pause", type=float, default=PAUSE_S,
                       help=f"seconds between lookups (default {PAUSE_S}: the keyless OTX limit)")
    for p in (d, f, v, b, s, c):
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
        if args.cmd in ("seeds", "preflight", "pivot", "bounce", "seal", "check"):
            if args.cmd in ("seeds", "preflight", "pivot", "bounce") and not args.server:
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
        if args.cmd == "bounce":
            base, op = server

            def row_of(inv_id):
                rows = server_call(base, "/api/investigations", opener=op)
                return next((r for r in rows if isinstance(r, dict) and r.get("id") == inv_id), None)

            stamp = fill_bounce(
                args.batch, args.out, model=args.model, context_pool=args.context_pool,
                max_wait_s=args.max_minutes * 60,
                find=lambda seed, model, since: find_submitted(
                    server_call(base, "/api/investigations", opener=op), seed, model, since),
                start=lambda body: server_call(base, "/api/investigations", opener=op, body=body),
                row_of=row_of,
                resume=lambda i: server_call(base, f"/api/investigations/{i}/resume", opener=op, body={}),
                stop=lambda i: server_call(base, f"/api/investigations/{i}/stop", opener=op, body={}),
                graph_of=lambda i: server_call(base, f"/api/investigations/{i}/graph", opener=op))
            print(f"{BOUNCE_ARM}: {len(stamp['runs'])} runs done → {args.out}; then the web arm, pivot, "
                  f"and seal with --arm {BOUNCE_ARM}={args.out}")
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
                              pause_s=args.pause, max_failed=args.max_failed,
                              allow_unstamped=args.allow_unstamped, drop=_drops(args.drop), **v2)
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
    except ArmIncomplete as e:
        print(str(e), file=sys.stderr)
        return EXIT_ARM
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
