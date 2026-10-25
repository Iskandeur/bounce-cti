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
only). A claim is what an arm would hand a defender: the domain, ip, url and hash
nodes backend.action_exports would put in a blocklist or a detection rule (no
lead, no unverified or defused node), minus the seed. Each claim lands in one
class:

- ``known``: already in a pulse at T. The arm could have read it there.
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

    python3 eval/prospective.py seal --batch <dir> --arm bounce=<dir> --arm web=<dir> \\
        [--horizon-days 14]
    python3 eval/prospective.py check --batch <dir> [--early]
    python3 eval/prospective.py score --batch <dir> [--check <file>] [--write]

``<batch>/seeds.json`` lists the batch: ``[{"label": "P1", "seed_type": "ip",
"seed_value": "…", "first_seen": "<UTC>", "source": "<where it was picked>"}]``.
An arm directory holds one ``<label>/graph.json`` per seed (the layout fetch.py
writes, and ``baseline.py run --seeds``). The manifest, the checks and the arms'
graphs stay out of the repository: claims can name victims and other third
parties. ``commitment.json`` and ``results.json`` / ``results.md`` (counts only)
are the parts meant to be committed.

Exit codes: 0 done; 1 the manifest is not the committed one; 2 usage or input
error; 3 the check is not due yet (``--early`` to run it anyway).

Stdlib only, plus backend.action_exports for the definition of a claim.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
# The definition of "what an arm would hand a defender" lives with the exports
# themselves: change what a blocklist leaves out, and the claims follow.
from backend.action_exports import _HASH_TYPES, _NETWORK_TYPES, _iter_actionable  # noqa: E402

JUDGE = "otx-pulses/1"
OTX_BASE = "https://otx.alienvault.com/api/v1/indicators"
CLAIM_TYPES = frozenset(_NETWORK_TYPES | _HASH_TYPES)
CLASSES = ("known", "ahead", "unconfirmed", "benign", "undetermined")
BAD_TAGS = {"malicious", "c2", "phishing", "malware", "attacker"}  # as eval/scorer.score_negative
_FILE_HASH_RE = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")
_RETRY_STATUS = {429, 500, 502, 503, 504}
PAUSE_S = 3.0  # between lookups: the keyless OTX API answers 429 past ~20 calls a minute
EXIT_TAMPERED, EXIT_USAGE, EXIT_NOT_DUE = 1, 2, 3


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


_UNJUDGEABLE = "OTX has no exact lookup"


def _error(msg: str) -> dict:
    return {"state": "error", "error": msg}


def _unjudgeable(r: dict) -> bool:
    return r.get("state") == "error" and str(r.get("error") or "").startswith(_UNJUDGEABLE)


def otx_lookup(ntype: str, value: str, *, key: str | None = None, opener=None,
               retries: int = 3, backoff_s: float = 15.0, sleep=time.sleep) -> dict:
    """``{"state": "listed"|"unlisted", "count", "pulses", "whitelist"}``, or
    ``{"state": "error", "error"}``. Listed in any section is listed; otherwise
    one failed section makes the whole answer an error: "in no pulse" needs every
    section to have answered."""
    paths = otx_paths(ntype, value)
    if not paths:
        return _error(f"{_UNJUDGEABLE} for this {ntype}")
    answers = [_otx_get(p, key=key, opener=opener, retries=retries, backoff_s=backoff_s, sleep=sleep)
               for p in paths]
    ok = [a for a in answers if a["state"] != "error"]
    pulses = sorted({p for a in ok for p in a["pulses"]})
    merged = {"state": "listed" if any(a["state"] == "listed" for a in ok) else "unlisted",
              "count": max([len(pulses)] + [a["count"] for a in ok]),
              "pulses": pulses, "whitelist": sorted({w for a in ok for w in a["whitelist"]})}
    if merged["state"] == "unlisted" and len(ok) < len(answers):
        return _error("; ".join(a["error"] for a in answers if a["state"] == "error"))
    return merged


def _otx_get(url: str, *, key, opener, retries, backoff_s, sleep) -> dict:
    """One section. An answer without ``pulse_info`` is an error, never "in no
    pulse": a reader that cannot see is not a negative."""
    headers = {"User-Agent": "bounce-cti-eval/prospective", "Accept": "application/json"}
    if key:
        headers["X-OTX-API-KEY"] = key
    opener = opener or urllib.request.urlopen
    last = "no attempt"
    wait = 0.0
    for attempt in range(retries + 1):
        if attempt:
            sleep(wait or backoff_s * attempt)
        wait = 0.0
        try:
            with opener(urllib.request.Request(url, headers=headers), timeout=60) as r:
                body = json.loads(r.read())
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}"
            if e.code in _RETRY_STATUS:
                # The keyless API answers 429 after ~60 calls in 3 minutes
                # (measured 2026-10-25); its Retry-After, when given, wins.
                retry_after = e.headers.get("Retry-After") if e.headers else None
                if retry_after and str(retry_after).isdigit():
                    wait = min(float(retry_after), 300.0)
                continue
            return _error(last)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last = f"network: {e}"
            continue
        except ValueError:
            return _error("answer is not JSON")
        pi = body.get("pulse_info") if isinstance(body, dict) else None
        if not isinstance(pi, dict) or not isinstance(pi.get("pulses"), list):
            return _error("answer has no pulse_info")
        pulses = sorted({str(p.get("id")) for p in pi["pulses"] if isinstance(p, dict) and p.get("id")})
        count = pi.get("count") if isinstance(pi.get("count"), int) else len(pulses)
        flags = [v for f in ("validation", "false_positive")
                 for v in (body.get(f) if isinstance(body.get(f), list) else [])]
        whitelist = sorted({str(v.get("source") or v.get("name") or "?") for v in flags
                            if isinstance(v, dict)})
        return {"state": "listed" if (count or pulses) else "unlisted", "count": max(count, len(pulses)),
                "pulses": pulses, "whitelist": whitelist}
    return _error(last)


def classify(at_t: dict | None, at_check: dict | None) -> str:
    if not at_t or not at_check or "error" in (at_t.get("state"), at_check.get("state")):
        return "undetermined"
    if at_t.get("whitelist") or at_check.get("whitelist"):
        return "benign"
    if at_t.get("state") == "listed":
        return "known"
    return "ahead" if at_check.get("state") == "listed" else "unconfirmed"


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
        if s["label"] in labels:
            raise ValueError(f"seed label {s['label']} appears twice")
        labels.add(s["label"])
    return seeds


def load_manifest(batch: Path) -> dict:
    """The manifest, if and only if it is the one the commitment names."""
    commitment = json.loads((batch / "commitment.json").read_text(encoding="utf-8"))
    digest = _sha256(batch / "manifest.json")
    if digest != commitment.get("manifest_sha256"):
        raise PermissionError(f"manifest.json is not the sealed one (sha256 {digest[:12]}, "
                              f"committed {str(commitment.get('manifest_sha256'))[:12]})")
    return json.loads((batch / "manifest.json").read_text(encoding="utf-8"))


# ── seal / check / score ───────────────────────────────────────────────────

def seal(batch: Path, arms: dict[str, Path], horizon_days: int, *, lookup=otx_lookup,
         now=None, pause_s: float = PAUSE_S, sleep=time.sleep) -> dict:
    if (batch / "manifest.json").exists():
        raise FileExistsError(f"{batch / 'manifest.json'} exists: a batch is sealed once")
    if horizon_days < 1:
        raise ValueError("the horizon is at least one day")
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
    keys = [k for per in claims.values() for k in per]
    keys += [f"{s['seed_type']}|{normalise(s['seed_type'], s['seed_value'])}" for s in seeds]
    at_t = _lookup_all(keys, lookup, pause_s, sleep)
    manifest = {
        "version": 1, "judge": JUDGE, "batch": batch.name,
        "sealed_at": _iso(sealed_at), "horizon_days": horizon_days,
        "due_at": _iso(sealed_at + timedelta(days=horizon_days)),
        "seeds": seeds, "arms": {a: {"source": str(d), "graphs": graphs[a]} for a, d in sorted(arms.items())},
        "claims": {lab: [per[k] for k in sorted(per)] for lab, per in claims.items()},
        "at_t": at_t,
    }
    _dump(batch / "manifest.json", manifest)
    commitment = {
        "version": 1, "judge": JUDGE, "batch": batch.name,
        "sealed_at": manifest["sealed_at"], "due_at": manifest["due_at"], "horizon_days": horizon_days,
        "manifest_sha256": _sha256(batch / "manifest.json"),
        "seeds": len(seeds),
        "claims_per_arm": {a: sum(1 for per in claims.values() for c in per.values() if a in c["arms"])
                           for a in sorted(arms)},
        "lookups_failed_at_t": sum(1 for r in at_t.values()
                                   if r.get("state") == "error" and not _unjudgeable(r)),
        "unjudgeable": sum(1 for r in at_t.values() if _unjudgeable(r)),
    }
    _dump(batch / "commitment.json", commitment)
    return commitment


class NotDue(Exception):
    pass


def check(batch: Path, *, early: bool = False, lookup=otx_lookup, now=None,
          pause_s: float = PAUSE_S, sleep=time.sleep) -> Path:
    manifest = load_manifest(batch)
    t = (now or utcnow)()
    due = _parse_iso(manifest["due_at"])
    if t < due and not early:
        raise NotDue(f"not due until {manifest['due_at']} (--early runs a provisional check)")
    lookups = _lookup_all(manifest["at_t"].keys(), lookup, pause_s, sleep)
    doc = {"version": 1, "judge": JUDGE, "checked_at": _iso(t), "early": t < due,
           "manifest_sha256": _sha256(batch / "manifest.json"), "lookups": lookups}
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


def score(manifest: dict, check_doc: dict) -> dict:
    if check_doc.get("judge") != manifest.get("judge"):
        raise ValueError(f"check judged by {check_doc.get('judge')}, manifest by {manifest.get('judge')}")
    arms = sorted(manifest["arms"])
    per_seed: dict[str, dict] = {}
    totals = {a: {c: 0 for c in CLASSES} | {"claims": 0, "ahead_malicious": 0} for a in arms}
    pool_total = 0
    for s in manifest["seeds"]:
        lab = s["label"]
        rows = {a: {c: 0 for c in CLASSES} | {"claims": 0, "ahead_malicious": 0} for a in arms}
        pool = set()
        for c in manifest["claims"].get(lab, []):
            k = f"{c['type']}|{c['value']}"
            cls = classify(manifest["at_t"].get(k), check_doc["lookups"].get(k))
            if cls == "ahead":
                pool.add(k)
            for a in c["arms"]:
                rows[a]["claims"] += 1
                rows[a][cls] += 1
                if cls == "ahead" and c["malicious"].get(a):
                    rows[a]["ahead_malicious"] += 1
        for a in arms:
            rows[a]["pooled_recall"] = round(100 * rows[a]["ahead"] / len(pool), 1) if pool else None
            for key in ("claims", "ahead_malicious", *CLASSES):
                totals[a][key] += rows[a][key]
        pool_total += len(pool)
        per_seed[lab] = {"pool": len(pool), "arms": rows}
    for a in arms:
        t = totals[a]
        judged = t["ahead"] + t["unconfirmed"]
        t["ahead_share"] = round(100 * t["ahead"] / judged, 1) if judged else None
        t["pooled_recall"] = round(100 * t["ahead"] / pool_total, 1) if pool_total else None
    checked_at = _parse_iso(check_doc["checked_at"])
    return {
        "batch": manifest["batch"], "judge": manifest["judge"], "sealed_at": manifest["sealed_at"],
        "due_at": manifest["due_at"], "checked_at": check_doc["checked_at"],
        "horizon_days": manifest["horizon_days"],
        "provisional": bool(check_doc.get("early")) or checked_at < _parse_iso(manifest["due_at"]),
        "pool": pool_total, "arms": totals, "seeds": per_seed,
    }


def _fmt(x) -> str:
    return "n/a" if x is None else (f"{x:.1f}" if isinstance(x, float) else str(x))


def render_md(r: dict) -> str:
    cols = ("claims", *CLASSES, "ahead_share", "pooled_recall")
    head = "| arm | " + " | ".join(cols) + " |"
    lines = [f"# Prospective batch {r['batch']}", "",
             f"Sealed {r['sealed_at']}, checked {r['checked_at']} (horizon {r['horizon_days']} days, "
             f"due {r['due_at']}), judge `{r['judge']}`."
             + (" **Provisional: checked before the horizon.**" if r["provisional"] else ""), "",
             head, "|" + "---|" * (len(cols) + 1)]
    for a, t in r["arms"].items():
        lines.append(f"| {a} | " + " | ".join(_fmt(t[c]) for c in cols) + " |")
    lines += ["", "Per seed (ahead / claims, pooled recall):", "",
              "| seed | pool | " + " | ".join(r["arms"]) + " |", "|" + "---|" * (len(r["arms"]) + 2)]
    for lab, s in r["seeds"].items():
        cells = [f"{s['arms'][a]['ahead']}/{s['arms'][a]['claims']} ({_fmt(s['arms'][a]['pooled_recall'])})"
                 for a in r["arms"]]
        lines.append(f"| {lab} | {s['pool']} | " + " | ".join(cells) + " |")
    lines += ["", "*ahead*: in no OTX pulse when the batch was sealed, in one at the check. "
              "*ahead_share* = ahead / (ahead + unconfirmed). *pooled_recall* = ahead / every arm's "
              "ahead claims on the same seed. A failed lookup is *undetermined*, never \"in no pulse\". "
              "Method: EVAL_PROTOCOL §4.E.", ""]
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
    s = sub.add_parser("seal")
    s.add_argument("--batch", type=Path, required=True)
    s.add_argument("--arm", action="append", required=True, help="name=<dir with <label>/graph.json>")
    s.add_argument("--horizon-days", type=int, default=14)
    c = sub.add_parser("check")
    c.add_argument("--batch", type=Path, required=True)
    c.add_argument("--early", action="store_true", help="check before the horizon (provisional)")
    for p in (s, c):
        p.add_argument("--pause", type=float, default=PAUSE_S,
                       help=f"seconds between lookups (default {PAUSE_S}: the keyless OTX limit)")
    r = sub.add_parser("score")
    r.add_argument("--batch", type=Path, required=True)
    r.add_argument("--check", type=Path, help="a check file (default: the latest in --batch)")
    r.add_argument("--write", action="store_true", help="write results.json and results.md in --batch")
    args = ap.parse_args(argv)
    key = os.environ.get("OTX_API_KEY") or None

    def lookup(ntype, value):
        return otx_lookup(ntype, value, key=key)

    try:
        if args.cmd == "seal":
            commitment = seal(args.batch, _arms(args.arm), args.horizon_days, lookup=lookup,
                              pause_s=args.pause)
            print(json.dumps(commitment, indent=2))
            if commitment["lookups_failed_at_t"]:
                print(f"warning: {commitment['lookups_failed_at_t']} lookups failed at T; those "
                      "claims stay undetermined for good", file=sys.stderr)
            print(f"commit {args.batch / 'commitment.json'} now: its date is the pre-registration")
            return 0
        if args.cmd == "check":
            path = check(args.batch, early=args.early, lookup=lookup, pause_s=args.pause)
            doc = json.loads(path.read_text(encoding="utf-8"))
            failed = sum(1 for v in doc["lookups"].values() if v.get("state") == "error")
            print(f"{path}: {len(doc['lookups'])} lookups, {failed} failed"
                  + (" (early: provisional)" if doc["early"] else ""))
            return 0
        manifest = load_manifest(args.batch)
        path = args.check or latest_check(args.batch)
        if path is None:
            raise FileNotFoundError(f"no check-*.json in {args.batch}: run check first")
        result = score(manifest, load_check(args.batch, path))
    except PermissionError as e:
        print(f"refusing: {e}", file=sys.stderr)
        return EXIT_TAMPERED
    except NotDue as e:
        print(str(e), file=sys.stderr)
        return EXIT_NOT_DUE
    except (ValueError, FileNotFoundError, FileExistsError, KeyError) as e:
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
