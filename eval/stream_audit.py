#!/usr/bin/env python3
"""How much of the agent's stream did the event log lose? (EVAL_PROTOCOL §4.A note)

    python eval/stream_audit.py [--db data/bounce.db] [--since 2026-10-15] [--runs runs]

Until 2026-10-15 the backend read the agent's stream-json through asyncio's
64 KiB line limit: the first longer line (a big tool result) ended the log of
its phase, silently. This script measures that from the database alone, read-only:

* **cut phases**: a phase that exited ``rc=0`` printed its ``result`` event, so
  ``rc=0`` with ``saw_result=false`` means the log lost at least that event.
  A phase killed by the watchdog or by quota (``rc != 0``) is not counted.
* **longest logged line**: each agent event re-serialised the way the CLI
  prints it (compact JSON). A wall just under 65,536 bytes is the old limit at
  work; lines past it after the fix are the fix at work.
* ``--runs``: for each archived eval run, how many of its scored
  investigations have a cut phase.

Exit 1 when a cut phase is found at or after ``--since``: run it after a deploy
of the fix, with ``--since`` set to the deploy date, and it should exit 0.
Stdlib only.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sqlite3
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OLD_LIMIT = 64 * 1024


def _connect(db: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{db}?mode=ro", uri=True)


def _phase_name(kind: str) -> str:
    name = kind[len("phase_"):-len("_exit")]
    return "pivot_drain" if name.startswith("pivot_drain") else name


def cut_phases(c: sqlite3.Connection, since: float = 0.0) -> dict:
    """Phase exits, and those that exited rc=0 without their result event."""
    total, cut = Counter(), Counter()
    invs, cut_invs = set(), set()
    latest = None
    rows = c.execute("SELECT investigation_id, kind, payload, created_at FROM events "
                     "WHERE kind LIKE 'phase_%_exit' AND created_at >= ?", (since,))
    for inv, kind, payload, ts in rows:
        try:
            msg = json.loads(payload).get("msg")
        except (ValueError, AttributeError):
            continue
        if not isinstance(msg, dict) or "saw_result" not in msg:
            continue
        name = _phase_name(kind)
        total[name] += 1
        invs.add(inv)
        if msg.get("rc") == 0 and not msg.get("saw_result"):
            cut[name] += 1
            cut_invs.add(inv)
            latest = ts if latest is None else max(latest, ts)
    return {"phases": sum(total.values()), "cut": sum(cut.values()),
            "cut_by_phase": dict(cut), "investigations": len(invs),
            "cut_investigations": sorted(cut_invs), "latest_cut": latest}


def longest_lines(c: sqlite3.Connection, since: float = 0.0, top: int = 5) -> dict:
    sizes = []
    rows = c.execute("SELECT kind, payload FROM events "
                     "WHERE kind LIKE 'agent_%' AND created_at >= ?", (since,))
    for kind, payload in rows:
        try:
            evt = json.loads(payload).get("msg")
        except (ValueError, AttributeError):
            continue
        if not isinstance(evt, dict):
            continue
        line = json.dumps(evt, ensure_ascii=False, separators=(",", ":"))
        sizes.append(len(line.encode("utf-8")))
    sizes.sort(reverse=True)
    return {"events": len(sizes), "longest": sizes[:top],
            "past_old_limit": sum(1 for s in sizes if s >= OLD_LIMIT)}


def scored_investigations(runs: Path) -> dict[str, list[str]]:
    """run folder → investigation ids of its scored cases (raw_scores.json)."""
    out = {}
    for raw in sorted(runs.glob("*/raw_scores.json")):
        try:
            doc = json.loads(raw.read_text(encoding="utf-8"))
        except ValueError:
            continue
        rows = doc if isinstance(doc, list) else list(doc.values()) if isinstance(doc, dict) else []
        ids = [r.get("inv_id") or r.get("investigation_id") for r in rows
               if isinstance(r, dict) and "error" not in r]
        out[raw.parent.name] = [i for i in ids if i]
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--db", type=Path, default=ROOT / "data" / "bounce.db")
    ap.add_argument("--since", help="only events at or after this date (YYYY-MM-DD, UTC)")
    ap.add_argument("--runs", type=Path, help="archived eval runs folder (e.g. runs)")
    args = ap.parse_args(argv)
    since = 0.0
    if args.since:
        since = dt.datetime.strptime(args.since, "%Y-%m-%d").replace(
            tzinfo=dt.timezone.utc).timestamp()
    c = _connect(args.db)

    lines = longest_lines(c, since)
    print(f"agent events: {lines['events']:,}; longest logged lines (bytes): "
          f"{', '.join(f'{s:,}' for s in lines['longest']) or '-'}; "
          f"at or past 64 KiB: {lines['past_old_limit']:,}")
    cut = cut_phases(c, since)
    print(f"phases: {cut['phases']:,}; exited rc=0 without their result event: {cut['cut']:,} "
          f"{cut['cut_by_phase'] or ''}")
    print(f"investigations with such a phase: {len(cut['cut_investigations']):,} "
          f"of {cut['investigations']:,}")
    if cut["latest_cut"] is not None:
        when = dt.datetime.fromtimestamp(cut["latest_cut"], dt.timezone.utc)
        print(f"latest: {when:%Y-%m-%d %H:%M} UTC")
    if args.runs:
        cut_ids = set(cut["cut_investigations"])
        known = {r[0] for r in c.execute("SELECT id FROM investigations")}
        n_all = n_cut = 0
        for run, ids in scored_investigations(args.runs).items():
            ids = [i for i in ids if i in known]
            if not ids:
                continue
            hit = [i for i in ids if i in cut_ids]
            n_all, n_cut = n_all + len(ids), n_cut + len(hit)
            print(f"  {run}: {len(hit)} of {len(ids)} scored investigations cut")
        print(f"scored investigations in the database: {n_all}; with a cut phase: {n_cut}")
    return 1 if (args.since and cut["cut"]) else 0


if __name__ == "__main__":
    sys.exit(main())
