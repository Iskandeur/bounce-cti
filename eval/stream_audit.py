#!/usr/bin/env python3
"""How much of the agent's stream did the event log lose? (EVAL_PROTOCOL §4.A note)

    python eval/stream_audit.py [--db data/bounce.db] [--since 2026-10-15T21:41Z]
                                [--prove-fix] [--runs runs]

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
* **loss events of the fixed code**: ``agent_stream_error`` (a pump died) and
  ``agent_stdout_oversize`` (a line past 8 MiB, logged by size and head only).

With ``--since`` (a day, ``2026-10-15``, or a UTC time, ``2026-10-15T21:41Z``;
a time with no zone is read as UTC) the exit code is a verdict on that window:

* **1**: a cut phase or a loss event at or after ``--since``.
* **3, undetermined**: no phase exited in the window, so there is nothing to
  judge. An empty window is never green. (2 stays argparse's usage error, so a
  typo in ``--since`` never reads as an empty window.)
* **0**: phases ran and none was cut.

``--prove-fix`` is the check to run after deploying the fix, with ``--since``
set to the deploy TIME: a whole day would count the old code's cuts from
earlier that day. It also needs a positive proof, at least one line of 64 KiB
or more logged in full in the window, since the old reader could log none.
Phases that ran clean without one exit 3: the fix has not been exercised yet.
Before scoring a run, plain ``--since <start of the run>`` is enough: a run
with no long line had nothing to lose.

A phase cut then killed (``rc != 0``) is not counted, so 0 is the floor of the
damage, never its measure. Stdlib only.
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
UNDETERMINED = 3  # exit code of a --since window with nothing to judge


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


LOSS_KINDS = ("agent_stream_error", "agent_stdout_oversize")


def loss_events(c: sqlite3.Connection, since: float = 0.0) -> dict[str, int]:
    """How many times the fixed reader still lost something, by event kind."""
    rows = c.execute("SELECT kind, COUNT(*) FROM events WHERE kind IN (?, ?) "
                     "AND created_at >= ? GROUP BY kind", (*LOSS_KINDS, since))
    return {kind: n for kind, n in rows}


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


def parse_since(raw: str) -> float:
    """``2026-10-15`` (00:00 UTC) or an ISO time such as ``2026-10-15T21:41Z``
    or ``2026-10-15 21:41:00+02:00``; a time without a zone is UTC."""
    raw = raw.strip()
    if raw.endswith(("Z", "z")):
        raw = raw[:-1] + "+00:00"
    when = dt.datetime.fromisoformat(raw)
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.timezone.utc)
    return when.timestamp()


def verdict(cut: dict, losses: dict, lines: dict, prove_fix: bool) -> tuple[int, str]:
    """Exit code and its reason for a ``--since`` window."""
    if cut["cut"] or losses:
        return 1, "FAIL: the log lost part of the agent stream in this window"
    if not cut["phases"]:
        return UNDETERMINED, "UNDETERMINED: no phase exited in this window, nothing to judge"
    if prove_fix and not lines["past_old_limit"]:
        return UNDETERMINED, ("UNDETERMINED: no line of 64 KiB or more was logged in this window, "
                   "so the fix has not been exercised yet")
    if prove_fix:
        return 0, (f"OK: {lines['past_old_limit']:,} line(s) of 64 KiB or more logged in full, "
                   f"no phase cut out of {cut['phases']:,}")
    return 0, f"OK: no phase cut out of {cut['phases']:,}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--db", type=Path, default=ROOT / "data" / "bounce.db")
    ap.add_argument("--since", help="only events at or after this UTC day or time "
                    "(2026-10-15 or 2026-10-15T21:41Z)")
    ap.add_argument("--prove-fix", action="store_true",
                    help="after a deploy: exit 0 only if a line of 64 KiB or more was "
                    "logged in full since --since")
    ap.add_argument("--runs", type=Path, help="archived eval runs folder (e.g. runs)")
    args = ap.parse_args(argv)
    if args.prove_fix and not args.since:
        ap.error("--prove-fix needs --since <deploy time>")
    since = 0.0
    if args.since:
        try:
            since = parse_since(args.since)
        except ValueError:
            ap.error(f"--since: not a day or an ISO time: {args.since!r}")
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
    losses = loss_events(c, since)
    print("loss events of the fixed reader: "
          + (", ".join(f"{k} {n}" for k, n in sorted(losses.items())) or "none"))
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
    if not args.since:
        return 0  # report only
    code, reason = verdict(cut, losses, lines, args.prove_fix)
    start = dt.datetime.fromtimestamp(since, dt.timezone.utc)
    print(f"since {start:%Y-%m-%d %H:%M} UTC: {reason}")
    return code


if __name__ == "__main__":
    sys.exit(main())
