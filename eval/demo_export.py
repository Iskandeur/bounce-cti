#!/usr/bin/env python3
"""Freeze one investigation into a static demo snapshot (roadmap J3).

    python eval/demo_export.py <inv_id> <name> --db data/bounce.db --dotenv .env

writes ``eval/demo/<name>.json``. ``cd frontend && npm run build:demo`` then
builds ``frontend/dist-demo/``: a static, read-only viewer of every snapshot in
``eval/demo/``, with no backend, no PIN and no API key. Any static host serves
it (GitHub Pages: ``.github/workflows/demo-pages.yml``, run by hand).

What a snapshot holds, and what it leaves out: ``backend/demo_snapshot.py``.
The owner of an investigation can also download one from the running app,
checked against the server's own secrets:
``GET /api/investigations/{id}/demo_snapshot``.

The database is opened read-only and the investigation's rows are copied into
a throwaway database first, so the export never writes to the source, even a
production one.

Exit codes: 0 written; 1 refused, nothing written (the snapshot contains the
value of a secret of ``--dotenv`` or of this process's environment, or a
``--forbid`` word); 2 bad input, including a ``--dotenv`` that can't be read: the
secrets that could leak are those of the instance that ran the investigation,
and checking against nothing would pass on nothing. Credential shapes
(``key=…``, ``Bearer …``) are reported as warnings: read them before publishing.
"""
from __future__ import annotations

import argparse
import re
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend import demo_snapshot  # noqa: E402

DEMO_DIR = ROOT / "eval" / "demo"
_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
# Rows copied into the throwaway database, per table.
_TABLES = {
    "investigations": "id=?",
    "nodes": "investigation_id=?",
    "edges": "investigation_id=?",
    "events": "investigation_id=?",
}


def _copy_investigation(src: sqlite3.Connection, dst: sqlite3.Connection, inv_id: str) -> None:
    for table, where in _TABLES.items():
        src_cols = [r[1] for r in src.execute(f"PRAGMA table_info({table})")]
        dst_cols = {r[1] for r in dst.execute(f"PRAGMA table_info({table})")}
        cols = [c for c in src_cols if c in dst_cols]
        if not cols:
            continue
        names = ", ".join(cols)
        rows = src.execute(f"SELECT {names} FROM {table} WHERE {where}", (inv_id,)).fetchall()
        dst.executemany(
            f"INSERT INTO {table} ({names}) VALUES ({', '.join('?' * len(cols))})",
            [tuple(r) for r in rows],
        )
    dst.commit()


def build_snapshot(db_path: Path, inv_id: str, label: str | None = None) -> dict | None:
    """The snapshot of `inv_id` from the database at `db_path` (opened
    read-only), or None if there is no such investigation."""
    src = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        row = src.execute("SELECT model FROM investigations WHERE id=?", (inv_id,)).fetchone()
        if row is None:
            return None
        with tempfile.TemporaryDirectory(prefix="bounce-demo-") as tmp:
            from backend import graph_store as gs

            saved = gs.DB_PATH
            gs.DB_PATH = Path(tmp) / "snapshot.db"
            try:
                gs.init_db()
                dst = sqlite3.connect(gs.DB_PATH)
                try:
                    _copy_investigation(src, dst, inv_id)
                finally:
                    dst.close()
                view = gs.share_view(inv_id, demo_snapshot.SECTIONS)
            finally:
                gs.DB_PATH = saved
    finally:
        src.close()
    return None if view is None else demo_snapshot.from_view(view, row[0], label)


def export(inv_id: str, name: str, db_path: Path, out_dir: Path = DEMO_DIR,
           dotenv: Path | None = None, forbid: list[str] | None = None,
           label: str | None = None) -> tuple[int, str]:
    """(exit code, message). 0 = written, 1 = refused, 2 = bad input."""
    if not _NAME.match(name):
        return 2, f"bad snapshot name {name!r}: lowercase letters, digits, '-' and '_' only"
    if not db_path.is_file():
        return 2, f"no database at {db_path}"
    dotenv = dotenv if dotenv is not None else ROOT / ".env"
    try:
        dotenv.read_bytes()
    except OSError as e:
        return 2, (f"cannot read {dotenv} to check the snapshot for secrets ({e.strerror}); "
                   "pass --dotenv <the .env of the instance that ran the investigation>")
    snap = build_snapshot(db_path, inv_id, label=label)
    if snap is None:
        return 2, f"no investigation {inv_id!r} in {db_path}"
    text = demo_snapshot.serialise(snap)
    secrets = demo_snapshot.known_secrets(dotenv)
    problems, warnings = demo_snapshot.check(text, secrets, forbid)
    lines = [f"warning: {w}" for w in warnings]
    lines.append(f"checked against {len({v for _, v in secrets})} secret value(s) "
                 f"({dotenv} and this process's environment)")
    if problems:
        lines += [f"REFUSED: {p}" for p in problems]
        return 1, "\n".join(lines + ["nothing written"])
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{name}.json"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(text + "\n", encoding="utf-8")
    tmp.replace(path)
    lines.append(f"wrote {path} ({len(text):,} bytes): {len(snap['graph']['nodes'])} nodes, "
                 f"{len(snap['graph']['edges'])} edges, {len(snap['events'])} timeline events")
    return 0, "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("inv_id")
    p.add_argument("name", help="snapshot name, e.g. case02 (file eval/demo/<name>.json)")
    p.add_argument("--db", type=Path, default=ROOT / "data" / "bounce.db")
    p.add_argument("--out-dir", type=Path, default=DEMO_DIR)
    p.add_argument("--dotenv", type=Path, default=None,
                   help="the .env of the instance that ran the investigation (default: ./.env)")
    p.add_argument("--forbid", action="append", default=[], metavar="WORD")
    p.add_argument("--label", default=None, help="one line shown above the demo")
    a = p.parse_args(argv)
    code, msg = export(a.inv_id, a.name, a.db, a.out_dir, a.dotenv, a.forbid, a.label)
    print(msg, file=sys.stderr if code else sys.stdout)
    return code


if __name__ == "__main__":
    sys.exit(main())
