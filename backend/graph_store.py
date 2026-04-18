"""SQLite-backed graph store. Single source of truth for the investigation."""
import json
import sqlite3
import time
import hashlib
from collections import Counter
from contextlib import contextmanager
from typing import Any, Optional
from .config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    seed_type TEXT,
    seed_value TEXT,
    created_at REAL,
    status TEXT,
    user_id INTEGER,
    model TEXT
);
CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,
    investigation_id TEXT,
    type TEXT,
    value TEXT,
    metadata TEXT,
    tags TEXT,
    confidence REAL,
    source TEXT,
    created_at REAL,
    UNIQUE(investigation_id, type, value)
);
CREATE TABLE IF NOT EXISTS edges (
    id TEXT PRIMARY KEY,
    investigation_id TEXT,
    src TEXT,
    dst TEXT,
    relation TEXT,
    evidence TEXT,
    source TEXT,
    confidence REAL,
    created_at REAL,
    UNIQUE(investigation_id, src, dst, relation)
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT,
    kind TEXT,
    payload TEXT,
    created_at REAL
);
CREATE TABLE IF NOT EXISTS cache (
    key TEXT PRIMARY KEY,
    value TEXT,
    created_at REAL
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pin_hmac TEXT UNIQUE NOT NULL,
    created_at REAL NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    allowed_models TEXT,
    label TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_investigations_user ON investigations(user_id);
CREATE INDEX IF NOT EXISTS idx_events_inv ON events(investigation_id);
"""


def _node_id(inv: str, type_: str, value: str) -> str:
    return hashlib.sha1(f"{inv}|{type_}|{value.lower()}".encode()).hexdigest()[:16]


def _edge_id(inv: str, src: str, dst: str, rel: str) -> str:
    return hashlib.sha1(f"{inv}|{src}|{dst}|{rel}".encode()).hexdigest()[:16]


@contextmanager
def conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


def _ensure_column(c, table: str, column: str, ddl: str):
    cols = [r["name"] for r in c.execute(f"PRAGMA table_info({table})")]
    if cols and column not in cols:
        c.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


def init_db():
    with conn() as c:
        # Migrations: add columns to pre-existing tables before creating indexes
        _ensure_column(c, "investigations", "user_id", "user_id INTEGER")
        _ensure_column(c, "investigations", "model", "model TEXT")
        # users table may pre-date is_admin/allowed_models
        if c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").fetchone():
            _ensure_column(c, "users", "is_admin", "is_admin INTEGER NOT NULL DEFAULT 0")
            _ensure_column(c, "users", "allowed_models", "allowed_models TEXT")
            _ensure_column(c, "users", "label", "label TEXT")
        c.executescript(SCHEMA)


def create_investigation(seed_type: str, seed_value: str, user_id: Optional[int] = None,
                         model: Optional[str] = None) -> str:
    inv_id = hashlib.sha1(f"{time.time()}|{seed_type}|{seed_value}".encode()).hexdigest()[:12]
    with conn() as c:
        c.execute(
            "INSERT INTO investigations(id, seed_type, seed_value, created_at, status, user_id, model) VALUES (?,?,?,?,?,?,?)",
            (inv_id, seed_type, seed_value, time.time(), "running", user_id, model),
        )
    return inv_id


def set_status(inv_id: str, status: str):
    with conn() as c:
        c.execute("UPDATE investigations SET status=? WHERE id=?", (status, inv_id))


def get_investigation_owner(inv_id: str) -> Optional[int]:
    with conn() as c:
        row = c.execute("SELECT user_id FROM investigations WHERE id=?", (inv_id,)).fetchone()
    return row["user_id"] if row else None


def add_node(inv_id: str, type_: str, value: str, metadata: dict | None = None,
             confidence: float = 0.8, source: str = "agent", tags: list[str] | None = None) -> dict:
    nid = _node_id(inv_id, type_, value)
    md = dict(metadata or {})
    # Track which sources have contributed data to this node (for multi-source convergence).
    sources_seen = list(set(md.get("sources_seen", []) + ([source] if source else [])))
    md["sources_seen"] = sources_seen
    md_json = json.dumps(md)
    tg = json.dumps(tags or [])
    now = time.time()
    with conn() as c:
        try:
            c.execute(
                "INSERT INTO nodes(id, investigation_id, type, value, metadata, tags, confidence, source, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (nid, inv_id, type_, value, md_json, tg, confidence, source, now),
            )
            event = {"kind": "node_added", "node": {"id": nid, "type": type_, "value": value,
                                                     "metadata": md, "tags": tags or [],
                                                     "confidence": confidence, "source": source}}
        except sqlite3.IntegrityError:
            row = c.execute("SELECT metadata, tags FROM nodes WHERE id=?", (nid,)).fetchone()
            existing_md = json.loads(row["metadata"] or "{}")
            # Save old sources_seen before update() overwrites it
            old_sources = existing_md.get("sources_seen", [])
            existing_md.update(md)
            # Merge sources_seen from both old and new metadata
            existing_md["sources_seen"] = list(set(old_sources + sources_seen))
            existing_tags = list(set(json.loads(row["tags"] or "[]") + (tags or [])))
            c.execute("UPDATE nodes SET metadata=?, tags=? WHERE id=?",
                      (json.dumps(existing_md), json.dumps(existing_tags), nid))
            event = {"kind": "node_updated", "node": {"id": nid, "type": type_, "value": value,
                                                       "metadata": existing_md, "tags": existing_tags,
                                                       "confidence": confidence, "source": source}}
        c.execute("INSERT INTO events(investigation_id, kind, payload, created_at) VALUES (?,?,?,?)",
                  (inv_id, event["kind"], json.dumps(event), now))
    return {"id": nid, "type": type_, "value": value}


def add_edge(inv_id: str, src_type: str, src_value: str, dst_type: str, dst_value: str,
             relation: str, evidence: str = "", source: str = "agent", confidence: float = 0.8) -> dict:
    src = _node_id(inv_id, src_type, src_value)
    dst = _node_id(inv_id, dst_type, dst_value)
    eid = _edge_id(inv_id, src, dst, relation)
    now = time.time()
    with conn() as c:
        try:
            c.execute(
                "INSERT INTO edges(id, investigation_id, src, dst, relation, evidence, source, confidence, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (eid, inv_id, src, dst, relation, evidence, source, confidence, now),
            )
            event = {"kind": "edge_added", "edge": {"id": eid, "src": src, "dst": dst,
                                                     "relation": relation, "evidence": evidence,
                                                     "source": source, "confidence": confidence}}
            c.execute("INSERT INTO events(investigation_id, kind, payload, created_at) VALUES (?,?,?,?)",
                      (inv_id, event["kind"], json.dumps(event), now))
        except sqlite3.IntegrityError:
            pass
    return {"id": eid, "src": src, "dst": dst, "relation": relation}


def tag_node(inv_id: str, type_: str, value: str, tag: str):
    nid = _node_id(inv_id, type_, value)
    with conn() as c:
        row = c.execute("SELECT tags FROM nodes WHERE id=?", (nid,)).fetchone()
        if not row:
            return
        tags = list(set(json.loads(row["tags"] or "[]") + [tag]))
        c.execute("UPDATE nodes SET tags=? WHERE id=?", (json.dumps(tags), nid))
        event = {"kind": "node_tagged", "node_id": nid, "tag": tag}
        c.execute("INSERT INTO events(investigation_id, kind, payload, created_at) VALUES (?,?,?,?)",
                  (inv_id, event["kind"], json.dumps(event), time.time()))


def get_graph(inv_id: str) -> dict:
    with conn() as c:
        nodes = [dict(r) for r in c.execute("SELECT * FROM nodes WHERE investigation_id=?", (inv_id,))]
        edges = [dict(r) for r in c.execute("SELECT * FROM edges WHERE investigation_id=?", (inv_id,))]
    for n in nodes:
        n["metadata"] = json.loads(n.get("metadata") or "{}")
        n["tags"] = json.loads(n.get("tags") or "[]")
    return {"nodes": nodes, "edges": edges}


def get_events_since(inv_id: str, since_id: int = 0) -> list[dict]:
    with conn() as c:
        rows = c.execute(
            "SELECT id, kind, payload, created_at FROM events WHERE investigation_id=? AND id>? ORDER BY id",
            (inv_id, since_id),
        ).fetchall()
    out = []
    for r in rows:
        p = json.loads(r["payload"])
        p["_id"] = r["id"]
        out.append(p)
    return out


def clear_investigation(inv_id: str):
    with conn() as c:
        c.execute("DELETE FROM nodes WHERE investigation_id=?", (inv_id,))
        c.execute("DELETE FROM edges WHERE investigation_id=?", (inv_id,))
        c.execute("DELETE FROM events WHERE investigation_id=?", (inv_id,))
        c.execute("UPDATE investigations SET status='cleared' WHERE id=?", (inv_id,))


def delete_investigation(inv_id: str):
    with conn() as c:
        c.execute("DELETE FROM nodes WHERE investigation_id=?", (inv_id,))
        c.execute("DELETE FROM edges WHERE investigation_id=?", (inv_id,))
        c.execute("DELETE FROM events WHERE investigation_id=?", (inv_id,))
        c.execute("DELETE FROM investigations WHERE id=?", (inv_id,))


def list_investigations(user_id: Optional[int] = None) -> list[dict]:
    with conn() as c:
        if user_id is None:
            rows = c.execute("SELECT * FROM investigations ORDER BY created_at DESC LIMIT 100").fetchall()
        else:
            rows = c.execute(
                "SELECT * FROM investigations WHERE user_id=? ORDER BY created_at DESC LIMIT 100",
                (user_id,),
            ).fetchall()
        invs = [dict(r) for r in rows]
        if not invs:
            return invs
        ids = [i["id"] for i in invs]
        qmarks = ",".join(["?"] * len(ids))
        seed_rows = c.execute(
            f"SELECT investigation_id, type, value, tags, created_at FROM nodes "
            f"WHERE investigation_id IN ({qmarks}) ORDER BY created_at",
            tuple(ids),
        ).fetchall()
    seed_map: dict[str, list] = {}
    for r in seed_rows:
        tags = json.loads(r["tags"] or "[]")
        if "seed" in tags:
            seed_map.setdefault(r["investigation_id"], []).append({
                "type": r["type"], "value": r["value"], "added_at": r["created_at"],
            })
    for i in invs:
        i["seeds"] = seed_map.get(i["id"], [])
    return invs


def get_investigation_seeds(inv_id: str) -> list[dict]:
    """Return the list of seed-tagged nodes for a single investigation, in order added."""
    with conn() as c:
        rows = c.execute(
            "SELECT type, value, tags, created_at FROM nodes WHERE investigation_id=? ORDER BY created_at",
            (inv_id,),
        ).fetchall()
    out = []
    for r in rows:
        tags = json.loads(r["tags"] or "[]")
        if "seed" in tags:
            out.append({"type": r["type"], "value": r["value"], "added_at": r["created_at"]})
    return out


# ── Admin queries ────────────────────────────────────────────────────────
def get_users_with_stats() -> list[dict]:
    """Return all users with per-user investigation + tool-use stats."""
    with conn() as c:
        user_rows = [dict(r) for r in c.execute(
            "SELECT id, created_at, is_admin, allowed_models, label FROM users ORDER BY id"
        )]
        out = []
        for u in user_rows:
            invs = [dict(r) for r in c.execute(
                "SELECT id, seed_type, seed_value, status, created_at FROM investigations WHERE user_id=? ORDER BY created_at DESC",
                (u["id"],),
            )]
            total = len(invs)
            done = sum(1 for i in invs if i["status"] == "done")
            running = sum(1 for i in invs if i["status"] == "running")
            err = sum(1 for i in invs if str(i["status"]).startswith("error"))
            # Last activity = max(created_at of investigations, event timestamps).
            last_active = max((i["created_at"] or 0) for i in invs) if invs else None
            if invs:
                row = c.execute(
                    "SELECT MAX(created_at) AS ts FROM events WHERE investigation_id IN ("
                    + ",".join("?" * len(invs)) + ")",
                    tuple(i["id"] for i in invs),
                ).fetchone()
                if row and row["ts"]:
                    last_active = max(last_active or 0, row["ts"])
            tools: Counter = Counter()
            for inv in invs:
                for (payload,) in c.execute(
                    "SELECT payload FROM events WHERE investigation_id=? AND kind='agent_assistant'",
                    (inv["id"],),
                ):
                    try:
                        d = json.loads(payload)
                    except Exception:
                        continue
                    for block in d.get("msg", {}).get("message", {}).get("content", []):
                        if block.get("type") == "tool_use":
                            name = block.get("name", "")
                            if name:
                                # Strip mcp__cti__ / mcp__graph__ prefix for readability
                                for p in ("mcp__cti__", "mcp__graph__"):
                                    if name.startswith(p):
                                        name = name[len(p):]
                                        break
                                tools[name] += 1
            out.append({
                "id": u["id"],
                "created_at": u["created_at"],
                "is_admin": bool(u["is_admin"]),
                "allowed_models": json.loads(u["allowed_models"]) if u["allowed_models"] else None,
                "label": u.get("label"),
                "last_active": last_active,
                "stats": {
                    "total": total, "done": done, "running": running, "error": err,
                    "tool_calls": sum(tools.values()),
                },
                "top_tools": tools.most_common(8),
                "investigations": invs,
            })
        return out


def update_user_allowed_models(user_id: int, allowed_models: Optional[list[str]]):
    val = json.dumps(allowed_models) if allowed_models else None
    with conn() as c:
        c.execute("UPDATE users SET allowed_models=? WHERE id=?", (val, user_id))


def update_user_label(user_id: int, label: Optional[str]):
    """Set or clear a short human-readable label for a user (admin-only)."""
    val = (label or "").strip() or None
    with conn() as c:
        c.execute("UPDATE users SET label=? WHERE id=?", (val, user_id))


def delete_user(user_id: int):
    """Cascade-delete user and everything they own."""
    with conn() as c:
        inv_ids = [r["id"] for r in c.execute(
            "SELECT id FROM investigations WHERE user_id=?", (user_id,)
        )]
        for iid in inv_ids:
            c.execute("DELETE FROM nodes WHERE investigation_id=?", (iid,))
            c.execute("DELETE FROM edges WHERE investigation_id=?", (iid,))
            c.execute("DELETE FROM events WHERE investigation_id=?", (iid,))
        c.execute("DELETE FROM investigations WHERE user_id=?", (user_id,))
        c.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        c.execute("DELETE FROM users WHERE id=?", (user_id,))


def get_node_by_id(inv_id: str, node_id: str) -> Optional[dict]:
    """Return a single node by its ID, or None if not found."""
    with conn() as c:
        row = c.execute(
            "SELECT * FROM nodes WHERE id=? AND investigation_id=?",
            (node_id, inv_id),
        ).fetchone()
    if not row:
        return None
    n = dict(row)
    n["metadata"] = json.loads(n.get("metadata") or "{}")
    n["tags"] = json.loads(n.get("tags") or "[]")
    return n


def get_evidence_for_value(value: str) -> list[dict]:
    """Search the cache table for entries whose key contains the given value.

    Returns a list of {key, value, created_at} dicts with the raw cached data.
    This lets analysts audit what the CTI sources actually returned.
    """
    with conn() as c:
        rows = c.execute(
            "SELECT key, value, created_at FROM cache WHERE key LIKE ?",
            (f"%{value}%",),
        ).fetchall()
    out = []
    for r in rows:
        try:
            parsed = json.loads(r["value"])
        except (json.JSONDecodeError, TypeError):
            parsed = r["value"]
        out.append({
            "cache_key": r["key"],
            "data": parsed,
            "cached_at": r["created_at"],
        })
    return out


def cache_get(key: str, ttl: float = 86400) -> Optional[Any]:
    with conn() as c:
        row = c.execute("SELECT value, created_at FROM cache WHERE key=?", (key,)).fetchone()
    if not row:
        return None
    if time.time() - row["created_at"] > ttl:
        return None
    return json.loads(row["value"])


def cache_set(key: str, value: Any):
    with conn() as c:
        c.execute("INSERT OR REPLACE INTO cache(key, value, created_at) VALUES (?,?,?)",
                  (key, json.dumps(value), time.time()))


init_db()
