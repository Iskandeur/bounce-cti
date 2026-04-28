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
CREATE TABLE IF NOT EXISTS shares (
    token TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    created_by INTEGER NOT NULL,
    created_at REAL NOT NULL,
    sections TEXT NOT NULL,
    expires_at REAL,
    revoked INTEGER NOT NULL DEFAULT 0,
    label TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_investigations_user ON investigations(user_id);
CREATE INDEX IF NOT EXISTS idx_events_inv ON events(investigation_id);
CREATE INDEX IF NOT EXISTS idx_shares_inv ON shares(investigation_id);
CREATE INDEX IF NOT EXISTS idx_shares_user ON shares(created_by);
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
                                                     "confidence": confidence, "source": source,
                                                     "created_at": now}}
        except sqlite3.IntegrityError:
            row = c.execute("SELECT metadata, tags, created_at FROM nodes WHERE id=?", (nid,)).fetchone()
            existing_md = json.loads(row["metadata"] or "{}")
            original_created_at = row["created_at"]
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
                                                       "confidence": confidence, "source": source,
                                                       "created_at": original_created_at}}
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


def set_node_tag(inv_id: str, node_id: str, tag: str, on: bool) -> Optional[dict]:
    """Toggle a single tag on a node by id. Returns the updated node dict
    so the caller can broadcast a `node_updated` event over the WebSocket
    (the existing `node_tagged` event is fire-and-forget; updating the
    full node record keeps every connected client in sync — including
    untag, which `node_tagged` doesn't model)."""
    with conn() as c:
        row = c.execute(
            "SELECT * FROM nodes WHERE id=? AND investigation_id=?",
            (node_id, inv_id),
        ).fetchone()
        if not row:
            return None
        existing = set(json.loads(row["tags"] or "[]"))
        if on:
            existing.add(tag)
        else:
            existing.discard(tag)
        tags_json = json.dumps(sorted(existing))
        c.execute("UPDATE nodes SET tags=? WHERE id=?", (tags_json, node_id))
        # Re-fetch full row so the event payload mirrors `add_node`'s shape.
        row2 = c.execute("SELECT * FROM nodes WHERE id=?", (node_id,)).fetchone()
        node = dict(row2)
        node["metadata"] = json.loads(node.get("metadata") or "{}")
        node["tags"] = json.loads(node.get("tags") or "[]")
        event = {"kind": "node_updated", "node": {
            "id": node["id"], "type": node["type"], "value": node["value"],
            "metadata": node["metadata"], "tags": node["tags"],
            "confidence": node.get("confidence") or 0.8,
            "source": node.get("source") or "user",
            "created_at": node.get("created_at") or time.time(),
        }}
        c.execute(
            "INSERT INTO events(investigation_id, kind, payload, created_at) VALUES (?,?,?,?)",
            (inv_id, event["kind"], json.dumps(event), time.time()),
        )
    return node


def set_node_user_note(inv_id: str, node_id: str, note: str) -> Optional[dict]:
    """Stash an analyst-written annotation on a node. Free text, capped to
    keep the metadata blob small. Empty string clears the note. Persists
    inside `metadata.user_note` and broadcasts a `node_updated` event."""
    note = (note or "").strip()[:200]
    with conn() as c:
        row = c.execute(
            "SELECT * FROM nodes WHERE id=? AND investigation_id=?",
            (node_id, inv_id),
        ).fetchone()
        if not row:
            return None
        md = json.loads(row["metadata"] or "{}")
        if note:
            md["user_note"] = note
        else:
            md.pop("user_note", None)
        c.execute("UPDATE nodes SET metadata=? WHERE id=?",
                  (json.dumps(md), node_id))
        row2 = c.execute("SELECT * FROM nodes WHERE id=?", (node_id,)).fetchone()
        node = dict(row2)
        node["metadata"] = json.loads(node.get("metadata") or "{}")
        node["tags"] = json.loads(node.get("tags") or "[]")
        event = {"kind": "node_updated", "node": {
            "id": node["id"], "type": node["type"], "value": node["value"],
            "metadata": node["metadata"], "tags": node["tags"],
            "confidence": node.get("confidence") or 0.8,
            "source": node.get("source") or "user",
            "created_at": node.get("created_at") or time.time(),
        }}
        c.execute(
            "INSERT INTO events(investigation_id, kind, payload, created_at) VALUES (?,?,?,?)",
            (inv_id, event["kind"], json.dumps(event), time.time()),
        )
    return node


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
        p["_ts"] = r["created_at"]
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


# ── Shares (link-based investigation sharing + clone) ─────────────────────
# Sections control what the share link exposes. 'graph' is the only mandatory
# section: a share without nodes/edges is meaningless. The other flags filter
# the response payload (and what the import endpoint copies into the
# recipient's account):
#   - 'graph':    nodes + edges (always on)
#   - 'report':   the investigation_summary node (key findings, IOCs, …)
#   - 'timeline': agent_* events (reasoning, tool calls, status changes)
#   - 'evidence': raw cached source data is reachable via the shared inv_id
#   - 'chats':    prompt_history embedded inside the report metadata
SHARE_SECTIONS = ("graph", "report", "timeline", "evidence", "chats")
SHARE_DEFAULTS = ("graph", "report", "timeline", "evidence")  # chats off by default


def _new_share_token() -> str:
    import secrets as _s
    return _s.token_urlsafe(18)


def normalize_sections(raw: Optional[list[str]]) -> list[str]:
    """Pin sections to the known set; always include 'graph'."""
    if not raw:
        return list(SHARE_DEFAULTS)
    out = [s for s in raw if s in SHARE_SECTIONS]
    if "graph" not in out:
        out.append("graph")
    return out


def create_share(inv_id: str, user_id: int, sections: list[str],
                 expires_at: Optional[float] = None,
                 label: Optional[str] = None) -> dict:
    sections = normalize_sections(sections)
    token = _new_share_token()
    now = time.time()
    with conn() as c:
        c.execute(
            "INSERT INTO shares(token, investigation_id, created_by, created_at, sections, expires_at, revoked, label) "
            "VALUES (?,?,?,?,?,?,0,?)",
            (token, inv_id, user_id, now, json.dumps(sections), expires_at, label),
        )
    return {"token": token, "investigation_id": inv_id, "created_by": user_id,
            "created_at": now, "sections": sections, "expires_at": expires_at,
            "revoked": False, "label": label}


def get_share(token: str) -> Optional[dict]:
    with conn() as c:
        row = c.execute("SELECT * FROM shares WHERE token=?", (token,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["sections"] = json.loads(d.get("sections") or "[]")
    d["revoked"] = bool(d["revoked"])
    return d


def list_shares_for_user(user_id: int) -> list[dict]:
    with conn() as c:
        rows = c.execute(
            "SELECT s.*, i.seed_type, i.seed_value FROM shares s "
            "LEFT JOIN investigations i ON i.id = s.investigation_id "
            "WHERE s.created_by=? ORDER BY s.created_at DESC",
            (user_id,),
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["sections"] = json.loads(d.get("sections") or "[]")
        d["revoked"] = bool(d["revoked"])
        out.append(d)
    return out


def list_shares_for_investigation(inv_id: str) -> list[dict]:
    with conn() as c:
        rows = c.execute(
            "SELECT * FROM shares WHERE investigation_id=? ORDER BY created_at DESC",
            (inv_id,),
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["sections"] = json.loads(d.get("sections") or "[]")
        d["revoked"] = bool(d["revoked"])
        out.append(d)
    return out


def revoke_share(token: str, user_id: int) -> bool:
    with conn() as c:
        cur = c.execute(
            "UPDATE shares SET revoked=1 WHERE token=? AND created_by=?",
            (token, user_id),
        )
        return cur.rowcount > 0


def delete_share(token: str, user_id: int) -> bool:
    with conn() as c:
        cur = c.execute(
            "DELETE FROM shares WHERE token=? AND created_by=?",
            (token, user_id),
        )
        return cur.rowcount > 0


def _filter_report_metadata(md: dict, sections: list[str]) -> dict:
    """Strip parts of the report metadata that aren't permitted by the share."""
    out = dict(md or {})
    if "chats" not in sections:
        # prompt_history holds the full back-and-forth with the agent
        out.pop("prompt_history", None)
    return out


def get_share_payload(token: str) -> Optional[dict]:
    """Public read of a share token. Returns the filtered investigation data,
    or None if the token is invalid / revoked / expired."""
    s = get_share(token)
    if not s or s["revoked"]:
        return None
    if s["expires_at"] and s["expires_at"] < time.time():
        return None
    inv_id = s["investigation_id"]
    sections = s["sections"]
    with conn() as c:
        inv_row = c.execute(
            "SELECT id, seed_type, seed_value, status, created_at, model FROM investigations WHERE id=?",
            (inv_id,),
        ).fetchone()
    if not inv_row:
        return None
    inv = dict(inv_row)

    graph = get_graph(inv_id)
    # Apply chat filter to the embedded report node, if present.
    if "report" not in sections:
        graph["nodes"] = [n for n in graph["nodes"] if n.get("type") != "report"]
    elif "chats" not in sections:
        for n in graph["nodes"]:
            if n.get("type") == "report":
                n["metadata"] = _filter_report_metadata(n.get("metadata") or {}, sections)
    seeds = get_investigation_seeds(inv_id)

    payload = {
        "share": {
            "token": s["token"],
            "sections": sections,
            "created_at": s["created_at"],
            "expires_at": s["expires_at"],
            "label": s["label"],
        },
        "investigation": {
            "id": inv["id"],
            "seed_type": inv["seed_type"],
            "seed_value": inv["seed_value"],
            "status": inv["status"],
            "created_at": inv["created_at"],
            "seeds": seeds,
        },
        "graph": graph,
    }

    if "timeline" in sections:
        # Surface only the agent-visible timeline items (reasoning + tool
        # calls + status). We deliberately omit `agent_user`, raw node_added
        # spam etc. — those are reconstructable from the graph.
        with conn() as c:
            evs = c.execute(
                "SELECT id, kind, payload, created_at FROM events "
                "WHERE investigation_id=? AND kind IN "
                "('agent_assistant', 'status_change', 'agent_starting', 'agent_exit', 'node_tagged') "
                "ORDER BY id",
                (inv_id,),
            ).fetchall()
        payload["events"] = []
        for r in evs:
            try:
                p = json.loads(r["payload"])
            except Exception:
                continue
            p["_id"] = r["id"]
            p["_ts"] = r["created_at"]
            payload["events"].append(p)
    return payload


def clone_investigation(source_inv_id: str, target_user_id: int,
                        sections: Optional[list[str]] = None,
                        model: Optional[str] = None) -> Optional[str]:
    """Copy a source investigation into the recipient's account.

    Recomputes node IDs against the new investigation_id (since `_node_id`
    hashes inv into the id), remaps edge endpoints accordingly, and writes
    everything as a single fresh investigation with status='done'. The
    recipient can then pivot, add seeds, ask the agent — it's their graph.

    `sections` mirrors share filtering: when 'report' is excluded the report
    node is omitted from the copy; when 'chats' is excluded the report's
    prompt_history is stripped before copy. Cache (evidence) is global so
    nothing to copy there — the new investigation can read it transparently
    if 'evidence' is included; otherwise the API layer can refuse.
    """
    sections = normalize_sections(sections or list(SHARE_SECTIONS))
    with conn() as c:
        src = c.execute(
            "SELECT seed_type, seed_value, model FROM investigations WHERE id=?",
            (source_inv_id,),
        ).fetchone()
    if not src:
        return None
    new_inv = create_investigation(
        src["seed_type"], src["seed_value"],
        user_id=target_user_id,
        model=model or src["model"] or "sonnet",
    )
    set_status(new_inv, "done")

    src_graph = get_graph(source_inv_id)
    id_map: dict[str, str] = {}
    now = time.time()
    with conn() as c:
        for n in src_graph["nodes"]:
            if n["type"] == "report" and "report" not in sections:
                continue
            md = n.get("metadata") or {}
            if n["type"] == "report" and "chats" not in sections:
                md = _filter_report_metadata(md, sections)
            new_id = _node_id(new_inv, n["type"], n["value"])
            id_map[n["id"]] = new_id
            c.execute(
                "INSERT OR IGNORE INTO nodes(id, investigation_id, type, value, metadata, tags, "
                "confidence, source, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (new_id, new_inv, n["type"], n["value"],
                 json.dumps(md),
                 json.dumps(n.get("tags") or []),
                 n.get("confidence") or 0.8,
                 (n.get("source") or "imported"),
                 n.get("created_at") or now),
            )
        for e in src_graph["edges"]:
            new_src = id_map.get(e["src"])
            new_dst = id_map.get(e["dst"])
            if not new_src or not new_dst:
                # Skip orphan edges (e.g. when 'report' was excluded and an
                # edge pointed at the report node).
                continue
            new_eid = _edge_id(new_inv, new_src, new_dst, e["relation"])
            c.execute(
                "INSERT OR IGNORE INTO edges(id, investigation_id, src, dst, relation, "
                "evidence, source, confidence, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (new_eid, new_inv, new_src, new_dst, e["relation"],
                 e.get("evidence") or "", (e.get("source") or "imported"),
                 e.get("confidence") or 0.8,
                 e.get("created_at") or now),
            )
        # Write a single import-marker event so the recipient's timeline
        # shows where the graph came from.
        c.execute(
            "INSERT INTO events(investigation_id, kind, payload, created_at) VALUES (?,?,?,?)",
            (new_inv, "imported",
             json.dumps({"kind": "imported", "from": source_inv_id, "sections": sections}),
             now),
        )
    return new_inv


def merge_into_investigation(source_inv_id: str, target_inv_id: str,
                             sections: Optional[list[str]] = None) -> dict:
    """Merge a source investigation's graph into an existing target.

    Use case: an analyst already has a graph, then receives a share link
    that contains overlapping IOCs. Cloning would land it as a separate
    investigation, leaving the duplicates dangling in two parallel graphs
    with no edge between them. Merging unifies them in a single graph:

    - Each source node is upserted into the target via `add_node`, which
      dedupes on `(target_inv_id, type, value)` and merges metadata,
      tags, and `sources_seen` into the existing row when it matches.
    - Each source edge is rewritten with the source/destination resolved
      via the source's (type, value) pair, then `add_edge` re-hashes the
      edge id against `target_inv_id`. The unique `(inv, src, dst, rel)`
      constraint suppresses redundant edges; new ones land cleanly.
    - The source's report node is skipped when the target already has one
      so the recipient's analysis is never overwritten by the share's.

    Returns counters so the UI can confirm 'X added, Y merged, Z edges'.
    """
    sections = normalize_sections(sections or list(SHARE_SECTIONS))
    src = get_graph(source_inv_id)
    tgt = get_graph(target_inv_id)
    target_keys = {(n["type"], (n.get("value") or "").lower()) for n in tgt["nodes"]}
    target_has_report = any(
        n.get("type") == "report" and n.get("value") == "investigation_summary"
        for n in tgt["nodes"]
    )

    nodes_added = 0
    nodes_merged = 0
    edges_added = 0
    # source_node_id -> (type, value) so we can rewrite edges below.
    id_lookup: dict[str, tuple[str, str]] = {}

    for n in src["nodes"]:
        if n["type"] == "report":
            if "report" not in sections:
                continue
            if n.get("value") == "investigation_summary" and target_has_report:
                # Don't clobber the recipient's analysis. They can still
                # open the share view directly to read the original report.
                continue
        md = n.get("metadata") or {}
        if n["type"] == "report" and "chats" not in sections:
            md = _filter_report_metadata(md, sections)
        key = (n["type"], (n.get("value") or "").lower())
        existed = key in target_keys
        # add_node handles upsert: first call inserts, second merges metadata
        # + tags + sources_seen, emits node_added / node_updated events so
        # any open WebSocket on the target investigation sees the merge live.
        add_node(
            target_inv_id, n["type"], n["value"],
            metadata=md, tags=n.get("tags") or [],
            source=(n.get("source") or "imported"),
            confidence=(n.get("confidence") or 0.8),
        )
        id_lookup[n["id"]] = (n["type"], n["value"])
        if existed:
            nodes_merged += 1
        else:
            nodes_added += 1
            target_keys.add(key)

    for e in src["edges"]:
        s_tv = id_lookup.get(e["src"])
        d_tv = id_lookup.get(e["dst"])
        if not s_tv or not d_tv:
            # Endpoint was filtered (e.g. report excluded). Skip silently.
            continue
        # add_edge dedupes by (inv, src, dst, relation); a redundant edge is
        # a no-op. We don't get a precise "edges merged vs new" count back
        # without an extra round-trip, so report the upper bound.
        add_edge(
            target_inv_id,
            s_tv[0], s_tv[1],
            d_tv[0], d_tv[1],
            e.get("relation") or "related",
            evidence=(e.get("evidence") or ""),
            source=(e.get("source") or "imported"),
            confidence=(e.get("confidence") or 0.8),
        )
        edges_added += 1

    # Audit trail so the recipient can see when/where this merge came from.
    with conn() as c:
        c.execute(
            "INSERT INTO events(investigation_id, kind, payload, created_at) VALUES (?,?,?,?)",
            (target_inv_id, "imported",
             json.dumps({
                 "kind": "imported",
                 "from": source_inv_id,
                 "mode": "merge",
                 "sections": sections,
                 "nodes_added": nodes_added,
                 "nodes_merged": nodes_merged,
                 "edges_added": edges_added,
             }),
             time.time()),
        )

    return {
        "target_inv_id": target_inv_id,
        "nodes_added": nodes_added,
        "nodes_merged": nodes_merged,
        "edges_added": edges_added,
    }


init_db()
