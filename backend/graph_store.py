"""SQLite-backed graph store. Single source of truth for the investigation."""
import json
import sqlite3
import time
import hashlib
from contextlib import contextmanager
from typing import Any, Optional
from .config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    seed_type TEXT,
    seed_value TEXT,
    created_at REAL,
    status TEXT
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


def init_db():
    with conn() as c:
        c.executescript(SCHEMA)


def create_investigation(seed_type: str, seed_value: str) -> str:
    inv_id = hashlib.sha1(f"{time.time()}|{seed_type}|{seed_value}".encode()).hexdigest()[:12]
    with conn() as c:
        c.execute(
            "INSERT INTO investigations(id, seed_type, seed_value, created_at, status) VALUES (?,?,?,?,?)",
            (inv_id, seed_type, seed_value, time.time(), "running"),
        )
    return inv_id


def set_status(inv_id: str, status: str):
    with conn() as c:
        c.execute("UPDATE investigations SET status=? WHERE id=?", (status, inv_id))


def add_node(inv_id: str, type_: str, value: str, metadata: dict | None = None,
             confidence: float = 0.8, source: str = "agent", tags: list[str] | None = None) -> dict:
    nid = _node_id(inv_id, type_, value)
    md = json.dumps(metadata or {})
    tg = json.dumps(tags or [])
    now = time.time()
    with conn() as c:
        try:
            c.execute(
                "INSERT INTO nodes(id, investigation_id, type, value, metadata, tags, confidence, source, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (nid, inv_id, type_, value, md, tg, confidence, source, now),
            )
            event = {"kind": "node_added", "node": {"id": nid, "type": type_, "value": value,
                                                     "metadata": metadata or {}, "tags": tags or [],
                                                     "confidence": confidence, "source": source}}
        except sqlite3.IntegrityError:
            # merge metadata
            row = c.execute("SELECT metadata, tags FROM nodes WHERE id=?", (nid,)).fetchone()
            existing_md = json.loads(row["metadata"] or "{}")
            existing_md.update(metadata or {})
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
    """Delete all nodes, edges and events for an investigation and reset it to running."""
    with conn() as c:
        c.execute("DELETE FROM nodes WHERE investigation_id=?", (inv_id,))
        c.execute("DELETE FROM edges WHERE investigation_id=?", (inv_id,))
        c.execute("DELETE FROM events WHERE investigation_id=?", (inv_id,))
        c.execute("UPDATE investigations SET status='cleared' WHERE id=?", (inv_id,))


def delete_investigation(inv_id: str):
    """Fully remove an investigation."""
    with conn() as c:
        c.execute("DELETE FROM nodes WHERE investigation_id=?", (inv_id,))
        c.execute("DELETE FROM edges WHERE investigation_id=?", (inv_id,))
        c.execute("DELETE FROM events WHERE investigation_id=?", (inv_id,))
        c.execute("DELETE FROM investigations WHERE id=?", (inv_id,))


def list_investigations() -> list[dict]:
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM investigations ORDER BY created_at DESC LIMIT 100")]


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
