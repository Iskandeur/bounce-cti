"""Demo snapshots: one investigation frozen for a public, static page (roadmap J3).

A snapshot is what a share link with the ``graph``, ``report`` and ``timeline``
sections shows (``graph_store.share_view``), minus what a public page has no
use for: the agent's session and request ids, token usage, the MCP config path
and working directory, and everything but the text and tool calls of an
assistant message. Report chats (``prompt_history``) never go in.

The static viewer (``frontend/demo/``, ``npm run build:demo``) reads these
files with ``SharedView``; ``eval/demo/`` holds the committed ones.

Two ways to make one, same rules:

* ``GET /api/investigations/{id}/demo_snapshot`` (owner only), checked against
  the server's own secrets;
* ``python eval/demo_export.py <inv_id> <name> --db … --dotenv …``, from a
  database file, checked against the ``.env`` of the instance that ran it.

A snapshot that contains a secret value, or a word the caller forbids, is
refused. A credential *shape* is only a warning (threat data carries tokens).

Stdlib only, pure except :func:`known_secrets` (reads a file and the
environment).
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from . import fixtures

SECTIONS = ["graph", "report", "timeline"]
FORMAT = 1
_NODE_KEYS = ("id", "type", "value", "metadata", "tags", "source", "confidence", "created_at")
_EDGE_KEYS = ("id", "src", "dst", "relation", "evidence", "source", "confidence")
_INV_KEYS = ("id", "seed_type", "seed_value", "status", "created_at", "seeds")


def reduce_event(e: dict) -> Optional[dict]:
    """The part of a timeline event that SharedView reads, or None to drop it."""
    kind = e.get("kind")
    out: dict = {"kind": kind, "_ts": e.get("_ts")}
    msg = e.get("msg") if isinstance(e.get("msg"), dict) else {}
    if kind == "agent_assistant":
        kept = []
        for b in (msg.get("message") or {}).get("content") or []:
            if not isinstance(b, dict):
                continue
            if b.get("type") == "text" and b.get("text"):
                kept.append({"type": "text", "text": b["text"]})
            elif b.get("type") == "tool_use":
                kept.append({"type": "tool_use", "name": b.get("name", ""),
                             "input": b.get("input") or {}})
        if not kept:
            return None
        out["msg"] = {"message": {"content": kept}}
    elif kind == "agent_exit":
        out["msg"] = {k: msg[k] for k in ("phase", "rc") if k in msg}
    elif kind == "status_change":
        # Written as {"kind", "status", …} (graph_store, main); older rows may
        # nest it under "msg".
        raw = e.get("msg")
        status = e.get("status") or (raw if isinstance(raw, str) else msg.get("status"))
        out["msg"] = {"status": status}
    elif kind == "node_tagged":
        out["tag"] = e.get("tag")
    elif kind != "agent_starting":
        return None
    return out


def from_view(view: dict, model: Optional[str], label: Optional[str] = None,
              now: Optional[float] = None) -> dict:
    """A snapshot from ``graph_store.share_view(inv_id, SECTIONS)``. PURE."""
    events = [x for x in (reduce_event(e) for e in view.get("events", [])) if x is not None]
    inv = view["investigation"]
    return {
        "share": {
            "sections": list(SECTIONS),
            "demo": {
                "format": FORMAT,
                "label": label,
                "model": model,
                "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                             time.gmtime(time.time() if now is None else now)),
            },
        },
        "investigation": {k: inv.get(k) for k in _INV_KEYS},
        "graph": {
            "nodes": [{k: n.get(k) for k in _NODE_KEYS} for n in view["graph"]["nodes"]],
            "edges": [{k: e.get(k) for k in _EDGE_KEYS} for e in view["graph"]["edges"]],
        },
        "events": events,
    }


def serialise(snapshot: dict) -> str:
    return json.dumps(snapshot, ensure_ascii=False, separators=(",", ":"))


def known_secrets(dotenv: Optional[Path]) -> list[tuple[str, str]]:
    """(name, value) of every secret to look for: the secret-looking entries of
    ``dotenv``, plus those of this process's environment."""
    out = list(fixtures.dotenv_secrets(dotenv)) if dotenv is not None else []
    out += [(placeholder, value) for value, placeholder in fixtures._secrets()]
    return out


def check(text: str, secrets: list[tuple[str, str]],
          forbid: Optional[list[str]] = None) -> tuple[list[str], list[str]]:
    """(problems, warnings) for a serialised snapshot. A problem blocks it.
    Messages name a secret, never print its value. PURE."""
    problems, warnings = [], []
    for name in sorted({name for name, value in secrets if value in text}):
        problems.append(f"contains the value of the secret {name}")
    low = text.lower()
    for word in forbid or []:
        w = word.strip()
        if w and w.lower() in low:
            problems.append(f"contains the forbidden word {w!r}")
    for shape in fixtures.CREDENTIAL_SHAPES:
        for m in shape.finditer(text):
            # Only the part before the value: a warning may be read by someone
            # who must not see the value itself.
            found = m.group(0)
            cut = min([i for i in (found.find("="), found.find(" ")) if i >= 0] or [0])
            warnings.append(f"credential-shaped text {found[:cut + 1][:16]!r}… ({len(found)} chars, "
                            f"at offset {m.start()}): threat data, or a leak? look before publishing")
    return problems, warnings
