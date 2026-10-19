"""Every snapshot committed under eval/demo/ is publishable as it stands.

The repository is public and `npm run build:demo` copies these files verbatim
into the static page, so a snapshot edited by hand, written by an older
exporter, or dropped in without going through `eval/demo_export.py` must fail
here rather than on the published page. The rules are those of
`backend/demo_snapshot.py`: the shape `from_view` writes, the events
`reduce_event` keeps, and `check` against the secrets of the CI environment.

With no snapshot committed, only the validator itself is exercised (on a
snapshot built by `from_view`), so the test stays meaningful either way.
"""
import json
import re
from pathlib import Path

import pytest

from backend import demo_snapshot as ds

DEMO_DIR = Path(__file__).resolve().parents[2] / "eval" / "demo"
# Same filter as frontend/vite.demo.config.js: anything else is silently left
# out of the build.
BUILD_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]*\.json$")
# What from_view and reduce_event strip; finding one back means the file did
# not come from them.
STRIPPED = {"session_id", "request_id", "usage", "prompt_history", "cwd", "mcp_config", "thinking"}


def _keys_everywhere(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _keys_everywhere(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _keys_everywhere(v)


def problems_of(snap: dict) -> list[str]:
    out = []
    if set(snap) != {"share", "investigation", "graph", "events"}:
        out.append(f"top-level keys {sorted(snap)}")
        return out
    share = snap["share"]
    if share.get("sections") != ds.SECTIONS:
        out.append(f"sections {share.get('sections')}")
    if (share.get("demo") or {}).get("format") != ds.FORMAT:
        out.append(f"format {(share.get('demo') or {}).get('format')} (expected {ds.FORMAT})")
    if not set(snap["investigation"]) <= set(ds._INV_KEYS):
        out.append(f"investigation keys {sorted(set(snap['investigation']) - set(ds._INV_KEYS))}")
    nodes, edges = snap["graph"].get("nodes", []), snap["graph"].get("edges", [])
    if not nodes:
        out.append("empty graph")
    ids = set()
    for n in nodes:
        if not set(n) <= set(ds._NODE_KEYS):
            out.append(f"node keys {sorted(set(n) - set(ds._NODE_KEYS))}")
        ids.add(n.get("id"))
    for e in edges:
        if not set(e) <= set(ds._EDGE_KEYS):
            out.append(f"edge keys {sorted(set(e) - set(ds._EDGE_KEYS))}")
        if e.get("src") not in ids or e.get("dst") not in ids:
            out.append(f"edge {e.get('id')} points outside the graph")
    for ev in snap["events"]:
        if ds.reduce_event(ev) != ev:
            out.append(f"event {ev.get('kind')!r} is not in its reduced form")
    leaked = STRIPPED & set(_keys_everywhere(snap))
    if leaked:
        out.append(f"stripped fields present: {sorted(leaked)}")
    problems, _ = ds.check(ds.serialise(snap), ds.known_secrets(None))
    return out + problems


def _sample_snapshot() -> dict:
    view = {
        "investigation": {"id": "inv1", "seed_type": "domain", "seed_value": "example.test",
                          "status": "done", "created_at": 1760000000, "seeds": [],
                          "owner_id": 7},
        "graph": {
            "nodes": [{"id": "a", "type": "domain", "value": "example.test", "metadata": {},
                       "tags": [], "source": "seed", "confidence": 1.0, "created_at": 1},
                      {"id": "b", "type": "ip", "value": "192.0.2.1", "metadata": {},
                       "tags": [], "source": "dns_resolve", "confidence": 0.9, "created_at": 2}],
            "edges": [{"id": "e", "src": "a", "dst": "b", "relation": "resolves_to",
                       "evidence": "", "source": "dns_resolve", "confidence": 0.9}],
        },
        "events": [
            {"kind": "agent_assistant", "_ts": 1, "msg": {"session_id": "s", "message": {
                "usage": {"x": 1},
                "content": [{"type": "thinking", "thinking": "…"}, {"type": "text", "text": "hi"}]}}},
            {"kind": "agent_stdout", "_ts": 2, "msg": "raw"},
        ],
    }
    return ds.from_view(view, model="sonnet", label="Sample", now=0)


def test_validator_accepts_what_from_view_writes():
    assert problems_of(_sample_snapshot()) == []


def test_validator_rejects_a_hand_edited_snapshot():
    snap = _sample_snapshot()
    snap["events"][0]["msg"]["session_id"] = "s"
    snap["graph"]["edges"][0]["dst"] = "nowhere"
    snap["share"]["demo"]["format"] = 0
    found = " | ".join(problems_of(snap))
    assert "session_id" in found and "outside the graph" in found and "format" in found


SNAPSHOTS = sorted(DEMO_DIR.glob("*.json")) if DEMO_DIR.exists() else []


@pytest.mark.parametrize("path", SNAPSHOTS, ids=[p.name for p in SNAPSHOTS])
def test_committed_snapshot_is_publishable(path: Path):
    assert BUILD_NAME.match(path.name), "the demo build skips this file name"
    snap = json.loads(path.read_text(encoding="utf-8"))
    assert problems_of(snap) == []
