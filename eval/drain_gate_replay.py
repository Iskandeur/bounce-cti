"""Replay the pivot-drain gate (agent_runner._concluded_benign) on a database.

For every investigation that started a pivot drain, rebuild its graph AS IT
STOOD when the drain started (from the node_added / node_updated / node_tagged
events), apply the gate exactly as Phase 4 does (CTI only), and compare with
what the drain actually added. The database is opened read-only.

    python eval/drain_gate_replay.py --db data/bounce.db [--seeds] [--inv ID ...]

Prints: drains replayed, drains the gate would skip (with the CTI calls they
spent and the malicious nodes they added), and, among the drains it keeps,
those that added malicious nodes on a `legitimate` hypothesis (the gate's
misses). Seed values are only printed with --seeds.
"""
import argparse
import json
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.agent_runner import _concluded_benign  # noqa: E402

BAD_TAGS = {"malicious", "c2", "phishing", "malware", "attacker"}  # as eval/scorer.score_negative
INFRA = {"domain", "ip", "asn", "ns", "registrar", "cert", "cert_serial", "cert_cn"}
ATTRIBUTION = {"actor", "threat_actor", "malware", "ransomware", "framework", "phishing_kit", "kit"}


def rebuild(db, inv, upto_id):
    nodes = {}
    for kind, payload in db.execute(
            "SELECT kind, payload FROM events WHERE investigation_id=? AND id<? "
            "AND kind IN ('node_added','node_updated','node_tagged') ORDER BY id", (inv, upto_id)):
        p = json.loads(payload)
        if kind in ("node_added", "node_updated"):
            n = p.get("node") or {}
            if n.get("id"):
                nodes[n["id"]] = dict(n)
        else:
            n = nodes.get(p.get("node_id"))
            if n is not None and p.get("tag") and p["tag"] not in (n.get("tags") or []):
                n["tags"] = list(n.get("tags") or []) + [p["tag"]]
    return nodes


def malicious(nodes):
    infra = sum(1 for n in nodes.values() if (n.get("type") or "").lower() in INFRA
                and any(str(t).lower() in BAD_TAGS for t in (n.get("tags") or [])))
    attr = sum(1 for n in nodes.values() if (n.get("type") or "").lower() in ATTRIBUTION)
    return infra, attr


def hypotheses(nodes):
    return [str((n.get("metadata") or {}).get("category")
                or (n.get("metadata") or {}).get("candidate_category") or "").lower()
            for n in nodes.values() if (n.get("type") or "").lower() == "report"
            and str(n.get("value") or "").lower().startswith("working_hypothesis")]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--db", default="data/bounce.db")
    ap.add_argument("--seeds", action="store_true", help="print seed values")
    ap.add_argument("--inv", nargs="*", help="only these investigations")
    a = ap.parse_args(argv)
    db = sqlite3.connect(f"file:{a.db}?mode=ro", uri=True)
    starts = db.execute("SELECT investigation_id, id FROM events "
                        "WHERE kind='phase_pivot_drain_starting' ORDER BY id").fetchall()
    rows = []
    for inv, sid in starts:
        if a.inv and inv not in a.inv:
            continue
        meta = db.execute("SELECT seed_type, seed_value, vertical FROM investigations WHERE id=?",
                          (inv,)).fetchone() or (None, None, "cti")
        before = rebuild(db, inv, sid)
        verdict = None
        if (meta[2] or "cti") == "cti":
            verdict = _concluded_benign(list(before.values()))
        end = db.execute("SELECT min(id) FROM events WHERE investigation_id=? AND id>? AND kind IN "
                         "('phase_lessons_learned_starting','phase_pivot_drain_starting')",
                         (inv, sid)).fetchone()[0] or 10 ** 12
        after = rebuild(db, inv, end)
        calls = 0
        for (payload,) in db.execute("SELECT payload FROM events WHERE investigation_id=? AND id>? "
                                     "AND id<? AND kind='agent_assistant'", (inv, sid, end)):
            calls += payload.count('"name": "mcp__cti__')
        (ib, ab), (ia, aa) = malicious(before), malicious(after)
        rows.append({"inv": inv, "seed_type": meta[0], "seed": meta[1], "vertical": meta[2] or "cti",
                     "skip": bool(verdict), "nodes": (len(before), len(after)),
                     "added_malicious": (ia - ib) + (aa - ab), "cti_calls": calls,
                     "legitimate": bool(hypotheses(before)) and all(
                         h == "legitimate" for h in hypotheses(before))})
    skips = [r for r in rows if r["skip"]]
    print(f"drains replayed: {len(rows)}")
    print(f"skipped by the gate: {len(skips)} (CTI calls they spent: {sum(r['cti_calls'] for r in skips)}; "
          f"of which added malicious nodes: {sum(1 for r in skips if r['added_malicious'] > 0)})")
    for r in skips:
        seed = f" {r['seed']}" if a.seeds else ""
        print(f"  {r['inv']} {r['seed_type']} nodes {r['nodes'][0]}->{r['nodes'][1]} "
              f"malicious added {r['added_malicious']} cti calls {r['cti_calls']}{seed}")
    misses = [r for r in rows if not r["skip"] and r["legitimate"] and r["added_malicious"] > 0]
    print(f"kept drains on a `legitimate` hypothesis that added malicious nodes: {len(misses)}")
    for r in misses:
        seed = f" {r['seed']}" if a.seeds else ""
        print(f"  {r['inv']} {r['vertical']} {r['seed_type']}{seed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
