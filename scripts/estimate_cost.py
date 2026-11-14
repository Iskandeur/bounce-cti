#!/usr/bin/env python3
"""Estimate last-30-days agentic spend from the live SQLite DB.

Run ON THE VPS (where data/bounce.db lives):

    python3 scripts/estimate_cost.py [--days 30] [--db data/bounce.db]

It does NOT call any API and does NOT need network. It reads the events log,
counts real `mcp__cti__*` tool_use blocks per investigation (the same signal
agent_runner._count_cti_calls uses), and converts CTI-call volume into a $
estimate per model. The conversion factors are coarse (cost was never logged),
so treat the output as an order-of-magnitude check against the $200 agentic
credit — not an invoice. Once usage-logging lands in agent_runner, this can be
replaced by exact token math.
"""
import argparse
import json
import sqlite3
import time

# $ per CTI call — anchored to the eval-run activity distribution (median ~30
# CTI calls/investigation) and typical Claude-Code agentic session costs.
# Bands are wide on purpose; central value used for the headline number.
COST_PER_CALL = {
    "opus":   (0.05, 0.08, 0.12),   # claude-opus-4-8  ($5/$25 per Mtok)
    "sonnet": (0.03, 0.05, 0.07),   # claude-sonnet-4-6 ($3/$15)
    "haiku":  (0.01, 0.015, 0.02),  # claude-haiku-4-5 ($1/$5)
}


def count_cti_calls(payload: str) -> int:
    try:
        d = json.loads(payload)
    except (json.JSONDecodeError, TypeError):
        return 0
    if d.get("kind") != "agent_assistant":
        return 0
    n = 0
    for block in d.get("msg", {}).get("message", {}).get("content", []):
        if block.get("type") == "tool_use" and \
           str(block.get("name", "")).startswith("mcp__cti__"):
            n += 1
    return n


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="data/bounce.db")
    ap.add_argument("--days", type=int, default=30)
    args = ap.parse_args()

    since = time.time() - args.days * 86400
    con = sqlite3.connect(args.db)

    invs = con.execute(
        "SELECT id, status, model FROM investigations WHERE created_at >= ?",
        (since,),
    ).fetchall()
    inv_ids = [r[0] for r in invs]
    by_status: dict[str, int] = {}
    for _id, status, _model in invs:
        by_status[status or "unknown"] = by_status.get(status or "unknown", 0) + 1

    total_calls = 0
    per_inv = []
    for inv_id, status, model in invs:
        rows = con.execute(
            "SELECT payload FROM events WHERE investigation_id=?", (inv_id,)
        ).fetchall()
        calls = sum(count_cti_calls(p) for (p,) in rows)
        total_calls += calls
        per_inv.append(calls)
    con.close()

    n = len(inv_ids)
    per_inv.sort()
    median = per_inv[n // 2] if n else 0

    print(f"\n=== {args.days} derniers jours (db: {args.db}) ===")
    print(f"Investigations lancées : {n}")
    print(f"  par statut : {by_status}")
    print(f"Appels CTI totaux       : {total_calls}")
    print(f"Appels CTI médian/inv   : {median}")

    print(f"\n=== Estimation de coût mensuel (extrapolé à 30 j) ===")
    scale = 30 / args.days
    for model, (lo, mid, hi) in COST_PER_CALL.items():
        month_calls = total_calls * scale
        print(f"  {model:6s}: {month_calls*lo:6.0f} $ – {month_calls*mid:6.0f} $ "
              f"– {month_calls*hi:6.0f} $   (central ~{month_calls*mid:.0f} $)")
    print("\nSeuil crédit agentique Max 20x = 200 $/mois.")
    print("Si le 'central' dépasse 200 $, le fallback API prendra le relais "
          "au-delà du crédit ; sinon les 200 $ suffisent.\n")


if __name__ == "__main__":
    main()
