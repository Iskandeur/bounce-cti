"""Where a run stands: phase, elapsed time, source calls against the budget.

Read by ``GET /api/investigations/{id}/progress``, which the UI polls while an
investigation runs. Everything comes from the ``events`` table and the
investigation row, so the answer is the same for every client and survives a
page reload.

"This run" is everything logged since the last ``agent_starting`` event. A
rerun deletes the earlier events; a resume, an added seed, a manual pivot and a
custom prompt keep them and each log their own ``agent_starting``, so each of
them is a run of its own.

The source-call count is the pivot-drain loop's own counter
(``agent_runner._count_cti_calls``): every ``tool_use`` block of the
investigation whose tool belongs to the vertical's source pool
(``mcp__cti__*`` for cti and osint, ``mcp__dd__*`` for dd), over the WHOLE
investigation. ``BOUNCE_TOTAL_CTI_BUDGET`` is compared to that count by the
drain loop alone: it stops opening rounds once the budget is nearly used. The
main and follow-up phases are bounded by their turn limits only, so the count
can end above the budget. A run that has no drain loop (added seed, manual
pivot, custom prompt, or ``BOUNCE_PIVOT_DRAIN_ROUNDS=0``) therefore reports no
ceiling. Context-pool calls (``mcp__ctx__*``) have their own budget and are
not counted here.

``compute`` and ``count_source_calls`` are pure; ``read_progress`` is the thin
database reader. Locked by tests/test_run_progress.py.
"""
import json
import os
import time
from typing import Iterable, Optional

from . import graph_store as gs
from . import verticals

# Same defaults as the drain loop in agent_runner.run_investigation
# (test_run_progress.py fails when the two part ways).
DEFAULT_TOTAL_BUDGET = "82"
DEFAULT_DRAIN_ROUNDS = "3"

# What kind of run an ``agent_starting`` event opens, from its ``phase`` field.
# run_investigation logs none: that is the full multi-phase investigation.
RUN_KINDS = ("investigation", "add_seed", "pivot", "custom_prompt")

# The drain loop logs ``phase_pivot_drain_starting`` once, before its rounds:
# a header carrying the loop's settings, with no matching exit.
_DRAIN_HEADER = "pivot_drain"
_DRAIN_ROUND_PREFIX = "pivot_drain_"


def source_prefix(vertical: Optional[str]) -> str:
    """MCP tool-name prefix of the vertical's source pool (``mcp__<pool>__``),
    as agent_runner._source_tool_prefix resolves it."""
    try:
        pool = verticals.get_vertical(vertical).source_pool
    except Exception:
        pool = "cti"
    return f"mcp__{pool}__"


def count_source_calls(payloads: Iterable[str], prefix: str) -> int:
    """Number of source-pool ``tool_use`` blocks in ``agent_assistant`` event
    payloads (raw JSON strings). One block is one call, parallel calls of a
    single turn included: the way the drain loop and the eval scorer count."""
    n = 0
    for payload in payloads:
        # A payload that never names the pool cannot hold a call to it; this
        # skips the JSON parse for most reasoning-only messages.
        if not payload or prefix not in payload:
            continue
        try:
            d = json.loads(payload)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(d, dict) or d.get("kind") != "agent_assistant":
            continue
        msg = d.get("msg")
        message = msg.get("message") if isinstance(msg, dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        for block in content if isinstance(content, list) else []:
            if isinstance(block, dict) and block.get("type") == "tool_use" \
               and str(block.get("name", "")).startswith(prefix):
                n += 1
    return n


def _phase_event(kind: str) -> Optional[tuple[str, str]]:
    """``phase_<name>_starting`` / ``phase_<name>_exit`` → (name, stage). The
    other ``phase_*`` kinds (``_done``, ``_skipped``, ``_needed``…) are
    bookkeeping and return None."""
    if not kind.startswith("phase_"):
        return None
    for stage in ("starting", "exit"):
        suffix = "_" + stage
        if kind.endswith(suffix):
            name = kind[len("phase_"):-len(suffix)]
            return (name, stage) if name else None
    return None


def _as_int(v) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def compute(events: list[dict], *, status: Optional[str], vertical: Optional[str],
            source_calls: int = 0, source_calls_run: int = 0,
            env_budget: Optional[int] = None, env_drain_rounds: Optional[int] = None,
            now: Optional[float] = None) -> dict:
    """The progress document, from the run's control events.

    ``events``: the events of the investigation from its last
    ``agent_starting`` on, oldest first, each ``{"kind", "ts", "payload"}``
    (``payload`` = the decoded event). Only ``agent_starting``, ``agent_exit``,
    ``status_change`` and ``phase_*`` kinds are read; anything else is skipped,
    and events before the last ``agent_starting`` are ignored, so the caller
    may pass more than the run.
    """
    start_idx = None
    for i, e in enumerate(events):
        if e.get("kind") == "agent_starting":
            start_idx = i
    out = {
        "status": status,
        "running": status == "running",
        "vertical": vertical,
        "now": now if now is not None else time.time(),
        "run": None,
        "phase": None,
        "phases": [],
        "drain": None,
        "source_calls": source_calls,
        "source_calls_run": source_calls_run,
        "ceiling": None,
    }
    if start_idx is None:
        return out

    first = events[start_idx]
    start_msg = (first.get("payload") or {}).get("msg")
    kind = start_msg.get("phase") if isinstance(start_msg, dict) else None
    run = {
        "kind": kind if kind in RUN_KINDS else "investigation",
        "started_at": first.get("ts"),
        "ended_at": None,
        "end_status": None,
        "stopped_by_user": False,
    }
    phases: list[dict] = []
    current: Optional[dict] = None
    drain_rounds = None
    drain_budget = None

    for e in events[start_idx + 1:]:
        kind_, ts, payload = e.get("kind") or "", e.get("ts"), e.get("payload") or {}
        if kind_ == "agent_exit":
            msg = payload.get("msg")
            run["ended_at"] = ts
            run["end_status"] = msg.get("status") if isinstance(msg, dict) else None
            continue
        if kind_ == "status_change":
            # `running` only precedes a run; any other status ends this one
            # (quota halt, ops error, service restart, stop by the user).
            if payload.get("status") and payload.get("status") != "running":
                run["ended_at"] = ts
                run["end_status"] = payload.get("status")
                run["stopped_by_user"] = bool(payload.get("stopped_by_user"))
            continue
        pe = _phase_event(kind_)
        if pe is None:
            continue
        name, stage = pe
        if name == _DRAIN_HEADER:
            msg = payload.get("msg")
            if stage == "starting" and isinstance(msg, dict):
                drain_rounds = _as_int(msg.get("max_rounds"))
                drain_budget = _as_int(msg.get("total_cti_budget"))
            continue
        if stage == "starting":
            if current and current["name"] == name:
                continue  # logged twice (corroborate_leads): keep the first
            if current:
                # The previous phase never logged its exit (spawn failure).
                phases.append({**current, "ended_at": None})
            current = {"name": name, "started_at": ts}
            # A phase starting means the run goes on, whatever was logged
            # before (a stop kills one phase; the next ones still start).
            run["ended_at"] = None
            run["end_status"] = None
            run["stopped_by_user"] = False
        elif current and current["name"] == name:
            phases.append({**current, "ended_at": ts})
            current = None

    if run["ended_at"] is not None and current:
        # The run ended under an open phase (service restart): it is over too.
        phases.append({**current, "ended_at": None})
        current = None

    out["run"] = run
    out["phase"] = current
    out["phases"] = phases

    # Drain round of the current phase, or of the last finished one.
    last_name = current["name"] if current else (phases[-1]["name"] if phases else "")
    round_no = None
    if last_name.startswith(_DRAIN_ROUND_PREFIX):
        round_no = _as_int(last_name[len(_DRAIN_ROUND_PREFIX):])
    if run["kind"] == "investigation":
        rounds = drain_rounds if drain_rounds is not None else env_drain_rounds
        if round_no is not None or drain_rounds is not None:
            out["drain"] = {"round": round_no, "max_rounds": rounds}
        # The budget only means something where a drain loop can run.
        budget = drain_budget if drain_budget is not None else env_budget
        if budget is not None and budget > 0 and (rounds is None or rounds > 0):
            out["ceiling"] = budget
    return out


def _env_int(name: str, default: str) -> Optional[int]:
    return _as_int(os.environ.get(name, default))


def read_progress(inv_id: str) -> Optional[dict]:
    """Progress of one investigation, or None when it does not exist.

    Polled by the UI, so it reads little: the control events of the current run
    and the ``agent_assistant`` rows (the large tool results are ``agent_user``
    rows and are never loaded)."""
    with gs.conn() as c:
        inv = c.execute("SELECT status, vertical FROM investigations WHERE id=?",
                        (inv_id,)).fetchone()
        if not inv:
            return None
        start_id = c.execute(
            "SELECT MAX(id) FROM events WHERE investigation_id=? AND kind='agent_starting'",
            (inv_id,)).fetchone()[0]
        control = []
        if start_id is not None:
            control = c.execute(
                "SELECT kind, payload, created_at FROM events "
                "WHERE investigation_id=? AND id>=? AND (kind IN "
                "('agent_starting','agent_exit','status_change') "
                "OR kind LIKE 'phase\\_%' ESCAPE '\\') ORDER BY id",
                (inv_id, start_id)).fetchall()
        assistant = c.execute(
            "SELECT id, payload FROM events WHERE investigation_id=? "
            "AND kind='agent_assistant'", (inv_id,)).fetchall()

    events = []
    for r in control:
        try:
            payload = json.loads(r["payload"])
        except (json.JSONDecodeError, TypeError):
            payload = {}
        events.append({"kind": r["kind"], "ts": r["created_at"],
                       "payload": payload if isinstance(payload, dict) else {}})

    vertical = inv["vertical"] or "cti"
    prefix = source_prefix(vertical)
    doc = compute(
        events, status=inv["status"], vertical=vertical,
        source_calls=count_source_calls((r["payload"] for r in assistant), prefix),
        source_calls_run=0 if start_id is None else count_source_calls(
            (r["payload"] for r in assistant if r["id"] > start_id), prefix),
        env_budget=_env_int("BOUNCE_TOTAL_CTI_BUDGET", DEFAULT_TOTAL_BUDGET),
        env_drain_rounds=_env_int("BOUNCE_PIVOT_DRAIN_ROUNDS", DEFAULT_DRAIN_ROUNDS),
    )
    return {"investigation_id": inv_id, **doc}
