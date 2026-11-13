"""Run progress (backend/run_progress.py, GET /api/investigations/{id}/progress).

The promise under test: the progress line the analyst reads says where the
CURRENT run stands, from the events the agent runner really logs. The current
run starts at the last `agent_starting`; the phase in flight is the one that
started and has not exited; the source calls are counted exactly as the
pivot-drain loop counts them, and the budget is shown only for a run that has
a drain loop to spend it.
"""
import itertools
import json
import re
import types
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import run_progress as rp

T0 = 1_800_000_000.0


def _events(*specs):
    """(kind, msg) or (kind, msg, top_level_fields) → the event dicts compute()
    reads, one second apart, shaped like agent_runner._log writes them."""
    out = []
    for i, spec in enumerate(specs):
        kind, msg = spec[0], spec[1] if len(spec) > 1 else {}
        payload = {"kind": kind, "msg": msg}
        if len(spec) > 2:
            payload = {"kind": kind, **spec[2]}
        out.append({"kind": kind, "ts": T0 + i, "payload": payload})
    return out


def _compute(events, status="running", vertical="cti", **kw):
    kw.setdefault("env_budget", 82)
    kw.setdefault("env_drain_rounds", 3)
    return rp.compute(events, status=status, vertical=vertical, now=T0 + 500, **kw)


# ── The run and its phases ─────────────────────────────────────────────────

def test_no_event_means_no_run():
    doc = _compute([], status="running")
    assert doc["run"] is None and doc["phase"] is None and doc["phases"] == []
    assert doc["running"] is True
    assert doc["ceiling"] is None  # nothing says yet what kind of run this is
    assert doc["now"] == T0 + 500


def test_mid_phase():
    doc = _compute(_events(("agent_starting", {"cwd": "/x"}),
                           ("phase_main_starting", {"prompt_preview": "…"})))
    assert doc["run"] == {"kind": "investigation", "started_at": T0, "ended_at": None,
                          "end_status": None, "stopped_by_user": False}
    assert doc["phase"] == {"name": "main", "started_at": T0 + 1}
    assert doc["phases"] == []
    assert doc["ceiling"] == 82


def test_between_phases():
    doc = _compute(_events(("agent_starting", {}),
                           ("phase_main_starting", {}),
                           ("phase_main_exit", {"rc": 0}),
                           ("phase_hypothesis_write_needed", {}),
                           ("phase2_needed", {"missing": []})))
    assert doc["phase"] is None
    assert doc["phases"] == [{"name": "main", "started_at": T0 + 1, "ended_at": T0 + 2}]
    assert doc["run"]["ended_at"] is None


def test_bookkeeping_phase_events_are_not_phases():
    doc = _compute(_events(("agent_starting", {}),
                           ("phase_main_starting", {}),
                           ("phase_watchdog_kill", {"reason": "max duration"}),
                           ("phase_main_exit", {"rc": -9}),
                           ("phase_hypothesis_write_done", {"rc": 0}),
                           ("phase_corroborate_leads_skipped", {"reason": "no pending leads"}),
                           ("phase_pivot_drain_skipped", {"reason": "concluded_benign"}),
                           ("phase_lessons_learned_done", {"rc": 0})))
    assert [p["name"] for p in doc["phases"]] == ["main"]
    assert doc["phase"] is None


def test_a_phase_logged_twice_at_its_start_is_one_phase():
    # _phase_corroborate_leads logs its own `_starting` (with the pending
    # count) and _run_claude_phase logs the generic one right after.
    doc = _compute(_events(("agent_starting", {}),
                           ("phase_corroborate_leads_starting", {"pending": 4}),
                           ("phase_corroborate_leads_starting", {"prompt_preview": "…"}),
                           ("phase_corroborate_leads_exit", {"rc": 0})))
    assert doc["phases"] == [{"name": "corroborate_leads",
                              "started_at": T0 + 1, "ended_at": T0 + 3}]


def test_several_drain_rounds():
    doc = _compute(_events(
        ("agent_starting", {}),
        ("phase_main_starting", {}), ("phase_main_exit", {"rc": 0}),
        ("phase_followup_starting", {}), ("phase_followup_exit", {"rc": 0}),
        ("phase_pivot_drain_starting", {"max_rounds": 4, "max_turns_per_round": 60,
                                        "convergence_threshold": 3,
                                        "total_cti_budget": 120}),
        ("phase_pivot_drain_1_starting", {}), ("phase_pivot_drain_1_exit", {"rc": 0}),
        ("phase_pivot_drain_round_done", {"round": 1, "delta_n": 9}),
        ("phase_pivot_drain_2_starting", {}),
    ), source_calls=64)
    assert doc["phase"]["name"] == "pivot_drain_2"
    assert [p["name"] for p in doc["phases"]] == ["main", "followup", "pivot_drain_1"]
    # The loop header carries the loop's settings and counts as no phase;
    # what it logged wins over the environment the route reads later.
    assert doc["drain"] == {"round": 2, "max_rounds": 4}
    assert doc["ceiling"] == 120
    assert doc["source_calls"] == 64


def test_the_drain_settings_stay_known_after_its_last_round():
    doc = _compute(_events(
        ("agent_starting", {}),
        ("phase_pivot_drain_starting", {"max_rounds": 3, "total_cti_budget": 82}),
        ("phase_pivot_drain_1_starting", {}), ("phase_pivot_drain_1_exit", {"rc": 0}),
        ("phase_pivot_drain_converged", {"round": 1, "delta_n": 0}),
        ("phase_lessons_learned_starting", {}),
    ))
    assert doc["phase"]["name"] == "lessons_learned"
    assert doc["drain"] == {"round": None, "max_rounds": 3}


def test_an_unknown_phase_name_goes_through_untouched():
    doc = _compute(_events(("agent_starting", {}),
                           ("phase_graph_audit_starting", {}),
                           ("phase_graph_audit_exit", {"rc": 0}),
                           ("phase_x_starting", {})))
    assert doc["phases"][0]["name"] == "graph_audit"
    assert doc["phase"]["name"] == "x"


def test_a_phase_that_never_exited_is_closed_by_the_next_start():
    # The claude binary could not be spawned: `_starting`, then no `_exit`.
    doc = _compute(_events(("agent_starting", {}),
                           ("phase_main_starting", {}),
                           ("phase_report_write_starting", {})))
    assert doc["phases"] == [{"name": "main", "started_at": T0 + 1, "ended_at": None}]
    assert doc["phase"]["name"] == "report_write"


# ── Which events are "this run" ────────────────────────────────────────────

def test_only_the_events_since_the_last_agent_starting_count():
    doc = _compute(_events(
        ("agent_starting", {}),
        ("phase_main_starting", {}), ("phase_main_exit", {"rc": 0}),
        ("phase_lessons_learned_starting", {}), ("phase_lessons_learned_exit", {"rc": 0}),
        ("agent_exit", {"rc": 0, "status": "done"}),
        ("status_change", {}, {"status": "running", "add_seed_type": "domain"}),
        ("agent_starting", {"phase": "add_seed", "seed_type": "domain"}),
        ("phase_add_seed_starting", {}),
    ), source_calls=70, source_calls_run=6)
    assert doc["run"]["kind"] == "add_seed"
    assert doc["run"]["started_at"] == T0 + 7
    assert doc["run"]["ended_at"] is None
    assert doc["phases"] == []
    assert doc["phase"] == {"name": "add_seed", "started_at": T0 + 8}
    # An added seed has no drain loop: the budget governs nothing in this run.
    assert doc["ceiling"] is None and doc["drain"] is None
    assert (doc["source_calls"], doc["source_calls_run"]) == (70, 6)


@pytest.mark.parametrize("kind", ["add_seed", "pivot", "custom_prompt"])
def test_run_kinds_without_a_drain_loop_report_no_ceiling(kind):
    doc = _compute(_events(("agent_starting", {"phase": kind}),
                           (f"phase_{kind}_starting", {})))
    assert doc["run"]["kind"] == kind
    assert doc["ceiling"] is None


def test_an_unknown_run_kind_reads_as_a_full_investigation():
    doc = _compute(_events(("agent_starting", {"phase": "something_new"})))
    assert doc["run"]["kind"] == "investigation"


def test_no_ceiling_when_the_drain_is_disabled():
    ev = _events(("agent_starting", {}), ("phase_main_starting", {}))
    assert _compute(ev, env_drain_rounds=0)["ceiling"] is None
    assert _compute(ev, env_budget=None)["ceiling"] is None
    assert _compute(ev, env_drain_rounds=3)["ceiling"] == 82


# ── Runs that ended ────────────────────────────────────────────────────────

def test_a_finished_run():
    doc = _compute(_events(("agent_starting", {}),
                           ("phase_main_starting", {}), ("phase_main_exit", {"rc": 0}),
                           ("agent_exit", {"rc": 0, "status": "done", "has_report": True})),
                   status="done")
    assert doc["running"] is False
    assert doc["phase"] is None
    assert doc["run"]["ended_at"] == T0 + 3 and doc["run"]["end_status"] == "done"


def test_a_run_halted_by_the_quota():
    doc = _compute(_events(
        ("agent_starting", {}),
        ("phase_main_starting", {}), ("phase_main_exit", {"rc": 0}),
        ("phase_followup_starting", {}),
        ("quota_exceeded", {"reset_at": T0 + 3600}),
        ("phase_followup_exit", {"rc": -15, "quota_hit": True}),
        ("status_change", {}, {"status": "quota_exceeded", "quota_reset_at": T0 + 3600}),
    ), status="quota_exceeded")
    assert doc["running"] is False and doc["phase"] is None
    assert [p["name"] for p in doc["phases"]] == ["main", "followup"]
    assert doc["run"]["ended_at"] == T0 + 6
    assert doc["run"]["end_status"] == "quota_exceeded"


def test_a_run_refused_before_its_first_phase():
    doc = _compute(_events(("agent_starting", {}),
                           ("agent_skipped_quota", {"reset_at": T0 + 60}),
                           ("status_change", {}, {"status": "quota_exceeded"})),
                   status="quota_exceeded")
    assert doc["phases"] == [] and doc["run"]["end_status"] == "quota_exceeded"


def test_a_run_ended_by_an_ops_error():
    doc = _compute(_events(
        ("agent_starting", {}),
        ("phase_main_starting", {}), ("phase_main_exit", {"rc": 0}),
        ("status_change", {}, {"status": "error: auth", "error_message": "401"}),
        ("investigation_auth_failed", {"message": "401"}),
    ), status="error: auth")
    assert doc["run"]["end_status"] == "error: auth" and doc["phase"] is None


def test_a_run_cut_by_a_service_restart_leaves_no_phase_in_flight():
    doc = _compute(_events(
        ("agent_starting", {}),
        ("phase_main_starting", {}),
        ("status_change", {}, {"status": "error: interrupted"}),
    ), status="error: interrupted")
    assert doc["phase"] is None
    assert doc["phases"] == [{"name": "main", "started_at": T0 + 1, "ended_at": None}]
    assert doc["run"]["ended_at"] == T0 + 2


def test_a_stop_is_recorded_and_a_later_phase_reopens_the_run():
    stopped = _events(
        ("agent_starting", {}),
        ("phase_main_starting", {}),
        ("status_change", {}, {"status": "done", "stopped_by_user": True}),
        ("phase_main_exit", {"rc": -15}),
    )
    doc = _compute(stopped, status="done")
    assert doc["run"]["stopped_by_user"] is True and doc["phase"] is None
    assert doc["phases"] == [{"name": "main", "started_at": T0 + 1, "ended_at": T0 + 3}]
    # A stop kills the phase in flight; run_investigation then goes on to its
    # next phase. The events say so, and so does the document.
    doc = _compute(stopped + [{"kind": "phase_report_write_starting", "ts": T0 + 4,
                               "payload": {"kind": "phase_report_write_starting", "msg": {}}}],
                   status="done")
    assert doc["phase"]["name"] == "report_write"
    assert doc["run"]["ended_at"] is None and doc["run"]["stopped_by_user"] is False


def test_a_status_change_to_running_does_not_end_a_run():
    doc = _compute(_events(("agent_starting", {}),
                           ("status_change", {}, {"status": "running"}),
                           ("phase_main_starting", {})))
    assert doc["run"]["ended_at"] is None and doc["phase"]["name"] == "main"


# ── Counting source calls ──────────────────────────────────────────────────

def _assistant(*tool_names, text="thinking"):
    blocks = [{"type": "text", "text": text}]
    blocks += [{"type": "tool_use", "id": f"t{i}", "name": n, "input": {"q": "x"}}
               for i, n in enumerate(tool_names)]
    return {"type": "assistant", "message": {"content": blocks}}


def test_count_source_calls_counts_blocks_of_the_pool_only():
    payloads = [json.dumps({"kind": "agent_assistant", "msg": m}) for m in (
        _assistant("mcp__cti__rdap_domain", "mcp__cti__crtsh_subdomains"),  # parallel
        _assistant("mcp__graph__add_node"),
        _assistant("mcp__ctx__web_search"),
        _assistant(text="I will call mcp__cti__virustotal_domain next"),     # prose
        _assistant("mcp__cti__rdap_domain"),                                 # a repeat counts
    )]
    payloads += ["not json mcp__cti__", "", None,
                 json.dumps({"kind": "agent_system", "msg": {"tools": ["mcp__cti__rdap_domain"]}})]
    assert rp.count_source_calls(payloads, "mcp__cti__") == 3
    assert rp.count_source_calls(payloads, "mcp__dd__") == 0


def test_the_pool_prefix_follows_the_vertical():
    assert rp.source_prefix("cti") == "mcp__cti__"
    assert rp.source_prefix("osint") == "mcp__cti__"   # the osint lens reuses the cti pool
    assert rp.source_prefix("dd") == "mcp__dd__"
    assert rp.source_prefix(None) == "mcp__cti__"
    assert rp.source_prefix("no-such-vertical") == "mcp__cti__"


def test_defaults_match_the_drain_loop():
    src = (Path(rp.__file__).parent / "agent_runner.py").read_text()
    budget = re.search(r'os\.environ\.get\("BOUNCE_TOTAL_CTI_BUDGET", "(\d+)"\)', src)
    rounds = re.search(r'os\.environ\.get\("BOUNCE_PIVOT_DRAIN_ROUNDS", "(\d+)"\)', src)
    assert budget and budget.group(1) == rp.DEFAULT_TOTAL_BUDGET
    assert rounds and rounds.group(1) == rp.DEFAULT_DRAIN_ROUNDS
    # The run kinds are the `phase` values the runners put on agent_starting.
    logged = set(re.findall(r'_log\(inv_id, "agent_starting", \{[^}]*?"phase": "(\w+)"',
                            src, flags=re.S))
    assert logged == set(rp.RUN_KINDS) - {"investigation"}


# ── Against the database, with the runner's own writer and counter ─────────

@pytest.fixture
def db(tmp_path, monkeypatch):
    for k in ("BOUNCE_TOTAL_CTI_BUDGET", "BOUNCE_PIVOT_DRAIN_ROUNDS"):
        monkeypatch.delenv(k, raising=False)
    path = tmp_path / "test.db"
    from backend import config, graph_store
    monkeypatch.setattr(config, "DB_PATH", path, raising=False)
    monkeypatch.setattr(graph_store, "DB_PATH", path, raising=False)
    graph_store.init_db()
    return graph_store


def _log_assistant(agent_runner, inv, *tool_names):
    agent_runner._log(inv, "agent_assistant", _assistant(*tool_names))


def test_read_progress_of_a_missing_investigation(db):
    assert rp.read_progress("no-such-inv") is None


def test_read_progress_before_any_event(db):
    inv = db.create_investigation("domain", "example.test", user_id=1)
    doc = rp.read_progress(inv)
    assert doc["investigation_id"] == inv
    assert doc["run"] is None and doc["source_calls"] == 0
    assert doc["status"] == "running" and doc["vertical"] == "cti"


@pytest.mark.parametrize("vertical,pool", [("cti", "cti"), ("osint", "cti"), ("dd", "dd")])
def test_the_count_is_the_drain_loop_s_own(db, vertical, pool):
    from backend import agent_runner
    inv = db.create_investigation("domain", "example.test", user_id=1, vertical=vertical)
    agent_runner._log(inv, "agent_starting", {"cwd": "/x"})
    agent_runner._log(inv, "phase_main_starting", {"prompt_preview": "…"})
    agent_runner._log(inv, "agent_system", {"tools": [f"mcp__{pool}__a", f"mcp__{pool}__b"]})
    _log_assistant(agent_runner, inv, f"mcp__{pool}__a", f"mcp__{pool}__b", "mcp__graph__add_node")
    _log_assistant(agent_runner, inv, "mcp__ctx__web_search", "mcp__other__a")
    agent_runner._log(inv, "agent_user", {"message": {"content": [
        {"type": "tool_result", "content": f"mcp__{pool}__a " * 50}]}})
    _log_assistant(agent_runner, inv, f"mcp__{pool}__a")
    doc = rp.read_progress(inv)
    assert doc["source_calls"] == agent_runner._count_cti_calls(inv) == 3
    assert doc["source_calls_run"] == 3
    assert doc["phase"]["name"] == "main" and doc["ceiling"] == 82


def test_a_resume_is_a_new_run_and_the_count_stays_cumulative(db, monkeypatch):
    from backend import agent_runner
    monkeypatch.setenv("BOUNCE_TOTAL_CTI_BUDGET", "40")
    inv = db.create_investigation("domain", "example.test", user_id=1)
    agent_runner._log(inv, "agent_starting", {})
    agent_runner._log(inv, "phase_main_starting", {})
    _log_assistant(agent_runner, inv, "mcp__cti__a", "mcp__cti__b")
    agent_runner._log(inv, "phase_main_exit", {"rc": -15, "quota_hit": True})
    agent_runner._finalise_quota_halt(inv, {"reset_at": T0, "message": "limit"})

    halted = rp.read_progress(inv)
    assert halted["status"] == "quota_exceeded" and halted["running"] is False
    assert halted["run"]["end_status"] == "quota_exceeded"
    assert [p["name"] for p in halted["phases"]] == ["main"]

    db.set_status(inv, "running")
    agent_runner._log(inv, "agent_resume", {"model": "opus"})
    agent_runner._log(inv, "agent_starting", {})
    agent_runner._log(inv, "phase_followup_starting", {})
    _log_assistant(agent_runner, inv, "mcp__cti__c")

    doc = rp.read_progress(inv)
    assert doc["running"] is True and doc["run"]["ended_at"] is None
    assert doc["phases"] == [] and doc["phase"]["name"] == "followup"
    # The drain loop compares the budget to every call of the investigation,
    # the ones made before the halt included.
    assert doc["source_calls"] == agent_runner._count_cti_calls(inv) == 3
    assert doc["source_calls_run"] == 1
    assert doc["ceiling"] == 40


def test_a_rerun_starts_from_nothing(db):
    from backend import agent_runner
    inv = db.create_investigation("domain", "example.test", user_id=1)
    agent_runner._log(inv, "agent_starting", {})
    agent_runner._log(inv, "phase_main_starting", {})
    _log_assistant(agent_runner, inv, "mcp__cti__a")
    agent_runner._log(inv, "phase_main_exit", {"rc": 0})
    agent_runner._log(inv, "agent_exit", {"rc": 0, "status": "done"})

    db.clear_investigation(inv)          # what POST /rerun does first
    db.set_status(inv, "running")
    cleared = rp.read_progress(inv)
    assert cleared["run"] is None and cleared["source_calls"] == 0

    agent_runner._log(inv, "agent_starting", {})
    agent_runner._log(inv, "phase_main_starting", {})
    doc = rp.read_progress(inv)
    assert doc["phases"] == [] and doc["phase"]["name"] == "main"
    assert doc["source_calls"] == 0


def test_an_interrupted_run_read_from_the_database(db):
    from backend import agent_runner
    inv = db.create_investigation("domain", "example.test", user_id=1)
    agent_runner._log(inv, "agent_starting", {})
    agent_runner._log(inv, "phase_main_starting", {})
    assert db.reconcile_orphaned_running() == 1   # the service restarted
    doc = rp.read_progress(inv)
    assert doc["status"] == "error: interrupted" and doc["phase"] is None
    assert doc["run"]["end_status"] == "error: interrupted"


# ── The route ──────────────────────────────────────────────────────────────

@pytest.fixture
def api(db):
    from backend import auth, main
    serial = itertools.count()

    def session():
        with db.conn() as c:
            uid = c.execute(
                "INSERT INTO users(pin_hmac, created_at, is_admin) VALUES (?, 0, 0)",
                (f"test-pin-{next(serial)}",),
            ).lastrowid
        return uid, auth.issue_session(uid)

    return types.SimpleNamespace(client=TestClient(main.app), session=session)


def test_the_route_answers_its_owner_only(api, db):
    from backend import agent_runner
    owner, owner_token = api.session()
    _, other_token = api.session()
    inv = db.create_investigation("domain", "example.test", user_id=owner)
    agent_runner._log(inv, "agent_starting", {})
    agent_runner._log(inv, "phase_main_starting", {})
    _log_assistant(agent_runner, inv, "mcp__cti__a")

    assert api.client.get(f"/api/investigations/{inv}/progress").status_code == 401

    api.client.cookies.set("session", owner_token)
    r = api.client.get(f"/api/investigations/{inv}/progress")
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"investigation_id", "status", "running", "vertical", "now",
                         "run", "phase", "phases", "drain", "source_calls",
                         "source_calls_run", "ceiling"}
    assert body["phase"]["name"] == "main" and body["source_calls"] == 1
    assert api.client.get("/api/investigations/no-such-inv/progress").status_code == 404

    api.client.cookies.set("session", other_token)
    assert api.client.get(f"/api/investigations/{inv}/progress").status_code == 404
