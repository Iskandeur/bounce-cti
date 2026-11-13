"""POST /api/investigations/{id}/stop ends the run, whatever phase it is in.

Until 2026-11-11 it ended one phase. The route killed the `claude -p` process
in flight and wrote status `done`; `run_investigation` read the killed phase
as a phase that had failed (rc=-15, no `result` event), went on to the phases
that do not depend on the main one (report write, lessons learned, and the
follow-up and pivot drain as well whenever a report node already existed), and
overwrote the status at the end with `error rc=-15`. The single-phase runs
(add seed, pivot, custom prompt) spawned nothing more but overwrote the status
the same way.

Nothing here spawns the real CLI: a fake `claude` executable hangs on the phase
to stop and answers at once on any other, and the tests on the control flow
alone fake the phase runner.
"""
import asyncio
import json
import os
import signal
import stat
import sys
import time

import pytest

import backend.agent_runner as ar
from backend import main

USER = 1


@pytest.fixture
def db(tmp_path, monkeypatch):
    path = tmp_path / "test.db"
    from backend import config, graph_store
    monkeypatch.setattr(config, "DB_PATH", path, raising=False)
    monkeypatch.setattr(graph_store, "DB_PATH", path, raising=False)
    graph_store.init_db()
    # Twice, as on any database that has seen two starts: on a new file the
    # first init_db creates `investigations` without `quota_reset_at`, which
    # only the next one adds, and resume_investigation writes that column.
    graph_store.init_db()
    root = tmp_path / "root"
    (root / "data").mkdir(parents=True)
    monkeypatch.setattr(ar, "ROOT", root)
    monkeypatch.setattr(ar, "_WATCHDOG_POLL_S", 0.05)
    monkeypatch.setenv("BOUNCE_PIVOT_DRAIN_ROUNDS", "3")
    monkeypatch.setattr(ar, "_append_lessons_ledger", lambda *a, **k: None)
    return graph_store


def _status(db, inv):
    with db.conn() as c:
        return c.execute("SELECT status FROM investigations WHERE id=?", (inv,)).fetchone()[0]


def _events(db, inv):
    with db.conn() as c:
        return [(r[0], json.loads(r[1])) for r in c.execute(
            "SELECT kind, payload FROM events WHERE investigation_id=? ORDER BY id", (inv,))]


def _stop_events(db, inv):
    return [p for k, p in _events(db, inv) if k == "status_change" and p.get("stopped_by_user")]


def _fake_claude(tmp_path, *, hang_on: int = 1):
    """An executable that appends its argv to `argv.jsonl`, prints the `system`
    init event, then hangs if this is its `hang_on`-th spawn, or prints a
    `result` event and exits 0 on any other."""
    log = tmp_path / "argv.jsonl"
    script = tmp_path / "fake-claude"
    script.write_text("\n".join([
        f"#!{sys.executable}",
        "import json, sys, time",
        f"log = {str(log)!r}",
        "with open(log, 'a') as f:",
        "    f.write(json.dumps(sys.argv[1:]) + '\\n')",
        "n = sum(1 for _ in open(log))",
        "print(json.dumps({'type': 'system', 'subtype': 'init', 'session_id': 's'}), flush=True)",
        f"if n == {hang_on}:",
        "    time.sleep(120)",
        "print(json.dumps({'type': 'result', 'subtype': 'success', 'is_error': False,"
        " 'result': 'ok'}), flush=True)",
    ]) + "\n", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script), log


def _spawns(log) -> int:
    return len(log.read_text().splitlines()) if log.exists() else 0


async def _until(cond, timeout=20.0):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not cond():
        assert loop.time() < deadline, "condition never came true"
        await asyncio.sleep(0.01)


async def _stop_when_in_flight(inv, run, log, *, spawns=1):
    """Start `run`, wait for its `spawns`-th process to be alive and registered
    (its argv line is in the log: a process killed before it wrote that line
    would shift the count the fake CLI hangs on), then stop it the way the
    browser does: through the route, which FastAPI runs in a worker thread."""
    task = asyncio.create_task(run)
    await _until(lambda: inv in ar._running_procs and _spawns(log) >= spawns)
    answer = await asyncio.to_thread(main.stop_inv, inv, USER)
    await asyncio.wait_for(task, 30)
    return answer


# ── How a killed phase returns ───────────────────────────────────────────────

def test_a_killed_phase_returns_as_a_failed_phase(tmp_path, db, monkeypatch):
    """The fact the old control flow missed: nothing in what a phase returns
    says a user killed it. It reads as rc=-SIGTERM, no result event, no quota."""
    fake, log = _fake_claude(tmp_path)
    monkeypatch.setattr(ar, "_resolve_claude_bin", lambda: fake)
    inv = db.create_investigation("domain", "example.com", user_id=USER)

    async def scenario():
        task = asyncio.create_task(ar._run_claude_phase(
            inv, "p", "s", "sonnet", dict(os.environ), tmp_path / "mcp.json"))
        await _until(lambda: inv in ar._running_procs and _spawns(log) == 1)
        assert ar.stop_investigation(inv) is True
        return await asyncio.wait_for(task, 30)

    rc, saw_result, has_report, quota = asyncio.run(scenario())
    assert rc == -signal.SIGTERM
    assert saw_result is False and has_report is False
    assert quota["hit"] is False
    assert inv not in ar._running_procs


# ── The whole run, with a process really killed ──────────────────────────────

def test_a_stop_during_the_main_phase_ends_the_run(tmp_path, db, monkeypatch):
    fake, log = _fake_claude(tmp_path)
    monkeypatch.setattr(ar, "_resolve_claude_bin", lambda: fake)
    inv = db.create_investigation("domain", "example.com", user_id=USER)
    db.set_status(inv, "running")

    answer = asyncio.run(_stop_when_in_flight(
        inv, ar.run_investigation(inv, "domain", "example.com", model="sonnet"), log))

    assert answer == {"ok": True, "killed": True}
    assert _spawns(log) == 1, "phases were spawned after the stop"
    assert _status(db, inv) == "done"
    assert len(_stop_events(db, inv)) == 1
    kinds = [k for k, _ in _events(db, inv)]
    assert "phase3_report_write_needed" not in kinds
    assert not [k for k in kinds if k.startswith("phase_lessons_learned")]
    # The run says why it ended, on the event the UI already listens to.
    exits = [p["msg"] for k, p in _events(db, inv) if k == "agent_exit"]
    assert len(exits) == 1
    assert exits[0]["stopped_by_user"] is True and exits[0]["status"] == "done"
    assert exits[0]["rc"] == -signal.SIGTERM


def test_a_stop_during_a_later_phase_ends_the_run_there(tmp_path, db, monkeypatch):
    """The main phase finishes (no report node: the fake agent writes nothing),
    the report-write phase is the one in flight when the stop comes."""
    fake, log = _fake_claude(tmp_path, hang_on=3)
    monkeypatch.setattr(ar, "_resolve_claude_bin", lambda: fake)
    inv = db.create_investigation("domain", "example.com", user_id=USER)
    db.set_status(inv, "running")

    asyncio.run(_stop_when_in_flight(
        inv, ar.run_investigation(inv, "domain", "example.com", model="sonnet"),
        log, spawns=3))

    assert _spawns(log) == 3, "phases were spawned after the stop"
    assert _status(db, inv) == "done"
    assert len(_stop_events(db, inv)) == 1


@pytest.mark.parametrize("runner", ["add_seed", "pivot", "custom_prompt"])
def test_a_stopped_follow_up_run_stays_done(tmp_path, db, monkeypatch, runner):
    """These three run one phase, so a stop spawned nothing more. They did
    overwrite the route's `done` with `error rc=-15`."""
    fake, log = _fake_claude(tmp_path)
    monkeypatch.setattr(ar, "_resolve_claude_bin", lambda: fake)
    inv = db.create_investigation("domain", "example.com", user_id=USER)
    db.set_status(inv, "running")
    run = {
        "add_seed": lambda: ar.run_add_seed(inv, "domain", "other.example", model="sonnet"),
        "pivot": lambda: ar.run_pivot(inv, "ip", "203.0.113.5", model="sonnet"),
        "custom_prompt": lambda: ar.run_custom_prompt(inv, "look again", model="sonnet"),
    }[runner]()

    asyncio.run(_stop_when_in_flight(inv, run, log))

    assert _spawns(log) == 1
    assert _status(db, inv) == "done"
    assert len(_stop_events(db, inv)) == 1
    exits = [p["msg"] for k, p in _events(db, inv) if k == "agent_exit"]
    assert [e.get("phase") for e in exits] == [runner]
    assert exits[0]["stopped_by_user"] is True and exits[0]["status"] == "done"


# ── Resume and rerun after a stop ────────────────────────────────────────────

def _fake_agent(db, phases):
    """A phase runner that does what a healthy agent does, with no process."""
    async def fake_phase(inv_id, prompt, system_prompt, model, env, mcp_cfg_path,
                         phase="main", **kw):
        phases.append(phase)
        if phase == "main":
            db.add_node(inv_id, "domain", "example.com", tags=["seed", "malicious"])
            db.add_node(inv_id, "report", "working_hypothesis",
                        metadata={"candidate_category": "commodity_malware"})
            db.add_node(inv_id, "report", "investigation_summary",
                        metadata={"threat_assessment": "malicious", "summary": "x"})
        elif phase == "lessons_learned":
            db.add_node(inv_id, "report", "lessons_learned", metadata={"blockers": []})
        return 0, True, True, {"hit": False, "reset_at": None, "message": ""}
    return fake_phase


@pytest.mark.parametrize("again", ["resume", "rerun"])
def test_a_stopped_investigation_runs_again(tmp_path, db, monkeypatch, again):
    fake, log = _fake_claude(tmp_path)
    monkeypatch.setattr(ar, "_resolve_claude_bin", lambda: fake)
    inv = db.create_investigation("domain", "example.com", user_id=USER)
    db.set_status(inv, "running")
    asyncio.run(_stop_when_in_flight(
        inv, ar.run_investigation(inv, "domain", "example.com", model="sonnet"), log))
    assert _status(db, inv) == "done"

    phases = []
    monkeypatch.setattr(ar, "_run_claude_phase", _fake_agent(db, phases))
    if again == "resume":
        asyncio.run(ar.resume_investigation(inv, model="sonnet"))
    else:
        db.clear_investigation(inv)
        db.set_status(inv, "running")
        asyncio.run(ar.run_investigation(inv, "domain", "example.com", model="sonnet"))

    assert phases[0] == "main" and "lessons_learned" in phases, phases
    assert _status(db, inv) == "done"
    exits = [p["msg"] for k, p in _events(db, inv) if k == "agent_exit"]
    assert not exits[-1].get("stopped_by_user")


def test_a_rerun_started_before_the_stopped_run_has_noticed_is_left_alone(db, monkeypatch):
    """A killed phase takes up to a watchdog poll (10 s in production) to
    return. A rerun clicked inside that window starts a second run of the same
    investigation: the stop must end the first one and only that one, and the
    first one must not write its ending over the second one's status."""
    inv = db.create_investigation("domain", "example.com", user_id=USER)
    db.set_status(inv, "running")
    release_old = asyncio.Event()
    old_phases, new_phases = [], []

    async def old_agent(inv_id, *a, phase="main", **kw):
        old_phases.append(phase)
        await release_old.wait()               # killed, not yet returned
        return -signal.SIGTERM, False, False, {"hit": False, "reset_at": None, "message": ""}

    async def scenario():
        monkeypatch.setattr(ar, "_run_claude_phase", old_agent)
        old = asyncio.create_task(ar.run_investigation(inv, "domain", "example.com"))
        await _until(lambda: old_phases == ["main"])
        await asyncio.to_thread(main.stop_inv, inv, USER)
        assert _status(db, inv) == "done"      # written by the route, at once

        # The rerun route: status running, then a new run.
        db.set_status(inv, "running")
        monkeypatch.setattr(ar, "_run_claude_phase", _fake_agent(db, new_phases))
        new = asyncio.create_task(ar.run_investigation(inv, "domain", "example.com"))
        await _until(lambda: "main" in new_phases)
        release_old.set()
        await asyncio.wait_for(asyncio.gather(old, new), 30)

    asyncio.run(scenario())
    assert old_phases == ["main"]
    assert "lessons_learned" in new_phases, new_phases
    assert _status(db, inv) == "done"
    assert len(_stop_events(db, inv)) == 1


# ── A stop that lands between two phases ─────────────────────────────────────

def test_a_stop_between_two_phases_ends_the_run(db, monkeypatch):
    """No process to kill: the route still answers for a running investigation,
    and the next phase is never spawned."""
    inv = db.create_investigation("domain", "example.com", user_id=USER)
    db.set_status(inv, "running")
    phases = []
    healthy = _fake_agent(db, phases)

    async def agent(inv_id, *a, phase="main", **kw):
        out = await healthy(inv_id, *a, phase=phase, **kw)
        if phase == "main":
            # The phase is over, the process gone: the stop finds nothing to kill.
            answer = await asyncio.to_thread(main.stop_inv, inv, USER)
            assert answer == {"ok": True, "killed": False}
        return out

    monkeypatch.setattr(ar, "_run_claude_phase", agent)
    asyncio.run(ar.run_investigation(inv, "domain", "example.com"))

    assert phases == ["main"]
    assert _status(db, inv) == "done"
    assert len(_stop_events(db, inv)) == 1


def test_the_phase_runner_spawns_nothing_for_a_stopped_run(tmp_path, db, monkeypatch):
    """The last line of defence, inside the phase runner itself: a run that was
    stopped does not get a new process, whoever asks for one."""
    fake, log = _fake_claude(tmp_path, hang_on=0)
    monkeypatch.setattr(ar, "_resolve_claude_bin", lambda: fake)
    inv = db.create_investigation("domain", "example.com", user_id=USER)

    async def scenario():
        ar._begin_run(inv)
        ar.stop_investigation(inv)
        return await ar._run_claude_phase(
            inv, "p", "s", "sonnet", dict(os.environ), tmp_path / "mcp.json", phase="followup")

    rc, saw_result, _has_report, quota = asyncio.run(scenario())
    assert (rc, saw_result, quota["hit"]) == (None, False, False)
    assert _spawns(log) == 0
    assert "phase_followup_not_started" in [k for k, _ in _events(db, inv)]


def test_a_stop_on_an_idle_investigation_changes_nothing(db, monkeypatch):
    """Nothing runs, nothing is written; and the next run is not stopped by it."""
    inv = db.create_investigation("domain", "example.com", user_id=USER)
    db.set_status(inv, "error rc=1")

    assert main.stop_inv(inv, USER) == {"ok": True, "killed": False}
    assert _status(db, inv) == "error rc=1"
    assert _stop_events(db, inv) == []

    phases = []
    monkeypatch.setattr(ar, "_run_claude_phase", _fake_agent(db, phases))
    db.set_status(inv, "running")
    asyncio.run(ar.run_investigation(inv, "domain", "example.com"))
    assert "lessons_learned" in phases
    assert _status(db, inv) == "done"


def test_deleting_a_running_investigation_ends_its_run(tmp_path, db, monkeypatch):
    """DELETE stops the agent the same way. The run used to carry on, phase
    after phase, on an investigation that no longer existed."""
    fake, log = _fake_claude(tmp_path)
    monkeypatch.setattr(ar, "_resolve_claude_bin", lambda: fake)
    inv = db.create_investigation("domain", "example.com", user_id=USER)
    db.set_status(inv, "running")

    async def scenario():
        task = asyncio.create_task(
            ar.run_investigation(inv, "domain", "example.com", model="sonnet"))
        await _until(lambda: inv in ar._running_procs and _spawns(log) == 1)
        await asyncio.to_thread(main.delete_inv, inv, USER)
        await asyncio.wait_for(task, 30)

    asyncio.run(scenario())
    assert _spawns(log) == 1, "phases were spawned on a deleted investigation"
    with db.conn() as c:
        assert c.execute("SELECT 1 FROM investigations WHERE id=?", (inv,)).fetchone() is None


# ── Runs chained by main.py ──────────────────────────────────────────────────

def test_a_stop_ends_a_chain_of_seeds(db, monkeypatch):
    """A batch in combined mode runs the first seed, then one add-seed run per
    other seed. A stop during the first one must not start the others."""
    from fastapi.testclient import TestClient
    from backend import auth

    with db.conn() as c:
        uid = c.execute("INSERT INTO users(pin_hmac, created_at, is_admin) VALUES (?, 0, 1)",
                        ("test-pin",)).lastrowid
    started = []

    async def fake_run(inv_id, seed_type, seed_value, model="opus", **kw):
        started.append(("run", seed_value))
        await asyncio.to_thread(main.stop_inv, inv_id, uid)

    async def fake_add_seed(inv_id, seed_type, seed_value, model="opus"):
        started.append(("add_seed", seed_value))

    monkeypatch.setattr(main, "run_investigation", fake_run)
    monkeypatch.setattr(main, "run_add_seed", fake_add_seed)
    monkeypatch.delenv("ADMIN_PIN", raising=False)
    # `with`: one event loop for the whole block, so the chain the route starts
    # as a background task keeps running after the response.
    with TestClient(main.app) as client:
        client.cookies.set("session", auth.issue_session(uid))
        r = client.post("/api/investigations/batch", json={
            "items": [{"seed_type": "domain", "seed_value": "a.example"},
                      {"seed_type": "domain", "seed_value": "b.example"},
                      {"seed_type": "domain", "seed_value": "c.example"}],
            "combined": True})
        assert r.status_code == 200, r.text
        inv = r.json()["started"][0]["id"]
        deadline = time.monotonic() + 10
        while not _stop_events(db, inv) and time.monotonic() < deadline:
            time.sleep(0.01)
        time.sleep(0.3)  # the time for the chain to (wrongly) start the next seed

    assert started == [("run", "a.example")]
    assert _status(db, inv) == "done"
    assert len(_stop_events(db, inv)) == 1
