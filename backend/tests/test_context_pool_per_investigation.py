"""Per-investigation context pool (backend/context_pool.py).

The promise under test: an admin can mount the context pool (model memory +
wrapped open web, as capped leads) for ONE CTI investigation, with no change to
the deployed .env, so an eval run can measure "Bounce-CTI with web" next to the
bare model with web (eval/baseline.py). Every part of the spawn agrees on it:
the MCP config, the tool whitelist, the system prompt and the corroboration
phase, on every later spawn too. The investigation next to it keeps the CTI
default (pool off, prompt byte-identical). A non-admin is refused before
anything starts, the kill switch still wins, and the eval runner never lets a
"with web" run go ahead without the pool and its web tools.
"""
import importlib.util
import itertools
import json
import sys
import types

import pytest
from fastapi.testclient import TestClient

from backend import fixtures, verticals


@pytest.fixture
def db(tmp_path, monkeypatch):
    for k in ("BOUNCE_CTX_ENABLED", "BOUNCE_CTX_WEB", fixtures.REPLAY_ENV,
              fixtures.CAPTURE_ENV, "BOUNCE_FIXTURE_CAPTURE", "BOUNCE_FIXTURE_DIR"):
        monkeypatch.delenv(k, raising=False)
    path = tmp_path / "test.db"
    from backend import config, graph_store
    monkeypatch.setattr(config, "DB_PATH", path, raising=False)
    monkeypatch.setattr(graph_store, "DB_PATH", path, raising=False)
    graph_store.init_db()
    return graph_store


@pytest.fixture
def runner(db, tmp_path, monkeypatch):
    from backend import agent_runner
    root = tmp_path / "root"
    (root / "data").mkdir(parents=True)
    monkeypatch.setattr(agent_runner, "ROOT", root)
    return agent_runner


def _servers(agent_runner, inv_id):
    cfg = json.loads(agent_runner._write_mcp_config(inv_id).read_text())
    return cfg["mcpServers"]


# ── Policy ─────────────────────────────────────────────────────────────────

def test_forcing_turns_the_pool_on_for_cti_only_when_asked():
    from backend import context_pool as cp
    assert cp.context_pool_enabled("cti") is False
    assert cp.context_pool_enabled("cti", forced=True) is True
    assert cp.context_pool_enabled("osint") is True  # the default is untouched


def test_the_kill_switch_wins_over_an_investigation_opt_in(monkeypatch):
    from backend import context_pool as cp
    monkeypatch.setenv("BOUNCE_CTX_ENABLED", "0")
    assert cp.context_pool_enabled("cti", forced=True) is False


# ── Storage ────────────────────────────────────────────────────────────────

def test_the_flag_is_stored_per_investigation(db):
    on = db.create_investigation("hash", "3df9", user_id=1, context_pool=True)
    off = db.create_investigation("hash", "3df9", user_id=1)
    assert db.get_context_pool(on) is True
    assert db.get_context_pool(off) is False
    assert db.get_context_pool("no-such-inv") is False


def test_a_database_from_before_the_column_is_migrated(tmp_path, monkeypatch):
    import sqlite3
    from backend import config, graph_store
    path = tmp_path / "old.db"
    with sqlite3.connect(path) as c:
        c.execute("CREATE TABLE investigations (id TEXT PRIMARY KEY, seed_type TEXT, "
                  "seed_value TEXT, created_at REAL, status TEXT)")
        c.execute("INSERT INTO investigations VALUES ('old-inv', 'hash', 'x', 0, 'done')")
    monkeypatch.setattr(config, "DB_PATH", path, raising=False)
    monkeypatch.setattr(graph_store, "DB_PATH", path, raising=False)
    graph_store.init_db()
    assert graph_store.get_context_pool("old-inv") is False


# ── Spawn wiring ───────────────────────────────────────────────────────────

def test_a_forced_cti_investigation_mounts_the_pool(runner, db):
    inv = db.create_investigation("hash", "3df9", context_pool=True)
    servers = _servers(runner, inv)
    assert verticals.CONTEXT_POOL_KEY in servers
    assert servers[verticals.CONTEXT_POOL_KEY]["env"]["BOUNCE_INV_ID"] == inv


def test_the_cti_investigation_next_to_it_keeps_the_default(runner, db):
    db.create_investigation("hash", "3df9", context_pool=True)
    other = db.create_investigation("hash", "3df9")
    assert verticals.CONTEXT_POOL_KEY not in _servers(runner, other)
    assert runner._context_pool_on(other, verticals.CTI) is False


def test_whitelist_and_prompt_follow_the_investigation(runner, db):
    inv = db.create_investigation("hash", "3df9", context_pool=True)
    ctx = runner._context_pool_on(inv, verticals.CTI)
    assert ctx is True
    tools = runner.build_allowed_tools_for(verticals.CTI, ctx)
    assert "mcp__ctx__web_search" in tools and "mcp__graph__corroborate_lead" in tools
    prompt = runner.build_system_prompt(runner.SYSTEM_PROMPT, verticals.CTI, ctx)
    assert prompt.endswith(verticals.CONTEXT_POOL_PROMPT_BLOCK)
    # The native web tools stay disallowed: the pool's own are cached,
    # budgeted, SSRF-guarded and can only mint leads.
    assert "WebSearch" in runner._DISALLOWED_TOOLS.split(",")


def test_cti_without_the_flag_is_byte_identical(runner, db):
    inv = db.create_investigation("hash", "3df9")
    ctx = runner._context_pool_on(inv, verticals.CTI)
    assert runner.build_system_prompt(runner.SYSTEM_PROMPT, verticals.CTI, ctx) == runner.SYSTEM_PROMPT
    assert runner.build_allowed_tools_for(verticals.CTI, ctx) == runner._ALLOWED_TOOLS


def test_the_spawn_itself_carries_the_pool(runner, db, monkeypatch):
    """_run_claude_phase builds the command line from the investigation."""
    import asyncio
    inv = db.create_investigation("hash", "3df9", context_pool=True)
    seen = {}

    async def fake_exec(*cmd, **kw):
        seen["cmd"] = list(cmd)
        raise RuntimeError("stop here")
    monkeypatch.setattr(runner, "_resolve_claude_bin", lambda: "/bin/claude")
    monkeypatch.setattr(runner.asyncio, "create_subprocess_exec", fake_exec)
    with pytest.raises(RuntimeError, match="stop here"):
        asyncio.run(runner._run_claude_phase(inv, "go", runner.SYSTEM_PROMPT, "opus",
                                             {}, runner.ROOT / "data" / "x.json"))
    cmd = seen["cmd"]
    assert "mcp__ctx__web_fetch" in cmd[cmd.index("--allowedTools") + 1]
    assert verticals.CONTEXT_POOL_PROMPT_BLOCK in cmd[cmd.index("--append-system-prompt") + 1]


# ── HTTP routes ────────────────────────────────────────────────────────────

@pytest.fixture
def api(runner, db, monkeypatch):
    from backend import auth, main
    started = []

    async def fake_run(inv_id, *a, **kw):
        started.append(inv_id)
    monkeypatch.setattr(main, "run_investigation", fake_run)
    serial = itertools.count()

    def session(is_admin):
        with db.conn() as c:
            uid = c.execute(
                "INSERT INTO users(pin_hmac, created_at, is_admin) VALUES (?, 0, ?)",
                (f"test-pin-{next(serial)}", int(is_admin)),
            ).lastrowid
        return uid, auth.issue_session(uid)

    return types.SimpleNamespace(client=TestClient(main.app), session=session,
                                 started=started)


def _start(api, token, **extra):
    api.client.cookies.set("session", token)
    return api.client.post("/api/investigations",
                           json={"seed_type": "hash", "seed_value": "3df9" * 8, **extra})


def test_admin_can_force_the_pool_and_is_told_what_mounts(api, db):
    _, token = api.session(is_admin=True)
    r = _start(api, token, context_pool=True)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["context_pool"] is True and body["context_pool_web"] is True
    assert db.get_context_pool(body["id"]) is True
    assert api.started == [body["id"]]


def test_the_answer_says_when_the_web_tools_are_off(api, monkeypatch):
    monkeypatch.setenv("BOUNCE_CTX_WEB", "0")
    _, token = api.session(is_admin=True)
    body = _start(api, token, context_pool=True).json()
    assert body["context_pool"] is True and body["context_pool_web"] is False


def test_a_non_admin_is_refused_before_anything_starts(api, db):
    uid, token = api.session(is_admin=False)
    r = _start(api, token, context_pool=True)
    assert r.status_code == 403
    assert api.started == []
    assert db.list_investigations(user_id=uid) == []


def test_the_kill_switch_refuses_instead_of_downgrading(api, db, monkeypatch):
    monkeypatch.setenv("BOUNCE_CTX_ENABLED", "0")
    uid, token = api.session(is_admin=True)
    r = _start(api, token, context_pool=True)
    assert r.status_code == 409
    assert api.started == []
    assert db.list_investigations(user_id=uid) == []


def test_without_the_flag_cti_answers_pool_off(api, db):
    _, token = api.session(is_admin=False)
    r = _start(api, token)
    assert r.status_code == 200, r.text
    assert r.json()["context_pool"] is False
    assert db.get_context_pool(r.json()["id"]) is False


# ── eval/sequential_runner.py ──────────────────────────────────────────────

@pytest.fixture
def seq(monkeypatch, tmp_path):
    import http.cookiejar
    monkeypatch.setattr(http.cookiejar.MozillaCookieJar, "load", lambda *a, **k: None)
    monkeypatch.setitem(sys.modules, "cases", types.SimpleNamespace(CASES=[], NEGATIVE_CASES=[]))
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.delenv("BOUNCE_EVAL_CAPTURE", raising=False)

    def load(ctx):
        if ctx:
            monkeypatch.setenv("BOUNCE_EVAL_CONTEXT_POOL", "1")
        else:
            monkeypatch.delenv("BOUNCE_EVAL_CONTEXT_POOL", raising=False)
        path = fixtures.PROJECT_ROOT / "eval" / "sequential_runner.py"
        spec = importlib.util.spec_from_file_location("sequential_runner_ctx_test", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.LOG_FILE = str(tmp_path / "runner.log")
        mod.META_FILE = str(tmp_path / "meta.json")
        mod.calls = []
        mod.answers = []

        def fake_req(method, p, body=None):
            mod.calls.append((method, p, body))
            return mod.answers.pop(0) if mod.answers else (200, {})
        mod.req = fake_req
        return mod
    return load


CASE = {"case_id": 2, "seed_type": "hash", "seed_value": "abc", "name": "c2", "inv_id": "NEW"}


def test_runner_asks_for_the_pool_only_when_told(seq):
    assert "context_pool" not in seq(False).submit_body(CASE)
    assert seq(True).submit_body(CASE)["context_pool"] is True


def test_runner_records_an_acknowledged_pool(seq):
    mod = seq(True)
    mod.answers = [(200, {"id": "inv-1", "context_pool": True, "context_pool_web": True})]
    meta = {"cases": {}}
    assert mod.submit_with_quota_retry(CASE, meta) == "inv-1"
    assert "context pool" in open(mod.LOG_FILE).read()


@pytest.mark.parametrize("answer", [
    {"id": "inv-1"},                                                      # an older server
    {"id": "inv-1", "context_pool": False, "context_pool_web": False},
    {"id": "inv-1", "context_pool": True, "context_pool_web": False},     # BOUNCE_CTX_WEB=0
])
def test_runner_stops_a_run_without_the_pool_or_its_web(seq, answer):
    mod = seq(True)
    mod.answers = [(200, answer)]
    meta = {"cases": {}}
    assert mod.submit_with_quota_retry(CASE, meta) is None
    assert ("POST", "/api/investigations/inv-1/stop", None) in mod.calls
    assert meta["cases"] == {}


def test_runner_gives_up_on_the_kill_switch(seq):
    mod = seq(True)
    mod.answers = [(409, {"detail": "context pool disabled on this server"})]
    assert mod.submit_with_quota_retry(CASE, {"cases": {}}) is None
    assert len(mod.calls) == 1
    assert "409" in open(mod.LOG_FILE).read()


def test_runner_without_the_flag_ignores_the_answer(seq):
    mod = seq(False)
    mod.answers = [(200, {"id": "inv-1", "context_pool": False})]
    assert mod.submit_with_quota_retry(CASE, {"cases": {}}) == "inv-1"
