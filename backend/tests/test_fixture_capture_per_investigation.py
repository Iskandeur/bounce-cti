"""Per-investigation fixture capture (EVAL_PROTOCOL §4.C).

The promise under test: an admin can ask for a capture when creating ONE
investigation, with no change to the deployed .env; every MCP server of that
investigation then records into its own capture directory, on every later
spawn too; a non-admin who asks is refused before anything starts; a rerun
starts from an empty capture; and the eval runner never lets a capture it asked
for silently turn into an uncaptured run.
"""
import importlib.util
import itertools
import json
import sys
import types

import pytest
from fastapi.testclient import TestClient

from backend import fixtures


@pytest.fixture
def db(tmp_path, monkeypatch):
    for k in (fixtures.REPLAY_ENV, fixtures.CAPTURE_ENV,
              "BOUNCE_FIXTURE_CAPTURE", "BOUNCE_FIXTURE_DIR"):
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


def _server_envs(agent_runner, inv_id):
    cfg = json.loads(agent_runner._write_mcp_config(inv_id).read_text())
    return {name: s["env"] for name, s in cfg["mcpServers"].items()}


# ── Storage ────────────────────────────────────────────────────────────────

def test_the_flag_is_stored_per_investigation(db):
    on = db.create_investigation("hash", "3df9", user_id=1, fixture_capture=True)
    off = db.create_investigation("hash", "3df9", user_id=1)
    assert db.get_fixture_capture(on) is True
    assert db.get_fixture_capture(off) is False
    assert db.get_fixture_capture("no-such-inv") is False
    listed = {i["id"]: i["fixture_capture"] for i in db.list_investigations(user_id=1)}
    assert listed == {on: 1, off: 0}


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
    assert graph_store.get_fixture_capture("old-inv") is False


# ── MCP wiring ─────────────────────────────────────────────────────────────

def test_a_captured_investigation_records_without_any_env_switch(runner, db):
    inv = db.create_investigation("hash", "3df9", fixture_capture=True)
    envs = _server_envs(runner, inv)
    assert set(envs) >= {"graph", "cti"}
    expected = str(runner.ROOT / "data" / "fixtures" / "capture" / inv)
    for env in envs.values():
        assert env["BOUNCE_FIXTURE_CAPTURE_DIR"] == expected


def test_an_uncaptured_investigation_next_to_it_is_untouched(runner, db):
    db.create_investigation("hash", "3df9", fixture_capture=True)
    other = db.create_investigation("hash", "3df9")
    for env in _server_envs(runner, other).values():
        assert not any(k.startswith("BOUNCE_FIXTURE") for k in env)


def test_replay_still_wins_over_a_captured_investigation(runner, db, monkeypatch):
    inv = db.create_investigation("hash", "3df9", fixture_capture=True)
    monkeypatch.setenv("BOUNCE_FIXTURE_DIR", "eval/fixtures/case02")
    for env in _server_envs(runner, inv).values():
        assert env["BOUNCE_FIXTURE_DIR"] == str(runner.ROOT / "eval/fixtures/case02")
        assert "BOUNCE_FIXTURE_CAPTURE_DIR" not in env


def test_reset_removes_only_that_investigations_capture(runner):
    root = runner.ROOT / "data" / "fixtures" / "capture"
    (root / "inv-a").mkdir(parents=True)
    (root / "inv-a" / "x.json").write_text("{}")
    (root / "inv-b").mkdir()
    assert runner.reset_fixture_capture("inv-a") is True
    assert not (root / "inv-a").exists() and (root / "inv-b").is_dir()
    assert runner.reset_fixture_capture("inv-a") is False  # nothing left


def test_reset_refuses_an_id_that_leaves_the_capture_root(runner):
    root = runner.ROOT / "data" / "fixtures" / "capture"
    (root / "inv-a").mkdir(parents=True)
    for bad in ("..", "../capture", "", "a/b"):
        assert runner.reset_fixture_capture(bad) is False
    assert (root / "inv-a").is_dir()


# ── HTTP routes ────────────────────────────────────────────────────────────

@pytest.fixture
def api(runner, db, monkeypatch):
    """The FastAPI app on the throwaway DB, with agent spawns stubbed out."""
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

    client = TestClient(main.app)
    return types.SimpleNamespace(client=client, session=session, started=started,
                                 main=main)


def _post(api, token, path, body):
    api.client.cookies.set("session", token)
    return api.client.post(path, json=body)


def test_admin_can_ask_for_a_capture(api, db):
    _, token = api.session(is_admin=True)
    r = _post(api, token, "/api/investigations",
              {"seed_type": "hash", "seed_value": "3df9" * 8, "capture": True})
    assert r.status_code == 200, r.text
    assert r.json()["fixture_capture"] is True
    assert db.get_fixture_capture(r.json()["id"]) is True
    assert api.started == [r.json()["id"]]


def test_a_non_admin_is_refused_before_anything_starts(api, db):
    uid, token = api.session(is_admin=False)
    r = _post(api, token, "/api/investigations",
              {"seed_type": "hash", "seed_value": "3df9" * 8, "capture": True})
    assert r.status_code == 403
    assert api.started == []
    assert db.list_investigations(user_id=uid) == []


def test_without_capture_nothing_changes_for_anyone(api, db):
    _, token = api.session(is_admin=False)
    r = _post(api, token, "/api/investigations",
              {"seed_type": "hash", "seed_value": "3df9" * 8})
    assert r.status_code == 200, r.text
    assert r.json()["fixture_capture"] is False
    assert db.get_fixture_capture(r.json()["id"]) is False


def test_a_rerun_starts_from_an_empty_capture(api, db, runner):
    uid, token = api.session(is_admin=True)
    inv = db.create_investigation("hash", "3df9" * 8, user_id=uid, fixture_capture=True)
    old = runner.fixture_capture_dir(inv)
    old.mkdir(parents=True)
    (old / "stale.json").write_text("{}")
    r = _post(api, token, f"/api/investigations/{inv}/rerun", {})
    assert r.status_code == 200, r.text
    assert not old.exists()
    assert db.get_fixture_capture(inv) is True  # the rerun captures again
    assert api.started == [inv]


def test_deleting_an_investigation_deletes_its_capture(api, db, runner):
    uid, token = api.session(is_admin=True)
    inv = db.create_investigation("hash", "3df9" * 8, user_id=uid, fixture_capture=True)
    other = db.create_investigation("hash", "3df9" * 8, user_id=uid, fixture_capture=True)
    for i in (inv, other):
        runner.fixture_capture_dir(i).mkdir(parents=True)
    api.client.cookies.set("session", token)
    assert api.client.delete(f"/api/investigations/{inv}").status_code == 200
    assert not runner.fixture_capture_dir(inv).exists()
    assert runner.fixture_capture_dir(other).is_dir()


# ── eval/sequential_runner.py ──────────────────────────────────────────────

@pytest.fixture
def seq(monkeypatch, tmp_path):
    """Import the runner without its live-run side effects (cookie jar, the
    /tmp/eval_run case list), with every HTTP call recorded instead."""
    import http.cookiejar
    monkeypatch.setattr(http.cookiejar.MozillaCookieJar, "load", lambda *a, **k: None)
    monkeypatch.setitem(sys.modules, "cases", types.SimpleNamespace(CASES=[], NEGATIVE_CASES=[]))
    monkeypatch.setattr(sys, "path", list(sys.path))  # the runner prepends /tmp/eval_run

    def load(capture):
        if capture:
            monkeypatch.setenv("BOUNCE_EVAL_CAPTURE", "1")
        else:
            monkeypatch.delenv("BOUNCE_EVAL_CAPTURE", raising=False)
        path = fixtures.PROJECT_ROOT / "eval" / "sequential_runner.py"
        spec = importlib.util.spec_from_file_location("sequential_runner_under_test", path)
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


def test_runner_asks_for_the_capture_only_when_told(seq):
    assert "capture" not in seq(False).submit_body(CASE)
    assert seq(True).submit_body(CASE)["capture"] is True


def test_runner_records_an_acknowledged_capture(seq):
    mod = seq(True)
    mod.answers = [(200, {"id": "inv-1", "fixture_capture": True})]
    meta = {"cases": {}}
    assert mod.submit_with_quota_retry(CASE, meta) == "inv-1"
    assert meta["cases"]["2"]["inv_id"] == "inv-1"


def test_runner_stops_a_run_the_server_did_not_capture(seq):
    """An older server ignores the field and starts the run anyway."""
    mod = seq(True)
    mod.answers = [(200, {"id": "inv-1"})]
    meta = {"cases": {}}
    assert mod.submit_with_quota_retry(CASE, meta) is None
    assert ("POST", "/api/investigations/inv-1/stop", None) in mod.calls
    assert meta["cases"] == {}


def test_runner_gives_up_on_a_refused_capture(seq):
    mod = seq(True)
    mod.answers = [(403, {"detail": "capture requires an admin session"})]
    assert mod.submit_with_quota_retry(CASE, {"cases": {}}) is None
    assert len(mod.calls) == 1
    assert "admin PIN" in open(mod.LOG_FILE).read()


def test_runner_without_capture_ignores_the_acknowledgement(seq):
    mod = seq(False)
    mod.answers = [(200, {"id": "inv-1"})]
    assert mod.submit_with_quota_retry(CASE, {"cases": {}}) == "inv-1"
