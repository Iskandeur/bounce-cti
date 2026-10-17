"""Demo snapshots (roadmap J3): one investigation frozen for a static public page.

The promises under test:
- a share link still returns exactly what it did (share_view was carved out of it);
- a snapshot keeps what the viewer reads and drops agent session ids, token
  usage, local paths, thinking blocks and report chats;
- the CLI never writes to the source database, refuses a snapshot that holds a
  secret or a forbidden word (and writes nothing), and refuses to run when it
  cannot read the .env it must check against;
- the route is owner-only and checks the server's own secrets;
- no refusal or warning ever prints a secret's value.
"""
import hashlib
import importlib.util
import itertools
import json
import os
import types

import pytest
from fastapi.testclient import TestClient

from backend import demo_snapshot, fixtures

SECRET = "sk-test-0123456789abcdef"  # a fake key, for the leak tests


@pytest.fixture
def db(tmp_path, monkeypatch):
    for k in list(os.environ):
        if fixtures.is_secret_name(k):
            monkeypatch.delenv(k, raising=False)
    path = tmp_path / "test.db"
    from backend import config, graph_store
    monkeypatch.setattr(config, "DB_PATH", path, raising=False)
    monkeypatch.setattr(graph_store, "DB_PATH", path, raising=False)
    graph_store.init_db()
    return graph_store


def _event(gs, inv, payload, ts=1000.0):
    with gs.conn() as c:
        c.execute("INSERT INTO events(investigation_id, kind, payload, created_at) VALUES (?,?,?,?)",
                  (inv, payload["kind"], json.dumps(payload), ts))


def _investigation(gs, user_id=1, report_extra=None):
    inv = gs.create_investigation("hash", "3df9" * 16, user_id=user_id, model="opus-5")
    gs.add_node(inv, "hash", "3df9" * 16, {"file_name": "Game.exe"}, tags=["seed"])
    gs.add_node(inv, "domain", "moonzonet.com", {"registrar": "x"})
    gs.add_edge(inv, "hash", "3df9" * 16, "domain", "moonzonet.com", "communicates_with")
    gs.add_node(inv, "report", "investigation_summary",
                {"summary": "MuddyWater backdoor", "threat_assessment": "malicious",
                 "prompt_history": [{"q": "private chat"}], **(report_extra or {})})
    _event(gs, inv, {"kind": "agent_starting", "msg": {"cwd": "/opt/app", "mcp_config": "/opt/app/data/mcp-x.json"}})
    _event(gs, inv, {"kind": "agent_assistant", "msg": {
        "type": "assistant", "session_id": "sess-1", "uuid": "u-1", "request_id": "req-1",
        "message": {"id": "msg-1", "model": "claude-opus-5",
                    "usage": {"input_tokens": 12, "output_tokens": 3},
                    "content": [
                        {"type": "thinking", "thinking": "hidden", "signature": "sig"},
                        {"type": "text", "text": "Pivoting on the C2 domain."},
                        {"type": "tool_use", "id": "tu-1", "name": "mcp__cti__virustotal_domain",
                         "input": {"domain": "moonzonet.com"}},
                    ]}}})
    _event(gs, inv, {"kind": "agent_assistant", "msg": {"message": {"content": [
        {"type": "thinking", "thinking": "only thoughts"}]}}})
    _event(gs, inv, {"kind": "status_change", "status": "done"})
    _event(gs, inv, {"kind": "node_tagged", "node_id": "n1", "tag": "c2"})
    _event(gs, inv, {"kind": "agent_exit", "msg": {"rc": 0, "status": "done", "has_report": True}})
    _event(gs, inv, {"kind": "agent_user", "msg": {"content": "tool result"}})  # not a timeline kind
    return inv


# ── share_view / share links ───────────────────────────────────────────────

def test_a_share_link_returns_what_it_did(db):
    inv = _investigation(db)
    sh = db.create_share(inv, 1, ["graph", "report", "timeline"], label="for a colleague")
    p = db.get_share_payload(sh["token"])
    assert list(p) == ["share", "investigation", "graph", "events"]
    assert p["share"] == {"token": sh["token"], "sections": ["graph", "report", "timeline"],
                          "created_at": sh["created_at"], "expires_at": None,
                          "label": "for a colleague"}
    assert set(p["investigation"]) == {"id", "seed_type", "seed_value", "status", "created_at", "seeds"}
    report = next(n for n in p["graph"]["nodes"] if n["type"] == "report")
    assert "prompt_history" not in report["metadata"]
    assert [e["kind"] for e in p["events"]] == ["agent_starting", "agent_assistant", "agent_assistant",
                                                "status_change", "node_tagged", "agent_exit"]
    db.revoke_share(sh["token"], 1)
    assert db.get_share_payload(sh["token"]) is None


def test_share_view_of_an_unknown_investigation_is_none(db):
    assert db.share_view("nope", demo_snapshot.SECTIONS) is None


# ── what a snapshot keeps ──────────────────────────────────────────────────

def test_a_snapshot_keeps_what_the_viewer_reads_and_nothing_private(db):
    inv = _investigation(db)
    snap = demo_snapshot.from_view(db.share_view(inv, demo_snapshot.SECTIONS), "opus-5",
                                   "Eval case 2", now=0)
    assert snap["share"] == {"sections": ["graph", "report", "timeline"],
                             "demo": {"format": 1, "label": "Eval case 2", "model": "opus-5",
                                      "exported_at": "1970-01-01T00:00:00Z"}}
    assert {n["value"] for n in snap["graph"]["nodes"]} == {"3df9" * 16, "moonzonet.com",
                                                            "investigation_summary"}
    assert snap["graph"]["edges"][0]["relation"] == "communicates_with"
    assert all("investigation_id" not in x for x in snap["graph"]["nodes"] + snap["graph"]["edges"])
    kinds = [e["kind"] for e in snap["events"]]
    # the thinking-only message is dropped; agent_user never was in the share
    assert kinds == ["agent_starting", "agent_assistant", "status_change", "node_tagged", "agent_exit"]
    assistant = snap["events"][1]
    assert assistant["msg"] == {"message": {"content": [
        {"type": "text", "text": "Pivoting on the C2 domain."},
        {"type": "tool_use", "name": "mcp__cti__virustotal_domain", "input": {"domain": "moonzonet.com"}},
    ]}}
    assert snap["events"][2]["msg"] == {"status": "done"}
    assert snap["events"][3]["tag"] == "c2"
    assert snap["events"][4]["msg"] == {"rc": 0}
    text = demo_snapshot.serialise(snap)
    for private in ("sess-1", "req-1", "msg-1", "input_tokens", "signature", "hidden",
                    "/opt/app", "mcp-x.json", "private chat", "tool result"):
        assert private not in text, private


def test_an_old_status_change_nested_under_msg_still_reads():
    assert demo_snapshot.reduce_event({"kind": "status_change", "msg": "running"})["msg"] == {"status": "running"}
    assert demo_snapshot.reduce_event({"kind": "status_change", "msg": {"status": "x"}})["msg"] == {"status": "x"}


# ── checks ─────────────────────────────────────────────────────────────────

def test_check_names_a_secret_and_never_prints_it():
    problems, warnings = demo_snapshot.check(f'{{"a":"{SECRET}"}}', [("VT_API_KEY", SECRET)], ["Acme"])
    assert problems == ["contains the value of the secret VT_API_KEY"]
    problems, _ = demo_snapshot.check('{"a":"made by ACME corp"}', [], ["acme"])
    assert problems == ["contains the forbidden word 'acme'"]
    _, warnings = demo_snapshot.check('{"u":"https://x/?apikey=ZZZZZZZZZZZZZZZZZZZZ"}', [], [])
    assert len(warnings) == 1 and "ZZZZ" not in warnings[0] and "'apikey='" in warnings[0]


def test_known_secrets_reads_the_dotenv_and_the_environment(tmp_path, monkeypatch):
    for k in list(os.environ):
        if fixtures.is_secret_name(k):
            monkeypatch.delenv(k, raising=False)
    env = tmp_path / ".env"
    env.write_text(f"VIRUSTOTAL_API_KEY={SECRET}\nPORT=8000\nSHORT_KEY=abc\n")
    monkeypatch.setenv("OTX_API_KEY", "otx-0123456789abcdef")
    got = dict(demo_snapshot.known_secrets(env))
    assert got["VIRUSTOTAL_API_KEY"] == SECRET
    assert "otx-0123456789abcdef" in got.values()
    assert "8000" not in got.values() and "abc" not in got.values()


# ── the CLI ────────────────────────────────────────────────────────────────

def _cli():
    path = fixtures.PROJECT_ROOT / "eval" / "demo_export.py"
    spec = importlib.util.spec_from_file_location("demo_export", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_the_cli_writes_a_snapshot_and_never_touches_the_source(db, tmp_path):
    inv = _investigation(db)
    cli = _cli()
    env = tmp_path / ".env"
    env.write_text("PORT=1\n")
    before = _sha(db.DB_PATH)
    code, msg = cli.export(inv, "case02", db.DB_PATH, tmp_path / "out", env, label="Eval case 2")
    assert code == 0, msg
    assert _sha(db.DB_PATH) == before
    snap = json.loads((tmp_path / "out" / "case02.json").read_text())
    assert snap["share"]["demo"]["model"] == "opus-5"
    assert snap["share"]["demo"]["label"] == "Eval case 2"
    assert len(snap["graph"]["nodes"]) == 3 and len(snap["events"]) == 5
    assert "prompt_history" not in json.dumps(snap)
    # the module-level DB path is put back
    assert db.DB_PATH == tmp_path / "test.db"


def test_the_cli_refuses_a_secret_and_writes_nothing(db, tmp_path):
    inv = _investigation(db, report_extra={"source_url": f"https://vt.example/?x={SECRET}"})
    env = tmp_path / ".env"
    env.write_text(f"VIRUSTOTAL_API_KEY={SECRET}\n")
    code, msg = _cli().export(inv, "case02", db.DB_PATH, tmp_path / "out", env)
    assert code == 1
    assert "VIRUSTOTAL_API_KEY" in msg and SECRET not in msg
    assert not (tmp_path / "out").exists()


def test_the_cli_refuses_a_forbidden_word(db, tmp_path):
    inv = _investigation(db, report_extra={"note": "seen at Acme SOC"})
    env = tmp_path / ".env"
    env.write_text("PORT=1\n")
    code, msg = _cli().export(inv, "case02", db.DB_PATH, tmp_path / "out", env, forbid=["acme"])
    assert code == 1 and "forbidden word" in msg
    assert not (tmp_path / "out").exists()


def test_the_cli_will_not_check_against_nothing(db, tmp_path):
    inv = _investigation(db)
    code, msg = _cli().export(inv, "case02", db.DB_PATH, tmp_path / "out", tmp_path / "missing.env")
    assert code == 2 and "cannot read" in msg
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("name", ["../x", "Case02", "a b", "", "x" * 65])
def test_the_cli_refuses_a_bad_name(db, tmp_path, name):
    env = tmp_path / ".env"
    env.write_text("PORT=1\n")
    code, _ = _cli().export("whatever", name, db.DB_PATH, tmp_path / "out", env)
    assert code == 2


def test_the_cli_says_so_when_the_investigation_does_not_exist(db, tmp_path):
    env = tmp_path / ".env"
    env.write_text("PORT=1\n")
    code, msg = _cli().export("nope", "case02", db.DB_PATH, tmp_path / "out", env)
    assert code == 2 and "no investigation" in msg


# ── the route ──────────────────────────────────────────────────────────────

@pytest.fixture
def api(db, monkeypatch):
    from backend import auth, main
    serial = itertools.count()

    def session():
        with db.conn() as c:
            uid = c.execute("INSERT INTO users(pin_hmac, created_at, is_admin) VALUES (?, 0, 0)",
                            (f"test-pin-{next(serial)}",)).lastrowid
        return uid, auth.issue_session(uid)

    return types.SimpleNamespace(client=TestClient(main.app), session=session)


def _get(api, token, path, **params):
    api.client.cookies.set("session", token)
    return api.client.get(path, params=params)


def test_the_owner_gets_a_snapshot(api, db):
    uid, token = api.session()
    inv = _investigation(db, user_id=uid)
    r = _get(api, token, f"/api/investigations/{inv}/demo_snapshot", label="Eval case 2")
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"snapshot", "warnings", "checked_secrets"}
    assert body["snapshot"]["share"]["demo"]["label"] == "Eval case 2"
    assert len(body["snapshot"]["events"]) == 5


def test_someone_else_gets_a_404(api, db):
    owner, _ = api.session()
    _, other = api.session()
    inv = _investigation(db, user_id=owner)
    assert _get(api, other, f"/api/investigations/{inv}/demo_snapshot").status_code == 404


def test_the_route_refuses_a_server_secret_without_printing_it(api, db, monkeypatch):
    uid, token = api.session()
    inv = _investigation(db, user_id=uid, report_extra={"leak": SECRET})
    monkeypatch.setenv("ONYPHE_API_KEY", SECRET)
    r = _get(api, token, f"/api/investigations/{inv}/demo_snapshot")
    assert r.status_code == 422
    assert SECRET not in r.text
    assert r.json()["detail"]["problems"] == ["contains the value of the secret <secret:ONYPHE>"]


def test_the_route_refuses_a_forbidden_word(api, db):
    uid, token = api.session()
    inv = _investigation(db, user_id=uid, report_extra={"note": "seen at Acme SOC"})
    r = _get(api, token, f"/api/investigations/{inv}/demo_snapshot", forbid=["acme", "other"])
    assert r.status_code == 422
    assert r.json()["detail"]["problems"] == ["contains the forbidden word 'acme'"]
