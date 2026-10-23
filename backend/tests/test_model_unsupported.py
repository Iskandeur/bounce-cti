"""A model id newer than the host's claude CLI must stop the run, loudly.

Measured on 2026-10-23 with the production CLI version (2.1.149) asked for
``claude-opus-5-5``: it answers ``API Error: 400 Claude Code 2.1.149 does not
support this model; version 2.1.280 or newer is required``, exits 1, and still
prints a ``result`` event (``is_error: true``). The phase logic read that event
as "the agent ran": every later phase spawned and failed the same way in under
a second, and the investigation ended ``done`` with zero nodes. The fake CLI
below replays the real stream of that run, trimmed to the fields read here.
"""
import asyncio
import json
import os
import stat
import sys

import pytest

import backend.agent_runner as ar

REFUSAL = ("API Error: 400 Claude Code 2.1.149 does not support this model; "
           "version 2.1.280 or newer is required. Run 'claude update', or update "
           "the Claude desktop app, then try again.")


def _fake_claude(tmp_path, *, refuse: bool):
    """An executable that writes its argv to ``argv.jsonl`` and plays either
    the real 2.1.149 refusal (exit 1) or a short successful turn (exit 0)."""
    if refuse:
        events = [
            {"type": "system", "subtype": "init", "session_id": "s", "model": "claude-opus-5-5",
             "claude_code_version": "2.1.149"},
            {"type": "assistant", "message": {"model": "<synthetic>", "role": "assistant",
                                              "content": [{"type": "text", "text": REFUSAL}]}},
            {"type": "result", "subtype": "success", "is_error": True, "api_error_status": 400,
             "num_turns": 1, "result": REFUSAL},
        ]
        code = 1
    else:
        events = [
            {"type": "system", "subtype": "init", "session_id": "s", "model": "x"},
            {"type": "result", "subtype": "success", "is_error": False, "result": "ok"},
        ]
        code = 0
    log = tmp_path / "argv.jsonl"
    script = tmp_path / "fake-claude"
    script.write_text("\n".join([
        f"#!{sys.executable}",
        "import json, sys",
        f"with open({str(log)!r}, 'a') as f:",
        "    f.write(json.dumps(sys.argv[1:]) + '\\n')",
        f"for e in {events!r}:",
        "    sys.stdout.write(json.dumps(e) + '\\n')",
        "    sys.stdout.flush()",
        f"sys.exit({code})",
    ]) + "\n", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script), log


def _spawned_models(log):
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    return [argv[argv.index("--model") + 1] for argv in calls]


@pytest.fixture
def db(tmp_path, monkeypatch):
    path = tmp_path / "test.db"
    from backend import config, graph_store
    monkeypatch.setattr(config, "DB_PATH", path, raising=False)
    monkeypatch.setattr(graph_store, "DB_PATH", path, raising=False)
    graph_store.init_db()
    root = tmp_path / "root"
    (root / "data").mkdir(parents=True)
    monkeypatch.setattr(ar, "ROOT", root)
    monkeypatch.setattr(ar, "_WATCHDOG_POLL_S", 0.05)
    monkeypatch.setenv("BOUNCE_PIVOT_DRAIN_ROUNDS", "3")
    return graph_store


def _status(db, inv):
    with db.conn() as c:
        return c.execute("SELECT status FROM investigations WHERE id=?", (inv,)).fetchone()[0]


def _events(db, inv):
    with db.conn() as c:
        return [(r[0], json.loads(r[1])) for r in c.execute(
            "SELECT kind, payload FROM events WHERE investigation_id=? ORDER BY id", (inv,))]


# ── Detection ────────────────────────────────────────────────────────────────

def test_the_real_refusal_is_detected():
    assert ar._detect_model_unsupported(REFUSAL)
    assert ar._detect_model_unsupported("claude code 2.0.1 DOES NOT SUPPORT THIS MODEL")


def test_other_failures_are_not_a_model_refusal():
    assert not ar._detect_model_unsupported("Failed to authenticate. API Error: 401 Invalid authentication credentials")
    assert not ar._detect_model_unsupported("Claude AI usage limit reached|1700000000")
    assert not ar._detect_model_unsupported("added node domain evil.com")
    assert not ar._detect_model_unsupported("")
    # ...and the refusal is not mistaken for an auth failure either.
    assert not ar._detect_auth_error(REFUSAL)


def test_a_tool_result_quoting_the_phrase_is_not_a_refusal(tmp_path, db, monkeypatch):
    """Only the CLI's own error (an is_error result, or stderr) counts: a page
    the agent fetched may well contain the words."""
    inv = db.create_investigation("domain", "example.com", user_id=1)
    events = [
        {"type": "system", "subtype": "init", "session_id": "s"},
        {"type": "user", "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "t", "content": [{"type": "text", "text": REFUSAL}]}]}},
        {"type": "result", "subtype": "success", "is_error": False, "result": "done"},
    ]
    script = tmp_path / "quoting-claude"
    script.write_text("\n".join([
        f"#!{sys.executable}", "import json, sys",
        f"for e in {events!r}:", "    sys.stdout.write(json.dumps(e) + '\\n')",
    ]) + "\n", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setattr(ar, "_resolve_claude_bin", lambda: str(script))
    asyncio.run(ar._run_claude_phase(inv, "p", "s", "sonnet", dict(os.environ), tmp_path / "mcp.json"))
    assert inv not in ar._model_unsupported


# ── The whole run ────────────────────────────────────────────────────────────

def test_a_refused_model_stops_the_run_after_one_phase(tmp_path, db, monkeypatch):
    fake, log = _fake_claude(tmp_path, refuse=True)
    monkeypatch.setattr(ar, "_resolve_claude_bin", lambda: fake)
    inv = db.create_investigation("domain", "example.com", user_id=1)

    asyncio.run(ar.run_investigation(inv, "domain", "example.com", model="opus"))

    assert _status(db, inv) == "error: model"
    assert len(log.read_text().splitlines()) == 1, "later phases were spawned on a refused model"
    events = _events(db, inv)
    kinds = [k for k, _ in events]
    assert "agent_model_unsupported" in kinds
    status = [p for k, p in events if k == "status_change"][-1]
    assert status["status"] == "error: model"
    # Actionable: which model, which CLI version is needed, what to do.
    assert "claude-opus-5" in status["error_message"]
    assert "2.1.280" in status["error_message"]
    assert "update the claude CLI" in status["error_message"]
    assert "another model" in status["error_message"]
    assert inv not in ar._model_unsupported  # consumed, not left for the next run


@pytest.mark.parametrize("runner", ["add_seed", "pivot", "custom_prompt"])
def test_follow_up_runs_do_not_report_done_on_a_refused_model(tmp_path, db, monkeypatch, runner):
    fake, _log = _fake_claude(tmp_path, refuse=True)
    monkeypatch.setattr(ar, "_resolve_claude_bin", lambda: fake)
    inv = db.create_investigation("domain", "example.com", user_id=1)
    if runner == "add_seed":
        asyncio.run(ar.run_add_seed(inv, "domain", "other.example", model="opus"))
    elif runner == "pivot":
        asyncio.run(ar.run_pivot(inv, "domain", "example.com", model="opus"))
    else:
        asyncio.run(ar.run_custom_prompt(inv, "look again", model="opus"))
    assert _status(db, inv) == "error: model"


def test_a_stale_refusal_does_not_fail_the_next_run(tmp_path, db, monkeypatch):
    fake, _log = _fake_claude(tmp_path, refuse=False)
    monkeypatch.setattr(ar, "_resolve_claude_bin", lambda: fake)
    inv = db.create_investigation("domain", "example.com", user_id=1)
    ar._model_unsupported[inv] = "left over from a crashed run"
    asyncio.run(ar.run_pivot(inv, "domain", "example.com", model="sonnet"))
    assert _status(db, inv) == "done"


# ── What the spawn is asked for ──────────────────────────────────────────────

@pytest.mark.parametrize("alias, cli_id", [
    ("opus", "claude-opus-5"), ("sonnet", "claude-sonnet-5-5"), ("haiku", "claude-haiku-5-5"),
    ("opus-4.7", "claude-opus-4-7"),
])
def test_the_spawn_gets_the_pinned_id_not_the_tier_name(tmp_path, db, monkeypatch, alias, cli_id):
    fake, log = _fake_claude(tmp_path, refuse=False)
    monkeypatch.setattr(ar, "_resolve_claude_bin", lambda: fake)
    inv = db.create_investigation("domain", "example.com", user_id=1)
    asyncio.run(ar._run_claude_phase(inv, "p", "s", alias, dict(os.environ), tmp_path / "mcp.json"))
    assert _spawned_models(log) == [cli_id]
