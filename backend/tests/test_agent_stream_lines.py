"""The agent's stream-json must reach the event log whatever the length of a line.

asyncio's StreamReader refuses a line longer than its limit (64 KiB by default):
``async for line in proc.stdout`` raises ValueError and the loop ends. In
``_run_claude_phase`` that error was swallowed by ``gather(...,
return_exceptions=True)``, so the first tool result over 64 KiB (a VirusTotal or
Onyphe report) silently ended the phase's event log. The agent kept working,
unlogged: its later tool calls, its ``result`` event and any quota marker never
reached the database. Measured on the production database on 2026-10-15: no
logged line above 65,494 bytes out of 53,315 agent events, and 418 of 1,383
phases exited rc=0 (so claude printed its ``result`` event) with
``saw_result=false``.
"""
import asyncio
import json
import os
import stat
import sys

import backend.agent_runner as ar
import backend.graph_store as gs


def _lines(data: bytes, limit: int = 1024, **kw) -> list:
    """Everything _iter_stream_lines yields for ``data``, read through a
    StreamReader with a small ``limit`` (the reader must be built inside the
    running loop)."""
    async def run():
        r = asyncio.StreamReader(limit=limit)
        r.feed_data(data)
        r.feed_eof()
        return [item async for item in ar._iter_stream_lines(r, **kw)]
    return asyncio.run(run())


def test_lines_longer_than_the_reader_limit_are_reassembled():
    long_line = b"x" * 10_000 + b"\n"
    got = _lines(b"first\n" + long_line + b"after\n" + b"no newline at eof")
    assert [line for line, _ in got] == [b"first\n", long_line, b"after\n", b"no newline at eof"]
    assert [size for _, size in got] == [6, 10_001, 6, 17]


def test_a_newline_found_past_the_limit_ends_its_own_line():
    # LimitOverrunError has two shapes: newline absent from the buffer, and
    # newline present but past the limit. The second must not swallow the
    # following line.
    got = _lines(b"a" * 3000 + b"\nb\n")
    assert [line for line, _ in got] == [b"a" * 3000 + b"\n", b"b\n"]


def test_a_line_past_the_cap_is_cut_and_the_stream_goes_on():
    got = _lines(b"y" * 5000 + b"\n" + b"next\n", max_bytes=100)
    assert got[0] == (b"y" * 100, 5001)
    assert got[1] == (b"next\n", 5)


def test_empty_stream_yields_nothing():
    assert _lines(b"") == []


# ── The real phase runner, on a real pipe ─────────────────────────────────

_BIG = 200_000  # a tool result well past 64 KiB, as a VirusTotal report is


def _fake_claude(tmp_path, big: int = _BIG):
    """An executable that prints the stream-json of a short agent turn whose
    tool result is ``big`` bytes long, then a stderr line of the same size."""
    events = [
        {"type": "system", "subtype": "init", "session_id": "s"},
        {"type": "assistant", "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": "toolu_big", "name": "mcp__cti__virustotal_file",
             "input": {"hash": "abc"}}]}},
        {"type": "user", "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "toolu_big",
             "content": [{"type": "text", "text": "v" * big}]}]}},
        {"type": "assistant", "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": "toolu_after", "name": "mcp__cti__rdap_domain",
             "input": {"domain": "example.com"}}]}},
        {"type": "result", "subtype": "success", "is_error": False},
    ]
    script = tmp_path / "fake-claude"
    body = "\n".join([
        f"#!{sys.executable}",
        "import json, sys",
        f"for e in {events!r}:",
        "    sys.stdout.write(json.dumps(e) + '\\n')",
        "    sys.stdout.flush()",
        f"sys.stderr.write('e' * {big} + '\\n')",
        "sys.stderr.write('stderr after\\n')",
    ])
    script.write_text(body + "\n", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script)


def test_phase_logs_every_event_after_a_tool_result_past_64k(tmp_path, monkeypatch):
    monkeypatch.setattr(gs, "DB_PATH", str(tmp_path / "t.db"))
    gs.init_db()
    inv = gs.create_investigation("hash", "abc", user_id=1)
    monkeypatch.setattr(ar, "_resolve_claude_bin", lambda: _fake_claude(tmp_path))
    monkeypatch.setattr(ar, "_WATCHDOG_POLL_S", 0.05)

    rc, saw_result, _has_report, quota = asyncio.run(ar._run_claude_phase(
        inv, "prompt", "system", "sonnet", dict(os.environ), tmp_path / "mcp.json"))

    assert rc == 0
    assert saw_result is True, "the result event after the big line was lost"
    assert quota["hit"] is False
    with gs.conn() as c:
        rows = c.execute("SELECT kind, payload FROM events WHERE investigation_id=? ORDER BY id",
                         (inv,)).fetchall()
    kinds = [r["kind"] for r in rows]
    assert kinds.count("agent_assistant") == 2
    assert "agent_result" in kinds
    big = [json.loads(r["payload"]) for r in rows if r["kind"] == "agent_user"]
    assert len(big) == 1
    assert big[0]["msg"]["message"]["content"][0]["content"][0]["text"] == "v" * _BIG
    # The tool call made after the big result counts toward the CTI budget.
    assert ar._count_cti_calls(inv) == 2
    stderr = [json.loads(r["payload"])["msg"] for r in rows if r["kind"] == "agent_stderr"]
    assert stderr == ["e" * _BIG, "stderr after"]
    assert "agent_stream_error" not in kinds
    exit_evt = json.loads(rows[-1]["payload"])
    assert rows[-1]["kind"] == "phase_main_exit" and exit_evt["msg"]["saw_result"] is True


def test_a_dead_pump_is_logged_not_swallowed(tmp_path, monkeypatch):
    """If a pump ever dies again, the phase says so in the event log instead of
    going quiet: the old failure was invisible because gather() swallowed it."""
    monkeypatch.setattr(gs, "DB_PATH", str(tmp_path / "t.db"))
    gs.init_db()
    inv = gs.create_investigation("hash", "abc", user_id=1)
    # Small output: nothing reads the pipes once the pumps are dead, and a fake
    # that filled a pipe would block until the phase's own timeouts end it.
    monkeypatch.setattr(ar, "_resolve_claude_bin", lambda: _fake_claude(tmp_path, big=10))
    monkeypatch.setattr(ar, "_WATCHDOG_POLL_S", 0.05)

    async def broken(stream, max_bytes=None):
        raise ValueError("Separator is not found, and chunk exceed the limit")
        yield  # pragma: no cover  (makes this an async generator)

    monkeypatch.setattr(ar, "_iter_stream_lines", broken)
    asyncio.run(ar._run_claude_phase(
        inv, "prompt", "system", "sonnet", dict(os.environ), tmp_path / "mcp.json"))
    with gs.conn() as c:
        errs = [json.loads(r["payload"])["msg"] for r in c.execute(
            "SELECT payload FROM events WHERE investigation_id=? AND kind='agent_stream_error'",
            (inv,)).fetchall()]
    assert {e["stream"] for e in errs} == {"stdout", "stderr"}
    assert all("ValueError" in e["error"] for e in errs)
