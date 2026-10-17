"""eval/stream_audit.py counts the phases whose log lost the agent stream."""
import importlib.util
import json
import sqlite3
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("stream_audit", ROOT / "eval" / "stream_audit.py")
audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(audit)


def _db(tmp_path, events, investigations=("inv_cut", "inv_ok", "inv_killed")):
    path = tmp_path / "bounce.db"
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE investigations (id TEXT PRIMARY KEY)")
    c.execute("CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, investigation_id TEXT, "
              "kind TEXT, payload TEXT, created_at REAL)")
    c.executemany("INSERT INTO investigations VALUES (?)", [(i,) for i in investigations])
    for inv, kind, msg, ts in events:
        c.execute("INSERT INTO events(investigation_id, kind, payload, created_at) VALUES (?,?,?,?)",
                  (inv, kind, json.dumps({"kind": kind, "msg": msg}), ts))
    c.commit()
    c.close()
    return path


def _exit(inv, phase, rc, saw, ts):
    return (inv, f"phase_{phase}_exit", {"rc": rc, "saw_result": saw, "has_report": True}, ts)


def test_only_a_clean_exit_without_its_result_counts_as_cut(tmp_path):
    t = time.time()
    path = _db(tmp_path, [
        _exit("inv_cut", "main", 0, False, t),            # cut: rc=0, no result logged
        _exit("inv_cut", "pivot_drain_1", 0, False, t),   # cut, grouped as pivot_drain
        _exit("inv_ok", "main", 0, True, t),              # clean
        _exit("inv_killed", "main", -9, False, t),        # killed: not evidence of a cut
    ])
    res = audit.cut_phases(audit._connect(path))
    assert res["phases"] == 4
    assert res["cut"] == 2
    assert res["cut_by_phase"] == {"main": 1, "pivot_drain": 1}
    assert res["cut_investigations"] == ["inv_cut"]
    assert res["investigations"] == 3


def test_since_bounds_the_window_and_sets_the_exit_code(tmp_path):
    now = time.time()
    day = time.strftime("%Y-%m-%d", time.gmtime(now))   # the day `now` falls in
    path = _db(tmp_path, [_exit("inv_cut", "main", 0, False, now - 30 * 86400),
                          _exit("inv_ok", "main", 0, True, now)])
    assert audit.cut_phases(audit._connect(path))["cut"] == 1
    assert audit.cut_phases(audit._connect(path), since=now - 3600)["cut"] == 0
    assert audit.main(["--db", str(path), "--since", day]) == 0
    assert audit.main(["--db", str(path)]) == 0       # no --since: report only
    fresh = tmp_path / "after-deploy"
    fresh.mkdir()
    path2 = _db(fresh, [_exit("inv_cut", "main", 0, False, now)])
    assert audit.main(["--db", str(path2), "--since", day]) == 1


def test_a_loss_event_of_the_fixed_reader_fails_the_check(tmp_path):
    now = time.time()
    day = time.strftime("%Y-%m-%d", time.gmtime(now))
    path = _db(tmp_path, [
        _exit("inv_ok", "main", 0, True, now),
        ("inv_ok", "agent_stdout_oversize", {"phase": "main", "bytes": 9_000_000}, now),
        ("inv_ok", "agent_stream_error", {"phase": "main", "stream": "stdout"}, now),
    ])
    assert audit.loss_events(audit._connect(path)) == {
        "agent_stdout_oversize": 1, "agent_stream_error": 1}
    assert audit.loss_events(audit._connect(path), since=now + 1) == {}
    assert audit.main(["--db", str(path), "--since", day]) == 1


def test_longest_lines_measures_the_printed_size(tmp_path):
    t = time.time()
    big = {"type": "user", "message": {"content": [{"type": "tool_result", "content": "v" * 70_000}]}}
    path = _db(tmp_path, [("inv_ok", "agent_user", big, t),
                          ("inv_ok", "agent_system", {"type": "system"}, t)])
    res = audit.longest_lines(audit._connect(path))
    assert res["events"] == 2
    assert res["longest"][0] > 70_000
    assert res["past_old_limit"] == 1


def test_runs_are_matched_to_their_scored_investigations(tmp_path, capsys):
    t = time.time()
    path = _db(tmp_path, [_exit("inv_cut", "main", 0, False, t), _exit("inv_ok", "main", 0, True, t)])
    run = tmp_path / "runs" / "2026-06-17_abc1234"
    run.mkdir(parents=True)
    (run / "raw_scores.json").write_text(json.dumps([
        {"case_id": 2, "inv_id": "inv_cut"}, {"case_id": 3, "inv_id": "inv_ok"},
        {"case_id": 4, "inv_id": "gone_from_db"}, {"case_id": 5, "error": "blocked"}]))
    assert audit.scored_investigations(tmp_path / "runs") == {
        "2026-06-17_abc1234": ["inv_cut", "inv_ok", "gone_from_db"]}
    audit.main(["--db", str(path), "--runs", str(tmp_path / "runs")])
    out = capsys.readouterr().out
    assert "2026-06-17_abc1234: 1 of 2 scored investigations cut" in out
    assert "scored investigations in the database: 2; with a cut phase: 1" in out


# ── The post-deploy canary (--since with a time, --prove-fix) ─────────────

def _utc(s):
    return audit.parse_since(s)


def _long_line(inv, ts):
    big = {"type": "user", "message": {"content": [{"type": "tool_result", "content": "v" * 70_000}]}}
    return (inv, "agent_user", big, ts)


def test_since_accepts_a_day_or_a_utc_time():
    assert _utc("2026-10-15") == _utc("2026-10-15T00:00Z")
    assert _utc("2026-10-15T21:41Z") == _utc("2026-10-15 21:41") == _utc("2026-10-15T23:41+02:00")
    assert _utc("2026-10-15T21:41Z") - _utc("2026-10-15") == (21 * 60 + 41) * 60


def test_an_empty_window_is_undetermined_never_green(tmp_path):
    old = _utc("2026-10-15T10:00Z")
    path = _db(tmp_path, [_exit("inv_ok", "main", 0, True, old)])
    for extra in ([], ["--prove-fix"]):
        assert audit.main(["--db", str(path), "--since", "2026-10-15T21:41Z", *extra]) == 3


def test_the_deploy_time_keeps_the_old_codes_cuts_out(tmp_path, capsys):
    """Deployed 21:41 UTC: a cut at 10:00 the same day is the old code's."""
    path = _db(tmp_path, [
        _exit("inv_cut", "main", 0, False, _utc("2026-10-15T10:00Z")),
        _long_line("inv_ok", _utc("2026-10-15T22:00Z")),
        _exit("inv_ok", "main", 0, True, _utc("2026-10-15T22:05Z")),
    ])
    assert audit.main(["--db", str(path), "--since", "2026-10-15"]) == 1
    capsys.readouterr()
    assert audit.main(["--db", str(path), "--since", "2026-10-15T21:41Z", "--prove-fix"]) == 0
    assert "1 line(s) of 64 KiB or more logged in full" in capsys.readouterr().out


def test_prove_fix_needs_a_long_line_in_the_window(tmp_path):
    path = _db(tmp_path, [_exit("inv_ok", "main", 0, True, _utc("2026-10-16T08:00Z"))])
    since = ["--since", "2026-10-15T21:41Z"]
    assert audit.main(["--db", str(path), *since]) == 0                 # nothing was at risk
    assert audit.main(["--db", str(path), *since, "--prove-fix"]) == 3  # but nothing is proven


def test_a_cut_after_the_deploy_still_fails_the_canary(tmp_path):
    path = _db(tmp_path, [
        _long_line("inv_ok", _utc("2026-10-16T08:00Z")),
        _exit("inv_cut", "main", 0, False, _utc("2026-10-16T08:01Z")),
    ])
    assert audit.main(["--db", str(path), "--since", "2026-10-15T21:41Z", "--prove-fix"]) == 1


def test_usage_errors_do_not_look_like_an_empty_window(tmp_path):
    path = _db(tmp_path, [])
    for argv in (["--since", "15/10/2026"], ["--prove-fix"]):
        with pytest.raises(SystemExit) as e:
            audit.main(["--db", str(path), *argv])
        assert e.value.code == 2
