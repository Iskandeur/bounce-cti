"""eval/prospective.py: the Bounce-CTI arm filled from the server one run at a time
(`bounce`), and what `seal` checks of every arm's runs before it seals: each start
within 48 h of the seed's first listing (EVAL_PROTOCOL §4.E rule 1), no failed run
sealed as an empty graph, no arm without start times unless asked. No network: the
server is faked."""
import importlib.util
import json
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "eval" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


P = _load("prospective")
T0 = datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)
UNLISTED = {"state": "unlisted", "count": 0, "pulses": [], "whitelist": []}
SEEDS = [{"label": "P1", "seed_type": "ip", "seed_value": "203.0.113.7",
          "first_seen": "2026-10-28T08:00:00Z", "source": "feed X"},
         {"label": "P2", "seed_type": "domain", "seed_value": "seed2.example",
          "first_seen": "2026-10-28T09:00:00Z", "source": "feed X"}]
GRAPH = {"nodes": [{"type": "domain", "value": "c2.evil-example.com", "tags": ["malicious"]}], "edges": []}


def _batch(tmp_path, seeds=SEEDS):
    batch = tmp_path / "lot1"
    batch.mkdir(parents=True)
    (batch / "seeds.json").write_text(json.dumps(seeds))
    return batch


class Server:
    """Investigations whose status follows a script, one step per poll."""

    def __init__(self, scripts, *, created_at=T0.timestamp() - 3600, ack=None):
        self.scripts = {k: list(v) for k, v in scripts.items()}  # seed value → statuses
        self.created_at = created_at
        self.ack = ack or {}
        self.invs = {}
        self.log = []

    def start(self, body):
        i = f"inv-{len(self.invs) + 1}"
        self.invs[i] = {"seed": body["seed_value"], "status": "running", "body": body}
        self.log.append(("start", body["seed_value"]))
        return {"id": i, **self.ack}

    def row_of(self, i):
        inv = self.invs.get(i)
        if inv is None:
            return None
        script = self.scripts[inv["seed"]]
        if script:
            inv["status"] = script.pop(0)
        self.log.append(("poll", inv["seed"], inv["status"]))
        return {"id": i, "status": inv["status"], "created_at": self.created_at, "model": inv["body"]["model"]}

    def resume(self, i):
        self.log.append(("resume", self.invs[i]["seed"]))
        return {"ok": True}

    def stop(self, i):
        self.log.append(("stop", self.invs[i]["seed"]))
        return {"ok": True}

    def graph_of(self, i):
        self.log.append(("graph", self.invs[i]["seed"]))
        return GRAPH


def _fill(batch, out, srv, **kw):
    return P.fill_bounce(batch, out, start=srv.start, row_of=srv.row_of, resume=srv.resume,
                         graph_of=srv.graph_of, stop=srv.stop, now=lambda: T0, sleep=lambda s: None,
                         poll_s=1, log=lambda *a: None, **kw)


# ── bounce: the arm, one run at a time ───────────────────────────────────

def test_bounce_runs_one_seed_at_a_time_and_writes_the_graphs_of_done_runs(tmp_path):
    batch, out = _batch(tmp_path), tmp_path / "bounce"
    srv = Server({"203.0.113.7": ["running", "running", "done"], "seed2.example": ["done"]})
    stamp = _fill(batch, out, srv)
    # P2 starts only once P1 has ended.
    assert srv.log.index(("start", "seed2.example")) > srv.log.index(("poll", "203.0.113.7", "done"))
    assert [e for e in srv.log if e[0] == "start"] == [("start", "203.0.113.7"), ("start", "seed2.example")]
    assert srv.invs["inv-1"]["body"] == {"seed_type": "ip", "seed_value": "203.0.113.7", "model": "opus-5",
                                         "vertical": "cti"}
    for lab in ("P1", "P2"):
        assert json.loads((out / lab / "graph.json").read_text()) == GRAPH
        run = stamp["runs"][lab]
        assert run["status"] == "done" and run["started_at"] == "2026-10-28T11:00:00Z"
        assert run["model_run"] == "opus-5" and run["nodes"] == 1
    assert json.loads((out / P.BOUNCE_STAMP).read_text()) == stamp


def test_a_run_that_does_not_end_done_writes_no_graph_and_the_arm_is_incomplete(tmp_path):
    batch, out = _batch(tmp_path), tmp_path / "bounce"
    srv = Server({"203.0.113.7": ["error: auth"], "seed2.example": ["done"]})
    with pytest.raises(P.ArmIncomplete, match=r"P1 \(error: auth\)"):
        _fill(batch, out, srv)
    assert not (out / "P1" / "graph.json").exists() and (out / "P2" / "graph.json").is_file()
    ended = json.loads((out / P.BOUNCE_STAMP).read_text())["runs"]["P1"]["finished_at"]
    # Run again, later: a failed run is not submitted twice (that would be choosing a better
    # run), nor asked again, and its record does not move.
    polls = len(srv.log)
    with pytest.raises(P.ArmIncomplete):
        P.fill_bounce(batch, out, start=srv.start, row_of=srv.row_of, resume=srv.resume, graph_of=srv.graph_of,
                      now=lambda: T0 + timedelta(hours=1), sleep=lambda s: None, log=lambda *a: None)
    assert len(srv.log) == polls
    assert json.loads((out / P.BOUNCE_STAMP).read_text())["runs"]["P1"]["finished_at"] == ended
    assert [e for e in srv.log if e[0] == "start"] == [("start", "203.0.113.7"), ("start", "seed2.example")]


def test_a_restart_or_the_quota_is_resumed_at_most_twice(tmp_path):
    batch, out = _batch(tmp_path, SEEDS[:1]), tmp_path / "bounce"
    srv = Server({"203.0.113.7": ["error: interrupted", "running", "quota_exceeded", "done"]})
    stamp = _fill(batch, out, srv)
    assert [r["after"] for r in stamp["runs"]["P1"]["resumes"]] == ["error: interrupted", "quota_exceeded"]
    assert stamp["runs"]["P1"]["status"] == "done"
    srv2 = Server({"203.0.113.7": ["error: interrupted"] * 3})
    with pytest.raises(P.ArmIncomplete, match="error: interrupted"):
        _fill(batch, tmp_path / "b2", srv2)
    assert sum(1 for e in srv2.log if e[0] == "resume") == P.BOUNCE_MAX_RESUMES


def test_a_quota_cooldown_answer_is_polled_again_not_counted(tmp_path):
    batch, out = _batch(tmp_path, SEEDS[:1]), tmp_path / "bounce"
    srv = Server({"203.0.113.7": ["quota_exceeded", "quota_exceeded", "done"]})
    calls = []

    def resume(i):
        calls.append(i)
        if len(calls) == 1:
            raise urllib.error.HTTPError("u", 425, "Too Early", {}, None)
        return {"ok": True}
    stamp = P.fill_bounce(batch, out, start=srv.start, row_of=srv.row_of, resume=resume, graph_of=srv.graph_of,
                          now=lambda: T0, sleep=lambda s: None, poll_s=1, log=lambda *a: None)
    assert len(calls) == 2 and len(stamp["runs"]["P1"]["resumes"]) == 1


def test_a_run_still_going_gives_the_hand_back_and_the_next_call_waits_for_it(tmp_path):
    batch, out = _batch(tmp_path), tmp_path / "bounce"
    srv = Server({"203.0.113.7": ["running"] * 5 + ["done"], "seed2.example": ["done"]})
    with pytest.raises(P.ArmIncomplete, match="still running"):
        _fill(batch, out, srv, max_wait_s=2)
    assert ("start", "seed2.example") not in srv.log  # nothing else starts while P1 runs
    stamp = _fill(batch, out, srv)
    assert [e for e in srv.log if e[0] == "start"] == [("start", "203.0.113.7"), ("start", "seed2.example")]
    assert stamp["runs"]["P1"]["inv_id"] == "inv-1" and stamp["runs"]["P1"]["status"] == "done"


def _flaky(fn, *errors):
    """``fn``, raising each of ``errors`` once first."""
    left = list(errors)

    def call(*a):
        if left:
            raise left.pop(0)
        return fn(*a)
    return call


def _http(code):
    return urllib.error.HTTPError("u", code, "x", {}, None)


def test_a_deploy_restart_out_of_reach_is_polled_through(tmp_path):
    # A deploy: connection refused, the proxy's 502, the graph route still down once,
    # the resume refused once while the server comes back.
    batch, out = _batch(tmp_path, SEEDS[:1]), tmp_path / "bounce"
    # Interrupted until a resume goes through: the first is refused, the second is not.
    srv = Server({"203.0.113.7": ["running", "error: interrupted", "error: interrupted", "done"]})
    logs = []
    stamp = P.fill_bounce(
        batch, out, start=srv.start, now=lambda: T0, sleep=lambda s: None, poll_s=1, log=logs.append,
        row_of=_flaky(srv.row_of, urllib.error.URLError("refused"), _http(502)),
        resume=_flaky(srv.resume, ConnectionRefusedError()),
        graph_of=_flaky(srv.graph_of, TimeoutError()))
    assert stamp["runs"]["P1"]["status"] == "done" and (out / "P1" / "graph.json").is_file()
    assert len(stamp["runs"]["P1"]["resumes"]) == 1
    assert sum("out of reach" in m for m in logs) == 3


def test_a_client_error_is_not_polled_through(tmp_path):
    batch, out = _batch(tmp_path, SEEDS[:1]), tmp_path / "bounce"
    srv = Server({"203.0.113.7": ["done"]})
    for code in (401, 404):
        with pytest.raises(urllib.error.HTTPError):
            P.fill_bounce(batch, out, start=srv.start, resume=srv.resume, graph_of=srv.graph_of,
                          row_of=_flaky(srv.row_of, _http(code)), now=lambda: T0, sleep=lambda s: None,
                          log=lambda *a: None)
    # The run submitted before the 401 is the one the next call waits for.
    assert [e for e in srv.log if e[0] == "start"] == [("start", "203.0.113.7")]


def test_the_context_pool_arm_stops_a_run_the_server_did_not_mount_it_for(tmp_path):
    batch = _batch(tmp_path)
    srv = Server({"203.0.113.7": ["done"]}, ack={"context_pool": True, "context_pool_web": False})
    with pytest.raises(ValueError, match="context pool"):
        _fill(batch, tmp_path / "ctx", srv, context_pool=True)
    assert ("stop", "203.0.113.7") in srv.log and srv.invs["inv-1"]["body"]["context_pool"] is True
    ok = Server({"203.0.113.7": ["done"], "seed2.example": ["done"]},
                ack={"context_pool": True, "context_pool_web": True})
    assert _fill(batch, tmp_path / "ctx2", ok, context_pool=True)["context_pool"] is True


def test_one_arm_directory_holds_one_batch_and_one_setting(tmp_path):
    batch, out = _batch(tmp_path), tmp_path / "bounce"
    _fill(batch, out, Server({"203.0.113.7": ["done"], "seed2.example": ["done"]}))
    with pytest.raises(ValueError, match="one arm, one setting"):
        _fill(batch, out, Server({}), model="sonnet")
    other = _batch(tmp_path / "x", SEEDS[:1])
    with pytest.raises(ValueError, match="other seeds"):
        _fill(other, out, Server({}))


# ── seal: when every arm ran ─────────────────────────────────────────────

def _arm(tmp_path, name, started_at="2026-10-28T11:00:00Z", **run):
    d = tmp_path / name
    for s in SEEDS:
        (d / s["label"]).mkdir(parents=True)
        (d / s["label"] / "graph.json").write_text(json.dumps(GRAPH))
        if started_at is not None:
            (d / s["label"] / "run.json").write_text(json.dumps({"started_at": started_at, "model": "m",
                                                                  "answer_parsed": True, **run}))
    return d


def _seal(batch, arms, **kw):
    return P.seal(batch, arms, 14, lookup=lambda t, v: UNLISTED, now=lambda: T0, pause_s=0, **kw)


def test_seal_records_when_each_arm_ran(tmp_path):
    batch = _batch(tmp_path)
    out = tmp_path / "bounce"
    _fill(batch, out, Server({"203.0.113.7": ["done"], "seed2.example": ["done"]}))
    c = _seal(batch, {"bounce": out, "web": _arm(tmp_path, "web", "2026-10-28T11:30:00Z")})
    assert c["runs"] == {"first_started_at": "2026-10-28T11:00:00Z", "last_started_at": "2026-10-28T11:30:00Z",
                         "max_hours_after_first_seen": 3.5, "unstamped_arms": []}
    m = json.loads((batch / "manifest.json").read_text())
    assert m["arms"]["bounce"]["runs"]["P1"]["inv_id"] == "inv-1"
    assert m["arms"]["web"]["runs"]["P2"] == {"started_at": "2026-10-28T11:30:00Z", "model": "m"}


def test_seal_refuses_a_run_started_more_than_48_h_after_its_seed_was_listed(tmp_path):
    batch = _batch(tmp_path)
    # P1 first listed 2026-10-28T08:00Z: 48 h later is the last start rule 1 accepts.
    late = _arm(tmp_path, "late", "2026-10-30T08:00:01Z")
    with pytest.raises(ValueError, match="over the 48 h of rule 1"):
        P.seal(batch, {"web": late}, 14, lookup=lambda t, v: UNLISTED, now=lambda: T0 + timedelta(days=3), pause_s=0)
    assert not (batch / "manifest.json").exists()
    edge = _arm(tmp_path, "edge", "2026-10-30T08:00:00Z")
    c = P.seal(batch, {"web": edge}, 14, lookup=lambda t, v: UNLISTED, now=lambda: T0 + timedelta(days=3), pause_s=0)
    assert c["runs"]["max_hours_after_first_seen"] == 48.0


def test_seal_refuses_a_start_outside_listing_and_seal(tmp_path):
    batch = _batch(tmp_path)
    with pytest.raises(ValueError, match="its time is wrong"):
        _seal(batch, {"web": _arm(tmp_path, "early", "2026-10-28T07:59:59Z")})  # before P1 was listed
    with pytest.raises(ValueError, match="its time is wrong"):
        _seal(batch, {"web": _arm(tmp_path, "future", "2026-10-28T12:00:01Z")})  # after the seal


def test_seal_refuses_a_web_run_that_ended_without_an_answer(tmp_path):
    batch = _batch(tmp_path)
    for i, run in enumerate(({"timed_out": True}, {"is_error": True}, {"answer_parsed": False})):
        with pytest.raises(ValueError, match="did not end in an answer"):
            _seal(batch, {"web": _arm(tmp_path, f"w{i}", **run)})
    assert not (batch / "manifest.json").exists()


def test_seal_refuses_a_bounce_arm_with_a_run_not_done(tmp_path):
    batch, out = _batch(tmp_path), tmp_path / "bounce"
    with pytest.raises(P.ArmIncomplete):
        _fill(batch, out, Server({"203.0.113.7": ["done"], "seed2.example": ["error: auth"]}))
    (out / "P2").mkdir()
    (out / "P2" / "graph.json").write_text(json.dumps(GRAPH))  # a graph put there by hand
    with pytest.raises(ValueError, match="P2 is error: auth"):
        _seal(batch, {"bounce": out})


def test_seal_refuses_a_bounce_arm_filled_for_another_batch(tmp_path):
    # Every batch labels its seeds P1, P2…: the other batch's graphs would seal as this one's.
    other, out = _batch(tmp_path / "other", [dict(s, seed_value=f"x{i}.example", seed_type="domain")
                                             for i, s in enumerate(SEEDS)]), tmp_path / "bounce"
    _fill(other, out, Server({"x0.example": ["done"], "x1.example": ["done"]}))
    with pytest.raises(ValueError, match="other seeds than this batch"):
        _seal(_batch(tmp_path), {"bounce": out})


def test_seal_refuses_an_arm_without_start_times_unless_asked_and_says_so(tmp_path):
    batch = _batch(tmp_path)
    bare = _arm(tmp_path, "bare", started_at=None)
    with pytest.raises(ValueError, match="no start time for P1, P2"):
        _seal(batch, {"web": bare})
    c = _seal(batch, {"web": bare}, allow_unstamped=True)
    assert c["runs"]["unstamped_arms"] == ["web"] and c["runs"]["first_started_at"] is None


def test_pivot_1_carries_its_start_like_the_other_arms(tmp_path):
    batch, out = _batch(tmp_path), tmp_path / "pivot"
    P.fill_pivot(batch, out, call=lambda body: GRAPH, now=lambda: T0 - timedelta(minutes=20))
    c = _seal(batch, {"pivot-1": out})
    assert c["runs"]["first_started_at"] == "2026-10-28T11:40:00Z" and c["runs"]["unstamped_arms"] == []


def test_the_cli_has_the_bounce_command_and_exit_5(tmp_path):
    assert P.EXIT_ARM == 5
    assert P.main(["bounce", "--batch", str(_batch(tmp_path)), "--out", str(tmp_path / "b")]) == P.EXIT_USAGE


def test_baseline_run_json_says_when_it_started_in_the_seal_s_format():
    B = _load("baseline")
    assert B._utc_iso(1_800_000_000) == "2027-01-15T08:00:00Z"
    assert P._parse_iso(B._utc_iso(1_800_000_000)) == datetime(2027, 1, 15, 8, 0, tzinfo=timezone.utc)
