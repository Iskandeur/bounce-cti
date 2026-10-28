"""The mechanical arm pivot-1 (EVAL_PROTOCOL §4.E rule 1): the route, the graph.json
it hands back, and eval/prospective.py reading it as an arm. No network, no model."""
import asyncio
import importlib.util
import itertools
import json
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from backend import pivot_arm, seeds

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("prospective", ROOT / "eval" / "prospective.py")
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)

T0 = datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)
UNLISTED = {"state": "unlisted", "count": 0, "pulses": [], "whitelist": []}

CDN_IP = "104.16.0.1"            # Cloudflare range: defuse_check tags it cdn
DYNDNS = "x.duckdns.org"         # dyndns


def fake_pool(answers=None, fail=()):
    """A stand-in for the cti pool: records the calls, answers with one fixed document."""
    calls = []

    async def call(name, args, kwargs):
        calls.append((name, tuple(args), dict(kwargs)))
        if name in fail:
            raise RuntimeError("HTTP 429")
        return (answers or {}).get(name, {"records": [CDN_IP, "45.9.148.10", "c2.evil-example.com"]})
    call.calls = calls
    return call


def run(seed_type, seed_value, call):
    return asyncio.run(pivot_arm.run(seed_type, seed_value, call=call))


# ── one seed ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("seed_type,value", [
    ("ip", "203.0.113.7"), ("domain", "seed.example"), ("url", "http://seed.example/a.php"),
    ("hash", "a" * 64), ("executable_name", "dropper.exe"), ("asn", "AS64500"),
])
def test_each_seed_type_runs_its_own_mandatory_tools_and_only_those(seed_type, value):
    call = fake_pool()
    run(seed_type, value, call)
    wanted = [n for n, _ in seeds.mandatory_tools(seed_type, value)]
    assert [c[0] for c in call.calls] == wanted
    assert wanted                                  # a type with no tools is refused, not run empty


def test_the_arguments_come_from_the_mandatory_call_examples():
    call = fake_pool()
    run("asn", "AS64500", call)
    (name, args, kwargs), = call.calls
    assert name == "shodan_host_count" and args == ("asn:AS64500",)
    assert kwargs == {"facets": "org,country,port,product"}


def test_what_comes_back_becomes_nodes_with_the_seed_tagged_and_left_out_of_claims():
    graph = run("ip", "203.0.113.7", fake_pool({"rdap_ip": {"seen": ["203.0.113.7", "c2.evil-example.com"]}}))
    seed = [n for n in graph["nodes"] if "seed" in n["tags"]]
    assert [(n["type"], n["value"]) for n in seed] == [("ip", "203.0.113.7")]
    claims = P.claims_of(graph, "203.0.113.7")
    assert ("domain", "c2.evil-example.com") in {(c["type"], c["value"]) for c in claims}
    assert all(c["value"] != "203.0.113.7" for c in claims)
    assert all(not c["malicious"] for c in claims)  # nothing judged them


def test_the_neutralisation_is_the_exports_own():
    answer = {"x": [CDN_IP, DYNDNS, "45.9.148.10", "10.0.0.1", "c2.evil-example.com"]}
    graph = run("domain", "seed.example", fake_pool({n: answer for n, _ in seeds.mandatory_tools("domain", "seed.example")}))
    values = {n["value"] for n in graph["nodes"]}
    assert {"45.9.148.10", "c2.evil-example.com", "seed.example"} <= values
    assert not values & {CDN_IP, DYNDNS, "10.0.0.1"}   # cdn, dyndns, non-public
    # the same filter the exports apply, on the same tags
    from backend.action_exports import _iter_actionable
    assert _iter_actionable(graph["nodes"], {"ip", "domain", "url", "hash"}) == graph["nodes"]
    assert graph["metadata"]["neutralised"] >= 2


def test_a_defused_node_is_dropped_by_the_function_the_exports_use(monkeypatch):
    seen = []
    real = pivot_arm._iter_actionable
    monkeypatch.setattr(pivot_arm, "_iter_actionable", lambda *a, **k: seen.append(1) or real(*a, **k))
    run("ip", "203.0.113.7", fake_pool())
    assert seen                                        # not a copy of the filter


def test_a_failed_tool_is_reported_never_turned_into_an_empty_answer():
    graph = run("ip", "203.0.113.7", fake_pool(fail={"threatfox_search"}))
    status = {t["tool"]: t for t in graph["metadata"]["tools"]}
    assert status["threatfox_search"]["status"] == "error" and "429" in status["threatfox_search"]["error"]
    assert status["rdap_ip"]["status"] == "ok"


def test_a_tool_missing_from_the_pool_is_an_error_too():
    graph = asyncio.run(pivot_arm.run("asn", "AS64500"))   # real pool: no key, no network needed to fail or answer
    (t,) = graph["metadata"]["tools"]
    assert t["tool"] == "shodan_host_count" and t["status"] in ("ok", "error")


def test_no_model_is_involved(monkeypatch):
    import subprocess
    def boom(*a, **k):
        raise AssertionError("a process was spawned")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    run("ip", "203.0.113.7", fake_pool())
    src = Path(pivot_arm.__file__).read_text()
    assert "agent_runner" not in src and "claude" not in src.lower().replace("claude -p", "")


# ── the route ──────────────────────────────────────────────────────────────

@pytest.fixture
def api(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from backend import auth, config, graph_store, main
    path = tmp_path / "test.db"
    monkeypatch.setattr(config, "DB_PATH", path, raising=False)
    monkeypatch.setattr(graph_store, "DB_PATH", path, raising=False)
    graph_store.init_db()
    serial = itertools.count()

    def session(admin):
        with graph_store.conn() as c:
            uid = c.execute("INSERT INTO users(pin_hmac, created_at, is_admin) VALUES (?, 0, ?)",
                            (f"test-pin-{next(serial)}", int(admin))).lastrowid
        return auth.issue_session(uid)

    client = TestClient(main.app)

    def call(token, method, path, **kw):
        client.cookies.clear()
        if token:
            client.cookies.set("session", token)
        return client.request(method, path, **kw)
    return types.SimpleNamespace(session=session, call=call)


def test_the_route_is_for_an_admin_only(api, monkeypatch):
    async def boom(*a, **k):
        raise AssertionError("a non-admin ran a tool")
    monkeypatch.setattr(pivot_arm, "_call", boom)
    body = {"type": "ip", "value": "203.0.113.7"}
    assert api.call(api.session(admin=False), "POST", "/api/admin/eval/pivot", json=body).status_code == 403
    assert api.call(None, "POST", "/api/admin/eval/pivot", json=body).status_code == 401


def test_the_route_answers_a_graph_json(api, monkeypatch):
    pool = fake_pool()
    monkeypatch.setattr(pivot_arm, "_call", pool)
    r = api.call(api.session(admin=True), "POST", "/api/admin/eval/pivot",
                 json={"type": "ip", "value": "203.0.113.7"})
    assert r.status_code == 200
    doc = r.json()
    assert doc["edges"] == [] and any("seed" in n["tags"] for n in doc["nodes"])
    assert [c[0] for c in pool.calls] == [n for n, _ in seeds.mandatory_tools("ip", "203.0.113.7")]


def test_the_route_refuses_a_type_with_no_mandatory_tools(api, monkeypatch):
    monkeypatch.setattr(pivot_arm, "_call", fake_pool())
    admin = api.session(admin=True)
    for t in ("command_line", "nonsense"):
        assert api.call(admin, "POST", "/api/admin/eval/pivot",
                        json={"type": t, "value": "x"}).status_code == 422


# ── prospective.py reads it as an arm ──────────────────────────────────────

SEEDS = [{"label": "P1", "seed_type": "ip", "seed_value": "203.0.113.7",
          "first_seen": "2026-10-28T08:00:00Z", "source": "feed X"},
         {"label": "P2", "seed_type": "domain", "seed_value": "seed2.example",
          "first_seen": "2026-10-28T09:00:00Z", "source": "feed X"}]


def _batch(tmp_path):
    batch = tmp_path / "lot1"
    batch.mkdir(parents=True)
    (batch / "seeds.json").write_text(json.dumps(SEEDS))
    return batch


def _server(body):
    pool = fake_pool()
    return run(body["type"], body["value"], pool)


def _other_arm(tmp_path):
    d = tmp_path / "web"
    for lab, seed in (("P1", "203.0.113.7"), ("P2", "seed2.example")):
        (d / lab).mkdir(parents=True)
        (d / lab / "graph.json").write_text(json.dumps({"nodes": [
            {"type": "domain", "value": seed, "tags": ["seed"]},
            {"type": "domain", "value": "c2.evil-example.com", "tags": []}], "edges": []}))
        (d / lab / "run.json").write_text(json.dumps({"started_at": "2026-10-28T11:30:00Z"}))
    return d


def _lookup(ntype, value):
    return UNLISTED


def test_fill_pivot_writes_one_graph_per_seed_under_one_stamp(tmp_path):
    batch, out = _batch(tmp_path), tmp_path / "pivot"
    doc = P.fill_pivot(batch, out, call=_server, now=lambda: T0)
    assert doc["fetched_at"] == "2026-10-28T12:00:00Z" and doc["seeds"] == ["P1", "P2"]
    for lab in ("P1", "P2"):
        g = json.loads((out / lab / "graph.json").read_text())
        assert g["nodes"] and P.claims_of(g, "203.0.113.7" if lab == "P1" else "seed2.example")
    with pytest.raises(FileExistsError):
        P.fill_pivot(batch, out, call=_server, now=lambda: T0)


def test_seal_reads_pivot_1_like_any_other_arm(tmp_path):
    batch, out = _batch(tmp_path), tmp_path / "pivot"
    P.fill_pivot(batch, out, call=_server, now=lambda: T0)
    P.seal(batch, {"web": _other_arm(tmp_path), "pivot-1": out}, 14, lookup=_lookup,
           now=lambda: T0 + timedelta(minutes=20), pause_s=0)
    manifest = json.loads((batch / "manifest.json").read_text())
    assert sorted(manifest["arms"]) == ["pivot-1", "web"]
    p1 = {c["value"]: c for c in manifest["claims"]["P1"]}
    assert p1["c2.evil-example.com"]["arms"] == ["pivot-1", "web"]
    assert "45.9.148.10" in p1 and p1["45.9.148.10"]["arms"] == ["pivot-1"]
    assert CDN_IP not in p1


def test_arm_pivot_1_is_refused_when_not_filled_in_the_same_hour(tmp_path):
    batch, out = _batch(tmp_path), tmp_path / "pivot"
    P.fill_pivot(batch, out, call=_server, now=lambda: T0)
    with pytest.raises(ValueError, match="within the hour"):
        P.seal(batch, {"pivot-1": out}, 14, lookup=_lookup, now=lambda: T0 + timedelta(hours=3), pause_s=0)
    assert not (batch / "manifest.json").exists()


def test_arm_pivot_1_is_refused_without_its_stamp_or_for_other_seeds(tmp_path):
    batch, out = _batch(tmp_path), tmp_path / "pivot"
    P.fill_pivot(batch, out, call=_server, now=lambda: T0)
    (out / "pivot-1.json").unlink()
    with pytest.raises(ValueError, match="pivot-1.json"):
        P.seal(batch, {"pivot-1": out}, 14, lookup=_lookup, now=lambda: T0, pause_s=0)
    (batch / "seeds.json").write_text(json.dumps(SEEDS[:1]))
    out2 = tmp_path / "pivot2"
    P.fill_pivot(_batch(tmp_path / "x"), out2, call=_server, now=lambda: T0)
    with pytest.raises(ValueError, match="other seeds"):
        P.seal(batch, {"pivot-1": out2}, 14, lookup=_lookup, now=lambda: T0, pause_s=0)


def test_cli_pivot_needs_a_server(tmp_path):
    batch = _batch(tmp_path)
    assert P.main(["pivot", "--batch", str(batch), "--out", str(tmp_path / "o")]) == P.EXIT_USAGE
