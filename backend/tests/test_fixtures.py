"""Fixture capture + offline replay of source responses (EVAL_PROTOCOL §4.C).

The promise under test: a response captured in one run is served byte-for-byte
in a later run with the network off, whatever the cache TTL and whatever the
replay database holds; a request the capture never saw fails loudly instead of
reaching the internet; and no secret ever lands in a fixture file.
"""
import asyncio
import json
import os
import re
from pathlib import Path

import httpx
import pytest

from backend import fixtures


@pytest.fixture
def db(tmp_path, monkeypatch):
    """graph_store bound to a throwaway DB, with no fixture mode inherited."""
    for k in (fixtures.REPLAY_ENV, fixtures.CAPTURE_ENV):
        monkeypatch.delenv(k, raising=False)
    path = tmp_path / "test.db"
    from backend import config, graph_store
    monkeypatch.setattr(config, "DB_PATH", path, raising=False)
    monkeypatch.setattr(graph_store, "DB_PATH", path, raising=False)
    graph_store.init_db()
    return graph_store


def _files(directory: Path) -> list[Path]:
    return sorted(p for p in directory.glob("*.json") if p.name != fixtures.ENV_FILE)


def _mock_http(monkeypatch, handler):
    """Route http_client's AsyncClient through an httpx.MockTransport."""
    from backend.sources import http_client
    real = httpx.AsyncClient

    def factory(*a, **kw):
        kw["transport"] = httpx.MockTransport(handler)
        return real(*a, **kw)
    monkeypatch.setattr(http_client.httpx, "AsyncClient", factory)


# ── Mode and classification ────────────────────────────────────────────────

def test_off_by_default(db):
    assert not fixtures.replaying() and not fixtures.capturing()
    assert fixtures.activate_for_process() == "fixtures: off"


def test_replay_wins_over_capture(tmp_path, monkeypatch):
    monkeypatch.setenv(fixtures.REPLAY_ENV, str(tmp_path / "r"))
    monkeypatch.setenv(fixtures.CAPTURE_ENV, str(tmp_path / "c"))
    assert fixtures.replaying() and not fixtures.capturing()


def test_relative_replay_dir_resolves_against_the_project_root(monkeypatch):
    monkeypatch.setenv(fixtures.REPLAY_ENV, "eval/fixtures/case02")
    assert fixtures.replay_dir() == fixtures.PROJECT_ROOT / "eval/fixtures/case02"


@pytest.mark.parametrize("key", ["counter|inv1|ctx_calls", "source_health|shodan",
                                 "pdf_source:inv1", "sample_source:inv1:17"])
def test_bookkeeping_keys_are_not_source_responses(key):
    assert not fixtures.is_source_key(key)


@pytest.mark.parametrize("key", ["internetdb|1.2.3.4", "GET|https://x/|None",
                                 "shodan|/dns/domain/x|[]", "dns|all|example.com"])
def test_source_keys(key):
    assert fixtures.is_source_key(key)


def test_every_cache_user_outside_sources_is_classified():
    """Lock: the cache table holds source responses AND bookkeeping. Only
    BOOKKEEPING_PREFIXES keeps the latter out of fixtures. A module outside
    backend/sources/ that starts using the cache may be adding a bookkeeping
    key: classify its prefix in backend/fixtures.py, then add the module here."""
    backend = Path(fixtures.__file__).parent
    users = set()
    for path in backend.rglob("*.py"):
        rel = path.relative_to(backend).as_posix()
        if rel.startswith(("sources/", "tests/")) or rel == "fixtures.py":
            continue
        if re.search(r"\bcache_(?:get|set)\(", path.read_text(encoding="utf-8")):
            users.add(rel)
    assert users == {"graph_store.py", "source_health.py", "main.py"}


# ── Capture ────────────────────────────────────────────────────────────────

def test_capture_records_writes_and_hits_but_not_bookkeeping(db, tmp_path, monkeypatch):
    db.cache_set("internetdb|1.2.3.4", {"ports": [22]})       # before capture: warm cache
    cap = tmp_path / "cap"
    monkeypatch.setenv(fixtures.CAPTURE_ENV, str(cap))

    assert db.cache_get("internetdb|1.2.3.4") == {"ports": [22]}  # a hit is recorded
    db.cache_set("crtsh|example.com", [{"name_value": "a.example.com"}])
    db.bump_counter("inv1", "ctx_calls")
    db.cache_set("source_health|shodan", {"status": "auth_required"})

    keys = sorted(json.loads(p.read_text())["key"] for p in _files(cap))
    assert keys == ["crtsh|example.com", "internetdb|1.2.3.4"]


def test_capture_is_canonical_and_stable(db, tmp_path, monkeypatch):
    """Same response, same bytes: a re-capture of unchanged data is an empty diff."""
    monkeypatch.setenv(fixtures.CAPTURE_ENV, str(tmp_path / "a"))
    db.cache_set("otx|ip|1.2.3.4", {"b": 2, "a": [1, "é"]})
    monkeypatch.setenv(fixtures.CAPTURE_ENV, str(tmp_path / "b"))
    db.cache_set("otx|ip|1.2.3.4", {"b": 2, "a": [1, "é"]})
    (fa,), (fb,) = _files(tmp_path / "a"), _files(tmp_path / "b")
    assert fa.name == fb.name and fa.read_bytes() == fb.read_bytes()
    assert "é" in fa.read_text(encoding="utf-8")  # readable diffs, not \\u escapes



def test_replay_keeps_the_order_the_agent_read(db, tmp_path, monkeypatch):
    cap = tmp_path / "cap"
    _capture(db, cap, monkeypatch, "otx|ip|1.2.3.4", {"zeta": 1, "alpha": 2})
    monkeypatch.setenv(fixtures.REPLAY_ENV, str(cap))
    assert list(db.cache_get("otx|ip|1.2.3.4")) == ["zeta", "alpha"]


@pytest.mark.parametrize("key,source", [
    ("GET|https://rdap.org/ip/1.2.3.4|None", "rdap.org"),
    ("FORM|https://mb-api.abuse.ch/api/v1/|{'query': 'get_info'}", "mb-api.abuse.ch"),
    ("shodan|/dns/domain/x|[]", "shodan"),
    ("dns|all|example.com", "dns"),
])
def test_source_of(key, source):
    assert fixtures.source_of(key) == source

def test_capture_never_breaks_the_live_call(db, tmp_path, monkeypatch):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")  # capture dir path is a file: every write fails
    monkeypatch.setenv(fixtures.CAPTURE_ENV, str(blocker))
    db.cache_set("internetdb|1.2.3.4", {"ports": [22]})  # must not raise
    monkeypatch.delenv(fixtures.CAPTURE_ENV)
    assert db.cache_get("internetdb|1.2.3.4") == {"ports": [22]}


# ── Secrets ────────────────────────────────────────────────────────────────

def test_secrets_are_redacted_from_key_and_value(db, tmp_path, monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEYS", "k-AAAAAAAAAAAA,k-BBBBBBBBBBBB")
    monkeypatch.setenv("OTX_API_KEY", "otx-secret-123456")
    monkeypatch.setenv("BOUNCE_ADMIN_PIN", "123456")  # too short to redact: ignored
    cap = tmp_path / "cap"
    monkeypatch.setenv(fixtures.CAPTURE_ENV, str(cap))
    db.cache_set("GET|https://api/x|{'key': 'k-BBBBBBBBBBBB'}",
                 {"echo": "otx-secret-123456", "n": 123456})

    text = "".join(p.read_text() for p in cap.iterdir())
    for secret in ("k-AAAAAAAAAAAA", "k-BBBBBBBBBBBB", "otx-secret-123456"):
        assert secret not in text
    doc = json.loads(_files(cap)[0].read_text())
    assert doc["key"] == "GET|https://api/x|{'key': '<secret:SHODAN>'}"
    assert doc["value"] == {"echo": "<secret:OTX>", "n": 123456}
    env = json.loads((cap / fixtures.ENV_FILE).read_text())
    assert "SHODAN_API_KEYS" in env["secret_env_names"]
    assert "k-AAAAAAAAAAAA" not in json.dumps(env)


def test_placeholder_is_per_source_whatever_the_var_spelling():
    assert {fixtures.secret_placeholder(n) for n in
            ("SHODAN_API_KEY", "SHODAN_API_KEYS", "SHODAN_KEY", "SHODAN_KEYS")} \
        == {"<secret:SHODAN>"}
    assert fixtures.secret_placeholder("OPENCTI_URL") == "<secret:OPENCTI_URL>"


# ── Replay ─────────────────────────────────────────────────────────────────

def _capture(db, cap, monkeypatch, key, value):
    monkeypatch.setenv(fixtures.CAPTURE_ENV, str(cap))
    db.cache_set(key, value)
    monkeypatch.delenv(fixtures.CAPTURE_ENV)


def test_replay_serves_the_capture_whatever_the_ttl_and_db(db, tmp_path, monkeypatch):
    cap = tmp_path / "cap"
    _capture(db, cap, monkeypatch, "internetdb|1.2.3.4", {"ports": [22]})
    with db.conn() as c:
        c.execute("DELETE FROM cache")  # the replay DB knows nothing
    monkeypatch.setenv(fixtures.REPLAY_ENV, str(cap))
    assert db.cache_get("internetdb|1.2.3.4", ttl=0) == {"ports": [22]}


def test_replay_never_writes_source_traffic_to_the_db(db, tmp_path, monkeypatch):
    monkeypatch.setenv(fixtures.REPLAY_ENV, str(tmp_path))
    db.cache_set("internetdb|9.9.9.9", {"ports": [1]})
    db.bump_counter("inv1", "ctx_calls")  # bookkeeping still works in replay
    with db.conn() as c:
        keys = [r["key"] for r in c.execute("SELECT key FROM cache")]
    assert keys == ["counter|inv1|ctx_calls"]
    assert db.get_counter("inv1", "ctx_calls") == 1


def test_replay_miss_is_reported(db, tmp_path, monkeypatch):
    monkeypatch.setenv(fixtures.REPLAY_ENV, str(tmp_path))
    assert db.cache_get("internetdb|8.8.8.8") is None
    assert "internetdb|8.8.8.8" in fixtures.misses()


def test_replay_finds_a_capture_made_with_a_real_key_using_a_placeholder(
        db, tmp_path, monkeypatch):
    """The capture box had a real key; the replay box has none. The stand-in
    placeholder redacts to the same <secret:…>, so the lookup still hits."""
    cap = tmp_path / "cap"
    monkeypatch.setenv("NETLAS_API_KEY", "real-netlas-key-0001")
    _capture(db, cap, monkeypatch, "GET|https://netlas/x|{'apikey': 'real-netlas-key-0001'}",
             {"items": [1]})
    monkeypatch.delenv("NETLAS_API_KEY")

    monkeypatch.setenv(fixtures.REPLAY_ENV, str(cap))
    assert fixtures.stand_in_secrets(cap) == ["NETLAS_API_KEY"]
    try:
        placeholder = os.environ["NETLAS_API_KEY"]
        assert placeholder.startswith("fixture-replay-")
        assert db.cache_get(f"GET|https://netlas/x|{{'apikey': '{placeholder}'}}") \
            == {"items": [1]}
    finally:
        os.environ.pop("NETLAS_API_KEY", None)  # set by stand_in, not by monkeypatch


def test_stand_in_only_for_secrets_present_at_capture(tmp_path, monkeypatch):
    """A source with no key at capture must still say "no key" in replay."""
    (tmp_path / fixtures.ENV_FILE).write_text(
        json.dumps({"secret_env_names": ["VIRUSTOTAL_API_KEY"]}))
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("ZOOMEYE_API_KEY", raising=False)
    monkeypatch.setenv("OTX_API_KEY", "already-here-0000")
    try:
        assert fixtures.stand_in_secrets(tmp_path) == ["VIRUSTOTAL_API_KEY"]
        assert "ZOOMEYE_API_KEY" not in os.environ
        assert os.environ["OTX_API_KEY"] == "already-here-0000"
    finally:
        os.environ.pop("VIRUSTOTAL_API_KEY", None)  # set by stand_in, not by monkeypatch


def test_activate_refuses_a_replay_dir_that_does_not_exist(tmp_path, monkeypatch):
    monkeypatch.setenv(fixtures.REPLAY_ENV, str(tmp_path / "typo"))
    with pytest.raises(SystemExit):
        fixtures.activate_for_process()


# ── Offline guard ──────────────────────────────────────────────────────────

def test_offline_guard_refuses_resolution_and_connects_then_restores():
    import socket
    real = socket.getaddrinfo
    restore = fixtures.install_offline_guard()
    try:
        with pytest.raises(OSError, match="fixture replay"):
            socket.getaddrinfo("example.com", 443)
        s = socket.socket()
        try:
            with pytest.raises(OSError, match="fixture replay"):
                s.connect(("127.0.0.1", 9))
        finally:
            s.close()
        # httpx resolves a host name first: the refusal surfaces under its name.
        with pytest.raises(httpx.ConnectError, match="fixture replay"):
            asyncio.run(_real_get("http://bounce-fixture-test.invalid/"))
        # An IP literal skips resolution; anyio renames the failure, but it
        # still fails before any byte leaves the box.
        with pytest.raises(httpx.ConnectError):
            asyncio.run(_real_get("http://127.0.0.1:9/"))
    finally:
        restore()
    assert socket.getaddrinfo is real


async def _real_get(url):
    async with httpx.AsyncClient(timeout=5) as c:
        return await c.get(url)


# ── End to end through a real source path ──────────────────────────────────

def test_round_trip_through_http_client_is_byte_identical_and_offline(
        db, tmp_path, monkeypatch):
    from backend.sources import http_client
    real_client = httpx.AsyncClient
    calls = []

    def live(request):
        calls.append(str(request.url))
        return httpx.Response(200, json={"query_status": "ok", "data": [{"sha256": "3df9…"}]})

    # 1. Capture: the live source answers, the response is recorded.
    cap = tmp_path / "cap"
    monkeypatch.setenv(fixtures.CAPTURE_ENV, str(cap))
    _mock_http(monkeypatch, live)
    first = asyncio.run(http_client.get_json("https://mb.example/api", params={"h": "3df9"}))
    monkeypatch.delenv(fixtures.CAPTURE_ENV)
    assert len(calls) == 1

    # 2. Replay on an empty DB, network off: same bytes, zero live calls.
    with db.conn() as c:
        c.execute("DELETE FROM cache")
    monkeypatch.setenv(fixtures.REPLAY_ENV, str(cap))
    monkeypatch.setattr(http_client.httpx, "AsyncClient", real_client)
    misses = tmp_path / "misses.jsonl"
    monkeypatch.setenv(fixtures.MISSES_ENV, str(misses))
    restore = fixtures.install_offline_guard()
    try:
        again = asyncio.run(http_client.get_json("https://mb.example/api", params={"h": "3df9"}))
        assert json.dumps(again, sort_keys=True) == json.dumps(first, sort_keys=True)
        assert len(calls) == 1
        # 3. A question the capture never asked fails under its own name,
        #    never goes live, and is counted in the investigation's miss log.
        with pytest.raises(httpx.ConnectError, match="fixture replay"):
            asyncio.run(http_client.get_json("http://127.0.0.1:9/other"))
        text = asyncio.run(http_client.get_text("https://mb.example/page"))
        assert text["status"] == 0 and "fixture replay" in text["error"]
    finally:
        restore()
    logged = [json.loads(l)["key"] for l in misses.read_text().splitlines()]
    assert logged == ["GET|http://127.0.0.1:9/other|None", "TXT|https://mb.example/page|None"]


def test_dns_goes_through_the_fixture_layer(tmp_path, monkeypatch):
    from backend.sources import dns_tools
    for k in (fixtures.REPLAY_ENV, fixtures.CAPTURE_ENV):
        monkeypatch.delenv(k, raising=False)
    asked = []

    async def fake_resolve(name, rtype):
        asked.append((name, rtype))
        return ["192.0.2.1"] if rtype == "A" else []
    monkeypatch.setattr(dns_tools, "_resolve", fake_resolve)

    cap = tmp_path / "cap"
    monkeypatch.setenv(fixtures.CAPTURE_ENV, str(cap))
    live = asyncio.run(dns_tools.resolve_all("moonzonet.example"))
    monkeypatch.delenv(fixtures.CAPTURE_ENV)
    assert live["A"] == ["192.0.2.1"] and len(asked) == 7

    monkeypatch.setenv(fixtures.REPLAY_ENV, str(cap))
    assert asyncio.run(dns_tools.resolve_all("moonzonet.example")) == live
    assert len(asked) == 7  # served from the fixture, no resolver call
    # A miss falls through to the (guarded, in a real replay) live resolver.
    asyncio.run(dns_tools.resolve_all("other.example"))
    assert ("other.example", "A") in asked


def test_dns_unchanged_when_fixtures_are_off(monkeypatch):
    from backend.sources import dns_tools
    for k in (fixtures.REPLAY_ENV, fixtures.CAPTURE_ENV):
        monkeypatch.delenv(k, raising=False)

    async def fake_resolve(name, rtype):
        return [rtype]
    monkeypatch.setattr(dns_tools, "_resolve", fake_resolve)
    out = asyncio.run(dns_tools.resolve_all("x.example"))
    assert out == {rt: [rt] for rt in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")}


# ── Per-investigation wiring of the MCP servers ────────────────────────────

@pytest.fixture
def runner(db, tmp_path, monkeypatch):
    from backend import agent_runner
    root = tmp_path / "root"
    (root / "data").mkdir(parents=True)
    monkeypatch.setattr(agent_runner, "ROOT", root)
    for k in ("BOUNCE_FIXTURE_CAPTURE", "BOUNCE_FIXTURE_DIR"):
        monkeypatch.delenv(k, raising=False)
    with db.conn() as c:
        c.execute("INSERT INTO investigations(id, seed_type, seed_value, status, created_at) "
                  "VALUES ('inv-fx', 'hash', '3df9', 'running', 0)")
    return agent_runner


def _server_envs(agent_runner):
    cfg = json.loads(agent_runner._write_mcp_config("inv-fx").read_text())
    return {name: s["env"] for name, s in cfg["mcpServers"].items()}


def test_mcp_config_has_no_fixture_vars_by_default(runner):
    for env in _server_envs(runner).values():
        assert not any(k.startswith("BOUNCE_FIXTURE") for k in env)


def test_capture_flag_gives_every_server_the_investigations_own_dir(runner, monkeypatch):
    monkeypatch.setenv("BOUNCE_FIXTURE_CAPTURE", "1")
    envs = _server_envs(runner)
    assert set(envs) >= {"graph", "cti"}
    expected = str(runner.ROOT / "data" / "fixtures" / "capture" / "inv-fx")
    for env in envs.values():
        assert env["BOUNCE_FIXTURE_CAPTURE_DIR"] == expected


def test_capture_flag_from_dotenv_needs_no_restart(runner):
    (runner.ROOT / ".env").write_text("BOUNCE_FIXTURE_CAPTURE=true\n")
    for env in _server_envs(runner).values():
        assert env["BOUNCE_FIXTURE_CAPTURE_DIR"].endswith("capture/inv-fx")


def test_replay_dir_is_passed_absolute_and_disables_capture(runner, monkeypatch):
    monkeypatch.setenv("BOUNCE_FIXTURE_DIR", "eval/fixtures/case02")
    monkeypatch.setenv("BOUNCE_FIXTURE_CAPTURE", "1")
    for env in _server_envs(runner).values():
        assert env["BOUNCE_FIXTURE_DIR"] == str(runner.ROOT / "eval/fixtures/case02")
        assert env["BOUNCE_FIXTURE_MISSES"].endswith("replay-misses/inv-fx.jsonl")
        assert "BOUNCE_FIXTURE_CAPTURE_DIR" not in env


# ── eval/fixture_tool.py ───────────────────────────────────────────────────

def _tool():
    import importlib.util
    path = fixtures.PROJECT_ROOT / "eval" / "fixture_tool.py"
    spec = importlib.util.spec_from_file_location("fixture_tool", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_promote_then_verify(db, tmp_path, monkeypatch):
    tool = _tool()
    capture_root = tmp_path / "capture"
    _capture(db, capture_root / "inv-fx", monkeypatch, "internetdb|1.2.3.4", {"ports": [22]})
    _capture(db, capture_root / "inv-fx", monkeypatch, "dns|all|x.example", {"A": []})
    out = tmp_path / "eval-fixtures"
    stale = out / "case02" / "0000stale.json"
    stale.parent.mkdir(parents=True)
    stale.write_text("{}")  # a previous capture's file must not survive

    assert tool.promote("inv-fx", "case02", capture_root, out, dotenv=tmp_path / "none") == []
    assert not stale.exists()
    assert len(_files(out / "case02")) == 2
    manifest = (out / "case02" / "MANIFEST.md").read_text()
    assert "inv-fx" in manifest and "| internetdb | 1 |" in manifest


def test_verify_catches_a_dotenv_secret_and_a_hand_edit(tmp_path):
    tool = _tool()
    d = tmp_path / "case"
    d.mkdir()
    key = "GET|https://x/|None"
    (d / fixtures.fixture_name(key)).write_text(
        fixtures.serialise(key, {"token_echo": "live-secret-value-42"}))
    dotenv = tmp_path / ".env"
    dotenv.write_text("PULSEDIVE_API_KEY=live-secret-value-42\nLOG_LEVEL=debug-verbose\n")
    problems = tool.verify(d, dotenv)
    assert any("PULSEDIVE_API_KEY" in p for p in problems)

    dotenv.write_text("")
    path = d / fixtures.fixture_name(key)
    path.write_text(path.read_text().replace('"key"', '"key" '))
    assert any("canonical" in p for p in tool.verify(d, dotenv))


def test_verify_fails_on_a_credential_in_a_key_but_only_warns_in_a_value(tmp_path):
    tool = _tool()
    d = tmp_path / "case"
    d.mkdir()
    bad_key = "GET|https://x/?apikey=0123456789abcdef0123|None"
    (d / fixtures.fixture_name(bad_key)).write_text(fixtures.serialise(bad_key, {}))
    phish = "urlscan|result|abc"
    (d / fixtures.fixture_name(phish)).write_text(fixtures.serialise(
        phish, {"page": "https://evil.example/login?token=AAAABBBBCCCCDDDDEEEE"}))
    warnings = []
    problems = tool.verify(d, tmp_path / "none", warnings)
    assert len(problems) == 1 and "credential-shaped key" in problems[0]
    assert len(warnings) == 1 and "threat data" in warnings[0]
