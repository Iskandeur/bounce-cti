"""Criminal IP domain report: never the scan endpoint, mute until a GET read
path is established, the admin probe answers status + shape only."""
import asyncio

import httpx

from backend import key_pool
from backend.sources import criminalip


def run(coro):
    return asyncio.run(coro)


def test_domain_report_is_mute_and_makes_no_request(monkeypatch):
    calls = []

    async def boom(*a, **k):
        calls.append(a)
        raise AssertionError("no HTTP request expected")

    monkeypatch.setattr(criminalip, "get_json", boom)
    monkeypatch.setattr(criminalip, "DOMAIN_READ_PATH", None)
    out = run(criminalip.domain_report("example.org"))
    assert "error" in out and not calls


def test_domain_report_uses_a_get_on_the_established_path(monkeypatch):
    seen = {}

    async def fake_get_json(url, headers=None, params=None, ttl=0, cache_key=None):
        seen.update(url=url, params=params)
        return {"ok": 1}

    monkeypatch.setattr(criminalip, "get_json", fake_get_json)
    monkeypatch.setattr(criminalip, "DOMAIN_READ_PATH", "/domain/report")
    monkeypatch.setattr(key_pool, "acquire", lambda s: "k")
    assert run(criminalip.domain_report("example.org")) == {"ok": 1}
    assert seen["url"].endswith("/v1/domain/report") and seen["params"] == {"query": "example.org"}


def test_no_candidate_nor_configured_path_is_the_scan_endpoint():
    paths = list(criminalip.DOMAIN_READ_CANDIDATES) + [criminalip.DOMAIN_READ_PATH or ""]
    assert not any("scan" in p for p in paths)


def test_shape_of_has_no_value():
    s = criminalip.shape_of({"data": {"score": 5, "who": "secret-name", "l": ["x", "y"]}})
    assert "secret-name" not in repr(s) and s["data"]["score"] == "int"
    assert s["data"]["l"] == {"type": "array", "len": 2, "item": "str"}


def test_probe_only_gets_and_returns_status_and_shape(monkeypatch):
    requests = []

    def handler(request: httpx.Request):
        requests.append(request)
        if request.url.path.endswith("/report"):
            return httpx.Response(200, json={"data": {"owner": "third-party"}})
        return httpx.Response(405, text="no")

    real = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient",
                        lambda **k: real(transport=httpx.MockTransport(handler), **k))
    monkeypatch.setattr(key_pool, "acquire", lambda s: "SECRETKEY")
    out = run(criminalip.probe_domain_paths("example.org"))
    assert {r.method for r in requests} == {"GET"}
    assert not any("scan" in r.url.path for r in requests)
    assert out["/domain/report"]["status"] == 200
    assert out["/domain/reports"] == {"status": 405, "shape": "non-json"}
    assert "third-party" not in repr(out) and "SECRETKEY" not in repr(out)
