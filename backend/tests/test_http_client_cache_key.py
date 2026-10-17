"""ALV-1773 : une clé d'API passée en paramètre ne doit jamais se retrouver dans une clé de cache."""
import asyncio

from backend.sources import http_client

SECRET = "s3cr3t-value-for-test"


def test_cache_params_drops_auth_params_keeps_others():
    out = http_client.cache_params({"key": SECRET, "minify": "true", "ApiKey": SECRET, "q": "a"})
    assert out == {"minify": "true", "q": "a"}


def test_cache_params_none_and_empty():
    assert http_client.cache_params(None) is None
    assert http_client.cache_params({}) == {}


def test_cache_params_list_of_tuples():
    assert http_client.cache_params([("key", SECRET), ("q", "a")]) == [("q", "a")]


def test_business_params_named_signature_stay_distinct():
    a = http_client.cache_params({"query": "get_siginfo", "signature": "FamilyA"})
    b = http_client.cache_params({"query": "get_siginfo", "signature": "FamilyB"})
    assert a != b


def test_get_json_cache_key_has_no_secret(monkeypatch):
    seen = []
    monkeypatch.setattr(http_client, "cache_get", lambda k, ttl=None: seen.append(k) or {"ok": 1})
    monkeypatch.setattr(http_client, "cache_set", lambda k, v: seen.append(k))
    asyncio.run(http_client.get_json("https://api.example.test/host/some-target",
                                     params={"key": SECRET}))
    assert seen and all(SECRET not in k for k in seen)


def test_same_key_after_rotation(monkeypatch):
    seen = []
    monkeypatch.setattr(http_client, "cache_get", lambda k, ttl=None: seen.append(k) or {"ok": 1})
    for secret in ("old", "new"):
        asyncio.run(http_client.get_json("https://x.test/a", params={"key": secret, "n": 1}))
    assert seen[0] == seen[1]
