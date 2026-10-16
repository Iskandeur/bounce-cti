"""ALV-1773 : la purge au démarrage retire les clés de cache qui portent un secret (base temporaire)."""
import pytest

import backend.graph_store as gs
from backend.sources import http_client

SECRET = "fake-shodan-key-0000"


def _keys():
    with gs.conn() as c:
        return {r["key"] for r in c.execute("SELECT key FROM cache")}


def test_purge_removes_only_legacy_secret_keys(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(gs, "DB_PATH", str(tmp_path / "t.db"))
    gs.init_db()
    legacy = [
        f"GET|https://api.shodan.io/shodan/host/1.2.3.4|{ {'key': SECRET, 'minify': 'true'} }",
        f"GET|https://example.test/api|{ {'q': 'a', 'ApiKey': SECRET} }",
        f"TXT|https://example.test/t|{[('token', SECRET), ('q', 'a')]}",
        f"FORM|https://example.test/f|{ {'api_key': SECRET} }",
        f"POST|https://example.test/p|{ {'access_token': SECRET, 'x': 1} }",
    ]
    kept = [
        f"GET|https://api.shodan.io/shodan/host/1.2.3.4|{ {'minify': 'true'} }",
        f"GET|https://mb.test/api|{ {'query': 'get_siginfo', 'signature': 'FamilyA'} }",
        "GET|https://example.test/plain|None",
        # « apikey » dans une valeur, pas en nom de paramètre
        f"GET|https://example.test/s|{ {'q': 'apikey'} }",
        # « api-key » ne doit pas être pris pour « api_key » (le _ de LIKE est échappé)
        f"GET|https://example.test/u|{ {'apiXkey': 'v'} }",
        # hors http_client : bookkeeping et clés de source maison
        f"counter|inv1|{ {'token': 1} }",
        "shodan|/shodan/host/1.2.3.4|[('minify', 'true')]",
    ]
    for k in legacy + kept:
        gs.cache_set(k, {"ok": True})

    assert gs.purge_secret_cache_keys() == len(legacy)
    assert _keys() == set(kept)
    assert all(SECRET not in k for k in _keys())
    # idempotent
    assert gs.purge_secret_cache_keys() == 0
    # rien du secret n'a été imprimé
    assert SECRET not in capsys.readouterr().out


def test_purge_covers_keys_that_http_client_used_to_write(tmp_path, monkeypatch):
    """La clé d'avant #68 (params bruts) est purgée ; celle d'aujourd'hui survit."""
    monkeypatch.setattr(gs, "DB_PATH", str(tmp_path / "t.db"))
    gs.init_db()
    url = "https://example.test/api"
    params = {"key": SECRET, "q": "a"}
    gs.cache_set(f"GET|{url}|{params}", {"old": True})
    gs.cache_set(f"GET|{url}|{http_client.cache_params(params)}", {"new": True})

    assert gs.purge_secret_cache_keys() == 1
    assert _keys() == {f"GET|{url}|{http_client.cache_params(params)}"}


def test_startup_hook_logs_count_only(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(gs, "DB_PATH", str(tmp_path / "t.db"))
    gs.init_db()
    gs.cache_set(f"GET|https://example.test/api|{ {'key': SECRET} }", {"ok": True})
    pytest.importorskip("fastapi")
    import backend.main as main
    monkeypatch.setattr(main.auth, "bootstrap_admin", lambda pin: None)
    main._bootstrap()
    out = capsys.readouterr().out
    assert "purged 1 cache row(s)" in out
    assert SECRET not in out
    assert _keys() == set()
