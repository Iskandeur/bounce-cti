"""backend/eval_judge.py: judge v2 and fresh seeds for prospective cases
(EVAL_PROTOCOL §4.E), and the two admin routes over them. No network: every
answer is faked through the opener, shaped as the feeds answer."""
import io
import itertools
import json
import types
import urllib.error
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from backend import eval_judge as J

NOW = datetime(2026, 10, 26, 18, 0, 0, tzinfo=timezone.utc)
KEY = "abusech-test-key"


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _opener(*answers):
    """Each answer: a dict (JSON body) or an int (HTTP error status). Records
    each request (url, method, headers, body)."""
    seen = []

    def opener(req, timeout):
        body = req.data.decode() if req.data else None
        seen.append(types.SimpleNamespace(url=req.full_url, method=req.get_method(),
                                          headers=dict(req.header_items()), body=body))
        a = answers[len(seen) - 1]
        if isinstance(a, int):
            raise urllib.error.HTTPError(req.full_url, a, "x", {}, None)
        return _Resp(json.dumps(a).encode())
    opener.seen = seen
    return opener


def _no_sleep(_):
    return None


def tf_entry(ioc, ioc_type, *, id_="1", first_seen="2026-10-26 09:12:00 UTC", reporter="abuse_ch",
             malware="win.asyncrat", printable="AsyncRAT", confidence=75, compromised=False, tags=None):
    return {"id": id_, "ioc": ioc, "ioc_type": ioc_type, "first_seen": first_seen, "reporter": reporter,
            "malware": malware, "malware_printable": printable, "confidence_level": confidence,
            "is_compromised": compromised, "threat_type": "botnet_cc", "tags": tags or ["asyncrat"]}


def otx(pulses=(), validation=()):
    return {"pulse_info": {"count": len(pulses), "pulses": [
        {"id": p, "created": "2026-10-27T10:00:00.917000", "author": {"username": f"user-{p}"}}
        for p in pulses]},
        "validation": [{"source": v} for v in validation], "false_positive": []}


# ── exact match: ThreatFox searches by substring ──────────────────────────

def test_threatfox_counts_only_the_entry_that_is_the_claim():
    # Measured on production's cache, 2026-10-26: a domain search also returns
    # the domains that contain it, an IP search the URLs that contain the IP.
    data = [tf_entry("sub.evil.example", "domain", id_="1"),
            tf_entry("xevil.example", "domain", id_="2"),
            tf_entry("http://evil.example/gate.php", "url", id_="3"),
            tf_entry("203.0.113.7:443", "ip:port", id_="4"),
            tf_entry("203.0.113.70:80", "ip:port", id_="5"),
            tf_entry("http://203.0.113.7/x", "url", id_="6"),
            tf_entry("Evil.Example", "domain", id_="7")]
    assert [e["id"] for e in J.threatfox_matches("domain", "evil.example", data)] == ["7"]
    assert [e["id"] for e in J.threatfox_matches("ip", "203.0.113.7", data)] == ["4"]
    assert [e["id"] for e in J.threatfox_matches("url", "http://evil.example/gate.php", data)] == ["3"]
    assert J.threatfox_matches("domain", "other.example", data) == []


def test_threatfox_lookup_states_and_what_it_keeps():
    o = _opener({"query_status": "ok", "data": [tf_entry("sub.evil.example", "domain")]})
    r = J.threatfox_lookup("domain", "evil.example", key=KEY, opener=o, sleep=_no_sleep)
    assert r["state"] == "unlisted"  # substring hits only: in no listing
    req = o.seen[0]
    assert req.method == "POST" and req.url == J.THREATFOX_API and req.headers["Auth-key"] == KEY
    assert json.loads(req.body) == {"query": "search_ioc", "search_term": "evil.example"}

    o = _opener({"query_status": "ok", "data": [tf_entry("evil.example", "domain", id_="9",
                                                         reporter="someone", compromised=True)]})
    r = J.threatfox_lookup("domain", "evil.example", key=KEY, opener=o, sleep=_no_sleep)
    assert r["state"] == "listed" and r["count"] == 1
    assert r["entries"] == [{"id": "9", "created": "2026-10-26T09:12:00Z", "author": "someone",
                             "family": "win.asyncrat", "compromised": True}]
    assert J.threatfox_lookup("ip", "203.0.113.7", key=KEY, sleep=_no_sleep,
                              opener=_opener({"query_status": "no_result", "data": "nothing"}))["state"] == "unlisted"
    bad = J.threatfox_lookup("ip", "203.0.113.7", key=KEY, sleep=_no_sleep,
                             opener=_opener({"query_status": "unknown_auth_key"}))
    assert bad == {"state": "error", "error": "query_status 'unknown_auth_key'"}
    assert J.threatfox_lookup("hash", "t" * 20, key=KEY, opener=_opener())["state"] == "n/a"


def test_a_rejected_key_is_not_retried_and_a_rate_limit_is():
    o = _opener(401)
    assert J.threatfox_lookup("ip", "203.0.113.7", key=KEY, opener=o, sleep=_no_sleep)["state"] == "error"
    assert len(o.seen) == 1
    o = _opener(429, {"query_status": "no_result"})
    assert J.threatfox_lookup("ip", "203.0.113.7", key=KEY, opener=o, sleep=_no_sleep)["state"] == "unlisted"
    assert len(o.seen) == 2


def test_urlhaus_by_host_and_by_url():
    host = {"query_status": "ok", "host": "evil.example", "url_count": 2, "urls": [
        {"id": 11, "url": "http://evil.example/a", "date_added": "2026-10-27 01:00:00 UTC", "reporter": "r1"},
        {"id": 12, "url": "http://evil.example/b", "date_added": "2026-10-26 23:00:00 UTC", "reporter": "r2"}]}
    o = _opener(host)
    r = J.urlhaus_lookup("domain", "evil.example", key=KEY, opener=o, sleep=_no_sleep)
    assert r["state"] == "listed" and [e["id"] for e in r["entries"]] == ["12", "11"]  # oldest first
    assert o.seen[0].url == J.URLHAUS_HOST and o.seen[0].body == "host=evil.example"
    o = _opener({"query_status": "ok", "id": 5, "url": "http://evil.example/a",
                 "date_added": "2026-10-27 01:00:00 UTC", "reporter": "r1"})
    r = J.urlhaus_lookup("url", "http://evil.example/a", key=KEY, opener=o, sleep=_no_sleep)
    assert r["entries"] == [{"id": "5", "created": "2026-10-27T01:00:00Z", "author": "r1"}]
    assert J.urlhaus_lookup("ip", "203.0.113.7", key=KEY, sleep=_no_sleep,
                            opener=_opener({"query_status": "no_results"}))["state"] == "unlisted"
    assert J.urlhaus_lookup("ip", "203.0.113.7", key=KEY, sleep=_no_sleep,
                            opener=_opener({"query_status": "invalid_host"}))["state"] == "error"
    assert J.urlhaus_lookup("hash", "a" * 64, key=KEY, opener=_opener())["state"] == "n/a"


def test_malwarebazaar_matches_any_of_the_three_hashes():
    sample = {"sha256_hash": "a" * 64, "sha1_hash": "b" * 40, "md5_hash": "c" * 32,
              "first_seen": "2026-10-26 08:00:00", "reporter": "r"}
    r = J.malwarebazaar_lookup("hash", "C" * 32, key=KEY, sleep=_no_sleep,
                               opener=_opener({"query_status": "ok", "data": [sample]}))
    assert r["state"] == "listed" and r["entries"][0] == {"id": "a" * 64, "created": "2026-10-26T08:00:00Z",
                                                         "author": "r"}
    assert J.malwarebazaar_lookup("hash", "d" * 64, key=KEY, sleep=_no_sleep,
                                  opener=_opener({"query_status": "hash_not_found"}))["state"] == "unlisted"
    assert J.malwarebazaar_lookup("hash", "t" * 20, key=KEY, opener=_opener())["state"] == "n/a"


# ── the merge and the whole judge ─────────────────────────────────────────

LISTED = {"state": "listed", "count": 1, "entries": [], "whitelist": []}
UNLISTED = {"state": "unlisted", "count": 0, "entries": [], "whitelist": []}
FAILED = {"state": "error", "error": "HTTP 503"}


def test_merge_listed_anywhere_unlisted_only_when_every_section_answered():
    assert J.merge({"otx": UNLISTED, "threatfox": LISTED, "urlhaus": FAILED})["state"] == "listed"
    r = J.merge({"otx": UNLISTED, "threatfox": UNLISTED, "urlhaus": FAILED})
    assert r["state"] == "error" and "urlhaus: HTTP 503" in r["error"]
    assert J.merge({"otx": UNLISTED, "threatfox": UNLISTED, "malwarebazaar": {"state": "n/a"}})["state"] == "unlisted"
    r = J.merge({"otx": {"state": "n/a"}, "threatfox": {"state": "n/a"}})
    assert r["state"] == "error" and J.is_unjudgeable(r)
    r = J.merge({"otx": dict(LISTED, whitelist=["majestic"]), "threatfox": UNLISTED})
    assert r["whitelist"] == ["majestic"] and set(r["sections"]) == {"otx", "threatfox"}


def test_judge_asks_every_section_of_a_domain_in_order():
    o = _opener(otx(), otx(["p1"]),                                   # OTX hostname, domain
                {"query_status": "no_result"},                        # ThreatFox
                {"query_status": "no_results"})                       # URLhaus host
    doc = J.judge([{"type": "domain", "value": "moonzonet.example"}], otx_key="otx-k",
                  abusech_key=KEY, opener=o, sleep=_no_sleep)
    assert doc["judge"] == J.JUDGE_V2
    r = doc["lookups"]["domain|moonzonet.example"]
    assert r["state"] == "listed"
    assert {s: a["state"] for s, a in r["sections"].items()} == {
        "otx": "listed", "threatfox": "unlisted", "urlhaus": "unlisted"}
    assert r["sections"]["otx"]["entries"] == [{"id": "p1", "created": "2026-10-27T10:00:00Z",
                                                "author": "user-p1"}]
    urls = [s.url for s in o.seen]
    assert "/hostname/" in urls[0] and "/domain/" in urls[1]
    assert urls[2:] == [J.THREATFOX_API, J.URLHAUS_HOST]
    assert o.seen[0].headers["X-otx-api-key"] == "otx-k"


def test_an_imphash_is_unjudgeable_and_costs_no_request():
    o = _opener()
    r = J.judge([{"type": "hash", "value": "t" * 20}], otx_key=None, abusech_key=KEY, opener=o,
                sleep=_no_sleep)["lookups"]["hash|" + "t" * 20]
    assert J.is_unjudgeable(r) and o.seen == []


def test_a_value_without_the_shape_of_its_type_never_reaches_the_otx_path():
    for ntype, value in (("domain", "evil.example/../../IPv4/1.1.1.1"), ("domain", "evil.example?x=1"),
                         ("domain", "evil\n.example"), ("ip", "203.0.113.7/x"), ("ip", "not-an-ip"),
                         ("hash", "a" * 64 + "\n"), ("url", "http://evil.example/\r\nHost: x")):
        assert J.otx_paths(ntype, value) == [], (ntype, value)
    assert [p.rsplit("/", 3)[1] for p in J.otx_paths("domain", "xn--80ak6aa92e.com")] == ["hostname", "domain"]
    assert J.otx_paths("ip", "2001:db8::1")[0].endswith("/IPv6/2001:db8::1/general")


def test_one_claim_that_breaks_its_lookup_stays_that_claims_error(monkeypatch):
    real = J.judge_one

    def flaky(ntype, value, **kw):
        if value == "boom.example":
            raise RuntimeError("a bug in one lookup")
        return real(ntype, value, **kw)
    monkeypatch.setattr(J, "judge_one", flaky)
    o = _opener(otx(), otx(), {"query_status": "no_result"}, {"query_status": "no_results"})
    doc = J.judge([{"type": "domain", "value": "boom.example"}, {"type": "domain", "value": "ok.example"}],
                  otx_key=None, abusech_key=KEY, opener=o, sleep=_no_sleep)
    assert doc["lookups"]["domain|boom.example"] == {"state": "error", "error": "judge: RuntimeError"}
    assert doc["lookups"]["domain|ok.example"]["state"] == "unlisted"


def test_the_judge_never_reads_the_cache(monkeypatch):
    # A check answered from the cache would repeat T and confirm nothing.
    from backend import graph_store

    def refuse(*a, **k):
        raise AssertionError("judge v2 read the cache")
    monkeypatch.setattr(graph_store, "cache_get", refuse)
    monkeypatch.setattr(graph_store, "cache_set", refuse)
    o = _opener(otx(), {"query_status": "no_result"}, {"query_status": "no_results"})
    J.judge([{"type": "ip", "value": "203.0.113.7"}], otx_key=None, abusech_key=KEY, opener=o, sleep=_no_sleep)
    assert len(o.seen) == 3


@pytest.mark.parametrize("raw, iso", [
    ("2026-10-25 14:03:11 UTC", "2026-10-25T14:03:11Z"),      # ThreatFox, URLhaus
    ("2026-10-25 14:03:11", "2026-10-25T14:03:11Z"),          # MalwareBazaar
    ("2026-10-25T14:03:11.917000", "2026-10-25T14:03:11Z"),   # OTX
    ("", None), (None, None), ("yesterday", None),
])
def test_feed_dates_in_one_form(raw, iso):
    assert J._utc(raw) == iso


# ── fresh seeds ────────────────────────────────────────────────────────────

def test_a_fresh_family_tagged_entry_is_eligible():
    # 203.0.113.0/24 (TEST-NET-3) is not a public address: an eligible ip seed needs a global one.
    c = J.candidate(tf_entry("45.67.89.10:8080", "ip:port", id_="1601"), NOW)
    assert c["seed_type"] == "ip" and c["seed_value"] == "45.67.89.10"
    assert c["first_seen"] == "2026-10-26T09:12:00Z" and c["source"] == "threatfox:1601"
    assert c["family"] == "win.asyncrat" and c["reporter"] == "abuse_ch" and c["excluded_by"] == []
    assert J.candidate(tf_entry("http://Evil.example:8080/x", "url"), NOW)["excluded_by"] == []
    assert J.candidate(tf_entry("A" * 64, "sha256_hash"), NOW)["seed_value"] == "a" * 64
    assert J.candidate({"ioc": "x", "ioc_type": "jarm"}, NOW) is None  # nothing Bounce-CTI seeds from


@pytest.mark.parametrize("entry, reason", [
    (tf_entry("evil.example", "domain", first_seen="2026-10-24 09:00:00 UTC"), "> 48 h"),
    (tf_entry("evil.example", "domain", malware="unknown", printable="Unknown malware"), "no family"),
    (tf_entry("evil.example", "domain", malware="win.unknown", printable="Unknown"), "no family"),
    (tf_entry("evil.example", "domain", confidence=25), "confidence"),
    (tf_entry("hacked-shop.example", "domain", compromised=True), "compromised"),
    (tf_entry("10.0.0.5:443", "ip:port"), "not a public address"),
    (tf_entry("203.0.113.7:443", "ip:port"), "not a public address"),
    (tf_entry("104.16.1.1:443", "ip:port"), "shared platform: cdn"),
    (tf_entry("https://bit.ly/abc", "url"), "shared platform: bit.ly"),
    (tf_entry("https://raw.githubusercontent.com/x/y/z.ps1", "url"), "shared platform"),
    (tf_entry("evil-app.herokuapp.com", "domain"), "shared platform"),
    (tf_entry("abc.trycloudflare.com", "domain"), "shared platform"),
    (tf_entry("evil.duckdns.org", "domain"), "shared platform"),
])
def test_the_rules_of_4E_exclude(entry, reason):
    c = J.candidate(entry, NOW)
    assert any(reason in r for r in c["excluded_by"]), c["excluded_by"]


def test_fresh_iocs_asks_get_iocs_and_ranks_newest_first():
    data = [tf_entry("old.example", "domain", id_="1", first_seen="2026-10-26 01:00:00 UTC"),
            tf_entry("new.example", "domain", id_="2", first_seen="2026-10-26 17:00:00 UTC"),
            tf_entry("x", "jarm", id_="3")]
    o = _opener({"query_status": "ok", "data": data})
    doc = J.fresh_iocs(abusech_key=KEY, days=30, now=NOW, opener=o, sleep=_no_sleep)
    assert json.loads(o.seen[0].body) == {"query": "get_iocs", "days": 7}  # clamped to ThreatFox's 1-7
    assert [c["seed_value"] for c in doc["candidates"]] == ["new.example", "old.example"]
    assert (doc["count"], doc["eligible"], doc["fetched_at"]) == (2, 2, "2026-10-26T18:00:00Z")
    assert J.fresh_iocs(abusech_key=KEY, now=NOW, sleep=_no_sleep,
                        opener=_opener({"query_status": "no_result"}))["count"] == 0
    with pytest.raises(RuntimeError, match="unknown_auth_key"):
        J.fresh_iocs(abusech_key=KEY, now=NOW, sleep=_no_sleep,
                     opener=_opener({"query_status": "unknown_auth_key"}))


# ── the routes ─────────────────────────────────────────────────────────────

@pytest.fixture
def api(tmp_path, monkeypatch):
    from backend import auth, config, graph_store, main
    path = tmp_path / "test.db"
    monkeypatch.setattr(config, "DB_PATH", path, raising=False)
    monkeypatch.setattr(graph_store, "DB_PATH", path, raising=False)
    graph_store.init_db()
    monkeypatch.setattr(config, "ABUSECH_KEY", KEY)
    monkeypatch.setattr(config, "OTX_KEY", "otx-k")
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


def test_the_routes_are_for_an_admin_only(api, monkeypatch):
    def boom(**kw):
        raise AssertionError("a non-admin reached a feed")
    monkeypatch.setattr(J, "fresh_iocs", boom)
    monkeypatch.setattr(J, "judge", boom)
    user = api.session(admin=False)
    assert api.call(user, "GET", "/api/admin/eval/fresh_iocs").status_code == 403
    assert api.call(user, "POST", "/api/admin/eval/judge", json={"claims": []}).status_code == 403
    assert api.call(None, "GET", "/api/admin/eval/fresh_iocs").status_code == 401


def test_the_routes_use_the_server_keys(api, monkeypatch):
    got = {}

    def fresh(**kw):
        got["fresh"] = kw
        return {"candidates": []}

    def judge(claims, **kw):
        got["judge"] = (claims, kw)
        return {"judge": J.JUDGE_V2, "lookups": {}}
    monkeypatch.setattr(J, "fresh_iocs", fresh)
    monkeypatch.setattr(J, "judge", judge)
    admin = api.session(admin=True)
    assert api.call(admin, "GET", "/api/admin/eval/fresh_iocs", params={"days": 1}).status_code == 200
    assert got["fresh"] == {"abusech_key": KEY, "days": 1}
    r = api.call(admin, "POST", "/api/admin/eval/judge", json={"claims": [{"type": "ip", "value": "203.0.113.7"}]})
    assert r.status_code == 200 and r.json()["judge"] == J.JUDGE_V2
    assert got["judge"] == ([{"type": "ip", "value": "203.0.113.7"}], {"otx_key": "otx-k", "abusech_key": KEY})
    assert KEY not in r.text


def test_the_routes_refuse_without_a_key_too_many_claims_and_a_failed_feed(api, monkeypatch):
    from backend import config
    admin = api.session(admin=True)
    too_many = {"claims": [{"type": "ip", "value": f"203.0.113.{i}"} for i in range(J.MAX_CLAIMS_PER_REQUEST + 1)]}
    assert api.call(admin, "POST", "/api/admin/eval/judge", json=too_many).status_code == 422

    def failed(**kw):
        raise RuntimeError("threatfox get_iocs: HTTP 503")
    monkeypatch.setattr(J, "fresh_iocs", failed)
    r = api.call(admin, "GET", "/api/admin/eval/fresh_iocs")
    assert r.status_code == 502 and "HTTP 503" in r.text
    monkeypatch.setattr(config, "ABUSECH_KEY", "")
    assert api.call(admin, "GET", "/api/admin/eval/fresh_iocs").status_code == 503
    assert api.call(admin, "POST", "/api/admin/eval/judge", json={"claims": []}).status_code == 503
