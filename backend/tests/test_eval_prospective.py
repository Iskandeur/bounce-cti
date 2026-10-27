"""eval/prospective.py: prospective cases, sealed at T and judged after a horizon
by an independent feed (EVAL_PROTOCOL §4.E). No network: the judge is faked."""
import importlib.util
import io
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
T0 = datetime(2026, 10, 26, 20, 0, 0, tzinfo=timezone.utc)
LISTED = {"state": "listed", "count": 1, "pulses": ["p1"], "whitelist": []}
UNLISTED = {"state": "unlisted", "count": 0, "pulses": [], "whitelist": []}
FAILED = {"state": "error", "error": "HTTP 429"}
WHITELISTED = {"state": "listed", "count": 50, "pulses": ["p9"], "whitelist": ["majestic"]}


def node(ntype, value, *tags):
    return {"id": f"{ntype}:{value}", "type": ntype, "value": value, "tags": list(tags), "metadata": {}}


# ── claims ─────────────────────────────────────────────────────────────────

def test_claims_are_what_an_export_would_ship_minus_the_seed():
    graph = {"nodes": [
        node("ip", "203.0.113.7", "seed"),
        node("domain", "Evil.Example.", "malicious"),
        node("domain", "evil.example"),               # same claim, other spelling
        node("domain", "cdn.example", "cdn"),          # defused: real but noise
        node("lead", "maybe.example"),                 # context-pool lead: not a finding
        node("domain", "unproven.example", "unverified"),
        node("hash", "ABCDEF0123456789ABCDEF0123456789"),
        node("asn", "AS64500"),                        # not shippable to a blocklist
        node("report", "investigation_summary"),
        node("url", "http://203.0.113.7/Gate.php"),
    ]}
    claims = P.claims_of(graph, "203.0.113.7")
    assert [(c["type"], c["value"]) for c in claims] == [
        ("domain", "evil.example"),
        ("hash", "abcdef0123456789abcdef0123456789"),
        ("url", "http://203.0.113.7/Gate.php"),
    ]
    assert claims[0]["malicious"] is True and claims[1]["malicious"] is False


def test_the_seed_is_left_out_by_value_even_untagged():
    graph = {"nodes": [node("ip", "203.0.113.7"), node("ip", "203.0.113.8")]}
    assert [c["value"] for c in P.claims_of(graph, "203.0.113.7")] == ["203.0.113.8"]


# ── the judge ──────────────────────────────────────────────────────────────

class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _opener(*answers):
    """Each answer: a dict (JSON body) or an int (HTTP error status)."""
    seen = []

    def opener(req, timeout):
        seen.append(req.full_url)
        a = answers[len(seen) - 1]
        if isinstance(a, int):
            raise urllib.error.HTTPError(req.full_url, a, "x", {}, None)
        return _Resp(json.dumps(a).encode())
    opener.seen = seen
    return opener


def _otx(pulses=(), validation=(), count=None):
    return {"pulse_info": {"count": len(pulses) if count is None else count,
                           "pulses": [{"id": p} for p in pulses]},
            "validation": [{"source": v} for v in validation], "false_positive": []}


def test_otx_listed_unlisted_and_whitelisted():
    r = P.otx_lookup("domain", "evil.example", opener=_opener(_otx(["b", "a"]), _otx()))
    assert r == {"state": "listed", "count": 2, "pulses": ["a", "b"], "whitelist": [],
                 "entries": [{"id": "a", "created": None, "author": None},
                             {"id": "b", "created": None, "author": None}]}
    assert P.otx_lookup("ip", "203.0.113.9", opener=_opener(_otx()))["state"] == "unlisted"
    r = P.otx_lookup("domain", "cdn.example", opener=_opener(_otx(["c"], ["whitelist", "akamai"]), _otx()))
    assert r["whitelist"] == ["akamai", "whitelist"]


def test_a_domain_is_asked_under_hostname_and_domain():
    # moonzonet.com, 2026-10-25: 0 pulses under /hostname/, 46 under /domain/.
    opener = _opener(_otx(), _otx(["p1", "p2"]))
    r = P.otx_lookup("domain", "moonzonet.example", opener=opener)
    assert r["state"] == "listed" and r["pulses"] == ["p1", "p2"]
    assert ["/hostname/" in opener.seen[0], "/domain/" in opener.seen[1]] == [True, True]
    # Listed under one section is listed even if the other failed...
    assert P.otx_lookup("domain", "x.example", opener=_opener(404, _otx(["p"])))["state"] == "listed"
    # ...but "in no pulse" needs both sections to have answered.
    r = P.otx_lookup("domain", "x.example", opener=_opener(_otx(), 404))
    assert r == {"state": "error", "error": "HTTP 404"}


def test_an_answer_without_pulse_info_is_an_error_never_unlisted():
    r = P.otx_lookup("ip", "203.0.113.9", opener=_opener({"detail": "endpoint moved"}))
    assert r["state"] == "error"
    r = P.otx_lookup("domain", "evil.example", opener=_opener({"detail": "endpoint moved"}, _otx()))
    assert r["state"] == "error"


def test_rate_limit_is_retried_then_reported_as_an_error():
    sleeps = []
    ok = _opener(429, _otx(["p"]))
    assert P.otx_lookup("ip", "203.0.113.9", opener=ok, sleep=sleeps.append)["state"] == "listed"
    assert len(ok.seen) == 2 and sleeps
    gone = _opener(503, 503, 503, 503)
    r = P.otx_lookup("ip", "203.0.113.9", opener=gone, sleep=lambda s: None)
    assert r == {"state": "error", "error": "HTTP 503"} and len(gone.seen) == 4
    assert P.otx_lookup("ip", "x", opener=_opener(404))["state"] == "error"


def test_retry_after_is_honoured_and_lookups_are_paced_per_request():
    sleeps = []

    def opener(req, timeout, _n=[0]):
        _n[0] += 1
        if _n[0] == 1:
            raise urllib.error.HTTPError(req.full_url, 429, "x", {"Retry-After": "7"}, None)
        return _Resp(json.dumps(_otx()).encode())
    assert P.otx_lookup("ip", "203.0.113.9", opener=opener, sleep=sleeps.append)["state"] == "unlisted"
    assert sleeps == [7.0]
    paced = []
    P._lookup_all(["domain|a.example", "ip|203.0.113.9", "url|http://a.example/x"],
                  lambda t, v: UNLISTED, 3.0, paced.append)
    assert paced == [6.0, 3.0]  # after the domain (two sections), after the ip


def test_otx_paths_by_type():
    one = lambda t, v: P.otx_paths(t, v)[0]  # noqa: E731
    assert one("ip", "2001:db8::1").endswith("/IPv6/2001:db8::1/general")
    assert one("ip", "203.0.113.9").endswith("/IPv4/203.0.113.9/general")
    assert [p.rsplit("/", 3)[1] for p in P.otx_paths("domain", "a.evil.example")] == ["hostname", "domain"]
    assert one("hash", "a" * 64).endswith(f"/file/{'a' * 64}/general")
    # A '?' or '#' left raw would end the path: OTX would look up a truncated URL.
    assert one("url", "http://evil.example/gate.php?id=1#x").endswith(
        "/url/http://evil.example/gate.php%3Fid=1%23x/general")
    assert P.otx_paths("asn", "AS64500") == []


def test_a_value_the_judge_cannot_express_is_not_looked_up():
    opener = _opener()
    r = P.otx_lookup("hash", "t" * 20, opener=opener)  # an imphash-like, not a file hash
    assert r["state"] == "error" and opener.seen == []


@pytest.mark.parametrize("at_t, at_check, cls", [
    (LISTED, LISTED, "known"),
    (UNLISTED, LISTED, "ahead"),
    (UNLISTED, UNLISTED, "unconfirmed"),
    (UNLISTED, WHITELISTED, "benign"),
    (WHITELISTED, WHITELISTED, "benign"),
    (FAILED, LISTED, "undetermined"),
    (UNLISTED, FAILED, "undetermined"),   # a failed check is never "still in no pulse"
    (None, LISTED, "undetermined"),
    (FAILED, WHITELISTED, "undetermined"),
])
def test_classify(at_t, at_check, cls):
    assert P.classify(at_t, at_check) == cls


# ── seal / check / score ───────────────────────────────────────────────────

SEEDS = [
    {"label": "P1", "seed_type": "ip", "seed_value": "203.0.113.7",
     "first_seen": "2026-10-26T08:00:00Z", "source": "feed X"},
    {"label": "P2", "seed_type": "domain", "seed_value": "seed2.example",
     "first_seen": "2026-10-26T09:00:00Z", "source": "feed X"},
]


def _batch(tmp_path, arms):
    batch = tmp_path / "batch-2026-10-26"
    batch.mkdir(parents=True)
    (batch / "seeds.json").write_text(json.dumps(SEEDS))
    dirs = {}
    for arm, per_seed in arms.items():
        d = tmp_path / arm
        for label, nodes in per_seed.items():
            (d / label).mkdir(parents=True)
            (d / label / "graph.json").write_text(json.dumps({"nodes": nodes, "edges": []}))
        dirs[arm] = d
    return batch, dirs


def _judge(table):
    """A fake judge: type|value → answer; anything else is unlisted."""
    calls = []

    def lookup(ntype, value):
        calls.append(f"{ntype}|{value}")
        return table.get(f"{ntype}|{value}", UNLISTED)
    lookup.calls = calls
    return lookup


ARMS = {
    "bounce": {"P1": [node("ip", "203.0.113.7", "seed"), node("domain", "c2a.example", "malicious"),
                      node("domain", "c2b.example"), node("domain", "old.example")],
               "P2": [node("domain", "seed2.example", "seed"), node("ip", "198.51.100.4")]},
    "web": {"P1": [node("ip", "203.0.113.7", "seed"), node("domain", "c2a.example", "malicious"),
                   node("domain", "c2c.example", "malicious")],
            "P2": [node("domain", "seed2.example", "seed")]},
}


def _sealed(tmp_path, at_t=None):
    batch, dirs = _batch(tmp_path, ARMS)
    judge = _judge(at_t or {"domain|old.example": LISTED, "ip|203.0.113.7": LISTED})
    commitment = P.seal(batch, dirs, 14, lookup=judge, now=lambda: T0, pause_s=0)
    return batch, commitment, judge


def test_seal_freezes_claims_and_commits_without_any_value(tmp_path):
    batch, commitment, judge = _sealed(tmp_path)
    manifest = json.loads((batch / "manifest.json").read_text())
    p1 = {c["value"]: c for c in manifest["claims"]["P1"]}
    assert p1["c2a.example"]["arms"] == ["bounce", "web"]
    assert p1["c2a.example"]["malicious"] == {"bounce": True, "web": True}
    assert "203.0.113.7" not in p1                       # the seed is not a claim...
    assert "ip|203.0.113.7" in manifest["at_t"]         # ...but its own state is recorded
    assert manifest["due_at"] == "2026-11-09T20:00:00Z"
    assert len(judge.calls) == len(set(judge.calls))     # one lookup per distinct value
    text = (batch / "commitment.json").read_text()
    for v in ("c2a.example", "c2b.example", "198.51.100.4", "203.0.113.7", "seed2.example"):
        assert v not in text
    assert commitment["claims_per_arm"] == {"bounce": 4, "web": 2}
    assert commitment["manifest_sha256"] == P._sha256(batch / "manifest.json")


def test_seal_refuses_a_missing_graph_and_a_second_seal(tmp_path):
    batch, dirs = _batch(tmp_path, {"bounce": {"P1": [node("ip", "203.0.113.7", "seed")]}})
    with pytest.raises(FileNotFoundError, match="P2"):
        P.seal(batch, dirs, 14, lookup=_judge({}), now=lambda: T0, pause_s=0)
    batch2, _, _ = _sealed(tmp_path / "again")
    with pytest.raises(FileExistsError):
        P.seal(batch2, {}, 14, lookup=_judge({}), now=lambda: T0, pause_s=0)


def test_a_failed_lookup_at_t_seals_nothing_unless_accepted(tmp_path):
    batch, dirs = _batch(tmp_path, ARMS)
    judge = _judge({"domain|c2b.example": FAILED})
    with pytest.raises(P.JudgeUnavailable, match="1 of"):
        P.seal(batch, dirs, 14, lookup=judge, now=lambda: T0, pause_s=0)
    assert not (batch / "manifest.json").exists() and not (batch / "commitment.json").exists()
    commitment = P.seal(batch, dirs, 14, lookup=judge, now=lambda: T0, pause_s=0, max_failed=1)
    assert commitment["lookups_failed_at_t"] == 1
    assert commitment["max_failed_accepted"] == 1  # the tolerance is in the commitment, not only the count
    # A value the judge cannot express is not a failure of the judge.
    batch2, dirs2 = _batch(tmp_path / "imphash", {"bounce": {
        "P1": [node("ip", "203.0.113.7", "seed"), node("hash", "f" * 20)],
        "P2": [node("domain", "seed2.example", "seed")]}})
    unjudgeable = {"hash|" + "f" * 20: {"state": "error", "error": "OTX has no exact lookup for this hash"}}
    c2 = P.seal(batch2, dirs2, 14, lookup=_judge(unjudgeable), now=lambda: T0, pause_s=0)
    assert (c2["lookups_failed_at_t"], c2["unjudgeable"]) == (0, 1)


def test_check_is_refused_before_the_horizon_unless_early(tmp_path):
    batch, _, _ = _sealed(tmp_path)
    with pytest.raises(P.NotDue):
        P.check(batch, lookup=_judge({}), now=lambda: T0 + timedelta(days=3), pause_s=0)
    path = P.check(batch, early=True, lookup=_judge({}), now=lambda: T0 + timedelta(days=3), pause_s=0)
    assert json.loads(path.read_text())["early"] is True


def test_a_manifest_edited_after_sealing_is_refused(tmp_path):
    batch, _, _ = _sealed(tmp_path)
    m = json.loads((batch / "manifest.json").read_text())
    m["claims"]["P1"].append({"type": "domain", "value": "late.example", "arms": ["bounce"],
                              "malicious": {"bounce": True}})
    (batch / "manifest.json").write_text(json.dumps(m))
    with pytest.raises(PermissionError):
        P.check(batch, lookup=_judge({}), now=lambda: T0 + timedelta(days=15), pause_s=0)
    assert P.main(["score", "--batch", str(batch)]) == P.EXIT_TAMPERED


def test_score_classes_and_pooled_recall(tmp_path):
    batch, _, _ = _sealed(tmp_path)
    later = {"domain|old.example": LISTED, "domain|c2a.example": LISTED,
             "domain|c2b.example": LISTED, "domain|c2c.example": FAILED, "ip|198.51.100.4": WHITELISTED}
    P.check(batch, lookup=_judge(later), now=lambda: T0 + timedelta(days=14), pause_s=0)
    manifest = P.load_manifest(batch)
    r = P.score(manifest, P.load_check(batch, P.latest_check(batch)))
    b, w = r["arms"]["bounce"], r["arms"]["web"]
    assert (b["claims"], b["known"], b["ahead"], b["benign"], b["undetermined"]) == (4, 1, 2, 1, 0)
    assert (w["claims"], w["ahead"], w["undetermined"]) == (2, 1, 1)
    # P1's pool = {c2a, c2b} (c2c undetermined); P2's pool is empty.
    assert r["pool"] == 2
    assert b["pooled_recall"] == 100.0 and w["pooled_recall"] == 50.0
    assert b["ahead_malicious"] == 1 and w["ahead_malicious"] == 1
    assert b["ahead_share"] == 100.0 and w["ahead_share"] == 100.0
    assert r["seeds"]["P2"]["arms"]["bounce"]["pooled_recall"] is None
    assert r["provisional"] is False
    md = P.render_md(r)
    assert "| bounce | 4 | 1 | 2 | 0 | 1 | 0 | 100.0 | 100.0 |" in md
    assert "Provisional" not in md
    # results.json and results.md are meant for the repo: counts, never a value.
    for v in ("c2a.example", "c2b.example", "198.51.100.4", "203.0.113.7", "seed2.example"):
        assert v not in json.dumps(r) and v not in md


def test_an_early_check_scores_provisional(tmp_path):
    batch, _, _ = _sealed(tmp_path)
    P.check(batch, early=True, lookup=_judge({}), now=lambda: T0 + timedelta(days=5), pause_s=0)
    r = P.score(P.load_manifest(batch), P.load_check(batch, P.latest_check(batch)))
    assert r["provisional"] is True and "Provisional" in P.render_md(r)


def test_a_check_of_another_batch_is_refused(tmp_path):
    batch, _, _ = _sealed(tmp_path / "a")
    other, _, _ = _sealed(tmp_path / "b", at_t={"domain|old.example": UNLISTED})
    path = P.check(other, lookup=_judge({}), now=lambda: T0 + timedelta(days=15), pause_s=0)
    with pytest.raises(PermissionError):
        P.load_check(batch, path)


def test_the_committed_copy_is_what_proves_the_pre_registration(tmp_path, monkeypatch):
    batch, _, _ = _sealed(tmp_path / "w")
    repo = tmp_path / "repo-eval-prospective"
    monkeypatch.setattr(P, "COMMITTED_DIR", repo)
    (repo / batch.name).mkdir(parents=True)
    (repo / batch.name / "commitment.json").write_text((batch / "commitment.json").read_text())
    P.load_manifest(batch)  # same manifest: fine
    # Rewrite the manifest AND the batch's own commitment: only the committed copy catches it.
    m = json.loads((batch / "manifest.json").read_text())
    m["horizon_days"] = 1
    P._dump(batch / "manifest.json", m)
    c = json.loads((batch / "commitment.json").read_text())
    c["manifest_sha256"] = P._sha256(batch / "manifest.json")
    P._dump(batch / "commitment.json", c)
    with pytest.raises(PermissionError, match="names"):
        P.load_manifest(batch)


def test_results_say_whether_the_committed_copy_was_found(tmp_path, monkeypatch):
    batch, _, _ = _sealed(tmp_path)
    monkeypatch.setattr(P, "COMMITTED_DIR", tmp_path / "nowhere")
    monkeypatch.setattr(P, "utcnow", lambda: T0 + timedelta(days=15))
    P.check(batch, lookup=_judge({}), pause_s=0)
    assert P.main(["score", "--batch", str(batch), "--write"]) == 0
    assert "No committed" in (batch / "results.md").read_text()
    (tmp_path / "nowhere" / batch.name).mkdir(parents=True)
    (tmp_path / "nowhere" / batch.name / "commitment.json").write_text((batch / "commitment.json").read_text())
    assert P.main(["score", "--batch", str(batch), "--write"]) == 0
    assert "Manifest checked against the committed" in (batch / "results.md").read_text()


def test_a_label_that_would_leave_its_directory_is_refused(tmp_path):
    batch = tmp_path / "b"
    batch.mkdir()
    for bad in ("../x", "P1\n"):
        (batch / "seeds.json").write_text(json.dumps([dict(SEEDS[0], label=bad)]))
        with pytest.raises(ValueError, match="letters"):
            P.load_seeds(batch)
        with pytest.raises(ValueError, match="letters"):
            _load("baseline").load_seeds(batch / "seeds.json")


def test_cli_exit_codes(tmp_path, monkeypatch):
    batch, _, _ = _sealed(tmp_path)
    monkeypatch.setattr(P, "utcnow", lambda: T0 + timedelta(days=1))
    assert P.main(["check", "--batch", str(batch)]) == P.EXIT_NOT_DUE
    assert P.main(["score", "--batch", str(batch)]) == P.EXIT_USAGE  # no check yet
    assert P.main(["seal", "--batch", str(batch), "--arm", "nodir"]) == P.EXIT_USAGE


# ── baseline.py runs a prospective batch ──────────────────────────────────

def test_baseline_runs_the_seeds_of_a_batch(tmp_path):
    B = _load("baseline")
    f = tmp_path / "seeds.json"
    f.write_text(json.dumps(SEEDS))
    seeds = B.load_seeds(f)
    case, negative, dname = B.case_for("P2", seeds)
    assert (case["seed_type"], case["seed_value"], negative, dname) == ("domain", "seed2.example", False, "P2")
    assert "seed2.example" in B.build_prompt(case, "web")
    assert B.case_for("2", seeds)[2] == "c02"          # the fixed cases are still there
    f.write_text(json.dumps([{"label": "P9", "seed_type": "ip"}]))
    with pytest.raises(ValueError):
        B.load_seeds(f)


# ── judge v2: through the server, with a positive control ─────────────────

def _v2(state, *, sections=None, whitelist=()):
    """A judge v2 answer: ``sections`` maps a section to (state, [(author, created)])."""
    secs = {}
    for name, (st, entries) in (sections or {}).items():
        secs[name] = {"state": st, "count": len(entries), "whitelist": [],
                      "entries": [{"id": f"{name}-{i}", "author": a, "created": c}
                                  for i, (a, c) in enumerate(entries)]}
    return {"state": state, "count": 0, "whitelist": list(whitelist), "sections": secs}


TF_SEEDS = [dict(SEEDS[0], source="threatfox:1601", reporter="tf-reporter", family="win.asyncrat"),
            dict(SEEDS[1], source="threatfox:1602", reporter="tf-reporter", family="win.remcos")]
SEEN_BY_TF = _v2("listed", sections={"otx": ("unlisted", []), "threatfox": ("listed", [("tf-reporter", None)])})
NOT_SEEN = _v2("unlisted", sections={"otx": ("unlisted", []), "threatfox": ("unlisted", [])})


def _v2_batch(tmp_path):
    batch, dirs = _batch(tmp_path, ARMS)
    (batch / "seeds.json").write_text(json.dumps(TF_SEEDS))
    return batch, dirs


def _lookup_all(table):
    calls = []

    def lookup_all(keys):
        calls.append(sorted(keys))
        return {k: table.get(k, NOT_SEEN) for k in keys}
    lookup_all.calls = calls
    return lookup_all


SEEDS_SEEN = {"ip|203.0.113.7": SEEN_BY_TF, "domain|seed2.example": SEEN_BY_TF}


def test_a_judge_blind_to_the_seeds_own_feed_seals_nothing(tmp_path):
    batch, dirs = _v2_batch(tmp_path)
    blind = {"ip|203.0.113.7": SEEN_BY_TF}  # P2's own feed answers unlisted
    with pytest.raises(P.JudgeUnavailable, match="P2: picked from threatfox, which answers unlisted"):
        P.seal(batch, dirs, 14, judge=P.JUDGE_V2, lookup_all=_lookup_all(blind), now=lambda: T0)
    assert not (batch / "manifest.json").exists()
    c = P.seal(batch, dirs, 14, judge=P.JUDGE_V2, lookup_all=_lookup_all(SEEDS_SEEN), now=lambda: T0)
    assert c["judge"] == P.JUDGE_V2
    # Judge v1 has no control: OTX alone may well not list a seed hours old.
    batch1, dirs1 = _batch(tmp_path / "v1", ARMS)
    (batch1 / "seeds.json").write_text(json.dumps(TF_SEEDS))
    P.seal(batch1, dirs1, 14, lookup=_judge({}), now=lambda: T0, pause_s=0)


def test_preflight_judges_the_seeds_alone(tmp_path):
    batch, _ = _v2_batch(tmp_path)
    la = _lookup_all({"ip|203.0.113.7": SEEN_BY_TF})
    res = P.preflight(batch, lookup_all=la)
    assert la.calls == [["domain|seed2.example", "ip|203.0.113.7"]]
    assert res["blind"] == ["P2: picked from threatfox, which answers unlisted"]
    assert res["seeds"]["P1"] == {"otx": "unlisted", "threatfox": "listed"}
    assert P.preflight(batch, lookup_all=_lookup_all(SEEDS_SEEN))["blind"] == []


def test_the_secondary_horizon_is_sealed_with_the_primary(tmp_path):
    batch, dirs = _batch(tmp_path, ARMS)
    c = P.seal(batch, dirs, 14, lookup=_judge({}), now=lambda: T0, pause_s=0)
    assert (c["secondary_horizon_days"], c["secondary_due_at"]) == (30, "2026-11-25T20:00:00Z")
    with pytest.raises(P.NotDue, match="2026-11-25"):
        P.check(batch, secondary=True, lookup=_judge({}), now=lambda: T0 + timedelta(days=20), pause_s=0)
    path = P.check(batch, lookup=_judge({}), now=lambda: T0 + timedelta(days=20), pause_s=0)
    assert json.loads(path.read_text())["horizon"] == "primary"
    path = P.check(batch, secondary=True, lookup=_judge({}), now=lambda: T0 + timedelta(days=31), pause_s=0)
    r = P.score(P.load_manifest(batch), P.load_check(batch, path))
    assert r["horizon_reached"] == "secondary" and "secondary horizon (30 days)" in P.render_md(r)
    for bad in (14, 7):
        b2, d2 = _batch(tmp_path / f"s{bad}", ARMS)
        with pytest.raises(ValueError, match="secondary"):
            P.seal(b2, d2, 14, secondary_days=bad, lookup=_judge({}), now=lambda: T0, pause_s=0)
    b3, d3 = _batch(tmp_path / "none", ARMS)
    assert P.seal(b3, d3, 14, secondary_days=0, lookup=_judge({}), now=lambda: T0,
                  pause_s=0)["secondary_due_at"] is None
    with pytest.raises(ValueError, match="no secondary"):
        P.check(b3, secondary=True, lookup=_judge({}), now=lambda: T0 + timedelta(days=40), pause_s=0)


def test_a_batch_is_checked_by_the_judge_that_sealed_it(tmp_path):
    batch, dirs = _v2_batch(tmp_path)
    P.seal(batch, dirs, 14, judge=P.JUDGE_V2, lookup_all=_lookup_all(SEEDS_SEEN), now=lambda: T0)
    with pytest.raises(ValueError, match="same judge"):
        P.check(batch, lookup=_judge({}), now=lambda: T0 + timedelta(days=15), pause_s=0)


def test_score_v2_says_who_confirmed_ahead_and_when(tmp_path):
    batch, dirs = _v2_batch(tmp_path)
    P.seal(batch, dirs, 14, judge=P.JUDGE_V2, lookup_all=_lookup_all(SEEDS_SEEN), now=lambda: T0)
    later = dict(SEEDS_SEEN)
    # c2a: confirmed by the seed's own reporter in the seed's own feed only (not independent), 1 day on.
    later["domain|c2a.example"] = _v2("listed", sections={
        "otx": ("unlisted", []), "threatfox": ("listed", [("tf-reporter", "2026-10-27T20:00:00Z")])})
    # c2b: an OTX pulse by someone else, 10 days on: independent.
    later["domain|c2b.example"] = _v2("listed", sections={
        "otx": ("listed", [("analyst", "2026-11-05T20:00:00Z")]), "threatfox": ("unlisted", [])})
    # old: another author, but in the seed's own feed: not independent either.
    later["domain|old.example"] = _v2("listed", sections={
        "otx": ("unlisted", []), "threatfox": ("listed", [("other-reporter", "2026-10-29T20:00:00Z")])})
    # c2c: the seed's reporter again, but in another feed: still not independent.
    later["domain|c2c.example"] = _v2("listed", sections={
        "urlhaus": ("listed", [("tf-reporter", "2026-10-28T08:00:00Z")]), "threatfox": ("unlisted", [])})
    path = P.check(batch, judge=P.JUDGE_V2, lookup_all=_lookup_all(later), now=lambda: T0 + timedelta(days=14))
    r = P.score(P.load_manifest(batch), P.load_check(batch, path))
    b, w = r["arms"]["bounce"], r["arms"]["web"]
    assert (b["ahead"], b["ahead_independent"]) == (3, 1)            # c2a, c2b, old; only c2b
    assert b["ahead_by_section"] == {"otx": 1, "threatfox": 2}
    assert b["ahead_delays_days"] == [1.0, 3.0, 10.0]
    assert (w["ahead"], w["ahead_independent"], w["ahead_delays_days"]) == (2, 0, [1.0, 1.5])  # c2a, c2c
    md = P.render_md(r)
    assert "| bounce | 3 | 1 | otx 1, threatfox 2 | 3.0 |" in md
    for v in ("c2a.example", "c2b.example", "tf-reporter", "other-reporter", "analyst", "203.0.113.7"):
        assert v not in json.dumps(r) and v not in md


def test_server_lookups_go_by_chunks_and_a_failed_chunk_is_an_error(monkeypatch):
    sent = []

    def call(base, path, *, opener, body=None, timeout=600):
        sent.append((path, [c["value"] for c in body["claims"]]))
        if len(sent) == 2:
            raise urllib.error.HTTPError(base + path, 502, "bad gateway", {}, None)
        return {"judge": P.JUDGE_V2,
                "lookups": {f"{c['type']}|{c['value']}": SEEN_BY_TF for c in body["claims"]}}
    monkeypatch.setattr(P, "server_call", call)
    keys = [f"domain|d{i}.example" for i in range(5)]
    out = P.server_lookup_all(keys, base="https://srv", opener=None, chunk=2)
    assert [len(v) for _, v in sent] == [2, 2, 1] and {p for p, _ in sent} == {"/api/admin/eval/judge"}
    assert [out[k]["state"] for k in sorted(keys)] == ["listed", "listed", "error", "error", "listed"]
    assert out["domain|d2.example"]["error"] == "server: HTTP 502"
    monkeypatch.setattr(P, "server_call", lambda *a, **k: {"judge": "otx-pulses/1", "lookups": {}})
    with pytest.raises(ValueError, match="expected"):
        P.server_lookup_all(keys, base="https://srv", opener=None)


def _fresh(*cands, fetched="2026-10-26T18:00:00Z"):
    return {"fetched_at": fetched, "count": len(cands), "candidates": [
        {"seed_type": "domain", "seed_value": v, "first_seen": t, "family": fam, "reporter": "r",
         "source": f"threatfox:{i}", "excluded_by": ex} for i, (v, t, fam, ex) in enumerate(cands)]}


def test_pick_is_mechanical_one_per_family_newest_first():
    fresh = _fresh(("a1.example", "2026-10-26T10:00:00Z", "win.a", []),
                   ("a2.example", "2026-10-26T12:00:00Z", "win.a", []),
                   ("b1.example", "2026-10-26T11:00:00Z", "win.b", []),
                   ("c1.example", "2026-10-26T17:00:00Z", "win.c", ["no family tag"]),
                   ("d1.example", "2026-10-26T09:00:00Z", "win.d", []),
                   ("e1.example", "2026-10-26T16:00:00Z", None, []))
    seeds = P.pick(fresh, 2)
    assert [(s["label"], s["seed_value"], s["family"]) for s in seeds] == [
        ("P1", "a2.example", "win.a"), ("P2", "b1.example", "win.b")]
    assert seeds[0]["picked"] == "pick/1 from fresh_iocs fetched 2026-10-26T18:00:00Z"
    assert P.pick(fresh, 2) == seeds                                    # same answer, same seeds
    assert [s["family"] for s in P.pick(fresh, 5, {"win.a"})] == ["win.b", "win.d"]
    for s in seeds:  # a picked seed is a valid seeds.json entry
        assert all(s.get(k) for k in ("label", "seed_type", "seed_value", "first_seen", "source"))


def test_seeds_are_picked_once(tmp_path, monkeypatch):
    batch = tmp_path / "lot1"
    jar = tmp_path / "cookies.txt"
    jar.write_text("# Netscape HTTP Cookie File\n")
    fresh = _fresh(("a1.example", "2026-10-26T10:00:00Z", "win.a", []))
    monkeypatch.setattr(P, "server_call", lambda *a, **k: fresh)
    args = ["seeds", "--batch", str(batch), "--server", "https://srv", "--cookies", str(jar), "--n", "3"]
    assert P.main(args) == 0
    assert [s["seed_value"] for s in json.loads((batch / "seeds.json").read_text())] == ["a1.example"]
    assert json.loads((batch / "fresh_iocs.json").read_text()) == fresh
    assert P.main(args) == P.EXIT_USAGE          # picking again after seeing them is choosing
    assert P.main(["preflight", "--batch", str(batch)]) == P.EXIT_USAGE   # needs --server
    lot2 = tmp_path / "lot2"
    assert P.main(["seeds", "--batch", str(lot2), "--server", "https://srv", "--cookies", str(jar),
                   "--avoid", str(batch / "seeds.json")]) == P.EXIT_USAGE  # its only family is taken
    assert not lot2.exists()  # a failed pick writes nothing: no fresh_iocs.json, no seeds.json


# ── the control reads an unseen seed by id (the 2026-10-27 canary) ─────────

def _present(eid, ioc, itype, *, wildcard="unlisted", exact="unlisted"):
    return {"state": "present", "id": eid, "ioc": ioc, "ioc_type": itype,
            "first_seen": "2026-10-26T19:00:00Z", "search": {"wildcard": wildcard, "exact": exact}}


def _lookup_entries(table):
    calls = []

    def lookup_entries(refs):
        calls.append(sorted(refs))
        return {r: table.get(r, {"state": "error", "error": "server: HTTP 502"}) for r in refs}
    lookup_entries.calls = calls
    return lookup_entries


CANARY = [{"label": f"P{i}", "seed_type": t, "seed_value": v, "first_seen": "2026-10-26T19:00:00Z",
           "source": f"threatfox:{1600 + i}", "reporter": "r", "family": f"f{i}"}
          for i, (t, v) in enumerate([("hash", "a" * 64), ("hash", "b" * 64), ("domain", "late.example"),
                                      ("domain", "seen.example")], start=1)]


def _canary_batch(tmp_path, seeds=CANARY):
    batch = tmp_path / "canary"
    batch.mkdir(parents=True)
    (batch / "seeds.json").write_text(json.dumps(seeds))
    return batch


def test_a_seed_in_its_feed_that_the_search_misses_is_late_not_blind(tmp_path):
    # 2026-10-27: ThreatFox's search returned 3 of 6 seeds picked from it an hour earlier.
    batch = _canary_batch(tmp_path)
    seen = {"hash|" + "a" * 64: SEEN_BY_TF, "domain|seen.example": SEEN_BY_TF}
    le = _lookup_entries({"threatfox:1602": _present("1602", "B" * 64, "sha256_hash", exact="listed"),
                          "threatfox:1603": _present("1603", "Late.Example.", "domain")})
    res = P.preflight(batch, lookup_all=_lookup_all(seen), lookup_entries=le)
    assert res["blind"] == [] and le.calls == [["threatfox:1602", "threatfox:1603"]]  # the unseen only
    assert set(res["late"]) == {"P2", "P3"}
    assert res["late"]["P2"] == {"entry": "1602", "first_seen": "2026-10-26T19:00:00Z",
                                 "search": {"wildcard": "unlisted", "exact": "listed"}}
    # Without the entries (none asked), the same answers are a refusal, as before.
    assert P.preflight(batch, lookup_all=_lookup_all(seen))["blind"] == [
        "P2: picked from threatfox, which answers unlisted", "P3: picked from threatfox, which answers unlisted"]
    # Every seed seen: nothing is read by id.
    le = _lookup_entries({})
    assert P.preflight(batch, lookup_all=_lookup_all({_k: SEEN_BY_TF for _k in (
        "hash|" + "a" * 64, "hash|" + "b" * 64, "domain|late.example", "domain|seen.example")}),
        lookup_entries=le)["late"] == {} and le.calls == []


@pytest.mark.parametrize("entry, why", [
    ({"state": "not_present", "id": "1602", "status": "no_result"}, "is no longer in the feed (query_status 'no_result')"),
    (_present("1602", "c" * 64, "sha256_hash"), "holds another value than the seed as picked"),
    ({"state": "error", "error": "query_status 'illegal_id'"}, "could not be read (query_status 'illegal_id')"),
    (None, "could not be read (server: HTTP 502)"),
])
def test_a_seed_gone_from_its_feed_or_read_otherwise_is_a_refusal(tmp_path, entry, why):
    batch = _canary_batch(tmp_path, CANARY[:2])
    res = P.preflight(batch, lookup_all=_lookup_all({"hash|" + "a" * 64: SEEN_BY_TF}),
                      lookup_entries=_lookup_entries({"threatfox:1602": entry} if entry else {}))
    assert len(res["blind"]) == 1 and res["late"] == {}
    assert res["blind"][0].startswith("P2: picked from threatfox, which answers unlisted; its entry 1602 ")
    assert why in res["blind"][0]


def test_a_search_that_returns_none_of_its_seeds_is_not_trusted(tmp_path):
    batch = _canary_batch(tmp_path, CANARY[:2])
    le = _lookup_entries({"threatfox:1601": _present("1601", "a" * 64, "sha256_hash"),
                          "threatfox:1602": _present("1602", "b" * 64, "sha256_hash")})
    res = P.preflight(batch, lookup_all=_lookup_all({}), lookup_entries=le)
    assert res["blind"] == ["threatfox: its search returns none of the seeds picked from it, so its "
                            "silence proves nothing yet; run preflight again in an hour"]


def test_an_ip_seed_is_the_host_of_its_entry(tmp_path):
    batch, _ = _v2_batch(tmp_path)
    p2 = {"domain|seed2.example": SEEN_BY_TF}
    le = _lookup_entries({"threatfox:1601": _present("1601", "203.0.113.7:443", "ip:port")})
    res = P.preflight(batch, lookup_all=_lookup_all(p2), lookup_entries=le)
    assert res["blind"] == [] and set(res["late"]) == {"P1"}
    le = _lookup_entries({"threatfox:1601": _present("1601", "203.0.113.70:443", "ip:port")})
    assert "another value" in P.preflight(batch, lookup_all=_lookup_all(p2), lookup_entries=le)["blind"][0]


def test_seal_records_the_late_seeds_and_the_check_is_strict(tmp_path):
    batch, dirs = _v2_batch(tmp_path)
    at_t = {"domain|seed2.example": SEEN_BY_TF}
    le = _lookup_entries({"threatfox:1601": _present("1601", "203.0.113.7:443", "ip:port")})
    c = P.seal(batch, dirs, 14, judge=P.JUDGE_V2, lookup_all=_lookup_all(at_t), lookup_entries=le,
               now=lambda: T0)
    assert c["seeds_late_at_t"] == 1 and "203.0.113.7" not in (batch / "commitment.json").read_text()
    manifest = P.load_manifest(batch)
    assert manifest["control_at_t"]["late"]["P1"]["entry"] == "1601"
    # A horizon on, the search still misses P1 while its entry is there: a blind search, not scored.
    path = P.check(batch, judge=P.JUDGE_V2, lookup_all=_lookup_all(at_t), lookup_entries=le,
                   now=lambda: T0 + timedelta(days=14))
    doc = P.load_check(batch, path)
    assert doc["control"]["blind"] == ["P1: picked from threatfox, which answers unlisted; its entry 1601 "
                                       "is still in the feed (search wildcard unlisted, exact unlisted): "
                                       "the search is blind"]
    with pytest.raises(P.JudgeUnavailable, match="Check again later"):
        P.score(manifest, doc)
    # The feed withdrew P1 since the seal: reported, and the batch is scored.
    gone = _lookup_entries({"threatfox:1601": {"state": "not_present", "id": "1601", "status": "no_result"}})
    path = P.check(batch, judge=P.JUDGE_V2, lookup_all=_lookup_all(at_t), lookup_entries=gone,
                   now=lambda: T0 + timedelta(days=15))
    r = P.score(manifest, P.load_check(batch, path))
    assert r["seeds_withdrawn"] == ["P1"] and "withdrew after the seal: P1" in P.render_md(r)
    # Returned by the search at last: scored, nothing withdrawn, nothing read by id.
    le = _lookup_entries({})
    path = P.check(batch, judge=P.JUDGE_V2, lookup_all=_lookup_all(SEEDS_SEEN), lookup_entries=le,
                   now=lambda: T0 + timedelta(days=16))
    doc = P.load_check(batch, path)
    assert P.score(manifest, doc)["seeds_withdrawn"] == [] and le.calls == []
    # A judge v2 check without its control (an older prospective.py) is not scored.
    doc.pop("control")
    with pytest.raises(ValueError, match="no positive control"):
        P.score(manifest, doc)


def test_cli_check_exits_4_on_a_blind_search(tmp_path, monkeypatch):
    batch, dirs = _v2_batch(tmp_path)
    P.seal(batch, dirs, 14, judge=P.JUDGE_V2, lookup_all=_lookup_all(SEEDS_SEEN), now=lambda: T0)
    jar = tmp_path / "cookies.txt"
    jar.write_text("# Netscape HTTP Cookie File\n")

    def call(base, path, *, opener, body=None, timeout=600):
        if body.get("entries"):
            return {"judge": P.JUDGE_V2, "lookups": {},
                    "entries": {r: _present(r.split(":")[1], "seed2.example", "domain") for r in body["entries"]}}
        return {"judge": P.JUDGE_V2, "lookups": {f"{c['type']}|{c['value']}": SEEN_BY_TF if c["type"] == "ip"
                                                 else NOT_SEEN for c in body["claims"]}}
    monkeypatch.setattr(P, "server_call", call)
    monkeypatch.setattr(P, "utcnow", lambda: T0 + timedelta(days=14))
    args = ["check", "--batch", str(batch), "--server", "https://srv", "--cookies", str(jar)]
    assert P.main(args) == P.EXIT_JUDGE
    assert P.main(["score", "--batch", str(batch)]) == P.EXIT_JUDGE


def test_a_claim_the_feed_dated_before_the_seal_is_known_not_ahead(tmp_path):
    batch, dirs = _v2_batch(tmp_path)
    P.seal(batch, dirs, 14, judge=P.JUDGE_V2, lookup_all=_lookup_all(SEEDS_SEEN), now=lambda: T0)
    later = dict(SEEDS_SEEN)
    before, after = "2026-10-26T19:30:00Z", "2026-10-27T08:00:00Z"      # T0 = 2026-10-26T20:00Z
    # c2a: a ThreatFox entry from before the seal, which the search did not return at T.
    later["domain|c2a.example"] = _v2("listed", sections={
        "otx": ("unlisted", []), "threatfox": ("listed", [("x", before)])})
    # c2b: URLhaus, a URL of the host added before the seal.
    later["domain|c2b.example"] = _v2("listed", sections={
        "otx": ("unlisted", []), "urlhaus": ("listed", [("y", before)])})
    # c2c: an OTX pulse created before the seal. A pulse's date is not the indicator's: still ahead.
    later["domain|c2c.example"] = _v2("listed", sections={
        "otx": ("listed", [("z", before)]), "threatfox": ("unlisted", [])})
    # old: listed after the seal: ahead.
    later["domain|old.example"] = _v2("listed", sections={
        "otx": ("unlisted", []), "threatfox": ("listed", [("x", after)])})
    path = P.check(batch, judge=P.JUDGE_V2, lookup_all=_lookup_all(later), now=lambda: T0 + timedelta(days=14))
    r = P.score(P.load_manifest(batch), P.load_check(batch, path))
    b, w = r["arms"]["bounce"], r["arms"]["web"]
    assert (b["known"], b["known_late"], b["ahead"], b["unconfirmed"]) == (2, 2, 1, 1)   # c2a c2b | old | P2's ip
    assert (w["known"], w["known_late"], w["ahead"]) == (1, 1, 1)                        # c2a | c2c
    assert b["ahead_by_section"] == {"threatfox": 1} and w["ahead_by_section"] == {"otx": 1}
    assert "bounce 2, web 1." in P.render_md(r)
    # The rule needs the seal's time: without it (judge v1), dates are not read.
    assert P.classify(NOT_SEEN, later["domain|c2a.example"]) == "ahead"
    assert P.classify(NOT_SEEN, later["domain|c2a.example"], T0) == "known"
    assert P.classify(NOT_SEEN, later["domain|c2c.example"], T0) == "ahead"


def test_server_entries_ask_the_judge_route_and_fail_closed(monkeypatch):
    sent = []

    def call(base, path, *, opener, body=None, timeout=600):
        sent.append((path, body))
        if len(sent) == 2:
            raise urllib.error.HTTPError(base + path, 502, "bad gateway", {}, None)
        first = body["entries"][0]
        return {"judge": P.JUDGE_V2, "lookups": {},
                "entries": {first: {"state": "not_present", "id": first.split(":")[1], "status": "no_result"}}}
    monkeypatch.setattr(P, "server_call", call)
    refs = sorted(f"threatfox:{i}" for i in range(P.MAX_ENTRIES_PER_REQUEST + 2))
    out = P.server_entries(refs + refs[:3], base="https://srv", opener=None)
    assert [len(b["entries"]) for _, b in sent] == [P.MAX_ENTRIES_PER_REQUEST, 2]
    assert {p for p, _ in sent} == {"/api/admin/eval/judge"} and all(b["claims"] == [] for _, b in sent)
    assert out[refs[0]]["state"] == "not_present"
    assert out[refs[1]]["error"] == "server: no entry lookup (an older server?)"
    assert out[refs[-1]]["error"] == "server: HTTP 502"


def test_cli_preflight_reads_unseen_seeds_by_id(tmp_path, monkeypatch, capsys):
    batch, _ = _v2_batch(tmp_path)
    jar = tmp_path / "cookies.txt"
    jar.write_text("# Netscape HTTP Cookie File\n")

    def call(base, path, *, opener, body=None, timeout=600):
        if body.get("entries"):
            return {"judge": P.JUDGE_V2, "lookups": {}, "entries": {
                "threatfox:1601": _present("1601", "203.0.113.7:443", "ip:port", exact="listed")}}
        return {"judge": P.JUDGE_V2, "lookups": {f"{c['type']}|{c['value']}": SEEN_BY_TF if c["type"] == "domain"
                                                 else NOT_SEEN for c in body["claims"]}}
    monkeypatch.setattr(P, "server_call", call)
    assert P.main(["preflight", "--batch", str(batch), "--server", "https://srv", "--cookies", str(jar)]) == 0
    out = capsys.readouterr().out
    assert "P1: entry 1601 is in the feed, its search does not return it yet (wildcard unlisted, exact listed)" in out
    assert "some by id only" in out
