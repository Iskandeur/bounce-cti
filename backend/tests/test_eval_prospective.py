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
    assert r == {"state": "listed", "count": 2, "pulses": ["a", "b"], "whitelist": []}
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
