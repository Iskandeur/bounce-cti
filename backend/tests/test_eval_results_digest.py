"""Tests for eval/results_digest.py — the published EVAL_RESULTS.md.

The digest is what a reader of the repo sees first about agent quality, so it
must (a) parse both rubric generations correctly, (b) never compare runs that
did not score the same cases, and (c) stay in sync with runs/ — a new run
committed without regenerating the page fails this suite.
"""
import importlib.util
import sys
from pathlib import Path

# eval/ is a script folder, not a package: load the module by path. It must be
# registered in sys.modules before exec, or @dataclass cannot resolve it.
_PATH = Path(__file__).resolve().parents[2] / "eval" / "results_digest.py"
_spec = importlib.util.spec_from_file_location("results_digest", _PATH)
rd = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = rd
_spec.loader.exec_module(rd)


V2_CARD = """# EVAL_PROTOCOL Scorecard — 2026-05-28 · commit ccee7e3

**Run environment**
- Model: `opus-4.7` (only model whitelisted on the eval account)

| Case | Status | NR   | ER   | PC   | DC  | BD  | RQ  | Overall | Calls | Hypothesis path |
|-----:|:------:|-----:|-----:|-----:|----:|----:|----:|--------:|------:|:----------------|
|  1 | done | 46.7 |   0.0 | 50.0 | 100 | 100 |  40 |  56.1 |    4 | Y |
|  2 | done | 55.6 |   0.0 | 75.0 | 100 | 100 |  40 |  **61.8** |   48 | Y |
|  3 | done | 47.1 |  66.7 | 100.0 | 100 |   0 |  70 |  64.0 |  115 | Y |
|  5 | quota-blocked |  7.7 |   0.0 | 25.0 | 100 | 100 |   0 |  38.8 |    4 | absent |
|  8 | done | 50.0 |  33.3 | 75.0 | 100 |  75 |  70 |  67.2 |   86 | Y |
|  9 | done | 50.0 | 100.0 | 75.0 | 100 |   0 |  40 |  60.8 |  127 | Y |
| 12 | done | 62.5 | 100.0 | 100.0 | 100 |   0 |  70 |  72.1 |   94 | Y |

## Aggregate metrics

| Metric | Target | This run |
|---|---|---|
| Overall (mean) | ≥ 65 | 60.5 |
"""

V3_CARD = """# EVAL_PROTOCOL Scorecard — 2026-06-17 · commit 71e5fb1

- Model: `opus-4.8` (eval account model for this nightly run)

## Capability scorecard (v3 — headline, decay-proof)

| Case | live | CAP | ΔCAP | PS | EFF | RST | HYP | REC | NR | MK |
|-----:|:----:|----:|-----:|---:|----:|----:|----:|----:|---:|---:|
| 1 | ERR | – | – | – | – | – | – | – | – | – |
| 2 | live | 100.0 | +0.0 | 100 | 100 | 100 | 100 | 65.2 | 64 | 100 |
| 9 | DECAY | 90.0 | +0.0 | 75 | 100 | 100 | 100 | n/a | 50 | 0 |
| N1 | – | 100 | – | – | – | 100 | – | – | – | – |

## Scorecard (v2 legacy track — context only)

| Case | Status | NR   | ER   | PC   | DC  | BD  | RQ  | Overall | Calls | Hypothesis path |
|-----:|:------:|-----:|-----:|-----:|----:|----:|----:|--------:|------:|:----------------|
|  1 | ERR | – | – | – | – | – | – | – | – | – |
|  2 | done | 63.6 |  33.3 | 100.0 | 100 | 100 |  70 |  77.8 |   24 | Y |
"""

BLOCKED_CARD = """# EVAL_PROTOCOL Scorecard — 2026-06-17 · commit 90c516b

> **RUN STATUS: BLOCKED — no cases completed.**
"""


def test_v2_table_parsed_and_unfinished_cases_dropped():
    run = rd.parse_scorecard("2026-05-28_ccee7e3", V2_CARD)
    assert (run.date, run.commit, run.model) == ("2026-05-28", "ccee7e3", "opus-4.7")
    done = run.v2_done()
    assert done[2] == 61.8          # bold markup stripped
    assert 5 not in done            # quota-blocked is not a completed case
    assert not run.v3 and not run.blocked


def test_aggregate_table_is_not_mistaken_for_a_case_table():
    run = rd.parse_scorecard("x", V2_CARD)
    assert {r.case for r in run.v2} == {"1", "2", "3", "5", "8", "9", "12"}


def test_v3_cap_separates_positive_and_negative_cases():
    run = rd.parse_scorecard("2026-06-17_71e5fb1", V3_CARD)
    assert run.v3_positive() == {2: 100.0, 9: 90.0}   # ERR row has no score
    assert run.v3_negative() == {"N1": 100.0}
    assert run.v2_done() == {2: 77.8}                  # legacy track still read


def test_blocked_run_is_flagged_not_scored():
    run = rd.parse_scorecard("2026-06-17_90c516b", BLOCKED_CARD)
    assert run.blocked
    assert run.v2_done() == {} and rd.subset_mean(run) is None


def test_unrecognised_scorecard_raises_instead_of_reading_as_an_outage():
    # Even with the bare word BLOCKED somewhere in a note: only the status
    # line marks a blocked run.
    renamed = V2_CARD.replace("Overall", "Total") + "\nCase 5 was BLOCKED by quota.\n"
    try:
        rd.parse_scorecard("2026-07-01_deadbee", renamed)
    except ValueError as exc:
        assert "not recognised" in str(exc)
    else:
        raise AssertionError("a scorecard with no known table must not be silently 'blocked'")


def test_subset_mean_requires_all_five_cases():
    full = rd.parse_scorecard("a", V2_CARD)
    assert rd.subset_mean(full) == round((61.8 + 64.0 + 67.2 + 60.8 + 72.1) / 5, 1)
    partial = rd.parse_scorecard("b", V3_CARD)   # only case 2 completed
    assert rd.subset_mean(partial) is None


def test_render_never_puts_a_partial_run_in_the_trend_table():
    runs = [rd.parse_scorecard("2026-05-28_ccee7e3", V2_CARD),
            rd.parse_scorecard("2026-06-17_71e5fb1", V3_CARD),
            rd.parse_scorecard("2026-06-17_90c516b", BLOCKED_CARD)]
    page = rd.render(runs)
    trend = page.split("## Like-for-like trend")[1].split("##")[0]
    assert "ccee7e3" in trend and "71e5fb1" not in trend
    assert "blocked — see scorecard" in page


BASELINE_DOC = {
    "meta": {"date": "2026-10-21", "models": {"bounce": ["claude-opus-5"],
                                              "web": ["claude-opus-5"], "memory": ["claude-opus-5"]}},
    "sides": {
        "bounce": {"2": {"nr": 60.0, "rec_ungated": 55.0, "actor_hit": True, "hallucinations": []},
                   "3": {"nr": 40.0, "rec_ungated": 45.0, "actor_hit": True, "hallucinations": []},
                   "N1": {"rst": 100}},
        "web": {"2": {"nr": 80.0, "rec_ungated": 70.0, "actor_hit": True, "hallucinations": [],
                      "run": {"hosts_read": ["www.rapid7.com"], "answer_key": "fetched"}},
                "3": {"nr": 20.0, "rec_ungated": 25.0, "actor_hit": False, "hallucinations": [],
                      "run": {"hosts_read": [], "answer_key": "in search results"}},
                "N1": {"rst": 100}},
        # case 3 missing on this side: the summary must only average what all sides scored
        "memory": {"2": {"nr": 9.1, "rec_ungated": 5.0, "actor_hit": False,
                         "hallucinations": [["actor", "X"]]},
                   "N1": {"rst": 0}},
    },
}


def test_baseline_summary_only_averages_the_cases_every_side_scored():
    rows = {r["side"]: r for r in rd.baseline_rows(BASELINE_DOC)}
    assert rows["bounce"]["cases"] == ["2"]
    assert rows["bounce"]["nr"] == 60.0 and rows["web"]["nr"] == 80.0
    assert rows["memory"]["untraceable"] == 1
    assert rows["memory"]["rst"] == 0
    # case 3 is not common to every side: its "in search results" is not counted
    assert rows["web"]["key_fetched"] == 1 and rows["web"]["key_seen"] == 0


def test_baseline_section_names_the_answer_key_caveat_and_drops_the_no_baseline_claim():
    runs = [rd.parse_scorecard("2026-06-17_71e5fb1", V3_CARD)]
    without = rd.render(runs)
    assert "There is no\n  external baseline" in without and "(baseline)" not in without
    page = rd.render(runs, ("2026-10-21", BASELINE_DOC))
    section = page.split("## Against the same model without the tool (baseline)")[1]
    assert "can read the answer key" in section and "Untraceable is not wrong" in section
    assert "eval/baseline/2026-10-21/results.md" in section
    assert "external baseline and no comparison" not in page
    assert "Against the same model without the tool** (NR mean, cases 2)" in page


def test_the_answer_key_line_shows_a_dash_when_no_case_was_keyed():
    import copy
    doc = copy.deepcopy(BASELINE_DOC)
    for r in doc["sides"]["web"].values():
        r.pop("run", None)
    section = "\n".join(rd.render_baseline("2026-10-21", doc))
    assert "fetched the write-up of – of the 1 cases" in section
    assert "search results only on – more" in section
    keyed = "\n".join(rd.render_baseline("2026-10-21", BASELINE_DOC))
    assert "fetched the write-up of 1 of the 1 cases" in keyed


def test_load_baseline_takes_the_latest_results(tmp_path):
    assert rd.load_baseline(tmp_path / "absent") is None
    for name, nr in (("2026-10-01", 1.0), ("2026-10-21", 2.0)):
        (tmp_path / name).mkdir()
        (tmp_path / name / "results.json").write_text(
            '{"meta": {}, "sides": {"web": {"2": {"nr": %s}}}}' % nr)
    (tmp_path / "2026-12-31").mkdir()   # a directory without results is not a run
    name, doc = rd.load_baseline(tmp_path)
    assert name == "2026-10-21" and doc["sides"]["web"]["2"]["nr"] == 2.0


def test_published_page_matches_the_archived_runs():
    """EVAL_RESULTS.md must be regenerated whenever runs/ changes."""
    assert rd.main(["--check"]) == 0, (
        "EVAL_RESULTS.md is stale — run `python eval/results_digest.py`")
