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
    assert "blocked — see post-mortem" in page


def test_published_page_matches_the_archived_runs():
    """EVAL_RESULTS.md must be regenerated whenever runs/ changes."""
    assert rd.main(["--check"]) == 0, (
        "EVAL_RESULTS.md is stale — run `python eval/results_digest.py`")
