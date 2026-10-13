"""Build EVAL_RESULTS.md — the published digest of every archived eval run.

Each run under ``runs/<date>_<sha>/`` ships a hand-reviewed ``scorecard.md``.
This script reads those scorecards (and nothing else: no network, no DB, no
API key) and renders one page that answers the question a reader actually
asks — *how good is the agent, and is it getting better?* — without hiding
the parts of the answer that are inconvenient.

Two rubric generations coexist in ``runs/``:

- **v2 "Overall"** (April → June): mixes recall against vendor ground truth
  with process scores. Every run since 2026-04-19 carries a v2 table (the v3
  runs keep it as a "legacy track"), so it is the only continuous series.
- **v3 "CAP"** (June onwards): the decay-proof capability score defined in
  EVAL_PROTOCOL.md §4.A, scored on the fresh subset only.

The two are never averaged together. The headline trend is computed on the
**same five cases** (the fresh subset 2, 3, 8, 9, 12) for every run that
scored all five, so a smoke run of three easy cases cannot pass for progress.

Usage:
    python eval/results_digest.py            # rewrite EVAL_RESULTS.md
    python eval/results_digest.py --check    # exit 1 if EVAL_RESULTS.md is stale

Stdlib only, so it runs in CI and on any checkout.
"""
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RUNS_DIR = REPO_ROOT / "runs"
OUTPUT = REPO_ROOT / "EVAL_RESULTS.md"

# The decay-resistant cases scored by every nightly run (EVAL_PROTOCOL §0/§6).
FRESH_SUBSET = (2, 3, 8, 9, 12)

_TITLE_RE = re.compile(r"(\d{4}-\d{2}-\d{2})\s*·\s*commit\s+`?([0-9a-f]{7,40})`?")
_MODEL_RE = re.compile(r"^-\s*Model:\s*`([^`]+)`", re.MULTILINE)
_NUM_RE = re.compile(r"-?\d+(?:\.\d+)?")
_BLOCKED_RE = re.compile(r"RUN STATUS:\s*BLOCKED")


@dataclass
class CaseRow:
    case: str            # "1".."12" or "N1".."N3"
    status: str          # v2 tables: done / quota_exceeded / ERR …; v3: live / DECAY / ERR / –
    score: float | None  # Overall (v2) or CAP (v3)


@dataclass
class Run:
    name: str
    date: str
    commit: str
    model: str
    v2: list[CaseRow] = field(default_factory=list)
    v3: list[CaseRow] = field(default_factory=list)
    blocked: bool = False

    def v2_done(self) -> dict[int, float]:
        """Positive cases that actually ran to completion, with a numeric score."""
        out: dict[int, float] = {}
        for r in self.v2:
            if r.case.isdigit() and r.status == "done" and r.score is not None:
                out[int(r.case)] = r.score
        return out

    def v3_positive(self) -> dict[int, float]:
        return {int(r.case): r.score for r in self.v3
                if r.case.isdigit() and r.score is not None}

    def v3_negative(self) -> dict[str, float]:
        return {r.case: r.score for r in self.v3
                if r.case.startswith("N") and r.score is not None}


def _clean(cell: str) -> str:
    return cell.replace("*", "").replace("`", "").strip()


def _to_float(cell: str) -> float | None:
    m = _NUM_RE.fullmatch(_clean(cell))
    return float(m.group(0)) if m else None


def _split_row(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def _tables(text: str) -> list[list[list[str]]]:
    """Every markdown table in ``text`` as rows of cells (separator row dropped)."""
    tables: list[list[list[str]]] = []
    current: list[list[str]] = []
    for line in text.splitlines():
        if line.lstrip().startswith("|"):
            cells = _split_row(line)
            if all(re.fullmatch(r":?-{2,}:?", c) for c in cells if c):
                continue
            current.append(cells)
        elif current:
            tables.append(current)
            current = []
    if current:
        tables.append(current)
    return tables


def _case_table(tables: list[list[list[str]]], score_col: str,
                status_col: str) -> list[CaseRow]:
    """First table whose header has ``Case`` and ``score_col``, parsed into rows."""
    for table in tables:
        header = [_clean(h) for h in table[0]]
        if "Case" not in header or score_col not in header:
            continue
        ci, si = header.index("Case"), header.index(score_col)
        ti = header.index(status_col) if status_col in header else None
        rows: list[CaseRow] = []
        for cells in table[1:]:
            if len(cells) <= max(ci, si):
                continue
            case = _clean(cells[ci])
            if not re.fullmatch(r"N?\d+", case):
                continue
            status = _clean(cells[ti]) if ti is not None and ti < len(cells) else ""
            rows.append(CaseRow(case=case, status=status, score=_to_float(cells[si])))
        return rows
    return []


def parse_scorecard(name: str, text: str) -> Run:
    title = text.splitlines()[0] if text else ""
    m = _TITLE_RE.search(title)
    date, commit = (m.group(1), m.group(2)) if m else (name[:10], name[11:])
    mm = _MODEL_RE.search(text)
    tables = _tables(text)
    run = Run(
        name=name, date=date, commit=commit,
        model=mm.group(1) if mm else "?",
        v2=_case_table(tables, "Overall", "Status"),
        v3=_case_table(tables, "CAP", "live"),
    )
    if not run.v2 and not run.v3:
        # Only a scorecard that says so is a blocked run. Anything else without
        # a recognised table is a format change, and must not be published as
        # an outage.
        if not _BLOCKED_RE.search(text):
            raise ValueError(f"{name}: no v2 'Overall' or v3 'CAP' case table "
                             "and no BLOCKED marker; scorecard format not recognised")
        run.blocked = True
    return run


def load_runs(runs_dir: Path = RUNS_DIR) -> list[Run]:
    if not runs_dir.is_dir():
        raise SystemExit(f"no runs directory at {runs_dir}: nothing to digest")
    runs = []
    for d in sorted(p for p in runs_dir.iterdir() if p.is_dir()):
        card = d / "scorecard.md"
        if card.exists():
            runs.append(parse_scorecard(d.name, card.read_text(encoding="utf-8")))
    return runs


def _mean(values) -> float | None:
    values = list(values)
    return round(sum(values) / len(values), 1) if values else None


def _fmt(x: float | None) -> str:
    return "–" if x is None else f"{x:.1f}"


def subset_mean(run: Run) -> float | None:
    """v2 Overall mean on the fresh subset, only if all five cases completed."""
    done = run.v2_done()
    if all(c in done for c in FRESH_SUBSET):
        return _mean(done[c] for c in FRESH_SUBSET)
    return None


def render(runs: list[Run]) -> str:
    out: list[str] = []
    w = out.append
    w("# Bounce-CTI — evaluation results")
    w("")
    w("> Generated by [`eval/results_digest.py`](eval/results_digest.py) from the")
    w("> archived scorecards in [`runs/`](runs/). Do not edit by hand: re-run the")
    w("> script after adding a run (a test fails if this page is stale).")
    w("> Rubric and case definitions: [`EVAL_PROTOCOL.md`](EVAL_PROTOCOL.md).")
    w("")

    scored = [r for r in runs if not r.blocked]
    trend = [(r, subset_mean(r)) for r in scored]
    trend = [(r, m) for r, m in trend if m is not None]
    v3_runs = [r for r in scored if r.v3_positive()]

    w("## Headline")
    w("")
    if trend:
        first, last = trend[0], trend[-1]
        w(f"- **Like-for-like trend (v2 Overall, same {len(FRESH_SUBSET)} cases "
          f"{', '.join(map(str, FRESH_SUBSET))}):** {_fmt(first[1])} on "
          f"{first[0].date} (`{first[0].commit}`) → {_fmt(last[1])} on "
          f"{last[0].date} (`{last[0].commit}`), over {len(trend)} comparable runs.")
    if v3_runs:
        caps = [_mean(r.v3_positive().values()) for r in v3_runs]
        w(f"- **Capability (v3 CAP, fresh subset):** {', '.join(_fmt(c) for c in caps)} "
          f"across the {len(v3_runs)} v3 runs (target ≥ 75, stretch ≥ 85).")
    w(f"- **Runs archived:** {len(runs)} ({len(runs) - len(scored)} marked "
      f"`RUN STATUS: BLOCKED`, documented in its scorecard rather than scored).")
    w("")

    w("## What these numbers are — and are not")
    w("")
    w("- **Self-graded.** Scores come from this project's own mechanical scorer")
    w("  (`eval/scorer.py`) plus a hand audit for hallucinations. There is no")
    w("  external baseline and no comparison against another tool.")
    w("- **The rubric moved.** v2 Overall (recall against vendor ground truth +")
    w("  process) and v3 CAP (decay-proof capability) measure different things and")
    w("  are never averaged together. The scorer itself was tightened along the way")
    w("  (e.g. the hallucination check on 2026-05-28), so an equal number in April")
    w("  and in June is not an identical measurement.")
    w("- **CAP is also the optimisation target** of the improvement loop, which")
    w("  makes it vulnerable to Goodhart's law. The v2 recall track is kept next to")
    w("  it precisely as a check that does not reward gaming the process score.")
    w("- **The live internet decays.** Ground truth comes from public vendor")
    w("  write-ups; infrastructure that has since been taken down cannot be")
    w("  re-observed. v3 marks such cases `DECAY` and skips their recall.")
    w("- **The model changed** (`opus-4.7` until 2026-05-31, `opus-4.8` after), so")
    w("  part of any later gain may be the model's, not the code's.")
    w("- **Hallucination is a hard gate, not a score.** One untraceable node fails")
    w("  the run. It fired once (2026-04-19, a misattribution through shared-hosting")
    w("  co-residency) and every later scorecard that audits it reports 0 (the")
    w("  targeted two-case run of 2026-05-04 `hypofirst` does not report it). The")
    w("  per-run audit lives in each scorecard.")
    w("")

    w(f"## Like-for-like trend — fresh subset ({', '.join(map(str, FRESH_SUBSET))})")
    w("")
    w("v2 Overall per case, for every run that completed all five.")
    w("")
    w("| Run | Model | " + " | ".join(f"C{c}" for c in FRESH_SUBSET) + " | Mean |")
    w("|---|---|" + "---:|" * len(FRESH_SUBSET) + "---:|")
    for r, m in trend:
        done = r.v2_done()
        w(f"| {r.date} `{r.commit}` | `{r.model}` | "
          + " | ".join(_fmt(done[c]) for c in FRESH_SUBSET) + f" | **{_fmt(m)}** |")
    w("")

    if v3_runs:
        w("## Capability track (v3 CAP)")
        w("")
        cases = sorted({c for r in v3_runs for c in r.v3_positive()})
        negs = sorted({n for r in v3_runs for n in r.v3_negative()})
        w("Positive cases are scored on CAP; negative (benign) cases on restraint only.")
        w("")
        w("| Run | " + " | ".join(f"C{c}" for c in cases) + " | CAP mean | "
          + " | ".join(negs) + " |")
        w("|---|" + "---:|" * (len(cases) + 1 + len(negs)))
        for r in v3_runs:
            pos, neg = r.v3_positive(), r.v3_negative()
            w(f"| {r.date} `{r.commit}` | "
              + " | ".join(_fmt(pos.get(c)) for c in cases)
              + f" | **{_fmt(_mean(pos.values()))}** | "
              + " | ".join(_fmt(neg.get(n)) for n in negs) + " |")
        w("")

    w("## Every archived run")
    w("")
    w("| Run | Model | Cases completed (v2) | v2 Overall mean | v3 CAP mean | Scorecard |")
    w("|---|---|---:|---:|---:|---|")
    for r in runs:
        if r.blocked:
            w(f"| {r.date} `{r.commit}` | `{r.model}` | 0 | – | – | "
              f"[blocked — see scorecard](runs/{r.name}/scorecard.md) |")
            continue
        done = r.v2_done()
        attempted = sum(1 for x in r.v2 if x.case.isdigit())
        v3m = _mean(r.v3_positive().values()) if r.v3_positive() else None
        w(f"| {r.date} `{r.commit}` | `{r.model}` | {len(done)}/{attempted} | "
          f"{_fmt(_mean(done.values()))} | {_fmt(v3m)} | "
          f"[scorecard](runs/{r.name}/scorecard.md) |")
    w("")
    w("The v2 mean in this table is over whatever cases each run completed (a")
    w("three-case smoke run and a twelve-case full run are not comparable); use the")
    w("like-for-like table above for trends.")
    w("")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if EVAL_RESULTS.md differs from a fresh render")
    args = ap.parse_args(argv)
    text = render(load_runs())
    if args.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if current != text:
            print("EVAL_RESULTS.md is stale: run `python eval/results_digest.py`",
                  file=sys.stderr)
            return 1
        return 0
    OUTPUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
