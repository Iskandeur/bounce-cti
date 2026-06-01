# v3 Capability re-score of the 2026-05-31 run (CAP baseline)

This run (commit `6e6aaeb`) was executed and scored under EVAL_PROTOCOL **v2**
(headline "overall mean" = 64.2). After the **v3.0** protocol landed
(2026-06-01), the *same collected data* was re-scored under the new decay-proof
**Capability (CAP)** track. These CAP numbers are the **delta baseline**
(`PRIOR_CAP` in `eval/render_reports.py`) for v3 runs going forward.

No new investigations were run — this is a re-score of the identical graphs +
transcripts.

| Case | live | CAP | PS | EFF | RST | HYP | REC | NR | MK |
|-----:|:----:|----:|---:|----:|----:|----:|----:|---:|---:|
| 1  | DECAY | 90.0  | 75  | 100 | 100 | 100 | n/a  | 53 | 100 |
| 2  | DECAY | 100.0 | 100 | 100 | 100 | 100 | n/a  | 56 | 0   |
| 3  | live  | 90.2  | 100 | 61  | 100 | 100 | 59.8 | 47 | 100 |
| 4  | DECAY | 90.5  | 100 | 62  | 100 | 100 | n/a  | 23 | 0   |
| 5  | DECAY | 100.0 | 100 | 100 | 100 | 100 | n/a  | 15 | 0   |
| 6  | DECAY | 70.0  | 25  | 100 | 100 | 100 | n/a  | 50 | 100 |
| 7  | DECAY | 100.0 | 100 | 100 | 100 | 100 | n/a  | 42 | 0   |
| 8  | live  | 65.0  | 75  | 0   | 100 | 100 | 58.3 | 50 | 100 |
| 9  | live  | 78.6  | 75  | 54  | 100 | 100 | 83.3 | 67 | 100 |
| 10 | DECAY | 68.0  | 20  | 100 | 100 | 100 | n/a  | 7  | 0   |
| 11 | DECAY | 100.0 | 100 | 100 | 100 | 100 | n/a  | 20 | 0   |
| 12 | DECAY | 80.0  | 50  | 100 | 100 | 100 | n/a  | 62 | 100 |

| Metric | Target | This run |
|---|---|---|
| **CAP mean** (headline) | ≥ 75 → 85 | **86.0** |
| PS floor | ≥ 70 | 76.7 |
| Restraint floor (4/6/11/12) | ≥ 80 | 100 |
| Hallucination | 0 (hard gate) | 0 ✅ |
| REC (LIVE only, context) | MK ≥ 50 | 67.1 (n=3: c3/c8/c9) |
| DATA_DECAYED (REC-skipped) | — | [1,2,4,5,6,7,10,11,12] |

## What the re-score reveals (vs the v2 "64.2")

- **The tool's real capability is ~86, not 64.** v2's mean was dragged down by
  scoring decayed-seed recall as failure. CAP isolates what the tool controls
  (pivot selection, budget/yield, restraint, hypothesis discipline).
- **The freshness gate flags 9/12 as DATA_DECAYED** — confirming that the suite's
  seeds are mostly stale and that recall, not capability, was the v2 drag. REC is
  now honestly scored over the **3 LIVE cases only** (c3/c8/c9), MK-weighted.
- **The two shipped fixes target the two lowest *non-decay* CAPs:** c6 (PS=25 —
  the `_is_parked` co-resident-parking short-circuit) and c8 (EFF=0 — the 98-call
  drain overshoot). Post-fix, both should rise (c6 PS↑ once followup/drain run;
  c8 EFF 0→~75 once calls ≤ 90), lifting CAP mean toward ~89–90.
- **c5 CAP=100 with NR=15** is the clearest illustration: the agent ran every
  expected pivot correctly; the Eye-Pyramid cross-brand attribution simply is not
  in any queryable feed (and OpenCTI is token-dead). That is a *data/ops* gap, not
  a tool gap — exactly what v3 stops penalizing.

**Top ops-action carried into v3:** refresh `OPENCTI_TOKEN` on the VPS (unblocks
attribution recall on c5/c10); refresh the stalest seeds (c2/c7/c10) so REC has
more than 3 LIVE cases.
