# Failure histogram — 2026-06-01 · commit de5a31b

## Top-level F-codes

| F-code                          | Cases hit | Cases (1-indexed) |
|---------------------------------|----------:|:------------------|
| F-RUN-ERROR | 7 | [1, 4, 5, 6, 7, 10, 11] |
| F-EDGE-RECALL (ER < 50, when GT edges exist) | 4 | [2, 3, 8, 12] |
| F-NODE-RECALL (NR < 50) | 1 | [3] |
| F-BUDGET (BD < 100) | 1 | [8] |
| F-BUDGET::no_extension_log | 1 | [8] |
| F-HYPOTHESIS-ABSENT (no working_hypothesis node) | 0 | [] |
| F-HYPOTHESIS-INVALID (missing history/final_category) | 0 | [] |
| F-PIVOT-MISS (PC < 60) | 0 | [] |
| F-REPORT (RQ < 70) | 0 | [] |
| F-DEFUSE-MISS (DC < 75) | 0 | [] |
| F-HALLUCINATION | 0 | [] |

## F-PIVOT-MISS breakdown by abstract pivot

| Pivot rule | Cases that missed it |
|----|----|
| `ct_burst_window` | [9] |
| `shodan_cert_cn_search` | [12] |

## Per-case CTI call count + graph size

| Case | CTI calls | Nodes | Edges | P3 tools used | BD | budget_ext |
|-----:|----------:|------:|------:|----:|---:|---:|
| 2 | 28 | 33 | 35 | 7 | 100 | 0 |
| 3 | 29 | 34 | 44 | 6 | 100 | 0 |
| 8 | 63 | 34 | 43 | 7 | 50 | 0 |
| 9 | 44 | 40 | 46 | 5 | 100 | 0 |
| 12 | 41 | 32 | 30 | 6 | 100 | 0 |