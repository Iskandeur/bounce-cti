# Failure histogram — 2026-06-17 · commit 69fc13c

## Top-level F-codes

| F-code                          | Cases hit | Cases (1-indexed) |
|---------------------------------|----------:|:------------------|
| F-RUN-ERROR | 7 | [1, 4, 5, 6, 7, 10, 11] |
| F-EDGE-RECALL (ER < 50, when GT edges exist) | 3 | [2, 3, 8] |
| F-NODE-RECALL (NR < 50) | 1 | [3] |
| F-REPORT (RQ < 70) | 1 | [9] |
| F-HYPOTHESIS-ABSENT (no working_hypothesis node) | 0 | [] |
| F-HYPOTHESIS-INVALID (missing history/final_category) | 0 | [] |
| F-PIVOT-MISS (PC < 60) | 0 | [] |
| F-DEFUSE-MISS (DC < 75) | 0 | [] |
| F-BUDGET (BD < 100) | 0 | [] |
| F-BUDGET::no_extension_log | 0 | [] |
| F-HALLUCINATION | 0 | [] |

## F-PIVOT-MISS breakdown by abstract pivot

| Pivot rule | Cases that missed it |
|----|----|
| `ct_burst_window` | [9] |
| `reverse_ip_seo_decoy` | [3] |
| `shodan_cert_cn_search` | [12] |

## Per-case CTI call count + graph size

| Case | CTI calls | Nodes | Edges | P3 tools used | BD | budget_ext |
|-----:|----------:|------:|------:|----:|---:|---:|
| 2 | 46 | 61 | 84 | 6 | 100 | 0 |
| 3 | 12 | 28 | 31 | 0 | 100 | 0 |
| 8 | 60 | 39 | 50 | 6 | 100 | 0 |
| 9 | 33 | 23 | 20 | 6 | 100 | 0 |
| 12 | 16 | 18 | 20 | 1 | 100 | 0 |