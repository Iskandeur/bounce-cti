# Failure histogram — 2026-05-31 · commit 6e6aaeb

## Top-level F-codes

| F-code                          | Cases hit | Cases (1-indexed) |
|---------------------------------|----------:|:------------------|
| F-EDGE-RECALL (ER < 50, when GT edges exist) | 8 | [1, 2, 3, 4, 5, 7, 8, 10] |
| F-REPORT (RQ < 70) | 6 | [2, 4, 5, 7, 10, 11] |
| F-NODE-RECALL (NR < 50) | 6 | [3, 4, 5, 7, 10, 11] |
| F-BUDGET (BD < 100) | 4 | [3, 4, 8, 9] |
| F-PIVOT-MISS (PC < 60) | 3 | [6, 10, 12] |
| F-EARLY-TERMINATION (≤ 8 CTI calls) | 2 | [1, 6] |
| F-HYPOTHESIS-ABSENT (no working_hypothesis node) | 0 | [] |
| F-HYPOTHESIS-INVALID (missing history/final_category) | 0 | [] |
| F-DEFUSE-MISS (DC < 75) | 0 | [] |
| F-BUDGET::no_extension_log | 0 | [] |
| F-HALLUCINATION | 0 | [] |

## F-PIVOT-MISS breakdown by abstract pivot

| Pivot rule | Cases that missed it |
|----|----|
| `cert_san_apex` | [8] |
| `content_fingerprint_pivot` | [6] |
| `crtsh_blocknovas` | [10] |
| `crtsh_seed` | [6] |
| `ct_burst_window` | [9] |
| `dns_txt_mx_cross_ref` | [10] |
| `rdap_origin` | [12] |
| `reverse_whois_email` | [1] |
| `shodan_cert_cn_search` | [12] |
| `urlscan_front_companies` | [10] |
| `urlscan_or_wayback_seed` | [6] |
| `wayback_seized` | [10] |

## Per-case CTI call count + graph size

| Case | CTI calls | Nodes | Edges | P3 tools used | BD | budget_ext |
|-----:|----------:|------:|------:|----:|---:|---:|
| 1 | 4 | 24 | 23 | 0 | 100 | 0 |
| 2 | 49 | 67 | 122 | 5 | 100 | 0 |
| 3 | 74 | 48 | 48 | 8 | 75 | 1 |
| 4 | 78 | 63 | 82 | 7 | 75 | 1 |
| 5 | 45 | 73 | 145 | 6 | 100 | 1 |
| 6 | 3 | 26 | 22 | 0 | 100 | 0 |
| 7 | 48 | 91 | 135 | 8 | 100 | 1 |
| 8 | 98 | 86 | 108 | 6 | 0 | 1 |
| 9 | 79 | 53 | 45 | 7 | 75 | 1 |
| 10 | 15 | 7 | 4 | 1 | 100 | 0 |
| 11 | 36 | 4 | 1 | 2 | 100 | 0 |
| 12 | 11 | 48 | 50 | 0 | 100 | 1 |