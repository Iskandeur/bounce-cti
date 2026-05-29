# Failure histogram — 2026-05-28 · commit ccee7e3

## Top-level F-codes

| F-code                          | Cases hit | Cases (1-indexed) |
|---------------------------------|----------:|:------------------|
| F-REPORT (RQ < 70) | 8 | [1, 2, 4, 5, 7, 9, 10, 11] |
| F-NODE-RECALL (NR < 50) | 7 | [1, 3, 4, 5, 7, 10, 11] |
| F-EDGE-RECALL (ER < 50, when GT edges exist) | 7 | [1, 2, 4, 5, 7, 8, 10] |
| F-BUDGET (BD < 100) | 5 | [3, 4, 8, 9, 12] |
| F-EARLY-TERMINATION (≤ 8 CTI calls) | 2 | [1, 6] |
| F-PIVOT-MISS (PC < 60) | 2 | [1, 10] |
| F-HYPOTHESIS-ABSENT (no working_hypothesis node) | 0 | [] |
| F-DEFUSE-MISS (DC < 75) | 0 | [] |
| F-BUDGET::no_extension_log | 0 | [] |
| F-HALLUCINATION | 0 | [] |

## F-PIVOT-MISS breakdown by abstract pivot

| Pivot rule | Cases that missed it |
|----|----|
| `crtsh_blocknovas` | [10] |
| `ct_burst_window` | [9] |
| `dns_txt_mx_cross_ref` | [10] |
| `rdap_ip` | [8] |
| `reverse_whois_email` | [1] |
| `shodan_or_onyphe_banner` | [2] |
| `soa_mname_pivot` | [1] |
| `urlscan_or_wayback_seed` | [6] |
| `wayback_seized` | [10] |

## Per-case CTI call count + graph size

| Case | CTI calls | Nodes | Edges | P3 tools used |
|-----:|----------:|------:|------:|----:|
| 1 | 4 | 27 | 36 | 0 |
| 2 | 48 | 89 | 104 | 5 |
| 3 | 115 | 52 | 55 | 10 |
| 4 | 120 | 77 | 83 | 8 |
| 5 | 56 | 165 | 230 | 7 |
| 6 | 4 | 29 | 27 | 0 |
| 7 | 45 | 167 | 160 | 7 |
| 8 | 86 | 97 | 126 | 11 |
| 9 | 127 | 79 | 88 | 7 |
| 10 | 18 | 8 | 8 | 3 |
| 11 | 43 | 4 | 1 | 4 |
| 12 | 94 | 60 | 77 | 8 |