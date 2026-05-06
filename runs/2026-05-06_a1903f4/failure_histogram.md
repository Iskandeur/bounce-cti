# Failure histogram — 2026-05-06 · commit a1903f4

## Top-level F-codes

| F-code                          | Cases hit | Cases (1-indexed) |
|---------------------------------|----------:|:------------------|
| F-EARLY-TERMINATION (≤ 8 CTI calls) | 1 | [2] |
| F-HYPOTHESIS-ABSENT (no working_hypothesis node) | 11 | [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12] |
| F-NODE-RECALL (NR < 50)         | 7 | [4, 5, 6, 7, 9, 10, 11] |
| F-PIVOT-MISS (PC < 60)          | 3 | [2, 6, 10] |
| F-REPORT (RQ < 70)              | 5 | [5, 7, 9, 10, 11] |
| F-EDGE-RECALL (ER < 50, when GT edges exist) | 11 | [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12] |
| F-DEFUSE-MISS (DC < 75)         | 0 | [] |
| F-BUDGET (BD < 100)             | 3 | [8, 11, 12] |
| F-BUDGET::no_extension_log      | 3 | [8, 11, 12] |
| F-HALLUCINATION                 | 0 | [] |

## F-PIVOT-MISS breakdown by abstract pivot

| Pivot rule | Cases that missed it |
|----|----|
| `banner_sibling_search` | [5] |
| `cert_san_apex` | [8] |
| `content_fingerprint_pivot` | [6] |
| `crtsh_blocknovas` | [10] |
| `ct_burst_window` | [9] |
| `dns_txt_mx_cross_ref` | [10] |
| `jarm_search` | [2] |
| `rdap_origin` | [12] |
| `reverse_dns_seed` | [10] |
| `reverse_ip_seo_decoy` | [3] |
| `reverse_whois_email` | [1] |
| `shodan_or_onyphe_banner` | [2] |
| `urlscan_front_companies` | [10] |
| `urlscan_or_wayback_seed` | [6] |
| `wayback_seized` | [10] |

## Per-case CTI call count + graph size

| Case | CTI calls | Nodes | Edges | P3 tools used |
|-----:|----------:|------:|------:|----:|
| 1 | 45 | 15 | 13 | 0 |
| 2 | 7 | 36 | 30 | 0 |
| 3 | 52 | 28 | 33 | 1 |
| 4 | 56 | 22 | 27 | 3 |
| 5 | 37 | 33 | 47 | 4 |
| 6 | 47 | 12 | 12 | 2 |
| 7 | 30 | 40 | 37 | 0 |
| 8 | 78 | 43 | 67 | 1 |
| 9 | 25 | 57 | 52 | 0 |
| 10 | 18 | 6 | 4 | 2 |
| 11 | 76 | 2 | 1 | 4 |
| 12 | 72 | 29 | 31 | 5 |
