# Failure histogram — 2026-05-21 · commit e54dec1

## Top-level F-codes

| F-code                          | Cases hit | Cases (1-indexed) |
|---------------------------------|----------:|:------------------|
| F-REPORT (RQ < 70) | 9 | [1, 2, 4, 5, 6, 9, 10, 11, 12] |
| F-EDGE-RECALL (ER < 50, when GT edges exist) | 9 | [1, 2, 3, 4, 5, 7, 8, 10, 12] |
| F-NODE-RECALL (NR < 50) | 7 | [1, 3, 4, 5, 10, 11, 12] |
| F-PIVOT-MISS (PC < 60) | 7 | [1, 3, 5, 6, 10, 11, 12] |
| F-EARLY-TERMINATION (≤ 8 CTI calls) | 5 | [5, 6, 10, 11, 12] |
| F-HYPOTHESIS-ABSENT (no working_hypothesis node) | 4 | [5, 10, 11, 12] |
| F-BUDGET (BD < 100) | 2 | [1, 7] |
| F-BUDGET::no_extension_log | 1 | [1] |
| F-DEFUSE-MISS (DC < 75) | 0 | [] |
| F-HALLUCINATION | 0 | [] |

## F-PIVOT-MISS breakdown by abstract pivot

| Pivot rule | Cases that missed it |
|----|----|
| `banner_sibling_search` | [5] |
| `cert_san_apex` | [8] |
| `content_fingerprint_pivot` | [6] |
| `crtsh_blocknovas` | [10] |
| `crtsh_seed` | [6, 11, 12] |
| `ct_burst_window` | [9] |
| `dns_resolve_seed` | [12] |
| `dns_txt_mx_cross_ref` | [10] |
| `historical_origin_pivot` | [11] |
| `rdap_origin` | [12] |
| `rdap_seed` | [11] |
| `reverse_dns_seed` | [10] |
| `reverse_ip_seo_decoy` | [3] |
| `reverse_whois_email` | [1] |
| `shodan_banner` | [5] |
| `shodan_cert_cn_search` | [12] |
| `shodan_or_onyphe_banner` | [2] |
| `soa_mname_pivot` | [1] |
| `threatfox_multi` | [5] |
| `urlscan_dom_pivot` | [11] |
| `urlscan_front_companies` | [10] |
| `urlscan_or_wayback_seed` | [6] |
| `vt_pdns_domain` | [3] |
| `vt_pdns_seed` | [11] |
| `wayback_seized` | [10] |

## Per-case CTI call count + graph size

| Case | CTI calls | Nodes | Edges | P3 tools used |
|-----:|----------:|------:|------:|----:|
| 1 | 125 | 79 | 103 | 8 |
| 2 | 25 | 15 | 15 | 1 |
| 3 | 12 | 30 | 34 | 0 |
| 4 | 42 | 28 | 29 | 7 |
| 5 | 4 | 1 | 0 | 0 |
| 6 | 3 | 31 | 33 | 0 |
| 7 | 65 | 68 | 71 | 7 |
| 8 | 9 | 12 | 11 | 0 |
| 9 | 24 | 31 | 32 | 5 |
| 10 | 2 | 1 | 0 | 0 |
| 11 | 0 | 0 | 0 | 0 |
| 12 | 0 | 0 | 0 | 0 |