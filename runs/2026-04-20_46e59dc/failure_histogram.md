# Failure histogram — 2026-04-20 · commit 46e59dc

## Top-level F-codes

| F-code              | Cases hit | Cases (1-indexed) |
|---------------------|----------:|:------------------|
| F-REPORT (RQ < 70)             | 11 | 1–3, 5, 7–11 (case 12 is the sole pass with RQ=70) |
| F-NODE-RECALL (NR < 50)        | 10 | 1, 3, 4, 5, 6, 7, 9, 10, 11, 12 |
| F-PIVOT-MISS (PC < 60)         |  9 | 1, 2, 3, 5, 6, 8, 10, 11, 12 |
| F-EDGE-RECALL (ER < 50, when GT edges exist) | 6 | 1, 2, 3, 7, 8, 10 |
| F-EARLY-TERMINATION (calls ≤ 7) | 9 | 1, 2, 3, 4, 5, 6, 7 (with rc=1), 9, 10, 11, 12 |
| F-DEFUSE-MISS (DC < 75)        |  0 | — |
| F-BUDGET (BD < 50)             |  0 | — (no case exceeded 60 calls) |
| F-HALLUCINATION                |  0 | — (heuristic + hand audit; see deltas.md) |
| F-CLUSTER-OVER                 |  0 | — (was 1 in prior run; R12+R13 fixed it) |

## F-PIVOT-MISS breakdown by abstract pivot

| Pivot rule                       | Hits | Cases that missed it |
|----------------------------------|-----:|:---------------------|
| `rdap_seed`                      | 4 | 1, 4, 5, 6 |
| `reverse_whois_email`            | 1 | 1 |
| `reverse_ip`                     | 1 | 1 |
| `shodan_or_onyphe_banner`        | 1 | 2 |
| `jarm_search`                    | 1 | 2 |
| `threatfox_muddywater`           | 1 | 2 |
| `vt_pdns_opmanager`              | 1 | 3 |
| `reverse_ip_seo_decoy`           | 1 | 3 |
| `urlscan_clickfix_path`          | 1 | 4 |
| `banner_sibling_search`          | 1 | 5 |
| `urlscan_or_wayback_seed`        | 1 | 6 |
| `content_fingerprint_pivot`      | 1 | 6 |
| `crtsh_sha1_cluster`             | 1 | 6 |
| `urlscan_sibling_tds`            | 1 | 7 |
| `cert_san_apex`                  | 1 | 8 |
| `ct_burst_window`                | 1 | 9 |
| `urlscan_kit_fingerprint`        | 1 | 9 |
| `reverse_dns_seed`               | 1 | 10 |
| `dns_txt_mx_cross_ref`           | 1 | 10 |
| `crtsh_blocknovas`               | 1 | 10 |
| `wayback_seized`                 | 1 | 10 |
| `rdap_namesilo`                  | 1 | 11 |
| `origin_banner_search`           | 1 | 11 |
| `urlscan_dom_cross_brand`        | 1 | 11 |
| `shodan_cert_cn`                 | 1 | 12 |
| `rdap_origin`                    | 1 | 12 |
| `vt_pdns_origin`                 | 1 | 12 |

## Concentrations

- **`rdap_seed` (4 cases)** is the single largest hit. RDAP for the seed is not in the mandatory-tools list in `agent_runner._missing_mandatory_tools`. Adding it would clear all 4 in one shot.
- **Case 10 alone has 4 distinct misses** — every IP-seed-specific pivot (reverse DNS, DNS TXT/MX, Wayback, blocknovas crt.sh) is absent. `reverse_dns(seed)` is the cheapest fix and unblocks the rest (lianxinxiao.com → blocknovas.com → siblings).
- **`shodan_cert_cn` (case 12)** is the R14 escalation — the rule is in the system prompt but isn't enforced via mandatory-tools or followup-prompt logic. The agent reads the rule and ignores it.
- **R11/R12/R13 hallucination guards held** — zero cases hit F-CLUSTER-OVER or F-HALLUCINATION this run (vs. 1 prior).

## Per-case CTI call count + graph size

| Case | CTI calls | Nodes | Edges | Comment |
|-----:|----------:|------:|------:|:--------|
| 1  |  9 |  9 |  8 | Phase_main exited fast; followup added 1 tool then report |
| 2  |  2 |  6 |  5 | **Most extreme F-EARLY-TERMINATION** — only `virustotal_file` + `malwarebazaar_hash` |
| 3  |  5 | 13 | 12 | |
| 4  |  7 |  7 |  6 | |
| 5  |  7 |  8 |  7 | |
| 6  |  6 |  9 |  8 | |
| 7  |  9 | 30 | 38 | Phase_main `rc=1` (saw_result=false but has_report=true) — agent crashed mid-run |
| 8  | 12 | 31 | 41 | Largest hash investigation |
| 9  |  8 |  4 |  3 | Tycoon 2FA — narrow but accurate |
| 10 |  7 |  3 |  2 | **Smallest graph** despite IP seed |
| 11 |  6 |  2 |  1 | Smishing Triad — agent only graphed seed + report after Cloudflare detect |
| 12 |  7 |  7 |  6 | |

## Failure flow

```
phase_main starts
  → makes 4-7 CTI calls (mandatory minus a few)
  → writes preliminary report or exits (rc=0, saw_result=true, has_report=false in 9 cases)
phase_followup starts (when missing tools detected)
  → calls the missing 1-3 tools (typically threatfox_search, virustotal_communicating_files)
  → writes report (or marks phase2_incomplete)
phase3_report_write rarely fires (most cases produced a report in main or followup)
```

The pattern is reproducible: the agent treats "phase_main_exit" as "investigation done" rather than as "minimum bar met". The mandatory-tools backstop catches the floor but doesn't lift the ceiling.
