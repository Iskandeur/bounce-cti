# Failure histogram — 2026-05-05 · commit c6dd4e9

## Top-level F-codes

| F-code                          | Cases hit | Cases (1-indexed) |
|---------------------------------|----------:|:------------------|
| F-EARLY-TERMINATION (≤ 8 calls) |  9        | 1, 2, 3, 6, 7, 8, 9, 10, 11, 12 (median 7) |
| F-HYPOTHESIS-ABSENT (no working_hypothesis node) | 9 | 1, 2, 3, 6, 7, 8, 9, 11, 12 |
| F-NODE-RECALL (NR < 50)         | 11        | 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 |
| F-PIVOT-MISS (PC < 60)          |  8        | 1, 2, 3, 5, 6, 8, 9, 10, 11, 12 |
| F-REPORT (RQ < 70)              | 11        | 1–11 (only case 12 has RQ=70) |
| F-EDGE-RECALL (ER < 50, when GT edges exist) | 4 | 1, 2, 7, 10 |
| F-DEFUSE-MISS (DC < 75)         |  0        | — (defuse floor 100) |
| F-BUDGET (BD < 100)             |  1        | 5 (BD=50, depth=4 trigger; per V2.1 spec) |
| F-BUDGET::no_extension_log      |  0        | — (no case exceeded 60 calls without a budget_extension; case 5 is the only one near the cap and it didn't extend by spec) |
| F-HALLUCINATION                 |  0        | — heuristic + hand audit on cases 1, 4, 5, 8 |
| F-SEED-DEAD                     |  1        | 11 (chosen seed produced no telemetry) |
| F-CLUSTER-OVER                  |  0        | — |
| F-CLUSTER-UNDER                 |  3        | 4 (backup IP cluster), 5 (cross-brand affiliate), 8 (Amadey C2 hub) |

## F-PIVOT-MISS breakdown by abstract pivot

| Pivot rule                       | Hits | Cases that missed it |
|----------------------------------|-----:|:---------------------|
| `reverse_whois_email`            | 1    | 1 |
| `reverse_ip`                     | 1    | 1 |
| `shodan_or_onyphe_banner`        | 1    | 2 |
| `jarm_search`                    | 1    | 2 |
| `vt_pdns_opmanager`              | 1    | 3 |
| `reverse_ip_seo_decoy`           | 1    | 3 |
| `urlscan_clickfix_path`          | 1    | 4 |
| `banner_sibling_search`          | 1    | 5 |
| `urlscan_or_wayback_seed`        | 1    | 6 |
| `content_fingerprint_pivot`      | 1    | 6 |
| `crtsh_sha1_cluster`             | 1    | 6 |
| `reverse_dns_or_pdns_keitaro`    | 1    | 7 |
| `urlscan_sibling_tds`            | 1    | 7 |
| `cert_san_apex`                  | 1    | 8 |
| `rdap_asn`                       | 1    | 8 |
| `ct_burst_window`                | 1    | 9 |
| `urlscan_kit_fingerprint`        | 1    | 9 |
| **`dns_txt_mx_cross_ref`**       | 1    | 10 |
| **`crtsh_blocknovas`**           | 1    | 10 |
| `wayback_seized`                 | 1    | 10 |
| `urlscan_front_companies`        | 1    | 10 |
| `origin_banner_search`           | 1    | 11 |
| `urlscan_dom_cross_brand`        | 1    | 11 |
| **`shodan_cert_cn`**             | 1    | 12 |
| `rdap_origin`                    | 1    | 12 |
| `vt_pdns_origin`                 | 1    | 12 |

## Concentration analysis

- The **single largest cross-case failure mode is F-EARLY-TERMINATION (9 cases)**. Median call count is 7. The agent treats the mandatory-tools list as the finish line.
- **F-HYPOTHESIS-ABSENT (9 cases)** is the second-largest. The hypothesis-first prompt arc is read but not acted on. This is a regression: the 2026-05-04 hypofirst smoke had Cases 1 + 7 producing valid hypothesis_history. This run, neither did. The behaviour drift suggests the hypothesis prose, while in the prompt, is not gated mechanically.
- The two together form the **dominant failure mode** for this iteration. Mechanical enforcement of `working_hypothesis` write should solve both at once: by forcing the model to commit to a hypothesis after some N calls, the playbook the model picks (apt_targeted, traffer_or_tds, commodity_malware) determines downstream pivots — without the hypothesis, the model defaults to "call mandatory then exit".
- Pivot-specific misses are now mostly **single-case**: `dns_txt_mx_cross_ref` (only case 10), `shodan_cert_cn` (only case 12), `content_fingerprint` (only case 6). Each fix only moves one case, but cumulatively they're the next ring of priority.
- **Phase 3 tools used in 2/12 cases** (4, 5). The autonomy engine is built but unreached because phase_main is too short.

## Per-case CTI call count + graph size

| Case | CTI calls | Nodes | Edges | Comment |
|-----:|----------:|------:|------:|:--------|
|  1   | 12        | 14    | 13    | Strongest non-Phase-3 case. Multiple historical IPs + nameservers + 5 PlugX hashes. No registrant email surfaced. |
|  2   | 3         | 8     | 7     | **Most extreme F-EARLY-TERMINATION** — only 3 cti calls. |
|  3   | 5         | 16    | 15    | VT communicating_files surfaced 11 hashes (graphed!) but `opmanager.pro` contacted_domain missed. |
|  4   | 31        | 27    | 32    | Best-paced run. Phase 3 fired across 7 sources. Working_hypothesis ✓. |
|  5   | 37        | 28    | 50    | Phase 2/3 chain fired but BFS depth=4 → BD 50. |
|  6   | 7         | 8     | 7     | Only RDAP. Tiny graph. |
|  7   | 7         | 6     | 5     | **Reproduces v4 result**: vt_pdns hint fix didn't trigger because vt_resolutions_ip wasn't called (depends on extracting IP from dns_resolve first). |
|  8   | 5         | 14    | 13    | Hash → contacted_url graphed but no apex/subdomain split done. |
|  9   | 8         | 5     | 4     | crt.sh + vt_pdns only. No CT-burst filter. |
| 10   | 8         | 6     | 5     | reverse_dns ran, returned `lianxinxiao.com`. No follow-up dns_resolve TXT/MX. |
| 11   | 7         | 2     | 1     | Smallest graph. Seed dead — no telemetry. |
| 12   | 8         | 9     | 8     | Strongest report (RQ=70) but no shodan_cert_cn. cert_cn node missed. |

## Failure flow

```
phase_main starts
  → makes 3-12 cti calls (median 7), mostly mandatory-tool floor
  → writes preliminary report (or none) and exits with rc=0 saw_result=true
phase_followup runs (when missing tools detected)
  → calls a few more tools, often only adds nodes already in graph
  → writes investigation_summary report
phase3_report_write rarely fires (most cases have summary by phase 2)

What is NOT happening:
  - working_hypothesis report node (9/12 cases skip it)
  - draining of pivot_tasks queue via next_pivot()
  - chained pivots from tool _pivot_hints (vt_file → contacted_ip → shodan_host;
    reverse_dns → dns_resolve TXT/MX; rdap → whoxy_reverse on cleartext registrant)
  - Phase 3 tools beyond cases 4 + 5
```

The single biggest behaviour-drift fix is **mechanical `working_hypothesis` enforcement**: after phase_main_exit, if no working_hypothesis node exists, run a small dedicated "write the hypothesis" phase. This forces commitment to a category, which selects a playbook that drives subsequent pivots.
