# Failure histogram — 2026-04-19 · commit abca49b

## Per-marker failure counts (cases failing each rubric dimension)

| Code | Description | Count | Cases |
|------|-------------|------:|-------|
| F-PIVOT-MISS | A pivot the GT lists was not exercised | **6/12** | 1, 2, 3, 5, 6, 10 |
| F-REPORT | Report missing marker OR actor OR node-list | **4/12** | 5, 7, 10, (+1,6 partial) |
| F-SRC-ABSENT | A GT node the agent should have pivoted to is absent | **6/12** | 3, 4, 5, 8, 9, 10 |
| F-DEFUSE-UNDER / F-DEFUSE-OVER | Noise leaked in or target was dropped | **0/12** | — |
| F-CLUSTER-OVER | Co-tenancy falsely linked | **0/12** | — |
| F-BUDGET | Over-ran tool / turn budget | **0/12** | — |
| F-HALLUCINATION | Attribution without tool evidence | **0/12** | — (prior run: 1) |
| F-SCHEMA | Report schema / required fields missing | **0/12** | — |

## Per-case classification

| Case | Codes (severity order) | Root cause |
|-----:|:-----------------------|:-----------|
|  1 | F-REPORT(partial), F-SRC-ABSENT | Report summary omits primary marker "reverse-whois" even though the pivot tradecraft was executed. 5 registrant-cluster domains not surfaced (no reverse-WHOIS tool → approximations via `urlscan` / `mnemonic` not explored). |
|  2 | F-PIVOT-MISS, F-REPORT(partial) | Phase 1 agent bailed after 2 CTI calls; phase 2 re-ran `virustotal_file`/`malwarebazaar_hash` instead of the missing `threatfox_search`/`otx_file`. JARM-sibling pivot never fired. |
|  3 | F-PIVOT-MISS, F-SRC-ABSENT | `opmanager.pro` + sibling SEO decoys not pivoted; `virustotal_resolutions_domain` did run but the 3 C2 IPs (109.205.x, 188.40.x, 172.96.x) came from ThreatFox, which was not queried. |
|  4 | OK | Passed — Cloudflare-tunnel behaviour handled correctly via R14. |
|  5 | F-REPORT, F-SRC-ABSENT | Eye Pyramid / Rhysida / Vice-Society / BlackCat attributions present in OTX pulses but never lifted into the report summary. ASN fingerprint sibling search not run. |
|  6 | F-PIVOT-MISS(partial) | "About Cats" content fingerprint pivot missing — `urlscan_search page.title` on the post title + `crt.sh` by SSL SHA1 never executed. |
|  7 | F-REPORT, F-PIVOT-MISS | Only 4 CTI calls, zero threat-intel queries. Keitaro TDS sibling search and SocGholish stage-2 DNS both missed. |
|  8 | F-SRC-ABSENT | AS51381 ASN node + `gitlab.bzctoons.net` apex not surfaced (cert-SAN pivot skipped). Report names Amadey+StealC correctly. |
|  9 | OK | Passed — Tycoon 2FA cert-SAN burst pivot executed cleanly. |
| 10 | F-PIVOT-MISS, F-REPORT, F-SRC-ABSENT | DNS TXT/MX on `lianxinxiao.com` never run → `blocknovas.com` pivot missed. Wayback not queried. Report missed entire DPRK attribution chain. |
| 11 | OK | Passed — R14 Cloudflare origin-unmask + NS cluster correctly surfaced. |
| 12 | OK | Passed — ClearFake cert-CN → Shodan origin-unmask executed. |

## Top 3 systemic failure modes

1. **Report surface quality (affects 5–7 cases)** — the agent runs the right
   tools but the report summary does not name the discriminating marker by
   exact value (JARM fingerprint, cert-CN, page title, registrant email) and
   does not list all actor/family aliases that appear in node metadata. This
   costs ~10–30 overall points per affected case.
2. **Premature phase-1 termination + phase-2 tool-repetition** — Case 2
   stopped at 2 calls, Case 7 at 4. Phase 2 should recover but re-runs already
   executed tools instead of the ones flagged missing.
3. **Missed secondary-source pivots** — ThreatFox family search, DNS TXT/MX
   records, Wayback archive lookups, `urlscan_search` by page title. These
   are the low-cost, high-yield pivots that unlock multi-seed campaigns
   (Cases 3, 5, 6, 7, 10).
