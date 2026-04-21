# EVAL_PROTOCOL_V2 Scorecard — 2026-04-20 · commit 46e59dc

**Run environment**
- Target: https://bounce.alexandre-pinoteau.fr/
- Model: `opus-4.7` (account-whitelist constraint; protocol default `sonnet` not available to this user)
- Mode: all 12 cases submitted in parallel via `POST /api/investigations`
- Wall time to last terminal status: ~21 min for all 12 cases
- Each case ran phase_main → phase_followup → (when needed) phase_report_write fallback
- Case 11 seed: `usps.com-tracksun.top` (different from prior run's `usps.com-posewxts.top`, picked best-effort by OSINT — DNS/crt.sh blocked from sandbox so freshness not independently verified)

| Case | Status | NR   | ER    | PC   | DC  | BD  | RQ  | Overall | Calls | Top failure |
|-----:|:------:|-----:|------:|-----:|----:|----:|----:|--------:|------:|:------------|
| 1  | done | 41.7 |   0.0 | 25.0 | 100 | 100 | 40 | 51.1 |  9 | F-PIVOT-MISS::reverse_whois_email + F-NODE-RECALL (sibling domains never enumerated) |
| 2  | done | 62.5 |   0.0 | 25.0 | 100 | 100 |  0 | 47.9 |  2 | F-EARLY-TERMINATION (only 2 CTI calls before report) + F-PIVOT-MISS::jarm_search |
| 3  | done | 35.7 |   0.0 | 50.0 | 100 | 100 | 40 | 54.3 |  5 | F-PIVOT-MISS::vt_pdns_opmanager + F-NODE-RECALL (decoy SEO domains missed) |
| 4  | done | 20.0 | 100.0 | 60.0 | 100 | 100 | 40 | 70.0 |  7 | F-NODE-RECALL (sibling Cloudflare-Tunnel IPs missed) |
| 5  | done | 10.0 | 100.0 | 50.0 | 100 | 100 |  0 | 60.0 |  7 | F-NODE-RECALL (Eye Pyramid ASNs not surfaced) + F-REPORT |
| 6  | done | 40.0 | 100.0 | 25.0 | 100 | 100 | 40 | 67.5 |  6 | F-PIVOT-MISS::content_fingerprint + F-PIVOT-MISS::crtsh_sha1_cluster |
| 7  | done |  8.3 |   0.0 | 80.0 | 100 | 100 |  0 | 48.1 |  9 | F-NODE-RECALL (33 nodes graphed but stage-2 host-only domains/ports not GT-matchable) + F-REPORT |
| 8  | done | 50.0 |   0.0 | 75.0 | 100 | 100 |  0 | 54.2 | 12 | F-PIVOT-MISS::cert_san_apex (apex/subdomain split not done) + F-REPORT |
| 9  | done | 33.3 | 100.0 | 50.0 | 100 | 100 | 40 | 70.5 |  8 | F-PIVOT-MISS::ct_burst_window |
| 10 | done |  7.7 |   0.0 | 20.0 | 100 | 100 |  0 | 37.9 |  7 | F-PIVOT-MISS x4 (no reverse_dns_seed, no DNS-TXT/MX, no crtsh-blocknovas, no Wayback) |
| 11 | done | 25.0 | 100.0 | 40.0 | 100 | 100 |  0 | 60.8 |  6 | F-PIVOT-MISS::origin_banner_search + F-REPORT (registrant/kit not graphed) |
| 12 | done | 40.0 | 100.0 | 25.0 | 100 | 100 | 70 | 72.5 |  7 | F-PIVOT-MISS::shodan_cert_cn (R14 origin-unmask query not fired) |

## Aggregate metrics

| Metric | Target | Observed (this run) | Prior run (2026-04-19_20ba0ef) | Verdict |
|--------|-------:|--------------------:|-------------------------------:|:-------:|
| Overall score (mean)       | ≥ 65 | **57.9** | 45.4 | ❌ FAIL (+12.5) |
| Pass rate (overall ≥ 70)   | ≥ 60 % | **25 %** (3/12: cases 4, 9, 12) | 0 % | ❌ FAIL (+25 pp) |
| Hallucination rate         | **0 % hard gate** | **0 %** by automated heuristic | 1/12 (Case 1 APT34 misattribution) | ✅ **GATE CLEARED** |
| Defuse floor (mean DC on 4/6/11/12) | ≥ 75 | **100** | 100 | ✅ PASS |
| Coverage floor (no marker < 40 on primary) | enforced | Markers below 40: **CT-burst, content-fingerprint, cert-CN→Shodan, reverse-WHOIS, JARM, reverse-DNS, urlscan-clickfix, urlscan-DOM** | same 6+ | ❌ FAIL |

## Headline movement vs. prior run (commit 20ba0ef)

1. **Hallucination gate cleared.** Prior run's Case 1 hallucination (Salt Typhoon seed mis-attributed to APT34/OilRig via M247 co-residency) is gone. New Case 1 report attributes only to Salt Typhoon / Earth Estries / DEMODEX / SNAPPYBEE / GHOSTSPIDER and lists historical IPs as neutral observations without sibling-clustering them. **R12 (no co-tenancy clustering) and R13 (no cross-campaign attribution merge) added in the prior fix held.**
2. **Mean overall score +12.5** (45.4 → 57.9). All 12 cases came in higher or roughly equal vs. the prior run on the same seed (except Case 11 which used a different seed).
3. **First passing cases ever**: cases 4 (Cloudflare-Tunnel/Interlock), 9 (Tycoon 2FA), and 12 (ClearFake) crossed the 70-overall threshold.
4. **Edge recall**: 6/12 cases now hit 100% (vs. 1/12 prior). Edges are simpler to score — when the agent does pivot, it now correctly emits the seed→IP / domain→IP edges.

## What still blocks the thresholds

- **F-EARLY-TERMINATION** is the dominant failure pattern. Median CTI tool count per case is 7 (range 2–12). The agent calls the *minimum* mandatory toolset and then writes a report instead of executing the second-tier pivots (`reverse_dns`, `dns_resolve` for TXT/MX, `wayback`, `urlscan_search` content-fingerprint queries, `shodan_search('ssl.cert.subject.CN:...')`).
- **F-PIVOT-MISS::rdap_seed** in 4 cases (1, 4, 5, 6). RDAP is not in the mandatory-tools list — the followup phase doesn't catch it. Easy fix.
- **F-REPORT** failed (RQ < 70) in 11/12 cases. The report nearly always names the seed and lists the actor, but rarely names the *exact* discriminating marker string (cert SHA1, JARM, registrant email) verbatim. The phase3_report_write prompt asks for it but the model produces paraphrases.

## Protocol deviations

1. **Model**: test account permitted only `opus-4.7` (not `sonnet`). This is stronger than sonnet, so failures are not attributable to model capability.
2. **Case 11 seed**: `usps.com-tracksun.top` selected via OSINT pattern matching on Smishing-Triad TTPs (NameSilo + Cloudflare front + .top + USPS lure) and chosen to differ from the prior run's seed to dodge cache. Freshness not independently verified — DNS resolution and crt.sh were intermittently blocked from this sandbox network.
3. **Scorer credits actor/malware names found in node tags and metadata** (not just dedicated actor-type nodes), since the agent writes some attributions as tags. This is a reasonable read of the protocol's "loose matching on relation names".
4. **Hallucination check is automated heuristic** (suspect actor/malware nodes whose value never appears in any tool result) — this run reports 0 such suspects. A hand audit of Cases 1, 5, 12 confirmed no fabricated attributions; Case 1's `Salt Typhoon` actor node, the three `DEMODEX/SNAPPYBEE/GHOSTSPIDER` malware nodes, and all historical IPs are sourced from OTX pulses present in the event log.

## Raw artifacts

All 12 cases' graphs, event streams, and run metadata are in
`/tmp/eval_run/artifacts/case_<NN>/`:
- `graph.json` — final graph (nodes, edges)
- `events.jsonl` — complete WebSocket event stream (every tool call, every status change)
- `meta.json`, `status.json` — submission meta
- `snapshot.json` — most recent server-side snapshot
