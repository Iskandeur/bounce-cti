# EVAL_PROTOCOL_V2 Scorecard — 2026-04-19 · commit 20ba0ef

**Run environment**
- Target: https://bounce.alexandre-pinoteau.fr/
- Model: `opus-4.7` (account whitelist — protocol default `sonnet` unavailable to this user)
- Mode: all 12 cases submitted in parallel via `POST /api/investigations`
- Wall time to last terminal status: **~6 min** for 11/12 cases, **~7 min** for case 1
- Each case ran phase_main; cases 4–9 also ran phase_followup; case 10 phase_followup flagged `phase2_incomplete`

| Case | Status | NR | ER | PC | DC | BD | RQ | Overall | Calls | Depth | Top failure |
|-----:|:------:|---:|---:|---:|---:|---:|---:|--------:|------:|------:|:------------|
| 1  | done | 11.1 | 0.0  | 50.0 | 100 | 100 | 40 | 50.2 | 12 | 2 | F-CLUSTER-OVER + F-SRC-ABSENT (reverse-WHOIS) |
| 2  | done | 33.3 | 0.0  | 25.0 | 100 | 100 | 70 | 54.7 |  4 | 3 | F-PIVOT-MISS (JARM / Shodan not fired) |
| 3  | done | 26.7 | 0.0  | 50.0 | 100 | 100 | 70 | 57.8 |  6 | 1 | F-PIVOT-MISS (no pDNS on `opmanager.pro`; no three-tier split) |
| 4  | done | 13.3 | 0.0  | 20.0 | 100 | 100 |  0 | 38.9 |  7 | 0 | F-REPORT + F-PIVOT-MISS (no ClickFix URLScan; no trycloudflare triage) |
| 5  | done |  4.5 | 0.0  | 25.0 | 100 | 100 |  0 | 38.3 |  7 | 0 | F-REPORT + F-PIVOT-MISS (wrong ASNs surfaced; no Eye Pyramid banner) |
| 6  | done |  3.4 | 0.0  | 50.0 | 100 | 100 |  0 | 42.2 |  7 | 1 | F-REPORT + F-PIVOT-MISS (no content-fingerprint / crt.sh SHA1) |
| 7  | done | 15.4 | 12.5 |  0.0 | 100 | 100 |  0 | 38.0 |  6 | 1 | F-REPORT + F-PIVOT-MISS (no stage-2 DNS; no Keitaro pivot) |
| 8  | done | 33.3 | 14.3 | 25.0 | 100 | 100 |  0 | 45.4 |  4 | 0 | F-REPORT + F-PIVOT-MISS (no cert-SAN apex check; no Amadey hub) |
| 9  | done |  4.0 | 0.0  | 50.0 | 100 | 100 |  0 | 42.3 |  7 | 1 | F-REPORT + F-PIVOT-MISS (no CT burst-window query) |
| 10 | done |  7.7 | 0.0  | 20.0 | 100 | 100 | 40 | 44.6 |  7 | 2 | F-PIVOT-MISS (no DNS TXT/MX on `lianxinxiao`; no Wayback) |
| 11 | done |  4.0 | 0.0  | 60.0 | 100 | 100 |  0 | 44.0 | 13 | 2 | F-REPORT (scorer harsh on feed-specific GT; qualitative result better) |
| 12 | done | 25.0 | 0.0  | 25.0 | 100 | 100 | 40 | 48.3 | 23 | 3 | F-PIVOT-MISS (no `ssl.cert.subject.CN:"…"` Shodan query for YACOLO-AS) |

## Aggregate metrics

| Metric | Target | Observed | Verdict |
|--------|-------:|---------:|:-------:|
| Overall score (mean) | ≥ 65 | **45.4** | ❌ FAIL |
| Pass rate (overall ≥ 70) | ≥ 60 % | **0 %** | ❌ FAIL |
| Hallucination rate | **0 % (hard gate)** | See §hallucinations below | ⚠ see note |
| Defuse floor (mean DC on 4/6/11/12) | ≥ 75 | **100** | ✅ PASS |
| Coverage floor (no marker < 40 on primary) | enforced | Markers below 40: **CT-burst, DNS TXT/MX, Cert-CN→Shodan, reverse-WHOIS, JARM, content-fingerprint** | ❌ FAIL |

## Protocol deviations

1. **Model**: test account permitted only `opus-4.7` (not `sonnet`). This is stronger than sonnet, so failures are not attributable to model capability.
2. **Case 11 seed**: `usps.com-posewxts.top` picked via OSINT (Unit42 global smishing writeup). Freshness not independently verified against Silent Push IOFA feed (no access). The agent did surface 14 plausible Smishing-Triad siblings + NameSilo + an AS132203 Tencent origin candidate, so the seed had residue. Scorer is harsh because NR denom is 50 from the protocol's per-feed cap.
3. **Scorer credits actor/malware names found in node tags** (not just dedicated actor-type nodes), since the agent writes those attributions as tags. This is a reasonable read of the protocol, which calls for "loose matching on relation names".

## Hallucination audit

Hot-spot hand audits (Cases 1, 5, 12):

- **Case 1**: The graph clusters `coinbase-wallet.co`, `yesbamk.in`, `o2vertragsservice.de` as `phishing_lookalike` siblings via co-residency on IP `193.239.84.207`. These are unrelated multi-tenant neighbours on a shared-hosting IP. The report node "APT34/OilRig & Saitama backdoor — co-resident IOCs on M247" attributes them to a **completely different APT** from Salt Typhoon — that is **F-CLUSTER-OVER** and borderline **F-HALLUCINATION** (the attribution is not supported by any tool output). Marked as a critical finding.
- **Case 5**: Found ASN `AS212238`, `AS214961` rather than the expected Eye Pyramid ASNs (`AS214943` Railnet, `AS215540` GCS, `AS215439` Play2Go). Unclear if these are real VT neighbours or hallucinated. Requires manual evidence inspection before ruling hallucination.
- **Case 12**: All surfaced nodes are supported by tool outputs (Cloudflare IPs correctly tagged `cdn`, Hetzner ASN legitimate, OTX `clearfake` report sourced from OTX). No hallucinations spotted.

**Provisional hallucination rate: 1 / 12 cases (Case 1 APT34 report)** → **breaches the 0 % hard gate**. Recommend a manual re-inspection of the Case 1 report node's sources; if it came from a literal OTX pulse titled "APT34/OilRig & Saitama", then it's not strictly a hallucination but a misapplied attribution (tool found an unrelated IOC and glued it to the seed). Either way, the system prompt must reject this linkage pattern.

## Raw artifacts

All 12 cases' graphs, event streams, and run metadata are in
`/tmp/eval_run/artifacts/case_<NN>/`:
- `graph.json` — final graph (nodes, edges)
- `events.jsonl` — complete WebSocket event stream (every tool call, every status change)
- `meta.json`, `status.json` — submission meta
