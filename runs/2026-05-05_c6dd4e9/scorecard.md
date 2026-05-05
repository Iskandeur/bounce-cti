# EVAL_PROTOCOL Scorecard — 2026-05-05 · commit c6dd4e9

**Run environment**
- Branch: `claude/friendly-edison-vhVPv` (local), against `main` deployed VPS at https://bounce.alexandre-pinoteau.fr/
- Model: `opus-4.7` (only model whitelisted on the eval account)
- Mode: full 12 cases, parallel submission via `asyncio.create_task` over 12 WebSockets
- Wall time: ~14 min for first 10 cases, ~14.5 min for the longest (case 5)
- Case 11 seed: `usps.com-redeliveryinfo.top` — picked best-effort against the Smishing-Triad pattern (NameSilo + Cloudflare-front + USPS lure + .top TLD), distinct from prior `usps.com-tracksun.top` (Apr-20 baseline). **Live freshness not verified** (sandbox DNS blocked); see deltas.md case 11 for impact.

## Scorecard

| Case | Status | NR   | ER    | PC   | DC  | BD  | RQ  | Overall | Calls | Hypothesis path |
|-----:|:------:|-----:|------:|-----:|----:|----:|----:|--------:|------:|:----------------|
|  1 | done | 41.7 |   0.0 | 50.0 | 100 | 100 | 40 |  55.3 | 12 | absent (regression vs 76fbe4c) |
|  2 | done | 62.5 |   0.0 | 50.0 | 100 | 100 | 40 |  58.8 |  3 | absent — only 3 cti calls (rate-limited?) |
|  3 | done | 35.7 |  50.0 | 50.0 | 100 | 100 | 40 |  62.6 |  5 | absent |
|  4 | done | 20.0 |   n/a | 80.0 | 100 | 100 | 40 |  68.0 | 31 | **commodity_malware** (1→2 transitions) |
|  5 | done | 10.0 |   n/a | 75.0 | 100 |  50 | 40 |  55.0 | 37 | **traffer_or_tds** (4 entries) — depth=4 hits BD 50 |
|  6 | done | 40.0 |   n/a | 25.0 | 100 | 100 | 40 |  61.0 |  7 | absent |
|  7 | done |  8.3 |   0.0 | 60.0 | 100 | 100 |  0 |  44.7 |  7 | absent (regression vs 76fbe4c hypofirst) |
|  8 | done | 50.0 |  50.0 | 50.0 | 100 | 100 | 40 |  65.0 |  5 | absent |
|  9 | done | 33.3 |   n/a | 50.0 | 100 | 100 | 40 |  64.7 |  8 | absent |
| 10 | done |  7.7 |   0.0 | 20.0 | 100 | 100 |  0 |  37.9 |  8 | **unclear** (2 entries) — but pivots still missed |
| 11 | done |  0.0 |   n/a | 60.0 | 100 | 100 |  0 |  52.0 |  7 | absent |
| 12 | done | 20.0 |   n/a | 25.0 | 100 | 100 | 70 |  63.0 |  8 | absent |

All 12 cases reached `done` cleanly. No borderline `rc=1 has_report=true` terminals this run.

## Aggregate metrics

| Metric                                       | Target           | This run           | Apr-20 baseline      | Δ |
|----------------------------------------------|-----------------:|-------------------:|---------------------:|---:|
| Overall (mean)                               | ≥ 65             | **57.3**          | 57.9                 | **−0.6** ❌ |
| Pass rate (overall ≥ 70)                     | ≥ 60 %           | **0/12 (0 %)**     | 3/12 (25 %)          | **−25 pp** ❌ |
| Hallucination rate                           | **0 % hard gate**| **0 %** ✅        | 0 %                  | = ✅ |
| Defuse floor (mean DC on cases 4/6/11/12)    | ≥ 75             | **100**            | 100                  | = ✅ |
| Coverage floor (no marker < 40 on primary)   | enforced         | breached: cases 7, 10, 11, 12 | breached: 6+ markers |  partial improvement |
| Working_hypothesis present                   | trend → 12/12    | **3/12** (4, 5, 10)| n/a (new metric)     | — |
| Phase 3 tools used                           | trend ↑          | **2/12 cases use any** (4, 5)| n/a (new metric) | regression vs hypofirst smoke |
| ER aggregate (excluding null-denom)          | n/a              | 16.7 (n=6)         | n/a                 | — |

**Verdict**: regression on the headline number (mean and pass rate). Hallucination gate cleared, defuse floor intact. The hypothesis-first behaviour did not consistently fire — 9/12 cases lack the `working_hypothesis` node — and Phase 3 tools were used in only 2/12 cases. The agent terminated phase_main extremely early (median 7 cti calls; 7 cases ≤ 8 calls).

## Delta vs prior runs

Per-case overall vs Apr-20 (full-12 baseline) and 2026-05-04 smoke runs:

| Case | Apr-20 | 2026-05-04 smoke / hypofirst | This run | Δ vs Apr-20 |
|-----:|-------:|----------------------------:|---------:|------------:|
|  1   | 51.1   | 74.4 (76fbe4c hypofirst)     |  55.3    | +4.2  |
|  2   | 47.9   | 72.6 (610baac)               |  58.8    | +10.9 |
|  3   | 54.3   | 69.0 (610baac)               |  62.6    | +8.3  |
|  4   | 70.0   | —                            |  68.0    | −2.0  |
|  5   | 60.0   | —                            |  55.0    | −5.0  |
|  6   | 67.5   | —                            |  61.0    | −6.5  |
|  7   | 48.1   | 57.5 (76fbe4c hypofirst)     |  44.7    | −3.4  |
|  8   | 54.2   | —                            |  65.0    | +10.8 |
|  9   | 70.5   | —                            |  64.7    | −5.8  |
| 10   | 37.9   | —                            |  37.9    |  ±0   |
| 11   | 60.8   | —                            |  52.0    | −8.8  (different seed; new seed had no telemetry) |
| 12   | 72.5   | —                            |  63.0    | −9.5  |

**Regressions vs 76fbe4c hypofirst smoke**:
- Case 1: 74.4 → **55.3** (−19.1). Working_hypothesis loop did NOT fire this run; only 2 pivots executed; whoxy_reverse/Phase 3 absent.
- Case 7: 57.5 → **44.7** (−12.8). 7 cti calls vs 68 prior; vt pdns hint did not surface co-resolvers; report blob too short for actor mention.

The hypofirst behaviour is not stable — it fires on ~25 % of runs against the same seed. The on-disk system prompt has the loop, but the agent at runtime only sometimes follows the OBSERVE → HYPOTHESIZE → PURSUE → RE-EVALUATE → SELF_CRITIQUE arc. **This is a behaviour drift, not a regression in code.** It is the central failure mode this iteration must address.

## What still blocks the thresholds

1. **F-EARLY-TERMINATION (9/12 cases)** — phase_main_exit at 3–12 cti calls. Agent quits before drainage of the pivot queue, before working_hypothesis, before Phase 3.
2. **F-HYPOTHESIS-ABSENT (9/12 cases)** — `working_hypothesis` report node not written. Direct mechanical regression — the system prompt "should" enforce it but isn't.
3. **F-PIVOT-MISS::shodan_cert_cn (case 12)** — R14 origin-unmask still ignored after 1+ year of being a documented gap.
4. **F-PIVOT-MISS::dns_txt_mx_cross_ref (case 10)** — `dns_resolve(<reverse_dns_result>, "MX/TXT")` not chained from `reverse_dns`. The whole BlockNovas cluster invisible.
5. **F-PIVOT-MISS::reverse_whois_email (case 1)** — registrar GMO/Onamae extracted but no cleartext registrant email surfaced in RDAP for Whoxy pivot.
6. **F-PIVOT-MISS::content_fingerprint (case 6)** — urlscan/dom_fingerprints never called on the seed — LummaC2 "About Cats" landing-page cluster invisible.

## Borderline & throttle flags

- **Case 5** depth=4 → BD 50 by V2.1 spec (37 calls but BFS reached length 4). Per-spec, not a code bug.
- No agent_rate_limit_event came in throttling state on any case (`status=allowed`, `isUsingOverage=false` everywhere). Median CTI per case is 7 — this is **agent decision, not API throttle**.
- Case 11 seed was a guess that produced no live telemetry (RDAP 404 on the .top registry, VT/OTX/threatfox empty). Treat its NR=0 as F-SEED-DEAD, not F-PIVOT-MISS. Methodology note recorded in runner constant.

## Hand audit (hallucination check, second pass)

Heuristic = 0 across all 12 cases. Hand audit on the largest graphs (cases 1, 4, 5, 8 — each > 14 nodes):
- Case 1 — `actor: <none>` graph node. Salt Typhoon / Earth Estries / APT29 / UNC4841 are listed in `report.metadata.threat_actors`. Each is sourced from the OTX pulse list (visible in event_corpus). Several appear together in pulses. The "APT29" inclusion is a borderline call — APT29 is not Salt Typhoon — but it's in the pulse names so it's not fabricated. Confidence: not a hallucination.
- Case 4 — Interlock C2 + ClickFix nodes all sourced from threatfox / VT relationships. No fabrication.
- Case 5 — Multiple ransomware family nodes (Rhysida, Vice Society, BlackCat, RansomHub, Fog) are in the report metadata; checked against threatfox tags returned for the 195.177.95.163 cluster — all corroborated.
- Case 8 — Amadey / StealC family + AS51381 ELITETEAM tagging — corroborated by VT/OTX in the event log.

**Halluc gate: still cleared.**
