# EVAL_PROTOCOL Scorecard — 2026-05-31 · commit 6e6aaeb

**Run environment**
- Branch: `claude/elegant-mendel-hvOvJ` (local), against `main` deployed VPS at https://bounce.alexandre-pinoteau.fr/ (HEAD == origin/main == 6e6aaeb at run start)
- Model: `opus-4.7` (only model whitelisted on the eval account)
- Mode: full 12 cases, **sequential one-by-one** submission (user EXCEPTIONAL MEASURE: avoid the shared 5-hour Anthropic quota burn-down; quota-survivable runner waits + resumes in place).
- Case 11 seed: `sunpass-tollservices.icu` — Smishing-Triad/Lighthouse-kit pattern (NameSilo + Cloudflare fronting + SunPass toll-billing lure + .icu TLD), distinct from the two prior runs (`usps-deliveryupdate-package.top`, `ezpass-tollbill-pay.cc`) to dodge a cached backend result. Live freshness not verified (sandbox DNS/IOFA-feed blocked) — NR expected ~0; case exercises PC/DC/BD.

## Scorecard

| Case | Status | NR   | ER   | PC   | DC  | BD  | RQ  | Overall | Calls | Hypothesis path |
|-----:|:------:|-----:|-----:|-----:|----:|----:|----:|--------:|------:|:----------------|
|  1 | done | 53.3 |  16.7 | 75.0 | 100 | 100 |  70 |  69.2 |    4 | Y (apt_targeted) |
|  2 | done | 55.6 |   0.0 | 100.0 | 100 | 100 |  40 |  65.9 |   49 | Y (apt_targeted) |
|  3 | done | 47.1 |  33.3 | 100.0 | 100 |  75 |  70 |  70.9 |   74 | Y (commodity_malware) |
|  4 | done | 23.1 |   0.0 | 100.0 | 100 |  75 |  40 |  56.3 |   78 | Y (commodity_malware) |
|  5 | done | 15.4 |   0.0 | 100.0 | 100 | 100 |   0 |  52.6 |   45 | Y (commodity_malware) |
|  6 | done | 50.0 | 100.0 | 25.0 | 100 | 100 |  70 |  74.2 |    3 | Y (commodity_malware) |
|  7 | done | 41.7 |   0.0 | 100.0 | 100 | 100 |  40 |  63.6 |   48 | Y (commodity_malware) |
|  8 | done | 50.0 |  33.3 | 75.0 | 100 |   0 |  70 |  54.7 |   98 | Y (commodity_malware) |
|  9 | done | 66.7 | 100.0 | 75.0 | 100 |  75 |  70 |  81.1 |   79 | Y (phishing_kit_cluster) |
| 10 | done |  7.1 |   0.0 | 20.0 | 100 | 100 |   0 |  37.9 |   15 | Y (legitimate) |
| 11 | done | 20.0 |   n/a | 100.0 | 100 | 100 |   0 |  64.0 |   36 | Y (smishing_hub) |
| 12 | done | 62.5 | 100.0 | 50.0 | 100 | 100 |  70 |  80.4 |   11 | Y (traffer_or_tds) |

## Aggregate metrics

| Metric                                       | Target           | This run           | 2026-05-28 prior   | Apr-20 baseline | Δ vs prior |
|----------------------------------------------|-----------------:|-------------------:|-------------------:|----------------:|-----------:|
| Overall (mean)                               | ≥ 65             | **64.2** | 60.5 | 57.9 | +3.7 |
| Pass rate (overall ≥ 70)                     | ≥ 60 %           | **4/12 (33 %)** | 2/12 (17 %) | 3/12 (25 %) | +2 |
| Hallucination rate                           | **0 % hard gate**| **0/12 (0 %)** ✅ | 0/12 | 0/12 | — |
| Defuse floor (mean DC on cases 4/6/11/12)    | ≥ 75             | **100** | 100 | 100 | — |
| Coverage floor (no marker < 40 on primary)   | enforced         | breached: [4, 5, 10] | breached: [4, 5, 10] | — | — |
| Working_hypothesis present                   | trend → 12/12    | **12/12** | 12/12 | n/a | +0 |
| Valid hypothesis (wh + history + final_cat)  | trend → 12/12    | **12/12** | n/a | n/a | — |
| Phase 3 tools used (any case)                | trend ↑          | **9/12** | 10/12 | n/a | -1 |
| ER aggregate (excluding null-denom)          | n/a              | 34.8 (n=11) | 16.7 (n=6) | n/a | — |

## Delta vs prior runs

| Case | Apr-20 | 2026-05-28 prior | This run | Δ vs prior | Δ vs Apr-20 |
|-----:|-------:|-----------------:|---------:|-----------:|------------:|
|  1 |  51.1 |  56.1 |  69.2 | +13.1 | +18.1 |
|  2 |  47.9 |  61.8 |  65.9 |  +4.1 | +18.0 |
|  3 |  54.3 |  64.0 |  70.9 |  +6.9 | +16.6 |
|  4 |  70.0 |  43.8 |  56.3 | +12.5 | -13.7 |
|  5 |  60.0 |  52.6 |  52.6 |  +0.0 |  -7.4 |
|  6 |  67.5 |  82.5 |  74.2 |  -8.3 |  +6.7 |
|  7 |  48.1 |  63.6 |  63.6 |  +0.0 | +15.5 |
|  8 |  54.2 |  67.2 |  54.7 | -12.5 |  +0.5 |
|  9 |  70.5 |  60.8 |  81.1 | +20.3 | +10.6 |
| 10 |  37.9 |  41.2 |  37.9 |  -3.3 |  +0.0 |
| 11 |  60.8 |  60.0 |  64.0 |  +4.0 |  +3.2 |
| 12 |  72.5 |  72.1 |  80.4 |  +8.3 |  +7.9 |

## Borderline & throttle flags

- Borderline terminals (rc=1 has_report=true / non-done): none
- Rate-limit-throttle suspects (≤8 CTI calls + tiny graph): [1, 6] — cross-check against freshness/decay notes before treating as code bug.

## Hand audit (hallucination check, second pass)

Heuristic + provenance pass = 0 across all 12 cases. Hand-audit spots (largest graphs + prior-hallucination cases):
- Case 7 (SocGholish, 91 nodes): spot-checked actor/malware/kit values — see deltas.md narrative.
- Case 8 (Amadey/StealC GitLab, 86 nodes): spot-checked actor/malware/kit values — see deltas.md narrative.
- Case 5 (Eye Pyramid cross-brand, 73 nodes): spot-checked actor/malware/kit values — see deltas.md narrative.
- Case 2 (MuddyRot, 67 nodes): spot-checked actor/malware/kit values — see deltas.md narrative.

**Halluc gate: cleared (pending narrative cross-check in deltas.md).**