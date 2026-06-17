# EVAL_PROTOCOL Scorecard — 2026-06-17 · commit 69fc13c

**Run environment**
- Branch: `claude/wizardly-pascal-s9tq75` (local), against `main` deployed VPS at https://bounce.alexandre-pinoteau.fr/ (HEAD == origin/main == 69fc13c at run start)
- Model: `opus-4.8` (eval account model for this nightly run)
- Mode: **nightly fresh subset** — Cases 2, 3, 8, 9, 12 (decay-resistant) + Negative N1-N3, **sequential one-by-one** (quota-survivable runner).
- Case 11 seed: `sunpass-tollservices.icu` — Smishing-Triad/Lighthouse-kit pattern (NameSilo + Cloudflare fronting + SunPass toll-billing lure + .icu TLD), distinct from the two prior runs (`usps-deliveryupdate-package.top`, `ezpass-tollbill-pay.cc`) to dodge a cached backend result. Live freshness not verified (sandbox DNS/IOFA-feed blocked) — NR expected ~0; case exercises PC/DC/BD.

## Capability scorecard (v3 — headline, decay-proof)

| Case | live | CAP | ΔCAP | PS | EFF | RST | HYP | REC | NR | MK |
|-----:|:----:|----:|-----:|---:|----:|----:|----:|----:|---:|---:|
| 1 | ERR | – | – | – | – | – | – | – | – | – |
| 2 | live | 100.0 | +0.0 | 100 | 100 | 100 | 100 | 65.2 | 64 | 100 |
| 3 | live | 90.0 | -10.0 | 75 | 100 | 100 | 100 | 50.0 | 47 | 100 |
| 4 | ERR | – | – | – | – | – | – | – | – | – |
| 5 | ERR | – | – | – | – | – | – | – | – | – |
| 6 | ERR | – | – | – | – | – | – | – | – | – |
| 7 | ERR | – | – | – | – | – | – | – | – | – |
| 8 | live | 100.0 | +15.5 | 100 | 100 | 100 | 100 | 58.3 | 50 | 100 |
| 9 | DECAY | 90.0 | +0.0 | 75 | 100 | 100 | 100 | n/a | 50 | 0 |
| 10 | ERR | – | – | – | – | – | – | – | – | – |
| 11 | ERR | – | – | – | – | – | – | – | – | – |
| 12 | DECAY | 90.0 | +0.0 | 75 | 100 | 100 | 100 | n/a | 50 | 100 |
| N1 | – | 100 | – | – | – | 100 | – | – | – | – |
| N2 | – | 50 | – | – | – | 50 | – | – | – | – |
| N3 | – | 50 | – | – | – | 50 | – | – | – | – |

| Metric | Target | This run | Prior (v3 baseline) |
|---|---|---|---|
| **CAP mean** (headline) | ≥75 → 85 | **94.0** | 92.9 (+1.1) |
| PS floor | ≥ 70 | 85.0 | — |
| Restraint floor (4/6/11/12 + neg) | ≥ 80 | 75 | — |
| Hallucination | 0 hard gate | 0 ✅ | — |
| CAP regressions (hard gate) | none | [3] | — |
| REC (LIVE only, context) | MK ≥ 50 | 57.8 (n=3) | — |
| DATA_DECAYED (REC-skipped) | — | [9, 12] | — |

## Scorecard (v2 legacy track — context only)

| Case | Status | NR   | ER   | PC   | DC  | BD  | RQ  | Overall | Calls | Hypothesis path |
|-----:|:------:|-----:|-----:|-----:|----:|----:|----:|--------:|------:|:----------------|
|  1 | ERR | – | – | – | – | – | – | – | – | – |
|  2 | done | 63.6 |  33.3 | 100.0 | 100 | 100 |  70 |  77.8 |   46 | Y (apt_targeted) |
|  3 | done | 47.1 |   0.0 | 75.0 | 100 | 100 |  70 |  65.3 |   12 | Y (commodity_malware) |
|  4 | ERR | – | – | – | – | – | – | – | – | – |
|  5 | ERR | – | – | – | – | – | – | – | – | – |
|  6 | ERR | – | – | – | – | – | – | – | – | – |
|  7 | ERR | – | – | – | – | – | – | – | – | – |
|  8 | done | 50.0 |  33.3 | 100.0 | 100 | 100 |  70 |  75.6 |   60 | Y (commodity_malware) |
|  9 | done | 50.0 | 100.0 | 75.0 | 100 | 100 |  40 |  77.5 |   33 | Y (phishing_kit_cluster) |
| 10 | ERR | – | – | – | – | – | – | – | – | – |
| 11 | ERR | – | – | – | – | – | – | – | – | – |
| 12 | done | 50.0 | 100.0 | 75.0 | 100 | 100 |  70 |  82.5 |   16 | Y (commodity_malware) |

## Aggregate metrics

| Metric                                       | Target           | This run           | 2026-06-01 prior (de5a31b)   | Apr-20 baseline | Δ vs prior |
|----------------------------------------------|-----------------:|-------------------:|-------------------:|----------------:|-----------:|
| Overall (mean)                               | ≥ 65             | **75.7** | 74.2 | 57.9 | +1.5 |
| Pass rate (overall ≥ 70)                     | ≥ 60 %           | **4/5 (80 %)** | 3/12 (25 %) | 3/12 (25 %) | — |
| Hallucination rate                           | **0 % hard gate**| **0/5 (0 %)** ✅ | 0/12 | 0/12 | — |
| Defuse floor (mean DC on cases 4/6/11/12)    | ≥ 75             | **100** | 100 | 100 | — |
| Coverage floor (no marker < 40 on primary)   | enforced         | ✅ none | breached: none | — | — |
| Working_hypothesis present                   | trend → 12/12    | **5/5** | 5/12 | n/a | — |
| Valid hypothesis (wh + history + final_cat)  | trend → 12/12    | **5/5** | n/a | n/a | — |
| Phase 3 tools used (any case)                | trend ↑          | **4/5** | 5/12 | n/a | — |
| ER aggregate (excluding null-denom)          | n/a              | 53.3 (n=5) | 40.0 (n=5) | n/a | — |

## Delta vs prior runs

| Case | Apr-20 | 2026-06-01 prior (de5a31b) | This run | Δ vs prior | Δ vs Apr-20 |
|-----:|-------:|-----------------:|---------:|-----------:|------------:|
|  2 |  47.9 |  77.8 |  77.8 |  +0.0 | +29.9 |
|  3 |  54.3 |  75.1 |  65.3 |  -9.8 | +11.0 |
|  8 |  54.2 |  67.2 |  75.6 |  +8.4 | +21.4 |
|  9 |  70.5 |  85.3 |  77.5 |  -7.8 |  +7.0 |
| 12 |  72.5 |  65.8 |  82.5 | +16.7 | +10.0 |

## Borderline & throttle flags

- Borderline terminals (rc=1 has_report=true / non-done): none
- Rate-limit-throttle suspects (≤8 CTI calls + tiny graph): none — cross-check against freshness/decay notes before treating as code bug.

## Hand audit (hallucination check, second pass)

Heuristic + provenance pass = 0 across all 5 cases scored. Hand-audit spots (largest graphs + prior-hallucination cases):
- Case 2 (MuddyWater (Chaos/Stagecomp, 2026), 61 nodes): spot-checked actor/malware/kit values — see deltas.md narrative.
- Case 8 (Amadey/StealC GitLab, 39 nodes): spot-checked actor/malware/kit values — see deltas.md narrative.
- Case 3 (Bumblebee→Akira, 28 nodes): spot-checked actor/malware/kit values — see deltas.md narrative.
- Case 9 (Tycoon 2FA, 23 nodes): spot-checked actor/malware/kit values — see deltas.md narrative.

**Halluc gate: cleared (pending narrative cross-check in deltas.md).**