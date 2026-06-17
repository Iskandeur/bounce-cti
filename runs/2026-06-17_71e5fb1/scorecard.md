# EVAL_PROTOCOL Scorecard — 2026-06-17 · commit 71e5fb1

**Run environment**
- Branch: `claude/vigilant-mayer-3ylpgh` (local), against `main` deployed VPS at https://bounce.alexandre-pinoteau.fr/ (HEAD == origin/main == 71e5fb1 at run start)
- Model: `opus-4.8` (eval account model for this nightly run)
- Mode: **nightly fresh subset** — Cases 2, 3, 8, 9, 12 (decay-resistant) + Negative N1-N3, **sequential one-by-one** (quota-survivable runner).
- Case 11 seed: `sunpass-tollservices.icu` — Smishing-Triad/Lighthouse-kit pattern (NameSilo + Cloudflare fronting + SunPass toll-billing lure + .icu TLD), distinct from the two prior runs (`usps-deliveryupdate-package.top`, `ezpass-tollbill-pay.cc`) to dodge a cached backend result. Live freshness not verified (sandbox DNS/IOFA-feed blocked) — NR expected ~0; case exercises PC/DC/BD.

## Capability scorecard (v3 — headline, decay-proof)

| Case | live | CAP | ΔCAP | PS | EFF | RST | HYP | REC | NR | MK |
|-----:|:----:|----:|-----:|---:|----:|----:|----:|----:|---:|---:|
| 1 | ERR | – | – | – | – | – | – | – | – | – |
| 2 | live | 100.0 | +0.0 | 100 | 100 | 100 | 100 | 65.2 | 64 | 100 |
| 3 | live | 100.0 | +10.0 | 100 | 100 | 100 | 100 | 59.8 | 47 | 100 |
| 4 | ERR | – | – | – | – | – | – | – | – | – |
| 5 | ERR | – | – | – | – | – | – | – | – | – |
| 6 | ERR | – | – | – | – | – | – | – | – | – |
| 7 | ERR | – | – | – | – | – | – | – | – | – |
| 8 | live | 100.0 | +0.0 | 100 | 100 | 100 | 100 | 58.3 | 50 | 100 |
| 9 | DECAY | 90.0 | +0.0 | 75 | 100 | 100 | 100 | n/a | 50 | 0 |
| 10 | ERR | – | – | – | – | – | – | – | – | – |
| 11 | ERR | – | – | – | – | – | – | – | – | – |
| 12 | DECAY | 90.0 | +0.0 | 75 | 100 | 100 | 100 | n/a | 50 | 100 |
| N1 | – | 100 | – | – | – | 100 | – | – | – | – |
| N2 | – | 100 | – | – | – | 100 | – | – | – | – |
| N3 | – | 100 | – | – | – | 100 | – | – | – | – |

| Metric | Target | This run | Prior (v3 baseline) |
|---|---|---|---|
| **CAP mean** (headline) | ≥75 → 85 | **96.0** | 94.0 (+2.0) |
| PS floor | ≥ 70 | 90.0 | — |
| Restraint floor (4/6/11/12 + neg) | ≥ 80 | 100 | — |
| Hallucination | 0 hard gate | 0 ✅ | — |
| CAP regressions (hard gate) | none | ✅ none | — |
| REC (LIVE only, context) | MK ≥ 50 | 61.1 (n=3) | — |
| DATA_DECAYED (REC-skipped) | — | [9, 12] | — |

## Scorecard (v2 legacy track — context only)

| Case | Status | NR   | ER   | PC   | DC  | BD  | RQ  | Overall | Calls | Hypothesis path |
|-----:|:------:|-----:|-----:|-----:|----:|----:|----:|--------:|------:|:----------------|
|  1 | ERR | – | – | – | – | – | – | – | – | – |
|  2 | done | 63.6 |  33.3 | 100.0 | 100 | 100 |  70 |  77.8 |   24 | Y (apt_targeted) |
|  3 | done | 47.1 |  33.3 | 100.0 | 100 | 100 |  70 |  75.1 |   33 | Y (commodity_malware) |
|  4 | ERR | – | – | – | – | – | – | – | – | – |
|  5 | ERR | – | – | – | – | – | – | – | – | – |
|  6 | ERR | – | – | – | – | – | – | – | – | – |
|  7 | ERR | – | – | – | – | – | – | – | – | – |
|  8 | done | 50.0 |  33.3 | 100.0 | 100 | 100 |  70 |  75.6 |   58 | Y (commodity_malware) |
|  9 | done | 50.0 | 100.0 | 75.0 | 100 | 100 |  40 |  77.5 |   32 | Y (fronted_c2) |
| 10 | ERR | – | – | – | – | – | – | – | – | – |
| 11 | ERR | – | – | – | – | – | – | – | – | – |
| 12 | done | 50.0 |   0.0 | 75.0 | 100 | 100 |  70 |  65.8 |   17 | Y (commodity_malware) |

## Aggregate metrics

| Metric                                       | Target           | This run           | 2026-06-17 prior (69fc13c)   | Apr-20 baseline | Δ vs prior |
|----------------------------------------------|-----------------:|-------------------:|-------------------:|----------------:|-----------:|
| Overall (mean)                               | ≥ 65             | **74.4** | 75.7 | 57.9 | -1.3 |
| Pass rate (overall ≥ 70)                     | ≥ 60 %           | **4/5 (80 %)** | 4/12 (33 %) | 3/12 (25 %) | — |
| Hallucination rate                           | **0 % hard gate**| **0/5 (0 %)** ✅ | 0/12 | 0/12 | — |
| Defuse floor (mean DC on cases 4/6/11/12)    | ≥ 75             | **100** | 100 | 100 | — |
| Coverage floor (no marker < 40 on primary)   | enforced         | ✅ none | breached: none | — | — |
| Working_hypothesis present                   | trend → 12/12    | **5/5** | 5/12 | n/a | — |
| Valid hypothesis (wh + history + final_cat)  | trend → 12/12    | **5/5** | n/a | n/a | — |
| Phase 3 tools used (any case)                | trend ↑          | **5/5** | 4/12 | n/a | — |
| ER aggregate (excluding null-denom)          | n/a              | 40.0 (n=5) | 53.3 (n=5) | n/a | — |

## Delta vs prior runs

| Case | Apr-20 | 2026-06-17 prior (69fc13c) | This run | Δ vs prior | Δ vs Apr-20 |
|-----:|-------:|-----------------:|---------:|-----------:|------------:|
|  2 |  47.9 |  77.8 |  77.8 |  +0.0 | +29.9 |
|  3 |  54.3 |  65.3 |  75.1 |  +9.8 | +20.8 |
|  8 |  54.2 |  75.6 |  75.6 |  +0.0 | +21.4 |
|  9 |  70.5 |  77.5 |  77.5 |  +0.0 |  +7.0 |
| 12 |  72.5 |  82.5 |  65.8 | -16.7 |  -6.7 |

## Borderline & throttle flags

- Borderline terminals (rc=1 has_report=true / non-done): none
- Rate-limit-throttle suspects (≤8 CTI calls + tiny graph): none — cross-check against freshness/decay notes before treating as code bug.

## Hand audit (hallucination check, second pass)

Heuristic + provenance pass = 0 across all 5 cases scored. Hand-audit spots (largest graphs + prior-hallucination cases):
- Case 3 (Bumblebee→Akira, 36 nodes): spot-checked actor/malware/kit values — see deltas.md narrative.
- Case 8 (Amadey/StealC GitLab, 33 nodes): spot-checked actor/malware/kit values — see deltas.md narrative.
- Case 2 (MuddyWater (Chaos/Stagecomp, 2026), 25 nodes): spot-checked actor/malware/kit values — see deltas.md narrative.
- Case 12 (ClearFake, 25 nodes): spot-checked actor/malware/kit values — see deltas.md narrative.

**Halluc gate: cleared (pending narrative cross-check in deltas.md).**