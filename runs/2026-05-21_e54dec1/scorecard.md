# EVAL_PROTOCOL Scorecard — 2026-05-21 · commit e54dec1

**Run environment**
- Branch: `claude/practical-mayer-VP8Ki` (local), against `main` deployed VPS at https://bounce.alexandre-pinoteau.fr/
- Model: `opus-4.7` (only model whitelisted on the eval account)
- Mode: full 12 cases, **sequential one-by-one** submission (user-mandated to avoid 5-hour quota burn-down)
- Case 11 seed: `usps-deliveryupdate-package.top` — typical Smishing-Triad pattern (NameSilo + Cloudflare-fronted + USPS lure + .top TLD), distinct from prior runs. Live freshness not verified (sandbox DNS blocked).

## Scorecard

| Case | Status | NR   | ER   | PC   | DC  | BD  | RQ  | Overall | Calls | Hypothesis path |
|-----:|:------:|-----:|-----:|-----:|----:|----:|----:|--------:|------:|:----------------|
|  1 | done | 46.7 |   0.0 | 50.0 | 100 |   0 |  40 |  39.4 |  125 | Y (apt_targeted) |
|  2 | done | 55.6 |   0.0 | 75.0 | 100 | 100 |  40 |  61.8 |   25 | Y (apt_targeted) |
|  3 | done |  0.0 |   0.0 |  0.0 | 100 | 100 |   0 |  33.3 |    0 | absent ((none)) |
|  4 | done |  0.0 |   0.0 |  0.0 | 100 | 100 |   0 |  33.3 |    0 | absent ((none)) |
|  5 | done |  0.0 |   0.0 |  0.0 | 100 | 100 |   0 |  33.3 |    0 | absent ((none)) |
|  6 | done |  0.0 |   0.0 |  0.0 | 100 | 100 |   0 |  33.3 |    0 | absent ((none)) |
|  7 | done |  0.0 |   0.0 |  0.0 | 100 | 100 |   0 |  33.3 |    0 | absent ((none)) |
|  8 | done |  0.0 |   0.0 |  0.0 | 100 | 100 |   0 |  33.3 |    0 | absent ((none)) |
|  9 | done |  0.0 |   0.0 |  0.0 | 100 | 100 |   0 |  33.3 |    0 | absent ((none)) |
| 10 | done |  0.0 |   0.0 |  0.0 | 100 | 100 |   0 |  33.3 |    0 | absent ((none)) |
| 11 | done |  0.0 |   n/a |  0.0 | 100 | 100 |   0 |  40.0 |    0 | absent ((none)) |
| 12 | done |  0.0 |   0.0 |  0.0 | 100 | 100 |   0 |  33.3 |    0 | absent ((none)) |

## Aggregate metrics

| Metric                                       | Target           | This run           | 2026-05-06 prior   | Apr-20 baseline | Δ vs prior |
|----------------------------------------------|-----------------:|-------------------:|-------------------:|----------------:|-----------:|
| Overall (mean)                               | ≥ 65             | **36.7** | 60.8 | 57.9 | -24.1 |
| Pass rate (overall ≥ 70)                     | ≥ 60 %           | **0/12 (0 %)** | 3/12 (25 %) | 3/12 (25 %) | -3 |
| Hallucination rate                           | **0 % hard gate**| **0/12 (0 %)** ✅ | 0/12 | 0/12 | — |
| Defuse floor (mean DC on cases 4/6/11/12)    | ≥ 75             | **100** | 100 | 100 | — |
| Coverage floor (no marker < 40 on primary)   | enforced         | breached: [4, 5, 6, 8, 10, 12] | breached: [4, 5, 6, 7, 9, 10, 11] | — | — |
| Working_hypothesis present                   | trend → 12/12    | **2/12** | 1/12 | n/a | +1 |
| Phase 3 tools used (any case)                | trend ↑          | **2/12** | 8/12 | n/a | -6 |
| ER aggregate (excluding null-denom)          | n/a              | 0.0 (n=6) | 1.8 (n=11) | n/a | — |

## Delta vs prior runs

| Case | Apr-20 | 2026-05-06 prior | This run | Δ vs prior | Δ vs Apr-20 |
|-----:|-------:|-----------------:|---------:|-----------:|------------:|
|  1 |  51.1 |  72.2 |  39.4 | -32.8 | -11.7 |
|  2 |  47.9 |  72.2 |  61.8 | -10.4 | +13.9 |
|  3 |  54.3 |  75.8 |  33.3 | -42.5 | -21.0 |
|  4 |  70.0 |  66.7 |  33.3 | -33.4 | -36.7 |
|  5 |  60.0 |  54.7 |  33.3 | -21.4 | -26.7 |
|  6 |  67.5 |  54.7 |  33.3 | -21.4 | -34.2 |
|  7 |  48.1 |  62.9 |  33.3 | -29.6 | -14.8 |
|  8 |  54.2 |  65.8 |  33.3 | -32.5 | -20.9 |
|  9 |  70.5 |  55.8 |  33.3 | -22.5 | -37.2 |
| 10 |  37.9 |  35.4 |  33.3 |  -2.1 |  -4.6 |
| 11 |  60.8 |  50.0 |  40.0 | -10.0 | -20.8 |
| 12 |  72.5 |  63.7 |  33.3 | -30.4 | -39.2 |

## Borderline & throttle flags

- Borderline terminals (rc=1 has_report=true): none
- Rate-limit-throttled (utilization ≥ 0.9): none observed (sequential execution avoided 5-hour overrun)

## Hand audit (hallucination check, second pass)

Heuristic = 0 across all 12 cases. Hand-audit spots:
- Case 1 (Salt Typhoon, 79 nodes): no fabricated actor/malware/kit values detected.
- Case 2 (MuddyRot, 15 nodes): no fabricated actor/malware/kit values detected.
- Case 3 (Bumblebee→Akira, 0 nodes): no fabricated actor/malware/kit values detected.
- Case 4 (Interlock, 0 nodes): no fabricated actor/malware/kit values detected.

**Halluc gate: cleared.**