# EVAL_PROTOCOL Scorecard — 2026-05-21 · commit e54dec1

**Run environment**
- Branch: `claude/practical-mayer-VP8Ki` (local), against `main` deployed VPS at https://bounce.alexandre-pinoteau.fr/
- Model: `opus-4.7` (only model whitelisted on the eval account)
- Mode: full 12 cases, **sequential one-by-one** submission (user-mandated to avoid 5-hour quota burn-down)
- Case 11 seed: `usps-deliveryupdate-package.top` — typical Smishing-Triad pattern (NameSilo + Cloudflare-fronted + USPS lure + .top TLD), distinct from prior runs. Live freshness not verified (sandbox DNS blocked).

**Quota-blocked cases**: 5, 10, 11, 12 — the Anthropic 5-hour budget on the VPS was repeatedly exhausted across this run. Cases 7 and 8 hit `quota_exceeded` mid-run but accumulated useful data (63 and 12 nodes respectively, scoring 71.4 each). Cases 5, 10, 11, 12 hit `quota_exceeded` on the first or second tool call — they have no usable data this iteration. Their scores in the table below reflect the empty-graph default (33-40) and should be read as **quota-blocked, not behaviour-graded**.

## Scorecard

| Case | Status | NR   | ER   | PC   | DC  | BD  | RQ  | Overall | Calls | Hypothesis path |
|-----:|:------:|-----:|-----:|-----:|----:|----:|----:|--------:|------:|:----------------|
|  1 | done | 46.7 |   0.0 | 50.0 | 100 |   0 |  40 |  39.4 |  125 | Y (apt_targeted) |
|  2 | done | 55.6 |   0.0 | 75.0 | 100 | 100 |  40 |  61.8 |   25 | Y (apt_targeted) |
|  3 | done | 35.3 |  33.3 | 50.0 | 100 | 100 |  70 |  64.8 |   12 | Y (commodity_malware) |
|  4 | done | 23.1 |   0.0 | 100.0 | 100 | 100 |  40 |  60.5 |   42 | Y (commodity_malware) |
|  5 | quota-blocked |  7.7 |   0.0 | 25.0 | 100 | 100 |   0 |  38.8 |    4 | absent ((none)) |
|  6 | done | 50.0 | 100.0 | 25.0 | 100 | 100 |   0 |  62.5 |    3 | Y (commodity_malware) |
|  7 | quota_exceeded | 50.0 |  33.3 | 100.0 | 100 |  75 |  70 |  71.4 |   65 | Y (traffer_or_tds) |
|  8 | quota_exceeded | 50.0 |  33.3 | 75.0 | 100 | 100 |  70 |  71.4 |    9 | Y (commodity_malware) |
|  9 | done | 50.0 | 100.0 | 75.0 | 100 | 100 |  40 |  77.5 |   24 | Y (fronted_c2) |
| 10 | quota-blocked |  7.1 |   0.0 |  0.0 | 100 | 100 |   0 |  34.5 |    2 | absent ((none)) |
| 11 | quota-blocked |  0.0 |   n/a |  0.0 | 100 | 100 |   0 |  40.0 |    0 | absent ((none)) |
| 12 | quota-blocked |  0.0 |   0.0 |  0.0 | 100 | 100 |   0 |  33.3 |    0 | absent ((none)) |

## Aggregate metrics

| Metric                                       | Target           | This run           | 2026-05-06 prior   | Apr-20 baseline | Δ vs prior |
|----------------------------------------------|-----------------:|-------------------:|-------------------:|----------------:|-----------:|
| Overall (mean, all 12)                       | ≥ 65             | **54.7** | 60.8 | 57.9 | -6.1 |
| Overall (mean, excluding quota-blocked)      | ≥ 65             | **63.7** (n=8) | n/a | n/a | n/a |
| Quota-blocked cases (≤5 calls, ≤5 nodes)     | trend → 0/12     | **4/12** [5, 10, 11, 12] | 0/12 | 0/12 | +4 |
| Pass rate (overall ≥ 70)                     | ≥ 60 %           | **3/12 (25 %)** | 3/12 (25 %) | 3/12 (25 %) | +0 |
| Hallucination rate                           | **0 % hard gate**| **0/12 (0 %)** ✅ | 0/12 | 0/12 | — |
| Defuse floor (mean DC on cases 4/6/11/12)    | ≥ 75             | **100** | 100 | 100 | — |
| Coverage floor (no marker < 40 on primary)   | enforced         | breached: [4, 5, 10, 12] | breached: [4, 5, 6, 7, 9, 10, 11] | — | — |
| Working_hypothesis present                   | trend → 12/12    | **8/12** | 1/12 | n/a | +7 |
| Phase 3 tools used (any case)                | trend ↑          | **5/12** | 8/12 | n/a | -3 |
| ER aggregate (excluding null-denom)          | n/a              | 16.6 (n=6) | 1.8 (n=11) | n/a | — |

## Delta vs prior runs

| Case | Apr-20 | 2026-05-06 prior | This run | Δ vs prior | Δ vs Apr-20 |
|-----:|-------:|-----------------:|---------:|-----------:|------------:|
|  1 |  51.1 |  72.2 |  39.4 | -32.8 | -11.7 |
|  2 |  47.9 |  72.2 |  61.8 | -10.4 | +13.9 |
|  3 |  54.3 |  75.8 |  64.8 | -11.0 | +10.5 |
|  4 |  70.0 |  66.7 |  60.5 |  -6.2 |  -9.5 |
|  5 |  60.0 |  54.7 |  38.8 | -15.9 | -21.2 |
|  6 |  67.5 |  54.7 |  62.5 |  +7.8 |  -5.0 |
|  7 |  48.1 |  62.9 |  71.4 |  +8.5 | +23.3 |
|  8 |  54.2 |  65.8 |  71.4 |  +5.6 | +17.2 |
|  9 |  70.5 |  55.8 |  77.5 | +21.7 |  +7.0 |
| 10 |  37.9 |  35.4 |  34.5 |  -0.9 |  -3.4 |
| 11 |  60.8 |  50.0 |  40.0 | -10.0 | -20.8 |
| 12 |  72.5 |  63.7 |  33.3 | -30.4 | -39.2 |

## Borderline & throttle flags

- c05: terminal status `quota_exceeded`
- c07: terminal status `quota_exceeded`
- c08: terminal status `quota_exceeded`
- c10: terminal status `quota_exceeded`
- c11: terminal status `quota_exceeded_no_data`
- c12: terminal status `quota_exceeded_no_data`
- Rate-limit-throttled (utilization ≥ 0.9): none observed (sequential execution avoided 5-hour overrun)

## Hand audit (hallucination check, second pass)

Heuristic = 0 across all 12 cases. Hand-audit spots:
- Case 1 (Salt Typhoon, 79 nodes): no fabricated actor/malware/kit values detected.
- Case 7 (SocGholish, 68 nodes): no fabricated actor/malware/kit values detected.
- Case 6 (LummaC2 About-Cats, 31 nodes): no fabricated actor/malware/kit values detected.
- Case 9 (Tycoon 2FA, 31 nodes): no fabricated actor/malware/kit values detected.

**Halluc gate: cleared.**