# EVAL_PROTOCOL Scorecard — 2026-05-06 · commit a1903f4

**Run environment**
- Branch: `claude/friendly-edison-qV50Y` (local), against `main` deployed VPS at https://bounce.alexandre-pinoteau.fr/
- Model: `opus-4.7` (only model whitelisted on the eval account)
- Mode: full 12 cases, parallel submission via `asyncio.create_task` over 12 WebSockets
- Case 11 seed: `usps-uspspackage-tracking.top` — picked from typical Smishing-Triad pattern (NameSilo + Cloudflare-fronted + USPS lure + .top TLD), distinct from prior runs (`usps.com-tracksun.top` Apr-20, `usps.com-redeliveryinfo.top` 2026-05-05). Live freshness not verified (sandbox DNS blocked).

## Scorecard

| Case | Status | NR   | ER   | PC   | DC  | BD  | RQ  | Overall | Calls | Hypothesis path |
|-----:|:------:|-----:|-----:|-----:|----:|----:|----:|--------:|------:|:----------------|
|  1 | done | 58.3 |  0.0 | 75.0 | 100 | 100 | 100 |  72.2 |   45 | Y (apt_infrastructure) |
|  2 | done | 83.3 |  0.0 | 50.0 | 100 | 100 | 100 |  72.2 |    7 | absent ((none)) |
|  3 | done | 80.0 |  0.0 | 75.0 | 100 | 100 | 100 |  75.8 |   52 | absent ((none)) |
|  4 | done | 30.0 |  0.0 | 100.0 | 100 | 100 |  70 |  66.7 |   56 | absent ((none)) |
|  5 | done | 13.3 |  0.0 | 75.0 | 100 | 100 |  40 |  54.7 |   37 | absent ((none)) |
|  6 | done |  8.0 |  0.0 | 50.0 | 100 | 100 |  70 |  54.7 |   47 | absent ((none)) |
|  7 | done | 37.5 |  0.0 | 100.0 | 100 | 100 |  40 |  62.9 |   30 | absent ((none)) |
|  8 | done | 50.0 | 20.0 | 75.0 | 100 |  50 | 100 |  65.8 |   78 | absent ((none)) |
|  9 | done | 20.0 |  0.0 | 75.0 | 100 | 100 |  40 |  55.8 |   25 | absent ((none)) |
| 10 | done | 12.5 |  0.0 |  0.0 | 100 | 100 |   0 |  35.4 |   18 | absent ((none)) |
| 11 | done |  0.0 |  n/a | 100.0 | 100 |  50 |   0 |  50.0 |   76 | absent ((none)) |
| 12 | done | 57.1 |  0.0 | 75.0 | 100 |  50 | 100 |  63.7 |   72 | absent ((none)) |

## Aggregate metrics

| Metric                                       | Target           | This run           | 2026-05-05 prior     | Apr-20 baseline | Δ vs prior |
|----------------------------------------------|-----------------:|-------------------:|---------------------:|----------------:|-----------:|
| Overall (mean)                               | ≥ 65             | **60.8** | 57.3 | 57.9 | +3.5 |
| Pass rate (overall ≥ 70)                     | ≥ 60 %           | **3/12 (25 %)** | 0/12 | 3/12 (25 %) | +3 |
| Hallucination rate                           | **0 % hard gate**| **0/12 (0 %)** ✅ | 0/12 | 0/12 | — |
| Defuse floor (mean DC on cases 4/6/11/12)    | ≥ 75             | **100** | 100 | 100 | — |
| Coverage floor (no marker < 40 on primary)   | enforced         | breached: [4, 5, 6, 7, 9, 10, 11] | breached: 7,10,11,12 | breached: 6+ | — |
| Working_hypothesis present                   | trend → 12/12    | **1/12** | 3/12 | n/a | -2 |
| Phase 3 tools used (any case)                | trend ↑          | **8/12** | 2/12 | n/a | +6 |
| ER aggregate (excluding null-denom)          | n/a              | 1.8 (n=11) | 16.7 (n=6) | n/a | — |

## Notes on metric changes

- **ER aggregate 1.8 (n=11) vs prior 16.7 (n=6)** is a *scorer-implementation
  change, not a real regression*. Prior runs marked Cases 4/5/6/9/11/12 as
  `n/a` (cluster shapes without per-edge GT pairs). The 2026-05-06 scorer
  is more strict: it uses §9's per-case `Ground-truth edges` lists as the
  denominator wherever they exist, even when the protocol's recommended
  match style is "aggregate / pattern-level". Listing this so the next
  iteration can either harden the scorer (read evidence/source on edges) or
  re-mark cluster-shape cases as `n/a` to match prior. Either approach is
  defensible. We did not retroactively touch the prior scorecard.
- **Working_hypothesis 1/12** is a true regression. The phase fires on all 12
  cases but rc=1 on 11/12 — diagnosed (system-prompt conflict + 4-turn budget
  too tight against ToolSearch overhead) and fixed mechanically in this
  commit; see proposed_fixes.md P0.

## Delta vs prior runs

| Case | Apr-20 | 2026-05-05 prior | This run | Δ vs prior | Δ vs Apr-20 |
|-----:|-------:|-----------------:|---------:|-----------:|------------:|
|  1 |  51.1 |  55.3 |  72.2 | +16.9 | +21.1 |
|  2 |  47.9 |  58.8 |  72.2 | +13.4 | +24.3 |
|  3 |  54.3 |  62.6 |  75.8 | +13.2 | +21.5 |
|  4 |  70.0 |  68.0 |  66.7 | -1.3 | -3.3 |
|  5 |  60.0 |  55.0 |  54.7 | -0.3 | -5.3 |
|  6 |  67.5 |  61.0 |  54.7 | -6.3 | -12.8 |
|  7 |  48.1 |  44.7 |  62.9 | +18.2 | +14.8 |
|  8 |  54.2 |  65.0 |  65.8 | +0.8 | +11.6 |
|  9 |  70.5 |  64.7 |  55.8 | -8.9 | -14.7 |
| 10 |  37.9 |  37.9 |  35.4 | -2.5 | -2.5 |
| 11 |  60.8 |  52.0 |  50.0 | -2.0 | -10.8 |
| 12 |  72.5 |  63.0 |  63.7 | +0.7 | -8.8 |

## Borderline & throttle flags

- Borderline terminals (rc=1 has_report=true): none
- Rate-limit-throttled (utilization ≥ 0.9): none

## Hand audit (hallucination check, second pass)

Heuristic = 0 across all 12 cases. Hand audit on the largest graphs verified:
- Case 9 (Tycoon 2FA, 57 nodes): no fabricated nodes; actor/malware/kit values trace to event corpus.
- Case 8 (Amadey/StealC GitLab, 43 nodes): no fabricated nodes; actor/malware/kit values trace to event corpus.
- Case 7 (SocGholish, 40 nodes): no fabricated nodes; actor/malware/kit values trace to event corpus.
- Case 2 (MuddyRot, 36 nodes): no fabricated nodes; actor/malware/kit values trace to event corpus.

**Halluc gate: cleared.**