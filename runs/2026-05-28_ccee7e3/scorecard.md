# EVAL_PROTOCOL Scorecard — 2026-05-28 · commit ccee7e3

**Run environment**
- Branch: `claude/amazing-planck-s7mNi` (local), against `main` deployed VPS at https://bounce.alexandre-pinoteau.fr/
- Model: `opus-4.7` (only model whitelisted on the eval account)
- Mode: full 12 cases, **sequential one-by-one** submission (user-mandated to avoid 5-hour quota burn-down)
- Case 11 seed: `ezpass-tollbill-pay.cc` — Smishing-Triad/Lighthouse-kit pattern (NameSilo + Cloudflare fronting + toll-payment lure + .cc TLD), distinct from prior run (`usps-deliveryupdate-package.top`) to dodge a cached backend result. Live freshness not verified (sandbox DNS blocked).

## Scorecard

| Case | Status | NR   | ER   | PC   | DC  | BD  | RQ  | Overall | Calls | Hypothesis path |
|-----:|:------:|-----:|-----:|-----:|----:|----:|----:|--------:|------:|:----------------|
|  1 | done | 46.7 |   0.0 | 50.0 | 100 | 100 |  40 |  56.1 |    4 | Y (apt_targeted) |
|  2 | done | 55.6 |   0.0 | 75.0 | 100 | 100 |  40 |  61.8 |   48 | Y (apt_targeted) |
|  3 | done | 47.1 |  66.7 | 100.0 | 100 |   0 |  70 |  64.0 |  115 | Y (commodity_malware) |
|  4 | done | 23.1 |   0.0 | 100.0 | 100 |   0 |  40 |  43.8 |  120 | Y (commodity_malware) |
|  5 | done | 15.4 |   0.0 | 100.0 | 100 | 100 |   0 |  52.6 |   56 | Y (traffer_or_tds) |
|  6 | done | 50.0 | 100.0 | 75.0 | 100 | 100 |  70 |  82.5 |    4 | Y (commodity_malware) |
|  7 | done | 41.7 |   0.0 | 100.0 | 100 | 100 |  40 |  63.6 |   45 | Y (socgholish_traffer_tds) |
|  8 | done | 50.0 |  33.3 | 75.0 | 100 |  75 |  70 |  67.2 |   86 | Y (commodity_malware) |
|  9 | done | 50.0 | 100.0 | 75.0 | 100 |   0 |  40 |  60.8 |  127 | Y (phishing_kit_cluster) |
| 10 | done |  7.1 |   0.0 | 40.0 | 100 | 100 |   0 |  41.2 |   18 | Y (legitimate) |
| 11 | done |  0.0 |   n/a | 100.0 | 100 | 100 |   0 |  60.0 |   43 | Y (smishing_hub) |
| 12 | done | 62.5 | 100.0 | 100.0 | 100 |   0 |  70 |  72.1 |   94 | Y (commodity_malware) |

## Aggregate metrics

| Metric                                       | Target           | This run           | 2026-05-21 prior   | Apr-20 baseline | Δ vs prior |
|----------------------------------------------|-----------------:|-------------------:|-------------------:|----------------:|-----------:|
| Overall (mean)                               | ≥ 65             | **60.5** | 54.7 | 57.9 | +5.8 |
| Pass rate (overall ≥ 70)                     | ≥ 60 %           | **2/12 (17 %)** | 3/12 (25 %) | 3/12 (25 %) | -1 |
| Hallucination rate                           | **0 % hard gate**| **0/12 (0 %)** ✅ | 0/12 | 0/12 | — |
| Defuse floor (mean DC on cases 4/6/11/12)    | ≥ 75             | **100** | 100 | 100 | — |
| Coverage floor (no marker < 40 on primary)   | enforced         | breached: [4, 5, 10] | breached: [4, 5, 6, 7, 9, 10, 11] | — | — |
| Working_hypothesis present                   | trend → 12/12    | **12/12** | 1/12 | n/a | +11 |
| Phase 3 tools used (any case)                | trend ↑          | **10/12** | 8/12 | n/a | +2 |
| ER aggregate (excluding null-denom)          | n/a              | 16.7 (n=6) | 1.8 (n=11) | n/a | — |

## Delta vs prior runs

| Case | Apr-20 | 2026-05-21 prior | This run | Δ vs prior | Δ vs Apr-20 |
|-----:|-------:|-----------------:|---------:|-----------:|------------:|
|  1 |  51.1 |  39.4 |  56.1 | +16.7 |  +5.0 |
|  2 |  47.9 |  61.8 |  61.8 |  +0.0 | +13.9 |
|  3 |  54.3 |  64.8 |  64.0 |  -0.8 |  +9.7 |
|  4 |  70.0 |  60.5 |  43.8 | -16.7 | -26.2 |
|  5 |  60.0 |  38.8 |  52.6 | +13.8 |  -7.4 |
|  6 |  67.5 |  62.5 |  82.5 | +20.0 | +15.0 |
|  7 |  48.1 |  71.4 |  63.6 |  -7.8 | +15.5 |
|  8 |  54.2 |  71.4 |  67.2 |  -4.2 | +13.0 |
|  9 |  70.5 |  77.5 |  60.8 | -16.7 |  -9.7 |
| 10 |  37.9 |  34.5 |  41.2 |  +6.7 |  +3.3 |
| 11 |  60.8 |  40.0 |  60.0 | +20.0 |  -0.8 |
| 12 |  72.5 |  33.3 |  72.1 | +38.8 |  -0.4 |

## Borderline & throttle flags

- Borderline terminals (rc=1 has_report=true): none
- Rate-limit-throttled (utilization ≥ 0.9): none observed (sequential execution avoided 5-hour overrun)

## Hand audit (hallucination check, second pass)

**Pass 1 (heuristic):** the raw corpus-only heuristic flagged 3 `person` nodes
across 2 cases — Case 2 `Johnik Makedonskiy`; Case 7 `Costel Savulescu` +
`Dmitrii Vladimirovich Malkov`. These tanked Cases 2/7 with a −15/−30 penalty
in the first scoring pass.

**Pass 2 (hand audit):** all three are **false positives** — they are RDAP
registrant / IP-block-owner vcards with full provenance in `metadata`:
- `Johnik Makedonskiy` — RDAP identitydigital.services registrant vcard for a
  cluster sibling (`emails:[modafabiches@outlook.com]`, declared NYC address w/
  invalid zip — a flagged false-persona, correctly tagged `false_persona`).
- `Costel Savulescu` — RIPE RDAP `ORG-CS1103-RIPE` for `170.168.61.0/24`
  (`source:rdap`, `asn:AS63023`).
- `Dmitrii Vladimirovich Malkov` — RIPE RDAP `ORG-DVM4-RIPE` for
  `176.53.146.0/23` (`source:rdap`, `asn:AS48108`).

Per §4.6 ("a node that **cannot be traced to any tool-call result**"), a node
whose `metadata.evidence`/`source`/`sources_seen` cites a specific RDAP object
IS traceable and is **not** a hallucination — the heuristic only missed them
because RDAP vcard names land in `metadata`, not in the truncated transcript
`result_preview`. The scorer's `hallucination_check` was upgraded this run to
be **provenance-aware** (clears a suspect when it carries `evidence`/`source`/
`sources_seen`/`provenance` metadata). Post-fix heuristic = 0 across all 12.

Other large graphs spot-checked (Case 8 / 97 nodes, Case 5 / 165 nodes, Case 7
/ 167 nodes): no fabricated actor/malware/family/kit values.

**Halluc gate: cleared (0/12).**

## Freshness / exogenous-factor notes (read before treating low NR as a bug)

- **Case 1 (materialplies.com)** — the seed has **decayed**: WHOIS now shows a
  benign 2026-04-03 GMO/Onamae re-registration (single A `160.16.200.77`, no
  MX/TXT, no keyboard-mash ProtonMail registrant). The agent still recovered
  the *historical* Salt Typhoon attribution from passive sources (tags
  `salt_typhoon`/`earth_estries`/`unc4841`/`ghostemperor` + C2 typosquat
  `updatemicfosoft.com`) but the live reverse-WHOIS sibling cluster is gone.
  Low NR here is data decay, not a tool failure (§3).
- **Case 10 (37.211.126.117)** — seed IP no longer carries the passive-DNS
  resolution to `lianxinxiao.com` (8 nodes recoverable; the DNS-TXT/MX cross-ref
  pivot has no live anchor). Largely exogenous decay.
- **Case 11 (ezpass-tollbill-pay.cc)** — best-effort OSINT seed pick is **not
  live** (sandbox cannot poll the Silent Push IOFA feed or DNS). 4 nodes; NR=0.
  This is a seed-selection limitation, not a Cloudflare-defuse failure. PC=100
  (the mandatory + adaptive pivots all fired against the dead seed).

## Dominant score drag (this run) → fixes shipped for next run

BD=0 on Cases 3 (115 calls) / 4 (120) / 9 (127) / 12 (94) — the unbounded
pivot-drain loop overshoots the §4.5 90-call ceiling. main+followup stayed ≤27
calls in all four; the drain rounds did 93–104 (single rounds hit 53–65 because
one agent turn emits several parallel `tool_use` blocks). A global CTI-call
ceiling (`BOUNCE_TOTAL_CTI_BUDGET=82`, clamps each drain round to remaining
budget) is shipped this commit — prospectively lands these in the BD=75 band
(they already log `budget_extension`), worth ≈ +3 to the mean next run.