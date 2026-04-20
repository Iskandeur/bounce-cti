# Deltas — abca49b vs 20ba0ef

## Per-case overall delta

| Case | 20ba0ef | abca49b | Δ | Key driver |
|-----:|--------:|--------:|--:|:-----------|
|  1 | 50.2 | 59.6 |  +9.4 | Hallucination fixed (-15 on 20ba0ef), actor now correctly named |
|  2 | 54.7 | 52.5 |  -2.2 | Premature exit persists; phase 2 re-ran wrong tools |
|  3 | 57.8 | 66.4 |  +8.6 | Scorer credits VT/OTX source fields; report quality up |
|  4 | 38.9 | 79.2 | **+40.3** | Phase 3 report-write fallback wrote `investigation_summary`; R14 drove Cloudflare origin pivots |
|  5 | 38.3 | 63.8 | +25.5 | Report node written; pivots broadened |
|  6 | 42.2 | 75.0 | **+32.8** | Report node written; LummaC2 correctly named |
|  7 | 38.0 | 65.6 | +27.6 | Report node written (though marker still missing) |
|  8 | 45.4 | 62.0 | +16.6 | Report quality up; Amadey+StealC named |
|  9 | 42.3 | 87.5 | **+45.2** | R14 + report fallback; Tycoon marker surfaced |
| 10 | 44.6 | 38.8 |  -5.8 | Report is present but remains empty of actor terms; DNS TXT/MX still skipped |
| 11 | 44.0 | 82.8 | **+38.8** | R14 Cloudflare-tunnel unmask; NameSilo NS cluster surfaced |
| 12 | 48.3 | 79.2 | +30.9 | R14 drove cert-CN Shodan unmask; report names ClearFake+Keitaro |

Mean delta: **+22.3** points.

## Regression set behaviour

- **Smoke set (2, 3, 7)** — Cases 3 and 7 improved (+9, +28). Case 2 regressed
  by 2 points; new F-PIVOT-MISS root cause is phase-2 re-running already-called
  tools instead of the missing `threatfox_search` / `otx_file`.
- **Cases 1, 5 (F-CLUSTER-OVER)** — Case 1 no longer hallucinates APT34;
  F-CLUSTER-OVER counts 0/12. R12 guardrail is working.
- **Case 12 (Shodan cert-CN)** — now executes the cert-CN unmask pivot and
  names ClearFake + Keitaro.
- **Cases 4, 6, 9 (phase_followup report-write)** — all three now have
  `investigation_summary` report nodes.

## What changed in abca49b

From commit message `abca49b agent: guardrails + report-write fallback from EVAL_PROTOCOL_V2 run`:
1. System-prompt rules R12 (no co-tenancy clustering), R13 (no cross-campaign
   attribution merge), R14 (mandatory Cloudflare origin-unmask).
2. New `phase3_report_write` step: if no `investigation_summary` node exists
   after phase 1 + optional phase 2, the agent is re-invoked with a tight
   single-purpose prompt and `max_turns=6` to write exactly one report node.

## What's still broken

1. **Report marker/actor surfacing** — even when pivots executed, the
   report summary skips naming the exact discriminator (JARM value, cert-CN,
   page title) or the actor aliases present in node metadata. 4 cases stuck
   at RQ=0, 5 more at RQ=40.
2. **Phase 2 re-running already-called tools** — 2 cases (Case 2, Case 7)
   have the same failure pattern.
3. **DNS TXT/MX + Wayback pivots** — Case 10 DPRK Contagious Interview chain
   is entirely absent. Agent needs explicit prompting for these pivots.
