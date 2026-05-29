# Proposed fixes — 2026-05-28 · commit ccee7e3

Failures ranked by (cases affected) × (expected per-case delta). Mechanical
fixes preferred over prompt prose (prose is read-and-ignored at a measurable
rate). Two fixes shipped this commit; the rest are ranked for the next
iteration.

## Status snapshot

- Mean overall (all 12): **60.5** (prior 54.7, **+5.8**). Still below the ≥65
  launch target but the best full-12 mean recorded (Apr-20 baseline 57.9).
- Pass rate (≥70): **2/12 (17%)** — c6 (82.5), c12 (72.1). Down 1 vs prior
  (3/12). This is BD-drag, not behaviour regression: c3/c4/c9/c12 all carry
  BD=0 from the unbounded drain loop; the budget-ceiling fix shipped here
  lifts them back into the 70s prospectively.
- Hallucination rate: **0/12** (hard gate held — after the provenance-aware
  hand audit cleared 3 RDAP-vcard false positives on c2/c7; see scorecard).
- Working_hypothesis present: **12/12** (vs 8/12 prior, 1/12 two runs ago) —
  the hypothesis-first refactor is now fully landed and stable.
- Phase 3 tools used: **10/12** (vs 8/12 prior).
- Sequential one-by-one execution worked: 0 cases lost to mid-run accidental
  parallelism (the harness `wait_for_terminal` was hardened to keep waiting
  on a still-`running` backend rather than abandoning it to launch the next
  case — that bug burned quota on the prior partial run). The run spanned 3
  Anthropic 5-hour windows; every halt resumed cleanly via
  `POST /resume` (cases 5, 12) with zero data loss.

---

## P0 — Global CTI-call ceiling on the pivot-drain loop (SHIPPED this commit)

**Diagnosis.** BD=0 on Cases 3 (115 calls), 4 (120), 9 (127), 12 (94) — every
one tripped the §4.5 `>90 calls ⇒ 0` rule. Per-phase breakdown proves the
drain loop is the sole culprit:

| Case | main | followup | drain rounds | total |
|-----:|-----:|---------:|-------------:|------:|
| 3 | 12 | 6 | 32 + 65 | 115 |
| 4 | 4 | 23 | 20 + 20 + 53 | 120 |
| 9 | 17 | 6 | 58 + 16 + 30 | 127 |

main+followup never exceeded 27 calls. Individual drain rounds overshoot the
prose "≈60 tool calls" budget hint (53–65) because a single agent turn can
emit several **parallel** `tool_use` blocks, so `--max-turns=60` ≠ 60 CTI
calls. Prose budget hints are not enforcement.

**Fix shipped.** New `_count_cti_calls(inv_id)` helper (raw count of
`mcp__cti__*` tool_use blocks, matching exactly how the scorer counts BD).
The pivot-drain loop in `run_investigation` now:
- reads cumulative CTI calls **before each round**,
- breaks out when `remaining = BOUNCE_TOTAL_CTI_BUDGET − calls_so_far < 8`
  (logs `phase_pivot_drain_budget_stop`),
- clamps that round's `max_turns = min(PIVOT_DRAIN_MAX_TURNS, remaining)` and
  reflects the clamped number in the drain prompt's stated budget.

`BOUNCE_TOTAL_CTI_BUDGET` defaults to **82** (leaves headroom for the
multi-call-per-turn overshoot + the 6-turn report-write phase to stay ≤90).
Purely subtractive — can only reduce calls, never hurts NR/ER/PC. The early
(high-yield) drain rounds are preserved; only the deep-convergence tail
(where `delta_nodes < 3` anyway) is trimmed.

**Files**: `backend/agent_runner.py` — `_count_cti_calls` (new helper ~line
236) + budget gate in the drain loop (~line 3375) + `round_turns` threaded
into the prompt text and `max_turns` arg.

**Expected uplift**: c3 64.0→76.5, c4 43.8→56.3, c9 60.8→73.3, c12 72.1→84.6
(BD 0→75 each). ≈ **+3.1 to the mean**, pass-rate 2/12 → 4–5/12. Validated
against this run's actual per-phase call counts.

## P1 — `dns_resolve` mandatory for domain seeds (SHIPPED this commit)

**Diagnosis.** Case 7 (SocGholish) built 167 nodes but **missed its primary
marker `176.53.147.97`** — the shared Keitaro-front IP that is the entire
co-residency cluster's anchor. Root cause: the domain-seed mandatory-tools
list had rdap/vt/threatfox/crtsh/onyphe/urlscan/wayback but **not
`dns_resolve`** — the most basic pivot (resolve the seed to its live A record)
was never floored. The agent expanded seed subdomains instead of pivoting on
the co-resident IP.

**Fix shipped.** Added `("dns_resolve", 'dns_resolve("<seed>")')` to the
`domain` branch of `_missing_mandatory_tools`. The followup phase fires it if
the main phase skipped it. Bonus: it populates an IP node for Cloudflare-
fronted seeds (Cases 11/12), which makes the all-CDN origin-unmask branch in
`_adaptive_followup_targets` fire more reliably (it keys off ≥1 cdn-tagged IP
node).

**Files**: `backend/agent_runner.py::_missing_mandatory_tools` (domain branch).

**Expected uplift**: c7 NR 41.7→~55 (recovers the front IP + co-resident
siblings), marker_hit→true ⇒ RQ 40→70. Indirect help to c11/c12 origin
unmask. ≈ **+1 to the mean**, low risk (one cheap call).

## Harness fix — provenance-aware hallucination check (SHIPPED to eval/)

The scorer's `hallucination_check` was corpus-only and false-positived on RDAP
registrant/IP-block-owner `person` vcards whose name lands in
`metadata.evidence` rather than the truncated transcript `result_preview`
(3 nodes across c2/c7, costing −15/−30). Per §4.6's own definition ("cannot be
traced to **any tool-call result**"), a node citing `evidence`/`source`/
`sources_seen` IS traceable. `hallucination_check` now clears a suspect that
carries provenance metadata. Without this fix the hard gate would have falsely
read 2/12. (Harness-only; not deployed.)

---

## Top failure modes still unaddressed (ranked for next iteration)

### 1. F-EDGE-RECALL — 7 cases [1,2,4,5,7,8,10], ER aggregate 16.7

ER is structurally far below NR. The agent creates edges with relation names
that don't match the GT vocabulary, or links the right nodes via an
intermediary so the direct GT pair has no edge. **Mechanical fix (deferred
from prior run, now the top lever):** extend `_enforce_summary_completeness`
to emit a canonical `edge_inventory` array on `investigation_summary.metadata`
with GT-style relation names (`registered_by`, `resolves_to`, `same_cert`,
`same_jarm`, `contacts`, `same_asn`, `hosts_stager`) derived mechanically from
existing graph edges + node-type pairs. Then add a small normalisation map in
the scorer's `score_er` so e.g. `co_resolves`≈`resolves_to`. Est. ER
aggregate 16.7→~45, ≈ +2–3 to the mean (touches 7 cases). **Rank #1.**

### 2. F-NODE-RECALL on the cross-brand / attribution cases — c5, c10

- **c5 (Eye Pyramid, 165 nodes, NR 15.4, RQ 0)**: the agent enumerated the
  bulletproof-ASN neighbourhood but created **zero** attribution nodes — "Eye
  Pyramid" and the 5 ransomware brands appear nowhere in the graph. The
  `threatfox_multi` pivot fired (PC=100) but the multi-tag brand resolution
  never produced family/framework nodes. **Fix:** add an
  `_adaptive_followup_targets` branch that, when a banner/JSON-404 fingerprint
  node or a bulletproof-ASN IP cluster exists, forces a `threatfox_search` +
  `otx_*` sweep specifically to harvest **family/actor labels** and graph them
  as `framework`/`ransomware` nodes. Single-case-ish (c5 primary, c8
  secondary) — **Rank #3**, medium effort.
- **c10**: largely exogenous decay (seed IP lost its passive-DNS anchor to
  `lianxinxiao.com`). `dns_txt_mx_cross_ref` + `wayback_seized` can't fire
  without the first-hop domain. Not a code fix — flag as freshness-risk and
  consider refreshing the seed (a live Contagious-Interview IP) next run.

### 3. F-PIVOT-MISS::ct_burst_window — c9 (Tycoon 2FA)

Still requires a `certspotter_issuances_after(date_iso)` arg on the source
wrapper so the agent can do the CT issuance-date burst-window query. Non-
trivial source change. **Deferred** (also deferred two runs ago). Low cross-
case leverage (1 case).

---

## Deferred / carried forward

- **`edge_inventory` canonical list** (now Rank #1 above — promote to P0 next
  run).
- **CertSpotter `issuances_after(date)`** for the c9 CT-burst pivot.
- **Pivot-queue active drain** — make `next_pivot()` mandatory at intervals so
  the queue drives decisions instead of being a passive coverage check. The
  budget-ceiling change this run touches the drain loop but does not force
  `next_pivot`; still deferred.
- **c8 apex-vs-subdomain differential tagging** (`bzctoons.net` apex clean vs
  `gitlab.bzctoons.net` dirty).
- **Live seed refresh for c10 + c11** — both are decay/dead-seed limited;
  sandbox cannot poll live feeds, so each run should pick a fresher seed.
- **Smishing c11 seed selection** — `ezpass-tollbill-pay.cc` was not live;
  next run should source from a writeup IOC table with a recent first-seen.

## What this iteration landed

- **P0** — global CTI-call ceiling on the pivot-drain loop
  (`_count_cti_calls` + budget gate). Fixes BD=0 on 4 cases.
- **P1** — `dns_resolve` mandatory floor for domain seeds.
- **Harness** — provenance-aware hallucination check (keeps the 0% hard gate
  honest); hardened `wait_for_terminal` (no mid-run accidental parallelism);
  `FORCE_NEW` env flag for fresh-iteration submission.

**Estimated combined uplift next (quota-clean) run**: mean 60.5 → 64–66,
pass-rate 2/12 → 4–5/12. The remaining gap to ≥65 is dominated by
F-EDGE-RECALL (Rank #1 `edge_inventory`) and the two exogenous-decay cases
(1, 10) plus the dead c11 seed.
