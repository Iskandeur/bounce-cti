# Proposed fixes — 2026-05-31 · commit 6e6aaeb

Failures ranked by (cases affected) × (expected per-case delta). Mechanical
fixes preferred over `SYSTEM_PROMPT` prose (prose is read-and-ignored at a
measurable rate). **Two fixes shipped this commit** (both target a regression
vs the 2026-05-28 run); the rest are ranked for the next iteration.

## Status snapshot

- Mean overall (all 12): **64.2** (prior 60.5, **+3.7**) — best full-12 mean
  recorded, just shy of the ≥65 launch target.
- Pass rate (≥70): **4/12 (33%)** — c3 (70.9), c9 (81.1), c12 (80.4), c6
  (74.2). Up from 2/12. The shipped budget-ceiling fix from last run worked:
  c3 BD 0→75 (115→74 calls), c4 BD 0→75 (120→78), c9 60.8→**81.1**.
- Hallucination rate: **0/12** (hard gate held — heuristic + provenance pass +
  hand-audit of the 5 largest graphs, see deltas.md).
- **Valid hypothesis (wh node + hypothesis_history + final_category): 12/12** —
  the hypothesis-first refactor is fully landed and stable (new behavioural
  metric, target met first time).
- Defuse floor (DC on 4/6/11/12): **100**. Coverage floor breached on
  **[4, 5, 10]** — identical to prior run, all exogenous (see below).
- ER aggregate **34.8 (n=11)** vs 16.7 (n=6) prior — but see "ER is bounded by
  NR" below; the absolute ER gain is mostly NR-driven, not a new edge fix.
- Quota: the run crossed one 5-hour window (c8 hit `quota_exceeded` at 23:47
  UTC); the quota-survivable runner recorded state, and on session restart it
  **resumed c8 in place** (no duplicate spawned despite `FORCE_NEW=1`) and drove
  8–12 to completion. Zero data loss.

---

## The dominant score drag this run is EXOGENOUS, not a tool regression

Before ranking code fixes, the honest accounting (per §3 freshness pre-check):
the low-NR cases are **decayed seeds or dead attribution feeds**, verified by
checking whether the missing markers appear *anywhere* in the tool-result
corpus:

- **c2 (MuddyRot)** — `91.235.234.202` / `146.19.143.14` (the C2 IPs) appear in
  **zero** tool results. VT no longer returns them as contacted IPs for this
  hash. NR/ER capped by decay.
- **c7 (SocGholish)** — `176.53.147.97` (the Keitaro-front anchor) appears in
  **zero** tool results; `dns_resolve(blackshelter.org)` was called (the floor
  works) but the live A-record has re-pointed. Decay.
- **c5 (Eye Pyramid)** — `eye pyramid` / `rhysida` / `blackcat` / the ASNs all
  appear in **zero** tool results. The agent enumerated 73 IP/ASN/cert nodes
  but the brand attribution is **not in any queryable feed** for this seed:
  ThreatFox returned no brand tag and **OpenCTI is DEAD** (`AUTH_REQUIRED` —
  token expired, see lessons-learned). The cross-brand attribution lives in
  Intrinsec's human analysis, not in passive sources. **Not mechanically
  recoverable.**
- **c10 (Contagious Interview)** — seed IP lost its passive-DNS anchor to
  `lianxinxiao.com`; no first-hop domain ⇒ the DNS-TXT/MX + crtsh + wayback
  chain has nothing to fire against. Decay (BlockNovas FBI-seized).
- **c11 (Smishing Triad)** — `sunpass-tollservices.icu` best-effort OSINT seed
  is not live (sandbox cannot poll the IOFA feed/DNS). NR≈0 by construction;
  PC=100 (all mandatory + Cloudflare-origin-unmask pivots fired against the
  dead seed).

**#1 operator action item (cannot be code-fixed from here — secret in `.env`):**
**Refresh the OpenCTI token.** OpenCTI is the designated community-KG
attribution source; with it dead, actor/family/campaign labels are blocked on
*every* case that needs them (c5 cross-brand, c10 actor, RQ `actor_hit` drag).
The source-health cache (shipped 6e6aaeb) correctly marks it dead and skips its
pivots, so there is no per-node rediscovery cost — but the attribution itself is
gone until `OPENCTI_TOKEN` is renewed on the VPS. This is the single
highest-leverage change available and it is an ops task, not a code task.

---

## P0 — `_is_parked` over-triggers on co-resident parked nodes (SHIPPED) — fixes c6 regression

**Diagnosis.** Case 6 (LummaC2 `rugtou.shop`, the designated **sinkhole test**)
regressed 82.5→74.2 and did only **3 CTI calls** — it never ran followup or the
pivot-drain (transcript shows only the `main` phase). The seed is correctly
tagged `le_seized` (Operation Endgame / Microsoft-DOJ takedown), which the
design *intends* to exempt from the parked short-circuit so the full historical
workflow runs. But `_is_parked()` loops over **every** node and returns `True`
on the first parked one — and a *co-resident enrichment IP*
(`172.234.24.211`, a post-expiry parking lander) is tagged `parking`. So the
whole investigation short-circuited on an unrelated node, skipping the
content-fingerprint / crtsh / urlscan pivots that are the entire point of the
case (PC 75→25; cert_sha1 + sibling `.shop` domains never recovered).

**Fix shipped.** `backend/agent_runner.py::_is_parked` now returns `False`
early if **the seed node** carries `le_seized` (tag or `metadata.sinkhole_kind`)
— making the LE-takedown exemption investigation-wide instead of a per-node
`continue` that the later loop overrides. Surgical: behaviour changes **only**
for `le_seized` seeds (which were already meant to be exempt). A genuinely
parked/sinkholed *seed* still short-circuits; a non-seed parked node no longer
aborts the run.

**Expected uplift**: c6 PC 25→~100 (mandatory crtsh/urlscan/wayback + adaptive
dom_fingerprints fire), NR likely 50→~65 (cert_sha1 / sibling domains
recoverable), → c6 ~74→~85. ≈ **+0.9 to the mean**, and re-arms the designated
sinkhole test. Low risk.

## P1 — Pivot-drain round overshoots the 90-call BD cliff (SHIPPED) — fixes c8 regression

**Diagnosis.** Case 8 (Amadey/StealC) regressed 67.2→54.7 because it hit **98
CTI calls → BD=0** (the §4.5 `>90 ⇒ 0` cliff). The global CTI ceiling
(`BOUNCE_TOTAL_CTI_BUDGET=82`) stops *starting* a drain round when
`remaining < 8`, but the round it *does* start is clamped in **turns**
(`round_turns = min(60, remaining_budget)`) — and a single agent turn emits
**several parallel `tool_use` blocks** (~2–3 CTI calls/turn). A round started at
74 calls with `remaining=8` ran ~8 turns ≈ 24 calls → 98. (c8 logs
`budget_extension`, so the fix lands it at BD=75, not 50.)

**Fix shipped.** In the drain loop (`backend/agent_runner.py`,
`run_investigation`), when the remaining allowance is small enough that a
parallel burst could blow past 90, re-budget the round in **calls, not turns**:
`if remaining_budget <= 24: round_turns = max(2, remaining_budget // 3)`. Early,
high-yield rounds (large `remaining_budget`) are **unchanged**, so there is no
coverage regression on c3/c4/c9 (which ended at 74/78/79, below the ceiling and
below the 24-headroom trigger on their early rounds). Worst-case ceiling now
≈82–88 < 90.

**Expected uplift**: c8 BD 0→75 ⇒ 54.7→~67.2 (recovers the regression). ≈ **+1.0
to the mean**. Low regression risk (only the near-ceiling round shrinks).

**Combined shipped uplift**: mean 64.2 → ~66, crossing the ≥65 launch target;
pass-rate 4/12 → ~5/12 (c8 back toward 70).

---

## Top failure modes still unaddressed (ranked for next iteration)

### 1. F-EDGE-RECALL is **bounded by NR**, not by edge creation — re-scope the prior "edge_inventory" idea

ER<50 on 8 cases [1,2,3,4,5,7,8,10]. **Root cause analysis (this run):** the
scorer's `score_er` already matches edges *relation-agnostically* (substring on
the node-value pair, either direction) — so ER is **not** a relation-vocabulary
problem. Every ER miss is either (a) a missing **endpoint node** (an NR miss —
e.g. c2's C2 IP, c7's anchor IP, c5's attribution nodes), or (b) an
**unmatchable abstract GT placeholder** (`alpha`/`beta`/`cluster`/`victim`/
`hosting_ip`/`unc4841` — these are not literal node values and can never match).
**The prior run's Rank-1 `edge_inventory` fix would be scorer-gaming** (it'd
inject edges into summary metadata the scorer doesn't read for ER). **De-scope
it.** Two real levers instead:
  - **(scorer/protocol)** Normalise abstract GT edges to concrete node values,
    or drop them from the ER denom (c1 has 3 of 5 unmatchable). Mechanical, in
    `eval/cases.py` + `eval/scorer.py`. Lifts ER honestly on c1.
  - **(tool)** Anything that lifts NR on a *non-decayed* case lifts ER for free.
    The only sizeable non-decayed NR gaps left are c4 (Interlock cluster) and
    c8 (Amadey C2 hub `185.215.113.x` + ASN — `cert_san_apex` pivot missed).
    Both are hard; see #2.

### 2. F-NODE-RECALL / F-PIVOT-MISS on the recoverable hubs — c8 ASN pivot, c12 cert-CN unmask

- **c8**: `cert_san_apex` pivot missed; `185.215.113.x` Amadey hub + `AS51381`
  never graphed. The contacted IP `62.60.226.159` → RDAP → ASN → ThreatFox-on-ASN
  chain stalled at the first IP. **Candidate fix:** an
  `_adaptive_followup_targets` branch that, for a non-CDN IP surfaced from a
  hash seed, forces `rdap_ip` → graph the ASN node → `threatfox_search(ASN)`.
  Single-case-ish; medium effort.
- **c12**: `shodan_cert_cn_search` + `rdap_origin` missed; origin IPs
  partially burned (§3 freshness note) so even a firing unmask finds little.
  Mostly exogenous; the adaptive all-CDN cert-CN branch exists but the origins
  are dead. Low leverage.

### 3. F-PIVOT-MISS::ct_burst_window — c9 (Tycoon 2FA)

Still needs a `certspotter_issuances_after(date_iso)` arg on the source wrapper
so the agent can do the CT issuance-date burst query. Non-trivial source
change. **Deferred** (3rd run running). c9 already passes (81.1); low leverage.

---

## Deferred / carried forward

- **Refresh OpenCTI token** (ops, not code) — #1 leverage; unblocks attribution
  on c5/c10 and RQ `actor_hit` across the board.
- **Abstract-GT-edge normalisation** in `eval/cases.py`/`scorer.py` — honest ER
  lift on c1 (and removes the misleading "edge_inventory" carry-over).
- **`cert_san_apex` / ASN-from-hash-contacted-IP adaptive branch** — c8 hub.
- **CertSpotter `issuances_after(date)`** for the c9 CT-burst pivot.
- **Live-seed refresh for c10 + c11** — both decay/dead-seed limited; sandbox
  cannot poll live feeds, so each run should pick a fresher seed.
- **Pivot-queue active drain** — `next_pivot()` is still a passive coverage
  check; the lessons-learned ledger repeatedly flags the queue ballooning
  (252 pending vs 30 done on c8) and low-value pivots (NSRL/`circl_hash_lookup`
  queued for 35 malicious hashes; bulk CDN-IP doc-pivots). Coalescing per-hash
  pivots + suppressing NSRL on `malicious`-tagged hashes would cut queue noise
  (note: the agent rarely *drains* these, so the BD impact is small — it's a
  coverage-clarity win, not a budget win).

## What this iteration landed

- **P0** — `_is_parked` LE-seized exemption made investigation-wide
  (`backend/agent_runner.py::_is_parked`). Fixes c6 regression + re-arms the
  sinkhole test.
- **P1** — pivot-drain near-ceiling round re-budgeted in calls (parallel
  `tool_use` accounting) (`backend/agent_runner.py` drain loop). Fixes c8 BD=0
  regression; no early-round coverage regression.
- **Harness** — quota-survivable + restart-safe sequential runner (resumes
  `quota_exceeded` in place, retries 429 submits, records inv_id at submit-time
  so a mid-wait death never duplicates); scorer emits the full
  `hypothesis_history` + `valid` flag; re-baselined render to 2026-05-28.

**Estimated combined uplift next (clean) run**: mean 64.2 → ~66, pass-rate
4/12 → ~5/12. The remaining gap to ≥80 is dominated by exogenous decay (c2, c4,
c7, c10), the dead OpenCTI token (c5, c10), and the dead c11 seed — i.e. mostly
**data freshness + one ops token refresh**, not tool logic.
