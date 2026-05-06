# Proposed fixes — 2026-05-06 · commit a1903f4

Failures ranked by (cases affected) × (expected per-case delta). Mechanical
fixes preferred over prompt prose. The first three are shipped in the same
commit as this run report.

## Status snapshot

- Mean overall: **60.8** (target ≥ 65, prior run 57.3, +3.5).
- Pass rate: **3/12** (Cases 1, 2, 3 cross 70 — first non-zero pass rate since the
  hypothesis-first refactor; prior run 0/12, Apr-20 baseline 3/12).
- Hallucination rate: **0/12** (hard gate held).
- Working_hypothesis present: **1/12** (regression vs prior 3/12 — `phase_hypothesis_write`
  is firing on all 12 cases but failing on 11/12 with rc=1, see P0 below).
- Phase 3 tools used: **8/12** cases (vs 2/12 prior — autonomy engine now
  reaches Phase 3 sources on most non-trivial cases).
- Median CTI calls per case: **47** (vs 7 prior — agents drain the queue properly).

## P0 — `phase_hypothesis_write` failing on 11/12 cases (SHIPPED this commit)

**Diagnosis.** The `phase_hypothesis_write` block at `agent_runner.py::run_investigation`
fires on every case (12/12 `phase_hypothesis_write_needed` events) but completes
successfully (`wh_present_after=true`) on only 1/12. The other 11/12 exit rc=1
without writing the working_hypothesis report node.

Two root causes diagnosed from the live event stream:

1. **System prompt conflict.** The phase used `_FOLLOWUP_SYSTEM_PROMPT`, which
   states *"Do NOT create a new report node — one already exists."* But the
   phase's actual job is exactly to create a `working_hypothesis` *report* node.
   Direct contradiction.
2. **Turn budget too tight.** `max_turns=4`, but the agent reaches for the
   harness `ToolSearch` tool first (1-3 turns) before invoking the MCP tools
   it needs (`get_graph` + `add_node` = 2 more turns). Total minimum 4-5
   turns — sometimes fits, often doesn't. Case 1 succeeded only because the
   agent happened to use a `select:` ToolSearch query (1 call), leaving
   exactly 3 turns for `get_graph` + `add_node` + end.

**Fix shipped.**
- New `_HYPOTHESIS_SYSTEM_PROMPT` in `backend/agent_runner.py` — permissive,
  explicitly authorises the single `add_node(report, working_hypothesis,…)`
  call and pre-names the exact MCP tool names so the model doesn't burn
  ToolSearch turns guessing.
- Bump `phase_hypothesis_write` `max_turns` from 4 → 8.

**Files**: `backend/agent_runner.py` (new prompt constant + the 2-line wiring change).

**Expected uplift**: 11 cases × ~5 points = ~4.5 points to mean. Critical because
without the working_hypothesis the per-category playbooks in `phase_followup`
(apt_targeted whoxy_reverse, infostealer dom_fingerprints, fronted_c2 cert-CN
unmask, …) stay un-anchored.

## P1 — Reverse-DNS → TXT/MX cross-reference for IP seeds (SHIPPED this commit)

**Diagnosis.** `F-PIVOT-MISS::dns_txt_mx_cross_ref` on Case 10 (Contagious
Interview). `reverse_dns(37.211.126.117)` returns `lianxinxiao.com`. The hint
in `backend/hints.py::hint_for_reverse_dns` already nudges the agent to call
`dns_resolve(<host>, "TXT")` + `dns_resolve(<host>, "MX")`. But the agent
ignored the hint on both 2026-05-05 and 2026-05-06 runs. The TXT/MX cross-ref
is the only pivot path to `blocknovas.com`, so without it Case 10 stays at
NR ~10 / PC 0.

**Fix shipped.** Add a graph-level branch in
`agent_runner.py::_adaptive_followup_targets` that fires for IP seeds:
- For each non-CDN domain hostname attached to the seed IP via reverse_dns
  / pdns / vt_resolutions_ip, check whether `dns_resolve(<host>, "TXT")` and
  `dns_resolve(<host>, "MX")` were both called.
- If not, emit them as adaptive followup targets (one per direction).
- Cap at 3 hosts per seed.

**Files**: `backend/agent_runner.py::_adaptive_followup_targets`.

**Expected uplift**: Case 10 NR ~12 → ~30, PC 0 → 60, overall 35.4 → ~52.
~1.4 points to mean. Defensive — also catches future reverse_dns-driven
DPRK / front-company cases.

## P2 — Seed-domain `dom_fingerprints` for cluster-class hypotheses (SHIPPED this commit)

**Diagnosis.** Cases 6 (LummaC2 About-Cats), 9 (Tycoon 2FA), 11 (Smishing Triad),
12 (ClearFake) are kit-templated phishing/infostealer/smishing/fronted-C2.
The discriminating markers (favicon mmh3, page title hash, tracking IDs,
form actions) live in the seed page's DOM. The existing per-node URL branch in
`_adaptive_followup_targets` only fires for explicit `url` nodes, not for the
seed domain itself, so `dom_fingerprints(url=https://<seed>/)` was never called
on the seed in any of these cases.

**Fix shipped.** Add a graph-level branch in `_adaptive_followup_targets`:
- If the working_hypothesis category ∈ {phishing_kit, phishing_kit_cluster,
  smishing_hub, smishing, infostealer, fronted_c2, drainer_kit, traffer_or_tds},
  OR the working_hypothesis is unset (defensive default — dom_fingerprints
  is cheap and idempotent for any domain seed),
- AND no `dom_fingerprints` call has been made on the seed domain or
  `https://<seed>/`,
- emit `dom_fingerprints(url="https://<seed>/")` as an adaptive followup target.

**Files**: `backend/agent_runner.py::_adaptive_followup_targets`.

**Expected uplift**: Cases 6, 9, 11, 12 each gain a kit-cluster expansion
pivot path. Cases 6 NR 8 → ~25, 9 NR 20 → ~35, 12 NR 57 → ~70 (already strong).
Combined ~1.5 points to mean.

**Indirect gain**: extracted favicon/title/tracking-id markers further trigger
the existing per-node adaptive branches (favicon → shodan/netlas/zoomeye,
title_hash → urlscan title-pivot), recursively expanding the cluster.

## P3 — Cert-CN unmask must fire when seed has 0 IP nodes (SHIPPED this commit)

**Diagnosis.** The all-CDN cert-CN unmask branch in `_adaptive_followup_targets`
required `ip_nodes and all(cdn-tagged)`. When the agent never called
`dns_resolve` on the seed (or the wrapper didn't auto-tag IPs as CDN), the
branch never fired — Case 12 ClearFake had only 0-1 IP nodes both runs.

**Fix shipped.** Loosen trigger to fire when:
- Classic case: `ip_nodes ≥ 1` AND no non-CDN IPs (existing behaviour), OR
- Defensive case: `ip_nodes == 0` AND the agent has called crtsh / certspotter
  on the seed (so cert evidence exists, meaning a Shodan cert-CN query has
  something concrete to find).

**Files**: `backend/agent_runner.py::_adaptive_followup_targets` (existing
all-CDN branch, condition broadened).

**Expected uplift**: Case 12 already at 63.7 (RQ=100, NR=57); the cert-CN
unmask should push origin IP discovery → NR 70+ and PC 75 → 100. ~0.5 points
to mean.

## Top failure modes (still unaddressed, ranked by next-iteration leverage)

1. **F-EDGE-RECALL** — ER aggregate 1.8 across 11 cases. Ground-truth edge
   matching is fragile (string-substring on src/dst values + relation). The
   models do create edges but with paraphrased relation names. Defer until we
   instrument the runner to also tag report.metadata.edge_inventory with the
   exact GT-style relations.
2. **F-PIVOT-MISS::ct_burst_window** (Case 9 Tycoon 2FA) — `certspotter_issuances`
   gets called but the burst-date filter doesn't get applied. Mechanical fix
   would require a new `certspotter_issuances_after(date_iso)` arg in the source
   wrapper, not a pure followup change. Defer to next iteration.
3. **Case 11 dead-seed problem** — the chosen FQDN produced no enrichment data
   from any source. Methodology issue, not a code bug. Defer until we have a
   sandbox-egress-friendly live-feed snapshot source.

## Deferred to next iteration

- Live Case 11 seed selection (sandbox cannot poll IOFA feeds; we picked from
  the typical Smishing-Triad pattern but freshness unverified).
- BFS-depth tracking inside the BD scorer (currently approximated by call
  count alone — V2.1 spec also penalises depth>3 which we cannot detect from
  event stream).
- ER scorer hardening — refactor `score_er` to read edge metadata
  (`evidence`/`source`) rather than match on src/dst values, so paraphrased
  relations don't tank the score.
- RQ marker direct-write from runner — currently the mechanical-extraction
  pass in `phase_report_write` injects markers as MUST-INCLUDE-VERBATIM, but
  the model still paraphrases ~50% of the time. Next iteration: write
  `discriminating_markers` directly into `report.metadata` from the runner
  before the model sees the report-write prompt.
- Case 4 Interlock backup-IP cluster (NR 30 → would need richer threatfox
  parse to extract the 5-IP cluster from a single threatfox response).

## What this iteration will land

- **P0** (phase_hypothesis_write fix) — `agent_runner.py` only.
- **P1** (reverse_dns → TXT/MX adaptive target) — `agent_runner.py::_adaptive_followup_targets`.
- **P2** (seed-domain dom_fingerprints adaptive target) — `agent_runner.py::_adaptive_followup_targets`.
- **P3** (cert-CN unmask 0-IP loosen) — `agent_runner.py::_adaptive_followup_targets`.

**Estimated combined uplift**: mean 60.8 → 68-71. Pass rate 3/12 → 5-7/12.
WH presence 1/12 → 11-12/12 (mechanical, gated on the hypothesis_write fix).
Hallucination rate stays at 0/12 (no new sources, no new prompts that change
attribution rules).
