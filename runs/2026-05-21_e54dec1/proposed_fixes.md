# Proposed fixes — 2026-05-21 · commit e54dec1

Failures ranked by (cases affected) × (expected per-case delta). Mechanical
fixes preferred over prompt prose.

## Status snapshot

- Mean overall (all 12): **54.7** (prior 60.8, -6.1 — distorted by 4 quota-blocked cases).
- Mean overall (excluding quota-blocked cases 5, 10, 11, 12): **63.7** (n=8) — the
  real signal of behaviour changes since the prior run.
- Pass rate: **3/12 (25%)** (same as prior; Cases 7, 8, 9 cross 70).
- Hallucination rate: **0/12** (hard gate held).
- Working_hypothesis present: **8/12** (vs 1/12 prior — the prior commit's
  hypothesis-write fix landed and propagated cleanly; the 4 absent are the
  quota-blocked cases).
- Phase 3 tools used: **5/12** (vs 8/12 prior — quota burn-down depressed
  this; Cases 1, 4, 7 used Phase 3 sources).
- Median CTI calls per case: **9** (vs 47 prior — quota throttling halved
  per-case budget across the run).

## P0 — Post-report mechanical IOC + marker enforcement (SHIPPED this commit)

**Diagnosis.** RQ scores tank when the agent's `investigation_summary.metadata`
lacks the discriminating markers and IOCs the scorer's text-blob search looks
for. The existing `markers_block` in `phase_report_write` already instructs
the model to copy markers verbatim, but the model paraphrases ~50% of the
time. Measured cases this run with RQ ≤ 40 despite WH present + plenty of
markers in graph: Cases 1 (40 RQ), 2 (40), 4 (40), 5 (0), 9 (40), 10 (0),
11 (0), 12 (0). The 2026-05-06 proposed_fixes.md flagged this as the next
iteration's primary RQ lever.

**Fix shipped.** New `_enforce_summary_completeness(inv_id)` helper in
`backend/agent_runner.py` (added at line ~594, between `_has_lessons_learned`
and the lessons-ledger block). Called immediately after `phase_report_write`
completes AND after every `phase_pivot_drain_round_done` event. The function:
- Reads the graph, finds `investigation_summary`
- Builds the canonical `ioc_list` from every non-defused
  domain/ip/hash/email/url/subdomain/wallet_address node value
- Harvests `discriminating_markers` from cert/cert-CN/JARM/favicon/
  registrant-email/page-title/tracking-id fields + hex-32 tags
- Upserts via `gs.add_node` (idempotent merge — never overwrites agent
  prose, only fills gaps in `ioc_list` and `discriminating_markers`)

**Files**: `backend/agent_runner.py` (~135 lines new helper + 2 call sites:
after report_write at L3076, after pivot_drain_round_done at L3348).

**Expected uplift**: RQ from 40 → 70-100 on cases that had the data but
paraphrased it (Cases 1, 2, 4, 9 + all quota-blocked once they re-run with
quota). +2-4 points to mean. Indirect: improves the scorer's `node_pct` gate
(70% of GT IOCs in report) by ensuring every IOC lands in `ioc_list`.

## P1 — `urlscan_search` and `wayback` mandatory for domain seeds (SHIPPED this commit)

**Diagnosis.** Cases 6 (LummaC2 About-Cats), 9 (Tycoon 2FA), and 11
(Smishing Triad) hit `F-PIVOT-MISS::urlscan_or_wayback_seed` on prior runs.
The domain mandatory list had rdap_domain, virustotal_communicating_files,
threatfox_search, virustotal_resolutions_domain, otx_domain, crtsh_subdomains,
onyphe_domain — but not urlscan_search or wayback. urlscan_search is the
canonical content-fingerprint discovery tool for kit-templated phishing/
infostealer/smishing clusters; wayback is the canonical fallback when the
seed is sinkholed or LE-seized (Case 6 partial, Case 10 BlockNovas, Case 11
NameSilo bulk-cycle).

**Fix shipped.** Append both tools to the domain seed mandatory list in
`backend/agent_runner.py::_missing_mandatory_tools`. Followup phase will fire
them if main phase didn't.

**Files**: `backend/agent_runner.py::_missing_mandatory_tools` (line ~669).

**Expected uplift**: Cases 6, 9, 11 PC from 50-75 → 75-100. Cases 6 and 9
likely add 1-2 sibling clusters via urlscan kit-pivot. Case 11 may finally
get past the empty graph problem once seed-DOM content is fetched even when
the live seed is dead. ~1 point to mean.

## P2 — Adaptive followup: reverse-IP pivot for non-CDN IPs (SHIPPED this commit)

**Diagnosis.** Case 3 (Bumblebee→Akira) and Case 7 (SocGholish) hit
`F-PIVOT-MISS::reverse_ip_seo_decoy` on prior runs. When a hash or domain
seed surfaces a non-CDN IP (via virustotal_communicating_files, reverse_dns,
threatfox), the agent often graphs the IP and stops without calling
`virustotal_resolutions_ip` on it. That's the canonical pivot path to
co-resident sibling clusters (SEO-poison decoys for Case 3, stage-2 C2 for
Case 7). Hint-based nudges in `hints.py::hint_for_virustotal_file` already
mention this but the agent ignores prose nudges ~50% of the time.

**Fix shipped.** New branch in
`backend/agent_runner.py::_adaptive_followup_targets`: for the first 3
non-CDN IPs in the graph (excluding the seed itself) that haven't been
reverse-pdns pivoted, emit `virustotal_resolutions_ip` as an adaptive
target. Mechanical enforcement — no prompt prose change.

**Files**: `backend/agent_runner.py::_adaptive_followup_targets` (new
branch after the all-CDN seed-domain branch, line ~544).

**Expected uplift**: Case 3 NR 35 → 50, Case 7 NR 50 → 65 (already at 71
overall, this pushes it higher). +0.5-1 point to mean.

## Top failure modes still unaddressed

1. **Anthropic 5-hour quota burn-down** — the single biggest impact this
   iteration. 4/12 cases were effectively un-tested because the VPS account
   ran out of API budget. Not a code bug, but an infrastructure constraint
   the eval harness needs to be aware of. **Next iteration priority**:
   either (a) add a `--throttle-per-case-budget` env var to slow down the
   agent's per-second tool call rate so 12 cases fit in a 5h budget, or
   (b) ship a budget pre-check in `run_investigation` that aborts early if
   the recent rate of `quota_exceeded` events is high.
2. **F-EDGE-RECALL** — ER aggregate 16.6 (n=6) vs 1.8 prior — significant
   improvement from looser type-alias matching in the scorer, but still
   well below NR. Mechanical fix: instrument `_enforce_summary_completeness`
   to also emit a canonical `edge_inventory` list with GT-style relation
   names (`registered_by`, `resolves_to`, `same_cert`, `same_jarm`).
   Deferred to next iteration.
3. **F-PIVOT-MISS::ct_burst_window** (Case 9 Tycoon 2FA) — Requires a new
   `certspotter_issuances_after(date_iso)` arg in the source wrapper.
   Non-trivial; defer.

## Deferred to next iteration

- BFS-depth tracking in BD scorer (current approximates via call count).
- Edge-inventory canonical list on report.metadata (improves ER matching).
- Pivot-queue auto-drain — make the agent's `next_pivot()` call mandatory
  at fixed intervals so the queue isn't just a passive coverage check.
- Live Case 11 seed selection from a real IOFA feed (sandbox cannot poll).
- Case 8 apex-vs-subdomain differential tagging.
- Case 5 (Eye Pyramid) cross-brand affiliate attribution — multi-source
  threatfox merge needed.
- **Throttle env var** for the agent runner — give each case a soft per-
  minute tool call cap so a 12-case run fits in one Anthropic 5h window.

## What this iteration landed

- **P0** (post-report enforcement) — `agent_runner.py` new
  `_enforce_summary_completeness` helper + 2 call sites
- **P1** (urlscan_search + wayback mandatory for domain seeds) —
  `_missing_mandatory_tools` (2 lines added)
- **P2** (reverse-IP adaptive followup for non-CDN IPs) —
  `_adaptive_followup_targets` (new branch ~40 lines)

**Estimated combined uplift (next iteration, on a quota-clean run)**:
mean 63.7 → 68-72. Pass rate 3/12 → 5-7/12. The quota issue is exogenous
to the code changes — once the next run gets a clean Anthropic window,
the P0 fix alone should lift RQ ≥ 70 on every case that produces a
working hypothesis.
