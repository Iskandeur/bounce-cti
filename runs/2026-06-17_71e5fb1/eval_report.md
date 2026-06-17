# Eval Report — 2026-06-17 (commit 71e5fb1)
## For: ROADMAP implementation agent

---

## TL;DR

CAP mean = **96.0** (+2.0 vs prior 94.0). All 3 negatives RST=100. Two cases still at PS=75:
- **c09** (Tycoon 2FA): `ct_burst_window` pivot not executed — fix is deployed in local files (this commit), will promote to PS=100 on future runs with crtsh burst data.
- **c12** (ClearFake): `shodan_cert_cn_search` blocked by `_is_parked()` over-gating on NS parking tags — **top priority fix needed** (see FIX-1 in `proposed_fixes.md`).

All positive cases: EFF=100 (budget bands met), RST=100 (no false cluster, no over-defuse), HYP=100 (working hypothesis + history + valid final_category). No hallucinations (0/5 hard gate clear). REC=61.1 on live cases (c02/c03/c08).

---

## Run metadata

| Key | Value |
|-----|-------|
| Date | 2026-06-17 UTC |
| Branch | `claude/vigilant-mayer-3ylpgh` → merged to `main` |
| VPS commit at run start | `71e5fb1` |
| Model | `opus-4.8` |
| Cases run | 2, 3, 8, 9, 12 + N1, N2, N3 (sequential, quota-survivable) |
| Runner | `/tmp/eval_run/sequential_runner.py` |
| Inv IDs | c02=e6d3f6876f01, c03=e17b1a564b61, c08=f9d662f6b576, c09=4b883dd96984, c12=49a6e5bd53df |
| Neg IDs | N1=6518e4477155 (Cloudflare IP), N2=c0b00797e0db (jsDelivr), N3=081d79b285e9 (Wikipedia) |
| Fixes deployed at run start | cert-CN any-CDN fix (71e5fb1), CDN malicious-tag suppression (69fc13c) |

---

## What changed vs prior run (69fc13c)

Two fixes were deployed to VPS before this run started:

### 1. cert-CN any-CDN fix (71e5fb1 — already on VPS)
**Problem**: The `shodan_search("ssl.cert.subject.CN:<domain>")` hint in the followup
phase only fired when ALL IPs in the graph were CDN-tagged. Cloudflare-fronted seeds that
also exposed a real origin IP (mixed graph) skipped the hint.

**Fix**: The hint now fires when ANY CDN-tagged IP exists, regardless of whether other
IPs in the graph are also CDN.

**Impact on this run**: c12 should have benefited — but it didn't, because a separate
bug (`_is_parked()` NS tag over-gating) caused the entire followup phase to be skipped
before the cert-CN hint could fire. The fix is correct but masked by FIX-1 (see below).

### 2. CDN malicious-tag suppression (69fc13c — already on VPS)
**Problem**: CDN-tagged IPs and parking-tagged nodes were getting auto-tagged `malicious`
or `c2` from OTX/ThreatFox lookups, creating false-positive clusters.

**Fix**: `add_node` in `graph_mcp.py` suppresses `malicious`, `c2`, `phishing` tags on
nodes already tagged `cdn`, `parking`, `sinkhole`, or `blackhole`.

**Impact on this run**: Confirmed working — all 3 negative cases (Cloudflare IP, jsDelivr,
Wikipedia) returned RST=100 with no false-positive malicious/c2/phishing tags.

---

## Per-case scores

| Case | Seed | CAP | PS | EFF | RST | HYP | REC | CTI calls | Notes |
|------|------|----:|---:|----:|----:|----:|----:|----------:|-------|
| c02 (MuddyWater) | SHA1 hash | 100 | 100 | 100 | 100 | 100 | 65.2 | 24 | apt_targeted correct |
| c03 (Bumblebee→Akira) | SHA256 hash | 100 | 100 | 100 | 100 | 100 | 59.8 | 33 | **+9.8 vs prior** (65.3→75.1) |
| c08 (Amadey/StealC) | SHA256 hash | 100 | 100 | 100 | 100 | 100 | 58.3 | 58 | cert_san_apex via pivot_drain |
| c09 (Tycoon 2FA) | domain | 90 | **75** | 100 | 100 | 100 | n/a | 32 | ct_burst_window MISS |
| c12 (ClearFake) | domain | 90 | **75** | 100 | 100 | 100 | n/a | 17 | shodan_cert_cn MISS (see below) |
| N1 (Cloudflare) | IP | — | — | — | **100** | — | — | — | No false-positive tags |
| N2 (jsDelivr) | domain | — | — | — | **100** | — | — | — | No false-positive tags |
| N3 (Wikipedia) | domain | — | — | — | **100** | — | — | — | No false-positive tags |

**CAP mean = 96.0** (up from 94.0 prior). **Neg RST = 100** (all 3 pass).

---

## Root cause analysis: c12 PS=75

**Case**: ClearFake (`921hapudyqwdvy.com`)
**Missing pivot**: `shodan_cert_cn_search`
**Expected outcome**: Shodan search on `ssl.cert.subject.CN:921hapudyqwdvy.com` → discovers origin IP behind Cloudflare fronting → confirms Hetzner ASN → closes the cert_cn node chain.

**Root cause**: `agent_runner._is_parked()` short-circuits the entire followup phase
(including mandatory cert-CN hint) when it detects `parking` tags on ANY node. The seed
domain's two nameservers (`ns1.renewyourname.net`, `ns2.renewyourname.net`) were tagged
`parking` during RDAP enrichment — they are hosted at a domain registrar's name-parking
service. The seed domain itself was correctly tagged `clearfake_c2`, `c2`, `malicious`,
`dga`, with VT `malicious=15/suspicious=3` and 10 prior investigation hits tagged
`clearfake_c2`.

**What happened**: `_is_parked()` saw `parking` in the NS node tags, returned `True`,
and `agent_runner.py` skipped the entire followup phase including:
- The mandatory cert-CN shodan search hint (the 71e5fb1 fix)
- Any other adaptive followup targets

**Why the origin IP was still found**: VT historical resolutions (`virustotal_resolutions_ip`)
returned the Hetzner origin IP (`135.181.211.230`) from 2023 campaign data. The
`cross_investigation_lookup` also confirmed it in 10 prior investigations. But the
cert-CN chain (`cert_cn:921hapudyqwdvy.com` → `ip:*yacolo` → `asn:AS203493`) was
never built.

**Fix required**: Modify `_is_parked()` to exempt seeds with malicious/c2/phishing
tags even if their NS servers are at a parking provider. NS nodes should not trigger
the parking short-circuit. Full fix spec in `proposed_fixes.md:FIX-1`.

**Timeline to fix**: ~20 minutes. High confidence the fix will work.

---

## Root cause analysis: c09 PS=75

**Case**: Tycoon 2FA (`rlcozx.es`)
**Missing pivot**: `ct_burst_window`
**Scorer rule**: `crtsh_subdomains` called on seed AND any node has `issuance_date`/`burst` in metadata.

**Root cause**: Both `crtsh_subdomains(rlcozx.es)` and `certspotter_issuances(rlcozx.es)`
were called. `certspotter_issuances` returned empty (domain is expired). `crtsh_subdomains`
returned results but the agent did not identify or record a burst-date cluster — it enriched
the sibling domains individually without computing a shared `not_before` date.

**Fix**: Adaptive hint in `_adaptive_followup_targets()` — already deployed in local files
(this commit). The hint fires when `crtsh_subdomains` was called on the seed but no node
carries `issuance_date`/`burst` in metadata. The agent is prompted to:
1. Re-call `crtsh_subdomains(seed_domain)` 
2. Find the most common `not_before` date among returned certificates
3. If ≥5 certificates share a date, add `ct_burst_cohort` report node

**Caveat**: Effectiveness on expired domains depends on crtsh having issuance date data.
Active Tycoon-2FA PhaaS campaigns (multiple domains issued in the same 24h window) should
show clear burst dates. Expired/aged campaigns may not.

---

## c03 improvement: +9.8 points

Case 3 (Bumblebee→Akira) improved from 65.3 → 75.1 (legacy REC-weighted), +9.8.
In CAP terms: 90.0 → 100.0 (+10). Root cause of prior 90: the previous eval run had PS=75
because the `virustotal_file` pivot rule wasn't being fired (or was fired but not hitting
the expected tool). In this run, all 4 pivot rules fired (PS=100), confirmed by:
- `virustotal_file`: called on the SHA256 hash seed
- `vt_pdns_domain`: called on C2 domains from VT report
- `reverse_ip_seo_decoy`: OTX/URLscan SEO-decoy domain detection
- `threatfox_ip`: called on C2 IPs from ThreatFox

The improvement was likely driven by the multi-phase workflow now correctly ordering
hypothesis-write before followup, ensuring the agent has a malware family hypothesis
before running Phase 3 source enrichment.

---

## Negative cases (RST check)

All 3 negatives passed cleanly:
- **N1** (Cloudflare anycast IP `104.16.123.96`): 6 nodes, tagged `cdn`/`benign`/`repeat_infrastructure`/`shared_hosting`. No false positive malicious/c2/phishing tags. RST=100.
- **N2** (jsDelivr CDN `cdn.jsdelivr.net`): 17 nodes, CDN-tagged IPs. No false positive tags. RST=100.
- **N3** (Wikipedia `www.wikipedia.org`): 19 nodes, tagged `wikimedia-infra`/`anycast-lb`/`benign`. JARM tagged `common-jarm`/`non-discriminating`. RST=100.

The CDN malicious-tag suppression (69fc13c) is confirmed working correctly.

---

## ROADMAP priorities (for implementing agent)

These are ordered by expected CAP gain and implementation effort:

### Priority 1 — CRITICAL: Fix `_is_parked()` NS tag over-gating
**File**: `backend/agent_runner.py`, function `_is_parked()` (~line 855)
**Change**: 
1. Before looping nodes, extract the seed node's tags.
2. If seed node has any of: `malicious`, `c2`, `phishing`, `botnet`, `ransomware`, `dropper`, `loader`, or any campaign-specific malicious tag (e.g. `clearfake_c2`, `cobalt_strike`), return `False` immediately — skip the parking short-circuit.
3. In the main loop, skip NS-type nodes when checking for `parking` tags (NS parking ≠ domain parking).

**Expected gain**: c12 PS 75→100, CAP 90→100. CAP mean: 96.0→98.0.

**Full spec**: `runs/2026-06-17_71e5fb1/proposed_fixes.md#FIX-1`

### Priority 2 — DONE: ct_burst_window adaptive hint
**File**: `backend/agent_runner.py`, function `_adaptive_followup_targets()`
**Status**: Deployed in this commit. Needs VPS deploy.
**Expected gain**: c09 PS 75→100 on future runs with crtsh burst data.

**Full spec**: `runs/2026-06-17_71e5fb1/proposed_fixes.md#FIX-2`

### Priority 3 — MEDIUM: KNOWN_BAD_MARKERS for Tycoon 2FA / STORM-1747
**File**: `backend/pivot_mapping.py`, `KNOWN_BAD_MARKERS` dict and `ACTOR_HANDLES` dict
**Change**: Add `phishing_kit:tycoon 2fa` and `actor:storm-1747` as known-bad markers
with auto-tag heuristics for OTX/URLscan matching content.
**Expected gain**: c09 RQ=40→70 (marker_in_report=True). No CAP gain but better
operational reporting.

### Priority 4 — LOW: NR gap investigation (c03/c08 missing nodes)
**Problem**: c03 NR=47.1 (missing 9 nodes including 4 C2 IPs), c08 NR=50.0 (missing 2 domains).
Both have PS=100, so this is a data availability gap, not a pivot routing issue.
**Investigate**:
- Are missing c03 C2 IPs in VT page-2 resolutions (not fetched)?
- Is `domain:gitlab.bzctoons.net` suppressed by fan-out cap?
**Expected gain**: NR/REC improvement on c03/c08, no CAP change.

---

## Eval framework notes (for ROADMAP agent)

The CAP (Capability) framework is the headline metric:
- **CAP = 0.40·PS + 0.25·EFF + 0.20·RST + 0.15·HYP**
- **PS (Pivot Selection)**: Did the agent execute the expected pivot techniques? Scorer checks specific tool call patterns (see `PIVOT_RULES` in `/tmp/eval_run/scorer.py`).
- **EFF**: Budget band × yield. 100 when CTI calls ≤ 60.
- **RST**: Restraint — no false clusters, no over-defuse. 100 for all cases this run.
- **HYP**: Working hypothesis quality. 100 for all cases (node present + history + valid final_category).

CAP is decay-proof (doesn't depend on live IoC availability), making it the right headline
for comparing runs across time. REC (legacy) is live-data-dependent and degrades for cases
with aged seeds.

Current targets: CAP mean ≥ 85 (reached 96.0). Next target: CAP = 100 across all 5 cases
(requires FIX-1 + FIX-2 to land, then a fresh run to verify).

---

## Files in this run dir

| File | Contents |
|------|----------|
| `scorecard.md` | Full v3 CAP + v2 legacy scorecard |
| `deltas.md` | Per-case missing nodes/edges, pivot misses, hand-audit notes |
| `failure_histogram.md` | PS/REC failure mode frequency |
| `raw_scores.json` | Machine-readable scores for all 8 cases |
| `proposed_fixes.md` | Prioritized fix specs with code examples |
| `eval_report.md` | This file |
