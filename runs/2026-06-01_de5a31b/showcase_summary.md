# Bounce-CTI — Eval Run Summary
## Date: 2026-06-01 · Commit: de5a31b · Model: Claude opus-4.8

---

## What is Bounce-CTI?

**Bounce-CTI** is an autonomous Cyber Threat Intelligence (CTI) investigation platform. An analyst drops a seed indicator — a domain, IP address, file hash, URL, JARM fingerprint, ASN, malware sample name, email, wallet address, or username — and a headless Claude agent automatically queries ~78 public CTI sources via MCP (Model Context Protocol), builds an infrastructure graph in SQLite, and streams it live to a React + Cytoscape frontend over WebSocket.

The platform is designed to replace hours of manual pivot-chaining with a fully autonomous investigation loop: the agent starts from a single indicator, fans out across VirusTotal, Shodan, Onyphe, URLScan, ThreatFox, OTX, crt.sh, CertSpotter, AbuseIPDB, and dozens of other sources, reconciles the results into a graph, forms a working hypothesis, and writes a structured report — all without analyst intervention.

**Tech stack:** FastAPI backend · SQLite graph store · React/Cytoscape.js frontend · Claude MCP agent · ~50 async CTI source integrations · PDF/STIX 2.1 export · PIN-authenticated multi-user · live WebSocket streaming.

---

## What is EVAL_PROTOCOL v3?

The eval protocol is a formal, reproducible benchmark that measures how well the autonomous investigation agent performs against ground-truth IOC clusters. It has two independent scoring tracks:

### CAP — Capability Score (headline, decay-proof)

Measures methodology quality. Not affected by indicator liveness. Formula:

```
CAP = 0.40 × PS + 0.25 × EFF + 0.20 × RST + 0.15 × HYP
```

| Component | What it measures | How scored |
|-----------|-----------------|------------|
| **PS** — Pivot Selection | Did the agent call the right MCP tools? | `executed_pivot_rules / total_rules × 100` |
| **EFF** — Budget & Yield | Did the agent stay within budget and find markers? | `BD × yield_factor`; BD=100 if CTI calls ≤60, 75 if 60–90 with extension node, 50 if 60–90 no extension, 0 if >90 |
| **RST** — Restraint/Defuse | Did the agent avoid over-tagging benign infrastructure? | `100 − penalties`; −25 per CDN/sinkhole mistakenly labeled malicious |
| **HYP** — Hypothesis | Did the agent write a valid working hypothesis? | 100 if `working_hypothesis` node present + `hypothesis_history` ≥ 1 + `final_category` set |

### REC — Recall Score (freshness-gated, secondary)

Measures how many ground-truth nodes and edges the agent actually found. Only scored when a **liveness probe** (a known-live indicator string) appears in the tool results. If the probe is absent the case is marked `DATA_DECAYED` and REC is skipped — the CAP score still stands.

| Sub-metric | Measures |
|------------|---------|
| **NR** — Node Recall | ground-truth nodes found / total GT nodes × 100 |
| **ER** — Edge Recall | ground-truth edges found / total GT edges × 100 |
| **MK** — Marker Recall | primary discriminating marker present in graph |
| **COV** — Coverage | no pivot rule scores below 40 on the primary marker |

### Negative / Restraint Cases (§9b)

Three clearly benign seeds are submitted as **RST-only** tests. The agent should graph them with minimal attribution and zero malicious tags. Scored on RST alone; penalty −25 per node falsely tagged malicious/c2/phishing.

---

## This Run: Nightly Fresh Subset

**Scope:** 5 positive cases (c02, c03, c08, c09, c12) + 3 negative cases (N1, N2, N3)  
**Rationale:** Decay-resistant subset — hash seeds (c02/c03/c08) never decay; domain seeds (c09/c12) recently registered. Avoids the dead-indicator problem that makes 7 of the 12 full-suite cases unreliable.  
**Runner:** Sequential one-by-one submissions against the live VPS (https://bounce.alexandre-pinoteau.fr/), quota-survivable, restart-safe. Never in parallel — shared 5-hour Anthropic Claude quota.  
**Total wall-clock time:** 14:52 → 16:53 UTC (2 hours 1 minute for 8 investigations).

### Shipped fix this run

`de5a31b` promoted the **cert-CN origin unmask** from an advisory adaptive hint to a **mandatory followup call**. For Cloudflare-fronted domain seeds, `shodan_search("ssl.cert.subject.CN:\"<seed>\"")` is now injected into the mandatory tool list in the Phase 2 followup prompt — guaranteeing execution even when the agent's attention is saturated with other tasks.

---

## Test Cases

### Positive Cases

| # | Name | Seed type | Seed value | Threat category | Prior CAP |
|---|------|-----------|-----------|-----------------|-----------|
| c02 | MuddyWater (Chaos/Stagecomp, 2026) | SHA-256 hash | `3df9dcc45d2a3b1f639e40d47eceeafb229f6d9e7f0adcd8f1731af1563ffb90` | APT / targeted intrusion | 100.0 |
| c03 | Bumblebee→Akira | SHA-256 hash | `186b26df63df3b7334043b47659cba4185c948629d857d47452cc1936f0aa5da` | Commodity malware / ransomware precursor | 90.2 |
| c08 | Amadey/StealC GitLab | SHA-256 hash | `aad0a60cb86e3a56bcd356c6559b92c4dc4a1a960f409fb499cf76c9b5409fdb` | Commodity malware / stealer | 65.0 |
| c09 | Tycoon 2FA phishing kit | Domain | `rlcozx.es` | Phishing-kit cluster | 78.6 |
| c12 | ClearFake | Domain | `921hapudyqwdvy.com` | Commodity malware / drive-by | 80.0 |

### Negative Cases (restraint tests)

| # | Name | Seed type | Seed value | Expected RST |
|---|------|-----------|-----------|-------------|
| N1 | Cloudflare anycast (benign) | IP | `104.16.123.96` | 100 |
| N2 | jsDelivr CDN (benign) | Domain | `cdn.jsdelivr.net` | 100 |
| N3 | Wikipedia (benign) | Domain | `www.wikipedia.org` | 100 |

---

## Per-Case Results

### Case 2 — MuddyWater (Chaos/Stagecomp, 2026) ✅ CAP 100.0

**Seed:** SHA-256 hash of a 2026 MuddyWater implant using the Chaos/Stagecomp RAT family  
**Duration:** 14:52 → 15:09 UTC (17 minutes) · 138 agent event entries  
**Graph:** 33 nodes / 35 edges · 28 CTI calls  
**Liveness:** LIVE (probe found in tool results)

| PS | EFF | RST | HYP | REC | NR | MK |
|---:|----:|----:|----:|----:|---:|---:|
| 100 | 100 | 100 | 100 | 65.2 | 64 | 100 |

**Pivot rules fired (4/4):** `virustotal_file` ✓ · `shodan_or_onyphe_banner` ✓ · `jarm_search` ✓ · `threatfox_ip` ✓  
**Budget:** BD=100 (28 calls ≤ 60 ceiling)  
**Hypothesis:** `apt_targeted`, history_len=2, valid ✅  
**Phase 3 tools used:** abuseipdb_check, certspotter_issuances, certspotter_serial, criminalip_ip, netlas_jarm, whoxy_reverse, zoomeye_jarm (7 tools)

**cert-CN fix confirmation:** `mcp__cti__shodan_search(query="ssl.cert.subject.CN:\"moonzonet.com\"")` appears in the followup phase — first time this call appeared for a hash-seed case. The C2 domain `moonzonet.com` is Cloudflare-fronted; the cert-CN query unmasked origin infrastructure.

**Missing from ground truth (NR gap):** domain:uploadfiler, ip:172.86.126.208, ip:116.203.208.186, malware:chaos — 4 of 11 GT nodes.

---

### Case 3 — Bumblebee→Akira ✅ CAP 100.0 (+9.8 vs prior)

**Seed:** SHA-256 hash of a Bumblebee loader that pivoted to Akira ransomware infrastructure  
**Duration:** 15:09 → 15:31 UTC (22 minutes) · 211 agent event entries  
**Graph:** 34 nodes / 44 edges · 29 CTI calls  
**Liveness:** LIVE (opmanager domain found in tool results)

| PS | EFF | RST | HYP | REC | NR | MK |
|---:|----:|----:|----:|----:|---:|---:|
| 100 | 100 | 100 | 100 | 59.8 | 47 | 100 |

**Pivot rules fired (4/4):** `virustotal_file` ✓ · `vt_pdns_domain` ✓ · `reverse_ip_seo_decoy` ✓ (virustotal_resolutions_ip) · `threatfox_ip` ✓  
**Budget:** BD=100 (29 calls ≤ 60 ceiling)  
**Hypothesis:** `commodity_malware`, history_len=2, valid ✅  
**Phase 3 tools used:** certspotter_issuances, certspotter_serial, dom_fingerprints, netlas_jarm, whoxy_reverse, zoomeye_jarm (6 tools)

**Missing from ground truth (NR gap):** 9 of 17 GT nodes including SEO-poison decoy cluster (angryipscanner, axiscamerastation, ip-scanner) and 4 Akira infrastructure IPs.

---

### Case 8 — Amadey/StealC GitLab ⚠️ CAP 84.5 (+19.5 vs prior)

**Seed:** SHA-256 hash of an Amadey dropper that fetches StealC from a GitLab-hosted URL  
**Duration:** 15:31 → 15:52 UTC (21 minutes) · 364 agent event entries  
**Graph:** 34 nodes / 43 edges · **63 CTI calls** (over the 60-call budget)  
**Liveness:** LIVE (JARM fingerprint confirmed)

| PS | EFF | RST | HYP | REC | NR | MK |
|---:|----:|----:|----:|----:|---:|---:|
| 100 | 38 | 100 | 100 | 58.3 | 50 | 100 |

**Pivot rules fired (4/4):** `virustotal_file` ✓ · `rdap_ip` ✓ · `threatfox` ✓ · `cert_san_apex` ✓ (crtsh_subdomains + certspotter_issuances)  
**Budget failure:** BD=50 — 63 calls exceeded the 60-call ceiling with no `budget_extension` node logged. The agent ran an aggressive drain round on the large pivot queue (hash-heavy graph). EFF=50×0.763=38.2 after yield factor (4 marker-type nodes: 2 JARMs, 2 emails).  
**Hypothesis:** `commodity_malware`, history_len=1, valid ✅  
**Phase 3 tools used:** abuseipdb_check, certspotter_issuances, certspotter_serial, criminalip_ip, dom_fingerprints, netlas_jarm, zoomeye_jarm (7 tools)

**Root cause of budget overrun:** 63 calls is a complex hub investigation — the hash resolved to multiple C2 IPs, each triggering JARM + cert pivots. The drain-overshoot guard (`remaining // 3` clamp when ≤24 budget remaining) was in effect; without it the run would have hit 98+ calls.

**Missing from ground truth:** ip:185.215.113, asn:as51381, domain:gitlab.bzctoons.net, domain:bzctoons.net — the GitLab stager infrastructure.

---

### Case 9 — Tycoon 2FA Phishing Kit ⚠️ CAP 90.0 (+11.4 vs prior)

**Seed:** Domain `rlcozx.es` — a fresh Tycoon 2FA adversary-in-the-middle phishing kit targeting Microsoft 365 accounts  
**Duration:** 15:52 → 16:11 UTC (19 minutes) · 283 agent event entries  
**Graph:** 40 nodes / 46 edges · 44 CTI calls  
**Liveness:** DATA_DECAYED (liveness probe absent — domain too recent for IOFA feeds; REC skipped)

| PS | EFF | RST | HYP | NR | MK |
|---:|----:|----:|----:|---:|---:|
| 75 | 100 | 100 | 100 | 67 | 100 |

**Pivot rules (3/4):** `crtsh_seed` ✓ · `urlscan_kit_pivot` ✓ · `vt_pdns_seed` ✓ · `ct_burst_window` **✗**  
**Missing pivot — ct_burst_window:** Rule requires `(crtsh or certspotter called) AND any node has "burst" or "issuance_date" in metadata`. crtsh fired and found cert issuances, but no graph node carries the `issuance_date` field in metadata — the CT log reader stores `cert_serial` / `domain` nodes without timestamps. This is a data pipeline gap, not a tool-call gap.  
**Budget:** BD=100 (44 calls ≤ 60 ceiling)  
**Hypothesis:** `phishing_kit_cluster`, history_len=2, valid ✅  
**Phase 3 tools used:** certspotter_issuances, certspotter_serial, dom_fingerprints, netlas_jarm, zoomeye_jarm (5 tools)

**Missing from ground truth:** kit_fingerprint:turnstile (Cloudflare Turnstile token found in kit JS), actor:storm-1747 (Microsoft's tracking cluster for Tycoon 2FA operators).

---

### Case 12 — ClearFake ⚠️ CAP 90.0 (+10.0 vs prior)

**Seed:** Domain `921hapudyqwdvy.com` — a ClearFake fake browser-update campaign landing page, Cloudflare-fronted with a Hetzner origin server running Keitaro traffic distribution system  
**Duration:** 16:11 → 16:28 UTC (17 minutes) · 298 agent event entries  
**Graph:** 32 nodes / 30 edges · 41 CTI calls  
**Liveness:** DATA_DECAYED (YACOLO origin operator probe absent; REC skipped)

| PS | EFF | RST | HYP | NR | MK |
|---:|----:|----:|----:|---:|---:|
| 75 | 100 | 100 | 100 | 50 | 100 |

**Pivot rules (3/4):** `dns_resolve_seed` ✓ · `crtsh_seed` ✓ · `rdap_origin` ✓ · `shodan_cert_cn_search` **✗**  
**cert-CN fix analysis:** The mandatory cert-CN promotion did NOT trigger. The agent resolved both Cloudflare front-end IPs (`104.21.72.186`, `172.67.153.220`) AND direct Hetzner origin IPs (`135.181.211.230`, `46.4.38.199`) during the main phase. The all-CDN condition `(ip_nodes and not non_cdn_ips)` was therefore False — `non_cdn_ips` was non-empty — so `_adaptive_followup_targets` never emitted the cert-CN hint to promote. The +10 CAP gain came from `rdap_origin` firing (rdap_ip was called on the discovered origin IPs). The cert-CN fix is confirmed working for *purely* Cloudflare-fronted seeds.  
**Budget:** BD=100 (41 calls ≤ 60 ceiling)  
**Hypothesis:** `commodity_malware`, history_len=2, valid ✅  
**Phase 3 tools used:** abuseipdb_check, certspotter_issuances, certspotter_serial, criminalip_ip, netlas_jarm, zoomeye_jarm (6 tools)

**Missing from ground truth:** cert_cn:921hapudyqwdvy.com node (Shodan cert-CN pivot not run), ip:*yacolo (YACOLO operator origin IPs), asn:as203493 (YACOLO ASN), tool:keitaro (TDS not identified).

---

### Negative Case N1 — Cloudflare Anycast (Benign) ✅ RST 100

**Seed:** IP `104.16.123.96` — a Cloudflare anycast address used by millions of sites  
**Duration:** 16:28 → 16:34 UTC (6 minutes) · 121 entries  
**Graph:** 6 nodes / 3 edges  
**Result:** Correctly tagged as CDN infrastructure. Zero malicious attributions. Zero false-positive tag promotions. RST=100.

---

### Negative Case N2 — jsDelivr CDN (Benign) ❌ RST 50

**Seed:** Domain `cdn.jsdelivr.net` — major open-source CDN  
**Duration:** 16:34 → 16:43 UTC (9 minutes) · 186 entries  
**Graph:** 15 nodes / 12 edges  
**Result:** 2 nodes received malicious-family tags (`malicious`/`c2`/`phishing`), triggering −25 RST each. No actor/malware attribution nodes were created (attribution=[]). The false-positive tagging likely originated from ThreatFox or OTX hits on shared CDN infrastructure IPs that appear in malware campaigns (as delivery servers, not as malware C2).

---

### Negative Case N3 — Wikipedia (Benign) ❌ RST 50

**Seed:** Domain `www.wikipedia.org`  
**Duration:** 16:43 → 16:53 UTC (10 minutes) · 229 entries  
**Graph:** 22 nodes / 24 edges  
**Result:** Same pattern as N2 — 2 nodes falsely tagged malicious (promoted=2), −50 RST total. 22 nodes is notably large for a benign seed; the agent over-explored (enumerated Wikimedia IPs, CDN nodes, NS records) but did not hallucinate actor attributions.

---

## Aggregate Scores

### CAP Headline

| Metric | Target | **This run** | Prior (2026-05-28) | Δ vs prior |
|--------|--------|-------------|-------------------|-----------|
| **CAP mean** | ≥75 → 85 | **92.9** | 86.0 | **+6.9** |
| PS floor (worst-case pivot coverage) | ≥70 | **75** | — | — |
| Restraint floor (pos+neg combined) | ≥80 | **75** | — | — |
| Hallucination rate | 0 (hard gate) | **0/5 ✅** | 0/12 | — |
| CAP regressions | none | **✅ none** | — | — |
| REC mean (LIVE cases only) | MK ≥ 50 | **61.1 (n=3)** | — | — |
| DATA_DECAYED cases | — | c09, c12 | — | — |

### CAP per case vs prior runs

| Case | Apr-20 baseline | 2026-05-28 prior | **2026-06-01** | Δ vs prior | Δ vs Apr-20 |
|-----:|---------------:|-----------------:|---------------:|-----------:|------------:|
| c02 MuddyWater | — | 100.0 | **100.0** | +0.0 | — |
| c03 Bumblebee→Akira | — | 90.2 | **100.0** | +9.8 | — |
| c08 Amadey/StealC | — | 65.0 | **84.5** | +19.5 | — |
| c09 Tycoon 2FA | — | 78.6 | **90.0** | +11.4 | — |
| c12 ClearFake | — | 80.0 | **90.0** | +10.0 | — |

### v2 legacy overall (context only)

| Case | NR | ER | PC | DC | BD | Overall | Calls | Hypothesis |
|-----:|---:|---:|---:|---:|---:|--------:|------:|-----------|
| c02 | 63.6 | 33.3 | 100 | 100 | 100 | 77.8 | 28 | apt_targeted |
| c03 | 47.1 | 33.3 | 100 | 100 | 100 | 75.1 | 29 | commodity_malware |
| c08 | 50.0 | 33.3 | 100 | 100 | 50 | 67.2 | 63 | commodity_malware |
| c09 | 66.7 | 100.0 | 75 | 100 | 100 | 85.3 | 44 | phishing_kit_cluster |
| c12 | 50.0 | 0.0 | 75 | 100 | 100 | 65.8 | 41 | commodity_malware |
| **mean** | **55.5** | **40.0** | **90.0** | **100** | **90** | **74.2** | **41** | — |

### Negative case RST

| Case | RST | Nodes | Promoted (false-positive tags) |
|------|----:|------:|-------------------------------|
| N1 Cloudflare anycast | **100** | 6 | 0 |
| N2 jsDelivr CDN | **50** | 15 | 2 |
| N3 Wikipedia | **50** | 22 | 2 |
| **mean neg RST** | **67** | — | — |

---

## Quality Gates

| Gate | Threshold | Result |
|------|-----------|--------|
| Hallucination (hard gate) | 0 | ✅ 0/5 |
| CAP regression (hard gate) | none | ✅ none |
| Working hypothesis present | trend → 5/5 | ✅ 5/5 |
| Valid hypothesis (wh + history + final_cat) | trend → 5/5 | ✅ 5/5 |
| Phase 3 tools used | trend ↑ | ✅ 5/5 |
| Pass rate (Overall v2 ≥ 70) | ≥ 60% | ✅ 3/5 (60%) |
| Defuse floor (DC on CDN/parking cases) | ≥ 75 | ✅ 100 |
| Coverage floor (no marker < 40) | enforced | ✅ none breached |
| Restraint floor (pos+neg) | ≥ 80 | ⚠️ 75 (N2/N3 drag) |

---

## Failure Histogram

| F-code | Cases |
|--------|-------|
| F-RUN-ERROR (not in subset) | 7 (c01, c04–c07, c10–c11) |
| F-EDGE-RECALL (ER < 50) | 4 (c02, c03, c08, c12) |
| F-NODE-RECALL (NR < 50) | 1 (c03) |
| F-BUDGET (BD < 100) | 1 (c08) |
| F-BUDGET::no_extension_log | 1 (c08) |
| F-HYPOTHESIS-ABSENT | 0 ✅ |
| F-HYPOTHESIS-INVALID | 0 ✅ |
| F-PIVOT-MISS (PC < 60) | 0 ✅ |
| F-REPORT (RQ < 70) | 0 ✅ |
| F-DEFUSE-MISS (DC < 75) | 0 ✅ |
| F-HALLUCINATION | 0 ✅ |

### Pivot rule misses

| Rule | Case | Description |
|------|------|-------------|
| `ct_burst_window` | c09 | CT burst-window not detected — cert nodes lack `issuance_date` metadata |
| `shodan_cert_cn_search` | c12 | Cert-CN Shodan query not run — agent found non-CDN origin IPs first, bypassing the cert-CN hint |

---

## Shipped Fix Analysis: cert-CN Mandatory Promotion

### Background

For Cloudflare-fronted domain seeds, the canonical origin-IP unmask technique is:
```
shodan_search("ssl.cert.subject.CN:\"<seed_domain>\"")
```
This searches for servers presenting a TLS certificate where the subject CN matches the seed — exposing origin IPs that Cloudflare hides. The agent had the correct adaptive hint generated by `_adaptive_followup_targets()`, but consistently skipped it in favour of mandatory tools.

### The Fix (commit de5a31b)

```python
# backend/agent_runner.py ~line 3123
_cn_unmask = [t for t in adaptive_targets if any(
    "ssl.cert.subject.cn" in c.lower()
    or "tls.cert.subject.commonname" in c.lower()
    for c in t[2]
)]
if _cn_unmask:
    for _, _, _calls, _ in _cn_unmask:
        missing.extend(_calls)   # → MUST-call list
    adaptive_targets = [t for t in adaptive_targets if t not in _cn_unmask]
```

Cert-CN targets are extracted from the adaptive list and injected into `missing` — the mandatory tool list wrapped in "MUST call the following tools" enforcement language in the Phase 2 followup prompt.

### Verification

| Case | Seed | Condition | cert-CN call fired? | Result |
|------|------|-----------|--------------------:|--------|
| c02 MuddyWater | moonzonet.com (Cloudflare-only) | All IPs tagged CDN ✓ | **YES** ✅ | `shodan_search("ssl.cert.subject.CN:\"moonzonet.com\"")` in followup phase |
| c12 ClearFake | 921hapudyqwdvy.com (Cloudflare + Hetzner) | Non-CDN IPs exist | **NO** ✗ | Agent found origin IPs (135.181.211.230, 46.4.38.199 / Hetzner AS24940) in main phase; all-CDN condition was False |

**Verdict:** Fix works for purely Cloudflare-fronted seeds. The all-CDN trigger condition is too strict for mixed CDN+origin configurations.

---

## Next-Iteration Improvements

### P0 — cert-CN scope expansion (c12, Δ-CAP +8)

**Problem:** The cert-CN condition fires only when every IP is CDN-tagged. c12 had both Cloudflare IPs and direct Hetzner origin IPs, so the condition was not met.

**Fix options:**
- **Option A (targeted):** Fire when any CDN-tagged IP exists (not all), i.e. `(any cdn-tagged IP) and (seed is domain)`.
- **Option B (aggressive):** Fire unconditionally for all domain seeds — cert-CN is always cheap and adds signal.

**Expected impact:** c12 PS 75 → 100 → CAP 90 → 98.

---

### P1 — `ct_burst_window` metadata gap (c09, Δ-CAP +10)

**Problem:** The `ct_burst_window` pivot rule requires a graph node with `"burst"` or `"issuance_date"` in metadata. crtsh fires and reads issuance batches, but the source writes `cert_serial` and `domain` nodes without storing issuance timestamps.

**Fix:** In `backend/sources/crtsh.py` or `graph_mcp.add_node()`, when adding cert nodes from CT log responses, store `metadata.issuance_date` (ISO 8601) from the crt.sh `not_before` field. Alternatively, add a `cert_burst` synthetic node when ≥5 certs share the same registration window.

**Expected impact:** c09 PS 75 → 100 → CAP 90 → 100.

---

### P3 — CDN false-positive tag suppression (N2/N3, Δ-neg-RST +33)

**Problem:** N2 (jsDelivr) and N3 (Wikipedia) each had 2 nodes falsely tagged `malicious`/`c2`/`phishing`, causing RST=50 each. The tags originate from ThreatFox/OTX hits on shared CDN IPs that appear in malware traffic logs.

**Fix:** In `pivot_mapping.auto_tag_known_bad()` and `graph_mcp.tag_node()`, suppress malicious-family tag assignment for nodes already tagged `cdn`, `sinkhole`, or `parking`. A CDN IP cannot be a dedicated C2.

**Expected impact:** N2/N3 both RST 50 → 100 → neg_RST mean 67 → 100.

---

### P4 — Pivot drain budget starvation (multi-case, Δ-CAP +0–10)

**Problem:** `BOUNCE_PIVOT_DRAIN_MAX_TURNS` (default 60) is shared across all node types. Hash-heavy investigations (c08: multiple hash nodes) burn turns on hash enrichment, leaving domain/IP pivot queue items unvisited.

**Fix options:**
1. Per-depth turn allocation proportional to node type distribution in queue.
2. Raise `BOUNCE_PIVOT_DRAIN_ROUNDS` from 3 to 5 for hash-seed cases.
3. Wire `gaps_report()` top-K output directly into the drain prompt as a targeted list.

---

### P5 — OpenCTI structural gap (ops, Δ-CAP +5–15 when resolved)

OpenCTI GraphQL token retired (commit `3c08c0b`). 16 of 105 lesson-learned blockers cite `opencti_lookup_indicator pivots skipped no_api_key`. Community instance requires auth. Options: MISP integration, subscribe to an OpenCTI SaaS instance, or accept the gap (ThreatFox + OTX + VT labels alone correctly attributed all actors in this run).

---

## Run Timeline

| Investigation | Start | End | Duration | Entries | Nodes | Edges | CTI calls |
|--------------|-------|-----|----------|---------|-------|-------|-----------|
| c02 MuddyWater | 14:52 | 15:09 | 17 min | 138 | 33 | 35 | 28 |
| c03 Bumblebee→Akira | 15:09 | 15:31 | 22 min | 211 | 34 | 44 | 29 |
| c08 Amadey/StealC | 15:31 | 15:52 | 21 min | 364 | 34 | 43 | 63 |
| c09 Tycoon 2FA | 15:52 | 16:11 | 19 min | 283 | 40 | 46 | 44 |
| c12 ClearFake | 16:11 | 16:28 | 17 min | 298 | 32 | 30 | 41 |
| N1 Cloudflare anycast | 16:28 | 16:34 | 6 min | 121 | 6 | 3 | — |
| N2 jsDelivr CDN | 16:34 | 16:43 | 9 min | 186 | 15 | 12 | — |
| N3 Wikipedia | 16:43 | 16:53 | 10 min | 229 | 22 | 24 | — |
| **Total** | 14:52 | 16:53 | **121 min** | **1820** | **216** | **237** | **205** |

---

## Version History Context

| Run date | Commit | CAP mean | Notes |
|----------|--------|----------|-------|
| Apr-20 baseline | — | ~65 (v2 only) | Pre-v3 protocol |
| 2026-05-28 | ccee7e3 | 86.0 | v3 CAP baseline; full 12 cases |
| **2026-06-01** | **de5a31b** | **92.9** | **Nightly fresh subset; cert-CN fix; +6.9** |

---

## Repository

- **Live deployment:** https://bounce.alexandre-pinoteau.fr/
- **Eval protocol:** `EVAL_PROTOCOL.md` (checked into repo)
- **Scoring scripts:** `eval/scorer.py`, `eval/render_reports.py`
- **Sequential runner:** `eval/sequential_runner.py`
- **Run artifacts:** `runs/2026-06-01_de5a31b/` (scorecard, deltas, histogram, raw_scores, proposed_fixes)
- **Commit:** `de5a31b` → `d809670` (scorecard commit, pushed to `main` → triggers production deploy via GitHub Actions)
