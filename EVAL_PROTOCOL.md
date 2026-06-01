# EVAL_PROTOCOL — Bounce-CTI Evaluation Protocol

> **Version** 3.0 · **Status** active · **Cadence** nightly CI on the fresh subset (§6); full suite on milestones + every non-trivial change to `agent_runner.py`, the MCP tool set, `defuse_lists.py`, `pivot_mapping.py`, or source integrations.
> **v3.0 (2026-06-01)** splits scoring into a decay-proof **Capability** track — the headline, improvement-driving metric — and a freshness-gated **Recall** track; adds a *mechanical* freshness gate that SKIPs decayed seeds instead of scoring them 0; adds negative/restraint cases; recalibrates targets to the capability track; and sets the deterministic fixture-replay harness as the standing engineering target. Renamed from `EVAL_PROTOCOL_V2.md` (V1 deleted) on 2026-05-03.

---

## 0. Purpose & design philosophy

This protocol benchmarks **bounce-cti** against curated real-world CTI cases (Silent Push, Sekoia, Trend Micro, DFIR Report, DomainTools, Intrinsec, DNSFilter, Trellix) plus a set of benign **negative/restraint** cases (§9b). Each positive case provides a single seed IOC, a ground-truth node/edge set, an expected pivot chain, a discriminating marker, and a diagnostic signal.

The goal is an **improvement loop**, not a leaderboard:

```
run → score CAPABILITY (decay-proof) → classify failures → ship ONE mechanical fix → re-run → repeat
```

**Core principle — separate what the *tool* controls from what the *live internet* controls.** A CTI tool's recall depends on whether a vendor's 2023–2025 IOC is *still resolvable in passive sources today* — which decays and is **not** a property of the tool. v2 scored decayed seeds as failures, so the headline number tracked data freshness as much as tool quality (the 2026-05-31 run measured this directly: half the low-recall cases had their primary marker absent from *every* live tool response). v3 fixes this with two tracks:

- **Capability (CAP)** — the **headline, improvement-driving** score. Decay-proof: it measures *did the agent select the right pivots, stay budget-disciplined, form and revise a hypothesis, defuse noise, and avoid hallucination* — computed from the event log + graph, **independent of whether the historical node is still live.**
- **Recall (REC)** — secondary, **freshness-gated**: node/edge/marker recall against ground truth, scored **only on cases whose data is still live** (§3 mechanical gate). Decayed cases are `SKIP`ped from REC, never scored 0.

CAP is what a code change can move; it is the number the nightly loop optimizes and gates on. REC is reported for context and to catch genuine pivot-method regressions on *live* cases. The fresh **smoke/CI subset** (Cases 2, 3, 8, 9, 12 + negatives — §6) is the nightly default; the full suite is for milestones.

---

## 1. Terminology

- **Seed** — the single IOC (domain, IPv4, or SHA256) submitted to the `/api/investigations` endpoint.
- **Ground-truth node** — an indicator the reference writeup explicitly documents as part of the cluster.
- **Ground-truth edge** — a relation between two ground-truth nodes the writeup explicitly asserts.
- **Expected pivot** — a tool call (or tool-call chain) a competent analyst would execute from the seed.
- **Defuse target** — noise the tool must correctly skip (CDN range, sinkhole, parking NS, DynDNS, unrelated same-/24, etc.).
- **Discriminating marker** — the specific pivot artifact that makes the cluster identifiable (favicon hash, JARM, cert CN, registrant email, CT burst, etc.).
- **Diagnostic signal** — what a failure on this specific case tells you about the tool's internals.

---

## 2. Operator workflow (the eval agent's role)

You are the evaluation agent (this is also the **nightly autonomous routine** — the runnable prompt lives at `eval/NIGHTLY_PROMPT.md`). For each case:

1. **Submit the seed** via `POST /api/investigations {seed_type, seed_value, model}` (model = the account's whitelisted model). Run cases **one-by-one (sequential)** to stay inside the shared 5-hour Anthropic window — the backend's `claude -p` investigations burn the *same* subscription quota as the eval driver, so a parallel burst exhausts it. The `eval/` harness is **quota-survivable** (waits on the `/api/quota` window + resumes `quota_exceeded` in place) and **restart-safe** (records each `inv_id` at submit-time so a mid-wait death never spawns a duplicate).
2. **Wait** for a terminal status (`done|failed|stopped|error|cleared`); resume `quota_exceeded` via `POST /api/investigations/{id}/resume` once the window refills.
3. **Extract** the final graph (`/graph`), the transcript (`/transcript` — tool calls + result previews), and the report node.
4. **Apply the freshness gate (§3) mechanically:** if the case's `liveness_probe` is absent from *every* tool result, mark `DATA_DECAYED` → **SKIP from REC** (still score CAP).
5. **Score CAP** (§4.A) — decay-proof, mechanical. **Score REC** (§4.B) only if the case is LIVE.
6. **Classify** every delta into a failure mode (§5). Tag exogenous misses `F-DATA-DECAYED` / `F-SRC-TOKEN-DEAD` so they never count against the tool.
7. **Write the run report** (§6): the CAP/REC split, failure histogram, an **ops-actions** list (seed/token refresh), and **one** ranked mechanical fix.

**Never** edit positive-case ground truth to match tool output. If a ground-truth entry is genuinely wrong, fix it in a separate commit and log it in the Changelog.

---

## 3. Freshness gate (mechanical — replaces eyeballing)

Vendor IOCs decay; a perfect investigator still recovers nothing from a dead seed. v3 makes the freshness check **mechanical and automatic** so decay can never masquerade as a tool regression.

### The gate

Every positive case defines a **`liveness_probe`** in `eval/cases.py` — the string (normally its discriminating marker, or a defined anchor IOC) that *must appear in at least one tool result* for the live sources to be considered to still carry the cluster. After a case runs, the scorer:

1. Scans the investigation's full **tool-result corpus** (all `kind=tool_result` previews/bodies).
2. If `liveness_probe` is present in ≥ 1 result → case is **LIVE** → score CAP **and** REC.
3. If absent from **all** results → case is **`DATA_DECAYED`** → score **CAP only**; **exclude from the REC aggregate** (never score it 0).

The nightly run executes against the **production instance**, which has real egress, so the backend's own source responses *are* the freshness oracle — no separate live-check infrastructure is needed.

### Why CAP is still valid on a decayed case

A pivot is "executed" the moment the agent *calls the right tool on the right upstream value* — whether or not the source returns data. So pivot-selection, restraint, hypothesis discipline, and budget are all measurable on a decayed seed. Only recall (which needs the data to still exist) is gated.

### Known decay-prone cases (kept for CAP, gated for REC)

| Case | Reason |
|------|--------|
| 2 (MuddyRot) | C2 IPs aged out of VT contacted-files |
| 6 (LummaC2) | Operation Endgame seizure + sinkholing |
| 7 (SocGholish) | live A-record re-pointed; anchor IP gone from passive DNS |
| 10 (Contagious Interview) | BlockNovas FBI-seized; lost passive-DNS anchor |
| 11 (Smishing Triad) | domains burn < 30 days — seed refreshed per run (below) |
| 12 (ClearFake) | 2023 origin IPs partially burned |

### Case 11 seed selection (mandatory, per run)

Pick a fresh Smishing-Triad FQDN: NameSilo registrar, Cloudflare-fronted (`104.21`/`172.67`), `.top|.cc|.icu|.shop|.xin` TLD, USPS/toll/retail/bank lure. Record it in `seed_actual` and document the OSINT basis in the `eval/cases.py` Case-11 comment (sandbox cannot live-verify). Because Case 11 is almost always `DATA_DECAYED` (dead seed), it contributes to CAP (PC/restraint/budget against the dead seed) but not REC.

---

## 4. Scoring rubric

Two **independent** tracks. **CAP is the headline** the loop optimizes and gates on; **REC is freshness-gated and secondary.** Both are mechanical (no agent judgment in the score).

### 4.A Capability score (CAP) — decay-proof, the metric the loop optimizes

Computed from the event log + graph, valid even when the seed has decayed.

| Dim | Weight | Definition |
|-----|-------:|------------|
| **PS — Pivot selection** | 0.40 | `executed expected pivots / total`. A pivot is "executed" if the event log shows the expected tool called on a value derived from an upstream graph node — **regardless of whether it returned data.** This is the core analyst skill and the primary improvement lever. (v2's PC, promoted to the dominant weight.) |
| **EFF — Budget & yield** | 0.25 | the §4.5 budget band **×** a yield factor. Budget band: 100 if CTI calls ≤ 60 ∧ depth ≤ 3; 75 if calls ∈ (60,90] ∧ every extension logged a `budget_extension` node citing yield; 50 if (60,90] unjustified or depth = 4; 0 if calls > 90 or depth > 4. Yield factor scales by discriminating-markers-or-net-new-nodes per call and penalizes wasted/redundant fan-out (e.g. NSRL on `malicious`-tagged hashes, doc-pivots on CDN IPs). Rewards *focused* investigation, not call-count alone. |
| **RST — Restraint / defuse** | 0.20 | `100 − 10·over-inclusion − 15·over-defuse − 20·false-cluster`, floored at 0. **Over-inclusion**: a defuse target graphed without a `defused` tag. **Over-defuse**: a GT node tagged `defused` and not pivoted. **False-cluster**: unrelated tenants linked on shared ASN/CDN. Includes the negative cases (§9b): benign infra clustered/attributed is a restraint failure. |
| **HYP — Hypothesis discipline** | 0.15 | 100 iff a `working_hypothesis` node exists **and** the `investigation_summary` carries a `hypothesis_history` (≥ 1 documented revision) **and** a `final_category` that **matches the case's true category**; partial credit (50) if the node exists but history/category is missing or mismatched; 0 if absent. |

**CAP = 0.40·PS + 0.25·EFF + 0.20·RST + 0.15·HYP.**

**Hallucination = hard gate (not a dimension).** Any node/edge whose value cannot be traced to a tool result *or* to provenance metadata (`evidence`/`source`/`sources_seen`) ⇒ the case's CAP is **zeroed** and the run is flagged. A single hallucination fails the run (§7).

### 4.B Recall score (REC) — freshness-gated, secondary

Scored **only on LIVE cases** (§3). **Never** averaged into CAP.

- **NR** — node recall: `GT nodes found / total` (type-aliased; case-insensitive on values).
- **ER** — edge recall over **concrete** GT edges only. Abstract placeholders (`alpha`, `beta`, `cluster`, `victim`, `hosting_ip`, …) are **excluded from the denominator** — they cannot match a literal node value and were silently dragging v2 ER.
- **MK — marker recovery** *(weighted heaviest, report prominently)* — did the tool **graph and report** the case's discriminating marker? Binary-ish, 0/50/100. This is the single most diagnostic recall signal.
- **COV — report coverage** — fraction of GT nodes named in the written report.

REC is reported per-case and as an aggregate over LIVE cases. A drop in REC on a **LIVE** case (marker present in tool results but not graphed/reported) **is** a genuine tool regression and must be classified (§5).

### 4.C Fixture-replay capability track (STANDING TARGET — build incrementally)

The live run is non-deterministic (decay + source flakiness), so live-run CAP still wobbles run-to-run. **Target state:** capture each tool's actual JSON response into a versioned fixture set and **replay it deterministically**, so CAP is byte-reproducible and *a code change is the only variable.* The backend already memoizes source responses in the `cache` table — the build is (1) a capture mode that snapshots a case's responses, (2) a replay mode (`BOUNCE_FIXTURE_DIR`) that serves them offline, (3) fixtures committed under `eval/fixtures/<case>/`. Until built, the **live-run CAP with the §3 freshness gate is the operative metric.** Standing objective for the nightly agent: snapshot the fresh-subset cases first (hashes don't decay), one case per idle night.

---

## 5. Failure mode taxonomy

Every delta (missing node, missing edge, wrong pivot, noise inclusion) must be tagged with one of these codes. Use the most specific code that applies.

| Code | Name | Typical fix |
|------|------|-------------|
| **F-SRC-ABSENT** | Source not integrated in the tool | Add MCP tool for the missing source |
| **F-SRC-DEAD** | Source returned empty / rate-limited / 5xx | Retry with backoff; add caching TTL check; not a tool-design bug |
| **F-PIVOT-MISS** | Source exists but agent didn't call it | System prompt reinforcement; add explicit step in workflow |
| **F-PIVOT-QUERY** | Source called but query was wrong (wrong field, truncated value, unrelated term) | System prompt example; query-construction guidance |
| **F-DEFUSE-UNDER** | Noise bled into graph (CDN/sinkhole/parking not filtered) | Update `defuse_lists.py`; add pre-pivot `defuse()` call |
| **F-DEFUSE-OVER** | Real IOC was defused away | Tighten defuse heuristic; add whitelist carve-outs |
| **F-CLUSTER-OVER** | False-positive edges (e.g., connecting unrelated tenants on the same bulletproof ASN) | System prompt restraint; require ≥ 2 corroborating markers for cluster edges |
| **F-CLUSTER-UNDER** | Related IOCs not connected (agent saw them but didn't link them) | Edge-creation guidance in system prompt |
| **F-BUDGET** | Agent ran out of calls before completing pivot chain | Raise budget, or tighten fan-out caps per pivot depth |
| **F-REPORT** | Finding in graph but not in written report | Report-generation step improvement |
| **F-HALLUCINATION** | Node or edge has no tool-call evidence | **Critical.** System prompt must forbid unsupported writes |
| **F-SCHEMA** | Graph node has wrong type (e.g., IP stored as domain) | MCP tool validation; schema enforcement |
| **F-DATA-DECAYED** | GT node absent from *every* live source response (seed decayed) | **Exogenous — NOT a tool failure.** Triggers REC SKIP (§3); refresh or retire the seed |
| **F-SRC-TOKEN-DEAD** | Integrated source returns systemic auth failure (e.g. OpenCTI `AUTH_REQUIRED`) | **Ops action** (refresh token in `.env`), not a code bug; list under the run report's "ops actions" |
| **F-OVER-ATTRIBUTION** | A negative/benign case (§9b) was clustered or attributed | Restraint failure; tighten defuse / require ≥ 2 corroborating markers for cluster edges |

---

## 6. Iteration loop & cadence

### Cadence (tiered)

- **Nightly CI (the default autonomous run):** the **fresh subset** — decay-resistant cases + negatives — run sequentially, scored on **CAP**, regression-gated on CAP. Fits one 5-hour window. Ship **exactly one** ranked mechanical fix.
  - **Fresh subset = Cases 2, 3, 8 (hash seeds — don't decay) + 9, 12 (recent marker-pivot cases) + all negative cases (§9b).**
- **Weekly / milestone:** the **full suite** (all 12 + negatives), refreshes the §3 decay verdicts and the Case-11 seed, and is mandatory before a milestone tag (push → prod, no staging).

### Run report (`runs/YYYY-MM-DD_<commit-sha>/`)

```
scorecard.md          # CAP (PS/EFF/RST/HYP) + REC (NR/ER/MK/COV, LIVE-only) per case;
                      #   CAP & REC aggregates; Δ-CAP vs prior; DATA_DECAYED skips; ops-actions
deltas.md             # per-case missing nodes/edges/markers, pivot misses, hand-audit notes
failure_histogram.md  # F-* counts incl. F-DATA-DECAYED, F-OVER-ATTRIBUTION, F-BUDGET::no_extension_log
proposed_fixes.md     # ranked fixes (cases × Δ-CAP) + deferred + ops-actions (e.g. token refresh)
raw_scores.json       # machine-readable CAP/REC breakdown + hypothesis_history, final_category,
                      #   phase3 tools, yield, liveness verdict
```

### Improvement priority (keyed off CAP — decay-proof)

1. Any `F-HALLUCINATION` — trust-breaking, **fails the run**.
2. Any **CAP regression** vs the prior run on any case — **P0** (this is the decay-proof regression signal; e.g. the 2026-05-31 c6/c8 regressions both surfaced here).
3. `F-SRC-ABSENT` blocking ≥ 3 cases — highest capability leverage.
4. Top `F-PIVOT-MISS` / `F-DEFUSE-*` / `F-OVER-ATTRIBUTION` — prefer **mechanical** fixes (`_missing_mandatory_tools`, `_adaptive_followup_targets`, `pivot_mapping._PIVOT_RULES`, `backend/hints.py`) over `SYSTEM_PROMPT` prose (prose is read-and-ignored at a measurable rate).
5. `F-DATA-DECAYED` / `F-SRC-TOKEN-DEAD` → log under **ops-actions** (seed refresh, token renewal). **Do not "fix" in code.**

### Regression discipline

A fix must not regress **CAP** on any case (LIVE or decayed). Before pushing to `main`: Python import check, and re-run the fresh subset if the fix touches the agent loop. The case(s) that motivated the fix + any sharing the same marker (§8) are mandatory in that re-run.

---

## 7. Aggregate metrics & gates

| Metric | Definition | Target |
|--------|------------|--------|
| **CAP mean** | Mean capability across scored cases (the headline) | ≥ 75 (v3 launch), ramp to ≥ 85 |
| **PS floor** | Mean pivot-selection across cases | ≥ 70 (the tool must pick the right pivots) |
| **Hallucination rate** | Cases with an untraceable node/edge | **0%. Hard gate.** |
| **Restraint floor** | Mean RST across defuse cases (4, 6, 11, 12) + negatives (§9b) | ≥ 80 |
| **CAP regression** | Any case's CAP below its prior run | **None. Hard gate.** |
| **REC (context only)** | NR/ER/MK/COV over LIVE cases | reported; **MK ≥ 50** on live primary cases. **No hard target** (data-dependent). |

A commit fails the gate if: **any hallucination, any CAP regression, or the PS / restraint floor is breached.** **Recall decay never fails the gate** — isolating tool capability from data freshness is the entire point of v3. The pre-v3 "overall mean / pass rate" numbers are retained in historical scorecards for trend continuity but are superseded by CAP.

---

## 8. Case index

| # | Seed | Type | Category | Difficulty | Primary marker | Graph shape | Diagnostic signal on failure |
|---|------|------|----------|-----------|----------------|-------------|------------------------------|
| 1 | `materialplies.com` | domain | APT (Salt Typhoon) | medium | registrant-email reverse-WHOIS | cluster | No reverse-WHOIS pivot path |
| 2 | `94278fa0...c472` | sha256 | APT (MuddyWater) | easy-med | JARM / TLS banner | hub | Non-DNS pivots broken |
| 3 | `186b26df...a5da` | sha256 | Ransomware (Akira) | medium | VT file→contacted-infra | chain | File pipeline broken |
| 4 | `64.94.84.85` | ipv4 | Ransomware (Interlock) | hard | Cloudflare Tunnel defuse | cluster | Tunnel ≠ fronting logic broken |
| 5 | `195.177.95.163` | ipv4 | Cross-brand RaaS | hard | bulletproof ASN + default-page hash | cluster | Affiliate attribution collapsed |
| 6 | `rugtou.shop` | domain | Infostealer (Lumma) | hard | SSL SHA1 cert cluster + content fingerprint | cluster | Sinkhole-defuse or content pivot broken |
| 7 | `blackshelter.org` | domain | TDS (SocGholish) | medium | shared-IP co-residency | chain | Two-tier infra modeling broken |
| 8 | `aad0a60c...9fdb` | sha256 | Loader+stealer (Amadey/StealC) | med-hard | apex-vs-subdomain disambiguation | chain | Compromised-legit-infra handling broken |
| 9 | `rlcozx.es` | domain | Phishing (Tycoon 2FA) | medium | CT issuance-date burst | cluster | CT burst clustering broken |
| 10 | `37.211.126.117` | ipv4 | DPRK phishing (Contagious Interview) | med-hard | DNS TXT/MX + Wayback | chain | Rare pivots broken |
| 11 | *(live pick)* | domain | Smishing (Triad) | hard | **Cloudflare origin unmask** | hub | Primary Cloudflare-defuse broken |
| 12 | `921hapudyqwdvy.com` | domain | Fronted C2 (ClearFake) | medium | **cert CN → Shodan origin** | hub | Textbook Cloudflare-defuse broken |

**Coverage map (marker → primary case):**

| Marker | Primary | Secondary |
|--------|---------|-----------|
| Registrant-email reverse-WHOIS | 1 | 6 |
| JARM / TLS banner | 2 | 5, 12 |
| VT file → contacted infra | 3 | 2, 8 |
| Cloudflare Tunnel defuse | 4 | — |
| Bulletproof ASN cross-brand | 5 | — |
| SSL SHA1 cert cluster | 6 | 12 |
| Shared-IP co-residency | 7 | — |
| Apex-vs-subdomain compromised-legit | 8 | — |
| CT issuance-date burst | 9 | — |
| DNS TXT/MX cross-reference | 10 | — |
| Cloudflare origin unmask (historical A) | 11 | — |
| Cert CN → Shodan origin | 12 | — |
| Sinkhole defuse (passive residue preserved) | 6 | 10 |
| Wayback as primary evidence | 10 | — |

---

## 9. Cases

### Case 1 — Salt Typhoon registrant-email tradecraft

| Field | Value |
|-------|-------|
| **Seed** | `materialplies.com` |
| **Type** | domain |
| **Category** | APT (Salt Typhoon / Earth Estries / UNC2286 — PRC MSS telco espionage) |
| **Difficulty** | medium |
| **Graph shape** | cluster (reverse-WHOIS grouping) |
| **Primary source** | https://www.silentpush.com/blog/salt-typhoon-2025/ (Silent Push, 2025-09-08) |
| **Corroboration** | https://www.trendmicro.com/en_us/research/24/k/earth-estries.html (Trend Micro, 2024-11-25) |
| **Freshness risk** | low — Trend Micro + Silent Push IOCs still live |

#### Expected pivot chain
1. RDAP / WHOIS on seed → registrant email `sdsdvxcdcbsgfe@protonmail.com`
2. Reverse-WHOIS on registrant email → cluster siblings (`colourtinctem.com`, `solveblemten.com`)
3. SOA MNAME + registration-date windowing (2020-05 → 2023) to tighten cluster
4. Pivot to Beta-cluster registrants (`oklmdsfhjnfdsifh@protonmail.com`, etc.) → `dateupdata.com`, `infraredsen.com`, `pulseathermakf.com`
5. VT passive-DNS on cluster domains → hosting IPs
6. Reverse-IP on hosting IPs → UNC4841 overlap domains

#### Ground-truth nodes (min. 12 of 18 for full NR)
- `domain: materialplies.com`
- `domain: colourtinctem.com`
- `domain: solveblemten.com`
- `domain: dateupdata.com`
- `domain: infraredsen.com`
- `domain: pulseathermakf.com`
- `email: sdsdvxcdcbsgfe@protonmail.com` (Alpha cluster)
- `email: oklmdsfhjnfdsifh@protonmail.com` (Beta cluster)
- `ip: <hosting IPs from Silent Push cluster — verify at run time>` (≥ 3 expected)
- `actor: Salt Typhoon / Earth Estries / UNC2286`
- `malware: Demodex`, `malware: SnappyBee`, `malware: GhostSpider`

#### Ground-truth edges (min. 6 of 10 for full ER)
- `materialplies.com` —[registered_by]→ `sdsdvxcdcbsgfe@protonmail.com`
- `colourtinctem.com` —[registered_by]→ `sdsdvxcdcbsgfe@protonmail.com`
- `solveblemten.com` —[registered_by]→ `sdsdvxcdcbsgfe@protonmail.com`
- Alpha cluster ↔ Beta cluster —[SOA_MNAME_reuse]→
- Cluster domains —[resolves_to]→ hosting IPs
- Hosting IPs —[overlaps_with]→ UNC4841 / Barracuda infra

#### Must-defuse
- **Generic ProtonMail presence** — protonmail.com registrants are heavily benign. The discriminator is keyboard-mash local-part + creation window, **not** the string "protonmail". Defuse any node clustered on `protonmail.com` alone.
- Shared Cloudflare fronting on any parked sibling domains.

#### Diagnostic signal
If NR < 30: **no reverse-WHOIS path** in the tool. The whole cluster is invisible to DNS/cert-only pivots.
If DC < 50: tool over-clustered on ProtonMail substring.

---

### Case 2 — MuddyRot JARM + banner fingerprint

| Field | Value |
|-------|-------|
| **Seed** | `94278fa01900fdbfb58d2e373895c045c69c01915edc5349cd6f3e5b7130c472` |
| **Type** | sha256 |
| **Category** | APT (MuddyWater / Mango Sandstorm / TA450 — Iran MOIS) |
| **Difficulty** | easy-to-medium |
| **Graph shape** | hub (one C2 fans to siblings) |
| **Primary source** | https://blog.sekoia.io/muddywater-replaces-atera-by-custom-muddyrot-implant-in-a-recent-campaign/ (Sekoia, 2024-07-15) |
| **Corroboration** | Check Point "BugSleep" research (same period) |
| **Freshness risk** | low — hashes don't decay |

#### Expected pivot chain
1. VT file lookup on seed → contacted IP `91.235.234.202:443`
2. Shodan / Onyphe banner on `91.235.234.202:443` → raw-TLS JARM fingerprint
3. JARM-based search → sibling C2 IPs (2–3 expected)
4. ThreatFox pivot on `ip:port` tagged `muddywater` / `bugsleep` → corroboration + sibling hashes
5. VT on sibling hashes → Egnyte staging URLs referenced in PDF lures

#### Ground-truth nodes (min. 6 of 9)
- `sha256: 94278fa01900fdbfb58d2e373895c045c69c01915edc5349cd6f3e5b7130c472` (seed)
- `sha256: b8703744...fbca` (sibling)
- `sha256: 73c677dd...b30e` (sibling)
- `ip: 91.235.234.202` (live C2)
- `ip: 146.19.143.14` (reported down — **negative-result test**)
- `url: egnyte.com/<staging path>` (lure staging)
- `actor: MuddyWater`
- `malware: MuddyRot` / `malware: BugSleep`

#### Ground-truth edges (min. 4 of 6)
- Seed hash —[contacts]→ `91.235.234.202`
- Sibling hashes —[same_family]→ seed
- C2 IPs —[share_JARM]→ each other
- ThreatFox IP —[tagged]→ `muddywater`

#### Must-defuse
- Same-/24 neighbors of `91.235.234.202` **without** JARM/banner match — do not cluster on /24 alone.
- Empty Wayback / URLScan result is a **valid negative**, not a failure.
- `146.19.143.14` being down is expected — tool should record and move on, not retry indefinitely.

#### Diagnostic signal
If PC < 40: **non-DNS pivots are broken** (JARM/Shodan not wired up). Canonical "DNS-only tool" shakeout.
If BD < 50: tool thrashed on the down IP.

---

### Case 3 — Bumblebee → AdaptixC2 → Akira (SEO-poisoned MSI)

| Field | Value |
|-------|-------|
| **Seed** | `186b26df63df3b7334043b47659cba4185c948629d857d47452cc1936f0aa5da` |
| **Type** | sha256 (trojanized `ManageEngine-OpManager.msi`) |
| **Category** | Ransomware affiliate / loader chain |
| **Difficulty** | medium |
| **Graph shape** | chain (MSI → loader C2 → C2-2 → ransomware) |
| **Primary source** | https://thedfirreport.com/2025/08/05/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira/ (DFIR Report, 2025-08-05) |
| **Corroboration** | Swisscom B2B CSIRT, Anvilogic, CyberSecurityNews |
| **Freshness risk** | low |

#### Expected pivot chain
1. VT file on seed → dropped DLL `a6df0b49a5ef9ffd6513bfe061fb60f6d2941a440038e2de8a7aeb1914945331` + contacted domain `opmanager[.]pro`
2. VT passive-DNS on `opmanager[.]pro` → hosting IP
3. Reverse-IP / Shodan → sibling SEO-poison decoy domains (`angryipscanner[.]org`, `axiscamerastation[.]org`, `ip-scanner[.]org`)
4. ThreatFox on AdaptixC2 IP `172.96.137.160` → family tag
5. Identify three distinct infra tiers: C2 (`109.205.195.211`, `188.40.187.145`), AdaptixC2 (`172.96.137.160`), exfil (`193.242.184.150`, `185.174.100.203`)

#### Ground-truth nodes (min. 10 of 15)
- `sha256: 186b26df...a5da` (seed MSI)
- `sha256: a6df0b49...5331` (dropped DLL)
- `domain: opmanager[.]pro`
- `domain: ev2sirbd269o5j[.]org`, `domain: 2rxyt9urhq0bgj[.]org` (Bumblebee DGA)
- `domain: angryipscanner[.]org`, `domain: axiscamerastation[.]org`, `domain: ip-scanner[.]org` (SEO decoys)
- `ip: 109.205.195.211`, `ip: 188.40.187.145` (Bumblebee C2)
- `ip: 172.96.137.160` (AdaptixC2)
- `ip: 193.242.184.150`, `ip: 185.174.100.203` (SSH-tunnel / SFTP exfil)
- `malware: Bumblebee`, `malware: AdaptixC2`, `ransomware: Akira`

#### Ground-truth edges (min. 7 of 11)
- Seed MSI —[drops]→ dropped DLL
- Seed MSI —[contacts]→ `opmanager[.]pro`
- Loader DGA domains —[same_family]→ Bumblebee C2 IPs
- SEO decoy domains —[themed_cluster]→ each other (Swisscom)
- AdaptixC2 IP —[C2_channel]→ victim
- Exfil IPs —[distinct_tier]→ not clustered with C2 IPs

#### Must-defuse
- Bumblebee DGA domains are short-lived — accept as one-shot evidence, don't fan out.
- Exfil IPs must be tagged as a **separate tier** — if they're merged into the C2 cluster, that's `F-CLUSTER-OVER`.

#### Diagnostic signal
If three-tier distinction is collapsed: system prompt doesn't enforce tier labeling. Tag as `F-CLUSTER-OVER`.
If SEO decoy cluster missed: reverse-IP / same-ASN pivot not firing.

---

### Case 4 — Interlock ClickFix via Cloudflare Tunnel

| Field | Value |
|-------|-------|
| **Seed** | `64.94.84.85` |
| **Type** | ipv4 |
| **Category** | Ransomware (Interlock — ~24 claimed victims through Q1 2025, incl. Texas Tech Health Sciences) |
| **Difficulty** | hard |
| **Graph shape** | cluster (8 backup IPs + ClickFix staging + tunnel family) |
| **Primary source** | https://blog.sekoia.io/interlock-ransomware-evolving-under-the-radar/ (Sekoia, 2025-04) |
| **Corroboration** | CISA/FBI AA25-203A (2025-07-24) |
| **Freshness risk** | low |

#### Expected pivot chain
1. RDAP + reverse DNS on seed → hosting ASN
2. VT passive-DNS on seed → backup-IP sibling discovery
3. ThreatFox tag `interlock` → cluster confirmation
4. URLScan keyword pivot on ClickFix path `additional-check.html` → decoy staging domains
5. Wayback / URLScan recover original PowerShell lure
6. Identify `trycloudflare.com` tunnel pattern with `/init1234` endpoint heuristic

#### Ground-truth nodes (min. 10 of 15)
- `ip: 64.94.84.85` (seed)
- `ip: 49.12.69.80`, `ip: 96.62.214.11`, `ip: 188.34.195.44`, `ip: 45.61.136.202` (backup IPs — ≥ 5 total expected)
- `domain: microsoft-msteams[.]com`, `domain: microstteams[.]com`, `domain: advanceipscaner[.]com`, `domain: ecologilives[.]com` (ClickFix staging)
- `url: advanceipscaner[.]com/additional-check.html` (lure path)
- `domain_family: *.trycloudflare.com` with `/init1234` endpoint (treat as **one aggregate node**, not per-tunnel)
- `malware: Interlock`, `ttp: ClickFix`

#### Ground-truth edges (min. 5 of 8)
- Backup IPs —[same_cluster]→ each other (ThreatFox corroboration)
- ClickFix staging domains —[delivery_chain]→ PowerShell lure
- `advanceipscaner[.]com` —[typosquat_of]→ Advanced IP Scanner (overlap with Case 3)
- Cloudflare Tunnel aggregate —[C2_channel]→ backup IPs

#### Must-defuse
- **Generic `*.trycloudflare.com`** — this is a legitimate Cloudflare service hosting millions of ephemeral tunnels. Discriminator: `/init1234` path + first-seen window. **Do not cluster every trycloudflare subdomain.**
- ClickFix decoys overlap with commodity ClearFake — disambiguate via delivery hash family.

#### Diagnostic signal
If DC < 40: tool either (a) expanded `*.trycloudflare.com` blindly (F-DEFUSE-UNDER), or (b) defused the whole tunnel family including the Interlock-specific pattern (F-DEFUSE-OVER). Check which.
**This is the Cloudflare *Tunnel* test**, distinct from Cloudflare *fronting* (Cases 11, 12). They require different defuse logic.

---

### Case 5 — Eye Pyramid cross-brand affiliate infrastructure

| Field | Value |
|-------|-------|
| **Seed** | `195.177.95.163` |
| **Type** | ipv4 |
| **Category** | Cross-brand ransomware affiliate (Rhysida / Vice Society / BlackCat / RansomHub / Fog on shared Eye Pyramid post-ex framework) |
| **Difficulty** | hard |
| **Graph shape** | cluster (bulletproof-ASN ecosystem) |
| **Primary source** | https://www.intrinsec.com/en/ip-cluster-linking-ransomware-activity-and-eye-pyramid-c2/ (Intrinsec, 2025-04-28) |
| **Corroboration** | DFIR Report Dec-2024 Fog case; GuidePoint Jan-2025 RansomHub Python backdoor |
| **Freshness risk** | low |

#### Expected pivot chain
1. RDAP on seed → ASN AS214943 (Railnet)
2. Shodan / Onyphe → Eye Pyramid default 404 JSON fingerprint
3. Banner-hash search → sibling IPs across Limenet, Aeza, Global Connectivity Solutions (AS215540), Play2Go (AS215439)
4. ThreatFox multi-tag resolution → `rhysida`, `vicesociety`, `blackcat`, `ransomhub`
5. VT passive-DNS on sibling IPs → victim-facing domains (sparse — mostly IP-based post-ex infra)

#### Ground-truth nodes (min. 15 of 22)
- `ip: 195.177.95.163` (seed)
- `asn: AS214943` (Railnet / Limenet)
- `asn: AS215540` (Global Connectivity Solutions)
- `asn: AS215439` (Play2Go)
- Sibling IPs on each ASN (≥ 10 expected across clusters)
- `framework: Eye Pyramid`
- `ransomware: Rhysida`, `ransomware: Vice Society`, `ransomware: BlackCat`, `ransomware: RansomHub`, `ransomware: Fog`
- `malware: Cobalt Strike`, `malware: Sliver`, `malware: Rhadamanthys` (co-hosted on seed)

#### Ground-truth edges (min. 8 of 12)
- Sibling IPs —[share_banner]→ each other (Eye Pyramid 404 JSON)
- Each ransomware brand —[uses_infra]→ Eye Pyramid cluster
- Bulletproof ASNs —[ecosystem]→ each other (cross-hoster tenancy)

#### Must-defuse
- Bulletproof hosters carry unrelated tenants — **must not anchor on ASN alone**. Require banner+ThreatFox corroboration.
- Eye Pyramid is open-source on GitHub since 2022 — banner match without ThreatFox/OTX corroboration is lower confidence; don't upgrade to attribution.

#### Diagnostic signal
If only one ransomware brand is linked: affiliate-level attribution collapsed into single-brand attribution (F-CLUSTER-UNDER). System prompt must allow multi-brand on shared infra.
If RQ < 50: report didn't mention the cross-brand affiliate-model finding — the whole point of the case.

---

### Case 6 — LummaC2 "About Cats" post-takedown cluster

| Field | Value |
|-------|-------|
| **Seed** | `rugtou.shop` |
| **Type** | domain |
| **Category** | Infostealer (LummaC2 / Lumma Stealer — MaaS) |
| **Difficulty** | hard |
| **Graph shape** | cluster (58 domains documented, 41 live at publication) |
| **Primary source** | https://www.domaintools.com/resources/blog/tracking-lummac2-infrastructure-with-cats (DomainTools, 2025-05-29) |
| **Corroboration** | CISA/FBI AA25-141b; Microsoft/DOJ 2,300-domain seizure May 2025; Trend Micro 2025-07 rebuild report |
| **Freshness risk** | **high** — post–Operation Endgame; sinkholing active |

#### Expected pivot chain
1. RDAP on seed → Namecheap registrar + `@inbox.eu` registrant pattern
2. URLScan / Wayback on seed → "About Cats" landing-page content fingerprint
3. Content-fingerprint pivot → 40+ sibling `.shop` domains
4. crt.sh on cluster → 5 SSL SHA1 cert fingerprints (e.g., `80b9e0f6a81ab78ee4e01152958e1322e6d7b6fa`)
5. SSL SHA1 pivot → additional cluster members (including aged-pre-use domains)
6. NS clustering via mail servers (`pinkipinevazzey.pw`, `fanlumpactiras.pw`)

#### Ground-truth nodes (min. 25 of 58 domains + 4 fingerprints for full NR)
- `domain: rugtou.shop` (seed)
- ≥ 24 of the 58 documented sibling `.shop` domains
- `cert_sha1: 80b9e0f6a81ab78ee4e01152958e1322e6d7b6fa` (≥ 1 of 5 expected)
- `domain: pinkipinevazzey.pw`, `domain: fanlumpactiras.pw` (mail servers)
- `registrant_pattern: @inbox.eu Eastern-European pseudonym`
- `malware: LummaC2`

#### Ground-truth edges (min. 10 of 15)
- Sibling domains —[share_content_fingerprint]→ each other (About Cats landing)
- Sibling domains —[share_cert_sha1]→ each other
- Cluster —[registered_via]→ Namecheap
- Domains —[mx_record]→ mail servers
- Seized subset —[sinkholed_by]→ Microsoft/DOJ (2025-05)

#### Must-defuse
- **Heavy Cloudflare fronting** (`104.21.x.x`) — must not collapse cluster to Cloudflare anycast.
- **Microsoft sinkhole artifacts** on the 2,300 seized domains — residual passive-DNS preserved is **good**; tool must not discard sinkholed-but-historically-useful data.
- Benign `.shop` lookalikes.

#### Diagnostic signal
- If Cloudflare defuse failed: F-DEFUSE-UNDER, check `defuse_lists.py` Cloudflare ranges.
- If sinkholed domains discarded entirely: F-DEFUSE-OVER on the sinkhole heuristic — tool needs to preserve historical passive-DNS even on sinkholed nodes.
- If NR < 30 but DC high: content-fingerprint pivot not implemented (URLScan DOM / HTTP title).
**This is the designated sinkhole-defusing test.**

---

### Case 7 — SocGholish via rogue Keitaro TDS

| Field | Value |
|-------|-------|
| **Seed** | `blackshelter.org` |
| **Type** | domain |
| **Category** | TDS / commodity loader (SocGholish / TA569 / Mustard Tempest) — doubles as benchmark TDS slot |
| **Difficulty** | medium |
| **Graph shape** | chain (TDS front → Keitaro → stage-2 C2) |
| **Primary source** | https://www.trendmicro.com/en_us/research/25/c/socgholishs-intrusion-techniques-facilitate-distribution-of-rans.html (Trend Micro, 2025-03-14) |
| **Corroboration** | Darktrace SocGholish→RansomHub writeup |
| **Freshness risk** | low |

#### Expected pivot chain
1. DNS A on seed → `176.53.147.97`
2. Reverse DNS / VT passive-DNS on `176.53.147.97` → co-hosted siblings (`rednosehorse.com`, `blacksaltys.com`, `packedbrick.com`, `newgoodfoodmarket.com`)
3. URLScan / Wayback on siblings → compromised-WP referrer pages calling Keitaro
4. Passive-DNS second hop → SocGholish stage-2 C2 subdomains (`virtual.urban-orthodontics.com`, `msbdz.crm.bestintownpro.com`)
5. Stage-2 DNS → `185.76.79.50`, `166.88.182.126`
6. ThreatFox confirms SocGholish family on stage-2 IPs

#### Ground-truth nodes (min. 8 of 13)
- `domain: blackshelter.org` (seed)
- `ip: 176.53.147.97` (Keitaro front)
- `domain: rednosehorse.com`, `domain: blacksaltys.com`, `domain: packedbrick.com`, `domain: newgoodfoodmarket.com` (TDS-front siblings)
- `domain: virtual.urban-orthodontics.com`, `domain: msbdz.crm.bestintownpro.com` (stage-2 C2, on compromised-legit)
- `ip: 185.76.79.50`, `ip: 166.88.182.126` (stage-2 C2)
- `malware: SocGholish`, `tool: Keitaro TDS` (legitimate software, weaponized instance)

#### Ground-truth edges (min. 5 of 8)
- Co-hosted siblings —[share_ip]→ `176.53.147.97`
- Compromised WPs —[referrer_to]→ TDS fronts (aggregate, not per-node)
- Stage-2 subdomains —[C2_channel]→ SocGholish payload
- Tiers are distinct: TDS-front (tier 1) ≠ stage-2 C2 (tier 2)

#### Must-defuse
- **Keitaro is legitimate commercial TDS software** — benign instances on shared VPSes must not false-flag the product.
- **Compromised WP referrers are victims**, not attacker-owned — aggregate them, don't add as individual graph nodes.

#### Diagnostic signal
If tier distinction is collapsed (TDS and stage-2 merged): F-CLUSTER-OVER on two-tier modeling.
If compromised WPs were added as attacker-owned nodes: victim/attacker attribution bug.

---

### Case 8 — Amadey → StealC via compromised self-hosted GitLab

| Field | Value |
|-------|-------|
| **Seed** | `aad0a60cb86e3a56bcd356c6559b92c4dc4a1a960f409fb499cf76c9b5409fdb` |
| **Type** | sha256 |
| **Category** | Commodity loader + infostealer (Amadey + StealC) |
| **Difficulty** | medium-hard |
| **Graph shape** | chain (hash → C2 → compromised GitLab → apex) |
| **Primary source** | https://www.trellix.com/blogs/research/amadey-exploiting-self-hosted-gitlab-to-distribute-stealc/ (Trellix, Dec 2025) |
| **Corroboration** | SC Media, OALABS, 0x0d4y on AS51381 ELITETEAM |
| **Freshness risk** | low |

#### Expected pivot chain
1. VT file on seed → contacted URL `http://62.60.226.159/xx.exe`
2. RDAP on `62.60.226.159` → ASN AS51381 (ELITETEAM)
3. ThreatFox pivot on ASN → Amadey-family C2 cluster (`185.215.113.x`)
4. VT/Trellix cross-reference → StealC staging at `gitlab.bzctoons.net`
5. Cert SAN on apex `bzctoons.net` → long-lived TLS, 2003 registration (**legitimate, compromised at subdomain**)
6. ThreatFox confirms StealC + Amadey family labels

#### Ground-truth nodes (min. 8 of 12)
- `sha256: aad0a60c...9fdb` (seed)
- `ip: 62.60.226.159` (contacted)
- `ip: 185.215.113.x` range (Amadey C2 hub — ≥ 3 IPs expected)
- `asn: AS51381` (ELITETEAM)
- `domain: gitlab.bzctoons.net` (compromised subdomain — **malicious**)
- `domain: bzctoons.net` (apex — **legitimate, tag `compromised_subdomain_only`**)
- `malware: Amadey`, `malware: StealC`

#### Ground-truth edges (min. 5 of 7)
- Seed hash —[contacts]→ `62.60.226.159`
- Amadey C2 cluster —[same_asn]→ AS51381
- `gitlab.bzctoons.net` —[hosts_stager]→ StealC
- Apex —[parent_of]→ gitlab subdomain, with **differential tagging** (apex clean, subdomain dirty)

#### Must-defuse
- **The 2003-registered apex `bzctoons.net` must NOT be flagged as malicious.** Only the GitLab subdomain is weaponized. This is the canonical false-positive test for cert-age / domain-reputation heuristics.
- Long-lived valid TLS cert on the apex is a trap for naïve "new cert = bad" logic.

#### Diagnostic signal
If apex is flagged malicious: F-DEFUSE-OVER on apex reputation. System prompt needs "apex vs subdomain scoping" guidance.
If only the seed hash's direct contact IP is recovered (no pivot to 185.215.113.x hub): F-PIVOT-MISS on ASN pivot.

---

### Case 9 — Tycoon 2FA cert-SAN burst pivot

| Field | Value |
|-------|-------|
| **Seed** | `rlcozx.es` |
| **Type** | domain |
| **Category** | Phishing / AiTM (Tycoon 2FA / Storm-1747 / Saad Tycoon Group — PhaaS targeting M365) |
| **Difficulty** | medium |
| **Graph shape** | cluster (CT-burst cohort → kit-fingerprint families) |
| **Primary source** | https://www.dnsfilter.com/blog/tycoon-2fa-infrastructure-expansion (DNSFilter, 2025-07-08) |
| **Corroboration** | Sekoia URLScan heuristic; Cyfirma 2025-11 rule (`ifelse.rlcozx.es/N@g38UiKmbi`) |
| **Freshness risk** | low-medium — Mar-2026 takedown disrupted a chunk but passive residue persists |

#### Expected pivot chain
1. crt.sh on seed → Let's Encrypt leaf certs + `ifelse.*` subdomain pattern
2. CT issuance-date extraction → 2025-04-07
3. crt.sh burst-window search for same-day `.es` issuances → 12 sibling roots (13 total `.es` roots)
4. URLScan pivot on kit CSS filename + Cloudflare Turnstile script → ~3,000 Tycoon pages across TLD generations (`.es`, `.ru`, `.sa.com`, `.it.com`, `.com.de`)
5. VT passive-DNS on sibling roots → shared NS / resolver IPs
6. Wayback / URLScan recover archived fake-M365 flow

#### Ground-truth nodes (min. 15 of 25)
- `domain: rlcozx.es` (seed)
- ≥ 12 sibling `.es` roots from the 2025-04-07 burst
- ≥ 5 cross-TLD kit siblings (`.ru`, `.sa.com`, `.it.com`, etc.)
- `kit_fingerprint: Tycoon 2FA CSS filename`
- `kit_fingerprint: Cloudflare Turnstile script`
- `actor: Storm-1747 / Saad Tycoon Group`
- `phishing_kit: Tycoon 2FA`

#### Ground-truth edges (min. 8 of 12)
- Sibling roots —[CT_burst_cohort]→ 2025-04-07
- Cross-TLD siblings —[share_kit_fingerprint]→ each other
- Roots —[uses_gating]→ Cloudflare Turnstile

#### Must-defuse
- Cloudflare Turnstile / Workers fronting layer.
- Let's Encrypt issuer is grab-bag noise — don't cluster on issuer alone.
- **Wildcard on root, not child FQDNs** — target-specific subdomains have very low query volume.

#### Diagnostic signal
If CT burst-window pivot missed: F-PIVOT-MISS on crt.sh date-range queries. System prompt needs "cluster by issuance date" guidance.
If cross-TLD siblings missed: URLScan DOM fingerprinting not wired as a primary pivot.

---

### Case 10 — Contagious Interview DPRK IPv4 → DNS-TXT/MX cross-reference

| Field | Value |
|-------|-------|
| **Seed** | `37.211.126.117` |
| **Type** | ipv4 |
| **Category** | DPRK job-lure phishing (Contagious Interview / UNC5342 / Famous Chollima) |
| **Difficulty** | medium-hard |
| **Graph shape** | chain (IP → C2 domain → DNS cross-ref → front companies) |
| **Primary source** | https://www.silentpush.com/blog/contagious-interview-front-companies/ (Silent Push, 2025-04-24) |
| **Corroboration** | Validin 2025-03-11; Socket 2025-11 (338+ malicious npm packages); FBI seizure 2025-04-23 |
| **Freshness risk** | medium-high — BlockNovas FBI-seized; Wayback is primary for archived flow |

#### Expected pivot chain
1. Reverse DNS + VT passive-DNS on seed → `lianxinxiao[.]com` (first seen 2024-08-12)
2. **DNS TXT/MX records** on `lianxinxiao[.]com` → cross-reference reveals `blocknovas[.]com` (**rare pivot, the whole point of the case**)
3. crt.sh on `blocknovas[.]com` → subdomains (`gitlab.`, `mail.`, `status.`)
4. Wayback on `gitlab.blocknovas[.]com` → JS pointing to `attisscmo[.]com`, `angeloper[.]com`, `softglide[.]co`
5. URLScan on front-company sites + Status Dashboard → archived interview flow
6. Tag payload families as **not infra**: `BeaverTail`, `InvisibleFerret`, `OtterCookie`

#### Ground-truth nodes (min. 8 of 13)
- `ip: 37.211.126.117` (seed, AS44477 Stark Industries)
- `domain: lianxinxiao[.]com` (C2 linking front companies)
- `domain: blocknovas[.]com` (seized)
- `domain: angeloper[.]com`, `domain: softglide[.]co`, `domain: attisscmo[.]com` (front companies)
- `subdomain: gitlab.blocknovas[.]com`, `subdomain: status.blocknovas[.]com`, `subdomain: mail.blocknovas[.]com`
- `malware: BeaverTail`, `malware: InvisibleFerret`, `malware: OtterCookie` (**payload, tagged not-infra**)
- `actor: Famous Chollima / UNC5342`

#### Ground-truth edges (min. 6 of 9)
- Seed IP —[resolves]→ `lianxinxiao[.]com`
- `lianxinxiao[.]com` —[dns_txt_mx_ref]→ `blocknovas[.]com` (the key edge)
- `blocknovas[.]com` —[parent_of]→ gitlab/mail/status subdomains
- Three front-company domains —[coordinated_by]→ `lianxinxiao[.]com`

#### Must-defuse
- **Stark Industries AS44477 is multi-tenant** — anchor on IP+DNS cross-reference, not ASN alone.
- Post-seizure sinkhole artifacts on BlockNovas — **use Wayback as primary** for archived content.

#### Diagnostic signal
If `lianxinxiao → blocknovas` cross-ref edge missed: F-PIVOT-MISS on DNS TXT/MX records. **This is the only case testing that pivot — if it fails, the tool is blind to non-A-record DNS.**
If seized domains returned empty and tool gave up: F-PIVOT-MISS on Wayback fallback.

---

### Case 11 — Smishing Triad (PRIMARY Cloudflare-defuse test)

| Field | Value |
|-------|-------|
| **Seed** | **PICK FRESH per §3** — current USPS/toll-lure FQDN from Silent Push Dec-2025 IOFA feed |
| **Type** | domain |
| **Category** | Smishing (Smishing Triad / Lighthouse kit, dev "Wang Duo Yu") — 121+ countries |
| **Difficulty** | hard |
| **Graph shape** | hub (origin IP fans out to thousands of Cloudflare-fronted lures) |
| **Primary source** | https://www.silentpush.com/blog/smishing-triad/ (Silent Push, 2025-04-10) |
| **Corroboration** | Krebs on Security (2025-04-10 and 2025-12); Prodaft 2025-03-24; Resecurity 2023/2024 baseline |
| **Freshness risk** | medium — seed FQDNs burn in < 30 days; refreshed each run |

#### Expected pivot chain
1. RDAP / WHOIS on seed → NameSilo registrar + bulk-registration timestamp
2. crt.sh on seed → wildcard `*.<tld>` SAN cluster
3. VT / Onyphe passive-DNS → Cloudflare (`104.21.x.x`) in foreground
4. **Pivot to origin**: non-Cloudflare historical A-records OR direct MX records → Tencent (AS132203) / Alibaba (AS45102) origin IPs
5. Shodan / Onyphe banner on origin → sibling lure FQDNs on same origin
6. URLScan DOM-template similarity → cross-brand clustering (USPS ↔ E-ZPass ↔ toll ↔ bank templates)

#### Ground-truth nodes (min. 20 of 50, **capped**)
- Chosen seed (recorded in `seed_actual`)
- ≥ 20 sibling lure FQDNs from the current IOFA feed cohort
- ≥ 3 Tencent / Alibaba origin IPs
- ≥ 3 DOM template families (USPS / toll / bank)
- `registrar: NameSilo`
- `kit: Lighthouse`
- `actor: Smishing Triad / Wang Duo Yu`

**Cap enforcement**: graph must have ≤ 200 total nodes — Smishing Triad has ~25,000 live domains in any 8-day window. Tool must apply per-hop fan-out limits.

#### Ground-truth edges (min. 8 of 12)
- Cloudflare-fronted lures —[historical_origin]→ Tencent/Alibaba IPs
- Origin IPs —[shared_by]→ sibling FQDNs
- DOM templates —[cross_brand_kit]→ different lure themes
- Lures —[registered_via]→ NameSilo

#### Must-defuse
- **Cloudflare fronting is the whole point.** Tool must pivot to **historical passive DNS** to find origin, not stop at Cloudflare edge.
- Shared Tencent / Alibaba IPs are multi-tenant — cluster on **DOM template + first-seen window**, not IP alone.
- `.top` / `.cc` TLDs are abused but also legitimate.

#### Diagnostic signal
If tool terminated at Cloudflare edge: **Cloudflare-defuse origin-pivot not implemented.** F-PIVOT-MISS on `historical_a_records`.
If budget exhausted before origin pivot: F-BUDGET — per-hop fan-out cap too loose; tool enumerated SANs before pivoting.
**This is the designated primary Cloudflare-defuse (origin unmask) test.**

---

### Case 12 — ClearFake cert-CN → Shodan origin (canonical)

| Field | Value |
|-------|-------|
| **Seed** | `921hapudyqwdvy.com` |
| **Type** | domain |
| **Category** | Fake-updates traffer / fronted C2 (ClearFake → Lumma / AMOS / Rhadamanthys) |
| **Difficulty** | medium |
| **Graph shape** | hub (one cert CN → 6 origin IPs) |
| **Primary source** | https://blog.sekoia.io/clearfake-a-newcomer-to-the-fake-updates-threats-landscape/ (Sekoia, 2023-10-20) + IOC repo https://github.com/SEKOIA-IO/Community/tree/main/IOCs/clearfake |
| **Corroboration** | Sekoia Mar-2025 EtherHiding variant (context) |
| **Freshness risk** | medium — origin IPs partially burned, cert-CN pivot still valid via historical Shodan |
| **Classic case justification** | Canonical cert-CN → Shodan pivot; no 2024-26 case replicates it as cleanly. The tool isn't re-finding live infra; it's re-deriving the **pivot method**. |

#### Expected pivot chain
1. DNS A on seed → Cloudflare edge (**noise — must not follow**)
2. crt.sh on seed → certificate CN issued for `921hapudyqwdvy.com`
3. **Shodan / Onyphe / Censys query** `ssl.cert.subject.CN:"921hapudyqwdvy.com"` → 5 origin IPs on AS203493 YACOLO-AS + 1 on AS24940 Hetzner
4. RDAP on origins → netblock operators
5. VT passive-DNS on origins → sibling throwaway ClearFake domains resolving to same /24
6. Shodan HTTP-body fingerprint → Keitaro TDS landing confirmation

#### Ground-truth nodes (min. 7 of 12)
- `domain: 921hapudyqwdvy.com` (seed)
- `cert_cn: 921hapudyqwdvy.com` (the pivot anchor)
- `ip: <5 origin IPs on AS203493 YACOLO-AS>` (≥ 3 recovered for full NR)
- `ip: <1 on AS24940 Hetzner>`
- `asn: AS203493 YACOLO-AS`, `asn: AS24940 Hetzner`
- ≥ 3 sibling ClearFake throwaway domains (from VT passive-DNS on origins)
- `tool: Keitaro TDS` (on origin)

#### Ground-truth edges (min. 5 of 7)
- Seed —[cert_cn]→ `921hapudyqwdvy.com`
- Cert CN —[leaked_on]→ 6 origin IPs (the unmask)
- Origin IPs —[same_asn]→ YACOLO-AS (for 5 of them)
- Sibling throwaway domains —[resolve_to]→ origin /24

#### Must-defuse
- **Cloudflare anycast IPs on the seed's DNS resolution** — must NOT follow as graph nodes.
- Let's Encrypt issuer (low signal).
- The attacker's operational mistake (CN exposed on origin) is the **sole anchor** — tool must pivot on cert, not DNS.

#### Diagnostic signal
If tool terminates at Cloudflare edge without attempting Shodan cert-CN query: **textbook Cloudflare-defuse failure.** F-PIVOT-MISS on `shodan_ssl_cn_search`.
If origin IPs found but Keitaro fingerprint missed: Shodan HTTP-body pivot not wired.
**This is the canonical Cloudflare-defuse (cert-CN unmask) test.** A DNS-only tool terminates here. A cert-aware tool unmasks.

---

## 9b. Negative / restraint cases (N-series) — scored on RST only

Benign seeds the tool must **not** cluster or attribute. A CTI tool that cries
wolf on a CDN edge IP or a popular SaaS host is *dangerous* — over-attribution
poisons downstream blocking. These cases make the restraint gate real (v2 had
only one restraint dimension and no benign seeds, so over-attribution was
invisible). They are decay-immune (benign infra stays benign), so they belong
in the nightly fresh subset.

**Scoring (RST, feeds §4.A and the §7 restraint floor):** 100 if the tool
defuses/limits correctly and the report states a *benign / no-malicious-cluster*
verdict; −25 per benign node promoted into a malicious cluster or tagged
malicious; **0 if any threat-actor / malware / kit attribution is asserted.**

| # | Seed | Type | Correct behaviour |
|---|------|------|-------------------|
| N1 | `104.16.123.96` | ipv4 | Cloudflare anycast — `defuse` as CDN, no cluster, no attribution |
| N2 | `cdn.jsdelivr.net` | domain | legitimate CDN/SaaS — doc-only, no malicious cluster |
| N3 | `www.wikipedia.org` | domain | popular-benign apex — defuse / shared-hosting, no cluster |

`liveness_probe` is N/A for negatives (they are never gated). Add more N-series
seeds as new false-positive classes appear in production triage.

---

## 10. Known gaps

Carried forward from the research phase, reviewed for V2.

- **Hash-seed scarcity** — writeups providing a clean file-hash seed **and** a documented passive-source pivot chain re-derivable from Bounce-CTI's sources are rare. Cases 2, 3, 8 are the strongest. A fourth high-quality hash case remains an open slot; candidates considered but deferred: Latrodectus (requires Team Cymru Augury), Mustang Panda (Unit 42 Nov-2025 — cut for space).

- **Live-check coverage is indirect** — the research environment could not hit crt.sh / URLScan / OTX / ThreatFox UIs directly. Freshness verdicts lean on the primary writeups' observations plus secondary corroboration. **The freshness pre-check in §3 is mandatory before each run.**

- **Only one pre-2024 case** — Case 12 (ClearFake, 2023-10). Retained because the cert-CN → Shodan pivot is canonical and no 2024-26 case replicates it.

- **Two Cloudflare-defuse cases with overlapping signal** — Cases 11 and 12 both test Cloudflare fronting, but exercise different mechanics (historical-origin-IP pivot vs cert-CN pivot). Keep both; they fail independently. If one had to be dropped for time, Case 12 (classic) has higher pedagogical value; Case 11 has higher freshness.

- **Case 11 seed must be refreshed per run** — Smishing Triad domains burn in < 30 days. Pre-run selection procedure in §3.

- **Candidates explicitly cut** — APT28 Nearest Neighbor (LOTL, no pivotable infra); APT28 Car-for-Sale (legit-service noise); Latrodectus (private NetFlow); ClearFake EtherHiding (on-chain, out of scope); Rockstar 2FA (overlaps Case 9); VexTrio Viper (private Infoblox telemetry); LabHost (2 years old); generic AiTM kits (no clean passive chain); crypto drainer infra (on-chain).

---

## 11. Changelog

- **v2.0** (2026-04) — Initial V2 protocol. 12 cases across 6 domains / 3 IPv4 / 3 hash seeds. All markers from the design matrix covered. Eval loop, scoring rubric, failure taxonomy, freshness pre-check codified.
- **v2.1** (2026-05-03) — Autonomy engine update. §4.5 BD scoring revised:
  yield-justified extensions (60, 90] earn 75 instead of 50. Reflects the new
  pivot queue + soft-cap budget logic introduced in `feat/autonomy-engine`.
  No case content changed.
- **v3.0** (2026-06-01) — **Capability/Recall split.** Headline metric is now
  the decay-proof **CAP** (PS 0.40 / EFF 0.25 / RST 0.20 / HYP 0.15) computed
  from the event log + graph; **REC** (NR/ER/MK/COV) is freshness-gated via a
  *mechanical* `liveness_probe` check (decayed seeds SKIP REC, never score 0).
  Added negative/restraint cases (§9b); `F-DATA-DECAYED` / `F-SRC-TOKEN-DEAD` /
  `F-OVER-ATTRIBUTION` codes; tiered cadence (nightly fresh-subset CI on CAP +
  weekly full); recalibrated targets to CAP (≥ 75 → 85) with CAP-regression and
  restraint hard gates; dropped abstract placeholders from the ER denominator;
  and set the deterministic **fixture-replay** harness (§4.C) as the standing
  engineering target. Motivated by the 2026-05-31 run: half the low-recall
  cases had their primary marker absent from *every* live tool response — i.e.
  the old "overall mean" tracked data freshness as much as tool quality. No
  positive-case ground truth changed. The runnable nightly routine is
  `eval/NIGHTLY_PROMPT.md`.

---

*Maintainer note — Alexandre:* the per-case diagnostic signal is the most important field for iteration. When something fails, read that line first before reading the ground-truth delta. It tells you *which piece of the tool* is broken, not just *that* something is missing.
