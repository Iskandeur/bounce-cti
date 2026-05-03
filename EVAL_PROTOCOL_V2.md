# EVAL_PROTOCOL_V2 — Bounce-CTI Evaluation Protocol

> **Version** 2.0 · **Status** active · **Cadence** run against every non-trivial change to `agent_runner.py` system prompt, MCP tool set, `defuse_lists.py`, or source integrations.

---

## 0. Purpose

This protocol benchmarks **bounce-cti** against 12 curated real-world CTI investigation cases drawn from reputable vendor writeups (Silent Push, Sekoia, Trend Micro, DFIR Report, DomainTools, Intrinsec, DNSFilter, Trellix). Each case provides a single seed IOC, a ground-truth node/edge set, an expected pivot chain, and a diagnostic signal (what it tells you if the tool fails it).

The goal is an **iteration loop**, not a leaderboard:

```
run cases → compute deltas → classify failures → adjust tool → re-run → repeat
```

If this protocol feels too heavy, run the **smoke set** (Cases 2, 3, 7 — one seed per IOC type, medium difficulty, fast). Full 12-case runs are for milestone checkpoints.

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

You are the evaluation agent. For each case:

1. **Pre-check freshness** (§3). If residual passive data is below the floor, mark the case `SKIP — data decayed` and move on. **Do not blame the tool for dead sources.**
2. **Submit the seed** via `POST /api/investigations` with the specified model (default `sonnet` unless a case notes otherwise).
3. **Wait** for `status: completed` (or `failed`) on `/api/investigations/{id}`.
4. **Extract** the final graph (`/api/investigations/{id}/graph`), the event log (`events` table, filter `agent_*`), the written report (last `report` node), and the tool-call count.
5. **Score** against the case's ground truth (§4) — this is mechanical counting, not judgment.
6. **Classify** every delta into a failure mode (§5).
7. **Record** the scorecard row (§7).
8. After all 12 cases: write a **run report** with aggregate metrics, top 3 failure modes by frequency, and one proposed fix per top failure (§6).

**Never** edit ground truth to match tool output. If a ground-truth entry is wrong (real research error, not tool failure), log it in `Changelog` and fix the protocol in a separate commit.

---

## 3. Freshness pre-check

The research that populated this protocol could not live-check crt.sh, URLScan, OTX, ThreatFox, or VT UIs. **Before every full run, verify each seed still has usable passive residue.**

### Procedure

For each seed, confirm **at least one** of:

- ≥ 1 crt.sh leaf cert for the seed or its parent cluster
- ≥ 1 OTX pulse referencing the seed
- ≥ 1 ThreatFox IOC entry for the seed or cluster sibling
- ≥ 1 URLScan scan (any time window) for the seed
- ≥ 1 VT passive-DNS resolution in the last 24 months
- For hash seeds: ≥ 5 VT engine detections

If **none** hold, mark `SKIP` in the scorecard and record the case as retired unless refreshed.

### Known freshness-risk cases

| Case | Risk | Reason |
|------|------|--------|
| 6 (LummaC2) | high | Microsoft/DOJ seized 2,300 domains May 2025; cluster partially sinkholed |
| 10 (Contagious Interview) | medium-high | BlockNovas seized by FBI Apr 2025; Wayback is primary evidence |
| 11 (Smishing Triad) | medium | Domains burn < 30 days; seed must be refreshed per-run from Silent Push IOFA feed |
| 12 (ClearFake) | medium | 2023-era origin IPs partially burned; cert-CN pivot still valid via historical Shodan |

### Case 11 seed selection (mandatory)

Case 11 defers its concrete seed. Before each run, pick a currently-live Smishing Triad FQDN meeting:
- Registered via NameSilo
- Cloudflare-fronted (`104.21.x.x` or `172.67.x.x`)
- `.top`, `.cc`, `.icu`, `.shop`, or `.xin` TLD
- USPS / toll / fake-retailer / bank lure pattern
- Meets freshness floor above

Record the chosen FQDN in the scorecard's `seed_actual` column.

---

## 4. Scoring rubric

Each case is scored on **6 dimensions**, each 0–100, then averaged (equal weight unless the case specifies weights).

### 4.1 Node recall (NR)
`|ground-truth nodes found| / |ground-truth nodes total|`
A node is "found" if the tool created a graph node with the same `type` and a `value` matching the ground-truth value (case-insensitive for domains, exact for IPs and hashes).

### 4.2 Edge recall (ER)
`|ground-truth edges found| / |ground-truth edges total|`
An edge is "found" if the tool created an edge between the correct pair with a plausibly matching `relation`. Loose matching on relation names (e.g., `resolves_to` ≈ `A_record` ≈ `dns_a`).

### 4.3 Pivot coverage (PC)
`|expected-pivot steps executed| / |expected-pivot steps total|`
A pivot step is "executed" if the event log shows at least one tool call of the expected type with a query derived from an upstream graph node. Tool calls with unrelated queries don't count.

### 4.4 Defuse correctness (DC)
Score = 100 − (10 × over-inclusion) − (15 × over-defuse)
- **Over-inclusion**: a defuse target appeared as a regular graph node without a defuse tag.
- **Over-defuse**: a ground-truth node was tagged `defused` and not pivoted on.
Floor at 0.

### 4.5 Budget discipline (BD)
- 100 if total MCP tool calls ≤ 60 AND max pivot depth ≤ 3
- 75 if calls in (60, 90] AND every extension was justified by a logged
  `budget_extension` event citing yield (≥ 1 discriminating fingerprint per
  5 calls during the extension window)
- 50 if calls in (60, 90] without justification, OR depth = 4
- 0  if calls > 90 or depth > 4

**Rationale (revised 2026-05-03)**: PURPOSE positions Bounce-CTI as a fast-triage
tool (~60 calls). The autonomy engine adds a yield-based extension to 90 for
genuinely complex cases (Smishing-Triad-class hubs, multi-tier C2). Cases that
need to extend should produce *measurable* extra signal — ergo the
`budget_extension` event log.

**Evaluation procedure**: count `agent_tool_use` events. For runs in (60, 90],
inspect the `budget_extension` events: each must precede the extension window
and cite ≥ 1 new fingerprint discriminant added during it (jarm, favicon_hash,
cert_serial, registrant_email, tracking_id, wallet_address, non-cloud-ASN
ip/domain). If yes → 75. If no → 50.

### 4.6 Report quality (RQ)
- 100 if the written report names the threat actor / family, lists ≥ 70% of ground-truth nodes, and mentions the primary discriminating marker by name
- 70 if 2 of 3
- 40 if 1 of 3
- 0 otherwise

**Per-case score** = mean(NR, ER, PC, DC, BD, RQ)

**Hallucination penalty** (applied after averaging): subtract 15 points per node or edge in the graph that cannot be traced to any tool-call result in the event log. A single hallucination poisons the run.

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

---

## 6. Iteration loop

After a run completes, the eval agent produces a **run report**:

```
runs/YYYY-MM-DD_<commit-sha>/
├── scorecard.md          # Table: case | NR | ER | PC | DC | BD | RQ | overall | top failure
├── deltas.md             # Per-case: missing nodes, missing edges, noise included, hallucinations
├── failure_histogram.md  # Count of each F-* code across all 12 cases
└── proposed_fixes.md     # Top 3 failure modes → specific code changes
```

### Priority rule

Fix in this order:
1. Any `F-HALLUCINATION` — trust-breaking, blocks all interpretation of other metrics
2. Any `F-SRC-ABSENT` that blocks ≥ 3 cases — highest leverage
3. Top `F-PIVOT-MISS` or `F-DEFUSE-*` — usually a system prompt tune
4. Everything else

### Regression discipline

When a fix lands, re-run **at least**:
- The case(s) that motivated the fix
- Any case sharing the same primary marker (see §8 marker coverage table)
- The smoke set (Cases 2, 3, 7)

Full 12-case runs are mandatory before merging to `main` (remember: push → prod, no staging).

---

## 7. Aggregate metrics & pass thresholds

| Metric | Definition | Current target |
|--------|------------|----------------|
| **Overall score** | Mean per-case score across the 12 cases (SKIPs excluded) | ≥ 65 (V2 launch), ramp to ≥ 80 |
| **Pass rate** | % of cases with per-case score ≥ 70 | ≥ 60% (V2 launch) |
| **Hallucination rate** | Cases with ≥ 1 hallucinated node or edge | **0%. Hard gate.** |
| **Defuse floor** | Mean DC across the 4 defuse-primary cases (4, 6, 11, 12) | ≥ 75 |
| **Coverage floor** | No marker (§8) scores below 40 on its primary case | enforced |

A commit fails the eval gate if any floor is breached, regardless of overall score.

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

---

*Maintainer note — Alexandre:* the per-case diagnostic signal is the most important field for iteration. When something fails, read that line first before reading the ground-truth delta. It tells you *which piece of the tool* is broken, not just *that* something is missing.
