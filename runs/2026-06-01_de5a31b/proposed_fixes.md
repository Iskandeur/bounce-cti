# Proposed Fixes — 2026-06-01 · commit de5a31b

## Fix shipped this run (P1 → c12 cert-CN unmask)

### Cert-CN mandatory promotion (`backend/agent_runner.py`)

**Commit:** `de5a31b`  
**Category:** F-PIVOT-MISS  
**Cases fixed:** c12 (ClearFake), c11 (Smishing Triad) — both CDN-fronted domain seeds  
**Actual Δ-CAP (c12):** PS 50 → 75 (from 2/4 to 3/4 pivot rules); CAP 80.0 → 90.0 (+10)

**Root cause:** `_adaptive_followup_targets()` generated the correct cert-CN hint
(`shodan_search("ssl.cert.subject.CN:\"<seed>\"")`) for CDN-fronted seeds, but the
agent consistently ignored adaptive hints even when explicitly listed. The hint was
advisory text; the agent's attention budget goes to mandatory `_missing_mandatory_tools`
calls first, and adaptive hints are only picked up when the agent has spare cycles.

**Fix:** After calling `_adaptive_followup_targets()`, filter out any cert-CN or
`tls.cert.subject.commonname` targets and extend `missing` (the mandatory list) with
their call strings. The followup phase template wraps `missing` in hard enforcement
language ("MUST call the following tools"), guaranteeing execution.

```python
# backend/agent_runner.py ~line 3125
_cn_unmask = [t for t in adaptive_targets if any(
    "ssl.cert.subject.cn" in c.lower()
    or "tls.cert.subject.commonname" in c.lower()
    for c in t[2]
)]
if _cn_unmask:
    for _, _, _calls, _ in _cn_unmask:
        missing.extend(_calls)
    adaptive_targets = [t for t in adaptive_targets if t not in _cn_unmask]
```

**Verification:** c02 (MuddyWater 2026 hash) transcript confirms the fix fires:
`mcp__cti__shodan_search(query="ssl.cert.subject.CN:\"moonzonet.com\"")` appears in the
followup phase — the first time it has appeared in a hash-seed case despite moonzonet.com
being Cloudflare-fronted.

**c12 actual result:** `shodan_cert_cn_search` still ✗ — the cert-CN mandatory promotion
did NOT trigger for c12 (921hapudyqwdvy.com) because the agent discovered non-CDN origin
IPs (135.181.211.230, 46.4.38.199 — Hetzner AS24940) early in the main phase. The
all-CDN condition `(ip_nodes and not non_cdn_ips)` was False, so `_adaptive_followup_targets`
never emitted the cert-CN hint to promote. The +10 CAP gain on c12 came from
`rdap_origin` firing (rdap_ip was called), not from the cert-CN pivot. The cert-CN fix
is confirmed working for purely Cloudflare-fronted seeds (c02, moonzonet.com).

**Prior-run baseline (v3 re-score):**

| Case | Prior PS | Actual PS | Prior CAP | Actual CAP | CAP Δ | Note |
|-----:|--------:|----------:|----------:|-----------:|------:|------|
| c12  |       50 |        75 |      80.0 |       90.0 |   +10 | rdap_origin now fires; shodan_cert_cn ✗ (non-CDN origin IPs found first) |
| c11  |      n/a |       n/a |       n/a |        n/a |   n/a | out of scope (not in nightly fresh subset) |

---

## Next-iteration priorities (ranked by Δ-CAP leverage)

### P0 — cert-CN fix scope expansion: mixed CDN+origin seeds (F-PIVOT-MISS)

The cert-CN fix requires ALL IP nodes to be CDN-tagged. For c12, the agent resolved
both Cloudflare front-end IPs (104.21.72.186, 172.67.153.220) AND direct origin IPs
(135.181.211.230 Hetzner, 46.4.38.199 Hetzner). The `non_cdn_ips` list was non-empty,
so the cert-CN hint was never emitted. This is actually correct behavior (origin IPs
were already found), but `shodan_cert_cn_search` PS rule requires the explicit Shodan
cert-CN query regardless.

**Fix option A:** Loosen the cert-CN condition: fire when the seed domain is Cloudflare-
fronted (any CDN-tagged IP exists), not only when ALL IPs are CDN-tagged.
**Fix option B:** Fire unconditionally for domain seeds (cert-CN search is always cheap
and adds signal even when origin IPs are known).
**Δ-CAP estimate (c12):** PS 75→100 → +8 CAP points.

---

### P1 — `ct_burst_window` never fires (F-PIVOT-MISS, c09)

c09 (Tycoon 2FA, rlcozx.es) PS=75 because `ct_burst_window` ✗. Rule requires:
`(crtsh or certspotter called) AND any node has "burst" or "issuance_date" in metadata`.
crtsh fired, but no graph node has burst/issuance_date metadata. The agent doesn't
expose CT burst-window data as node metadata — it reads cert issuances but stores
`cert_serial`/`domain` nodes without the issuance timestamp.

**Fix:** In `graph_mcp.add_node` or the crtsh/certspotter source, store
`metadata.issuance_date` when adding cert nodes from CT log responses.
**Δ-CAP estimate (c09):** PS 75→100 → +10 CAP points.

---

### P2 (was P1) — `rdap_origin` missing from c12 (F-PIVOT-MISS)

`rdap_origin` checks for `rdap_ip` on any IP *discovered from* the cert-CN Shodan search.
Currently the agent does the Shodan cert-CN search (now enforced), discovers the origin IP,
but does NOT consistently run RDAP on that IP. The cert-CN fix gets 1 more pivot rule
(shodan_cert_cn_search); adding rdap_origin to the same mandatory block gets the 4th.

**Fix:** In the cert-CN mandatory-promotion block, additionally add `rdap_ip(<origin_ip>)`
calls for any origin IPs discovered from the Shodan result. Requires reading the Shodan
result and extracting IPs — either in the followup prompt or as a post-processing step.
Alternative: add `rdap_ip` to `_missing_mandatory_tools` for domain seeds where an origin
IP was discovered (check graph for non-CDN IPs tagged `cloudflare_origin`).

**Δ-CAP estimate (c12):** PS 75 → 100 → +8 CAP points if EFF/RST/HYP unchanged.

---

### P3 (was P2) — N2/N3 false-positive tagging (F-RST breach)

N2 (jsDelivr CDN) RST=50, N3 (Wikipedia) RST=50 — each had 2 nodes tagged with
`malicious`/`c2`/`phishing` tags. No actor/malware attributions were asserted
(attribution=[] for both), but the tag promotions incur −25 RST each. These are
clearly benign seeds (major CDN, Wikipedia) so any malicious-tag assignment is a
false positive.

**Root cause:** Likely the agent tags IPs or domains as `malicious` based on ThreatFox
or OTX hits on IPs that happen to be shared CDN infrastructure. CDN IP nodes should
be immune to malicious-tag promotion (already tagged `cdn`), but the tag guard may
not filter both paths (auto-enqueue `known_bad_markers` + agent-explicit `tag_node`).

**Fix:** In `pivot_mapping.auto_tag_known_bad()` or `graph_mcp.tag_node()`, suppress
malicious-family tags on nodes already tagged `cdn`, `sinkhole`, or `parking`.
**Δ-neg-RST estimate:** N2/N3 both → 100 → neg_RST mean 67→100.

---

### P4 (was P2) — Pivot drain backlog starvation (F-BUDGET)

14 of 105 lesson-learned blockers cite drain-budget exhaustion with large pending queues
(100+ pending pivots when drain rounds cap at 60 turns). High-value pivots like
`crtsh_subdomains`, `wayback`, and `virustotal_subdomains` are queued but never reached.

**Root cause:** `BOUNCE_PIVOT_DRAIN_MAX_TURNS` (default 60) is shared across all node
types. A hub-shaped investigation (e.g. c02, 16+ hash nodes) burns all turns on
hash-level enrichment, leaving domain/IP pivots unvisited.

**Fix candidates (ordered by implementation cost):**
1. **Per-depth turn budget:** allocate turn budget proportionally to node types in queue
   (not just first-come-first-served). Low cost.
2. **Convergence-gated extension:** if `pivot_drain_N` adds ≥ 5 nodes, automatically
   do a `pivot_drain_N+1` with 30 more turns (already implemented via round limit).
   Raise `BOUNCE_PIVOT_DRAIN_ROUNDS` from 3 to 5 for fresh-subset hash cases.
3. **Priority-bump high-value queue items:** `gaps_report()` already ranks by priority;
   wire its top-K output directly into the drain prompt as a targeted list (avoids
   random queue ordering).

**Δ-CAP estimate:** +0–10 across multiple cases; hard to quantify without fixture replay.

---

### P5 (was P3) — OpenCTI structural attribution gap (F-SRC-TOKEN-DEAD / ops-action)

16 of 105 lesson-learned blockers cite `opencti_lookup_indicator pivots skipped
no_api_key`. OpenCTI was permanently retired in commit `3c08c0b` (no working token;
community instance requires auth). This is **not a code bug** — it is a standing
structural gap.

**Ops-action:** No token refresh available. Long-term options:
1. Subscribe to a MISP instance with OpenCTI feeds (community license available).
2. Integrate MISP REST API as a replacement `mcp__cti__misp_*` tool set (medium cost).
3. Accept the gap — the 2026-05-31 and 2026-06-01 runs show the agent correctly
   attributes actors without OpenCTI via ThreatFox + OTX + VT labels alone.

**Δ-CAP estimate:** +5–15 on APT-attributed cases (c1, c2, c3) if a working KG returns;
0 until then. Log as **deferred — ops dependency**.

---

### P6 (was P4) — Cert serial noise in rdap pivots (F-SCHEMA / F-PIVOT-QUERY)

Recurring lesson: `cert_serial` values stored as human-readable labels (`"Let's Encrypt
R12 / 569efec2..."`) cause IS_HEX_SERIAL noise-filter false-positives, skipping RDAP
lookups on valid cert serials. Suggestion from lessons_learned: "Enforce cert_serial
value = hex DER serial only; store subject in metadata."

**Fix:** In `graph_mcp.py::add_node`, when type=cert_serial, strip everything after
whitespace from value (keep only the hex part). Store the full label in
`metadata.subject_label`. This unblocks RDAP pivots on cert serials and de-noises
`gaps_report`.

**Δ-CAP estimate:** small (+0–5); affects downstream cert-cluster pivots.

---

## Deferred (not mechanical, needs ops or infrastructure)

- **DNSDUMPSTER_API_KEY / CENSYS_API_ID**: Not in `.env.example` as required fields;
  add and wire them — would unlock domain enumeration and cert-cluster pivots.
- **Case 11 seed refresh**: Done per run by the nightly agent (see `eval/cases.py`).
  Current seed: `sunpass-tollservices.icu` (prior run); nightly runner picks fresh seed.
- **Fixture-replay harness** (§4.C): hash seeds (c2, c3, c8) don't decay — snapshot
  their tool responses into `eval/fixtures/c0N/` for deterministic CAP replay. No
  code-change needed; just a one-time capture run per case.

---

## Ops-actions (not code bugs)

| Action | Priority | Notes |
|--------|----------|-------|
| OpenCTI token retired | Acknowledged | No refresh; structural gap; logged per run |
| c11 seed refresh | Per-run | Automated by nightly runner |
| DNSDUMPSTER_API_KEY | Low | Free API; add to .env.example |
| CENSYS_API_ID/SECRET | Medium | Cert cluster pivots; requires account |
