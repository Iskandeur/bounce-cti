# Proposed Fixes — 2026-06-17 · commit 69fc13c

## Fix shipped this run (P3 → CDN/parking malicious tag suppression)

### Malicious-tag guard on CDN/parking nodes (`backend/graph_store.py`)

**Commit:** `c127a807`  
**Category:** F-RST breach (F-OVER-ATTRIBUTION)  
**Cases fixed:** N2 (jsDelivr CDN), N3 (Wikipedia) — benign seeds false-positive tagged  
**Actual Δ-RST:** N1 RST=100 (was 100), N2 RST=50 (was 50 → target 100), N3 RST=50 (was 50 → target 100)
**Restraint floor gate:** neg RST mean=67 (target ≥80)

**Root cause:** ThreatFox/OTX returns IOC hits for shared CDN IPs (Cloudflare anycast,
Fastly `151.101.0.0/16`). The agent tagged these infrastructure nodes as `malicious`/`c2`
despite the `cdn` tag being present. Two code paths could promote these tags:
`add_node()` upsert (merging incoming tags) and `tag_node()` (explicit promotion).

**Fix:** Added `_NOISE_TAGS = frozenset({"cdn", "parking"})` and
`_MALICIOUS_TAGS = frozenset({"malicious", "c2", "phishing", "malware", "attacker"})`
constants, then guarded both `add_node()` upsert path and `tag_node()` to suppress
any tag in `_MALICIOUS_TAGS` when the node already carries a tag in `_NOISE_TAGS`.

---

## Next-iteration priorities (ranked by Δ-CAP leverage)

### P0 — cert-CN fix scope expansion: mixed CDN+origin seeds (F-PIVOT-MISS)

c12 this run: CAP=90.0, PS=75, `shodan_cert_cn_search` ✗ still missing

The cert-CN fix requires ALL IP nodes to be CDN-tagged. For c12 (921hapudyqwdvy.com),
the agent resolves both Cloudflare IPs AND direct origin IPs (Hetzner AS24940). The
`non_cdn_ips` list is non-empty, so the cert-CN hint is never emitted.

**Fix option A:** Loosen the cert-CN condition — fire when the seed domain is
Cloudflare-fronted (any CDN-tagged IP exists), not only when ALL IPs are CDN-tagged.
**Fix option B:** Fire unconditionally for domain seeds (cert-CN search is always cheap).
**Δ-CAP estimate (c12):** PS 75→100 → +8 CAP points if other dims stable.

---

### P1 — `ct_burst_window` never fires (F-PIVOT-MISS, c09)

c09 this run: CAP=90.0, PS=75, `ct_burst_window` ✗ still missing

Rule requires: `(crtsh or certspotter called) AND any node has "burst" or
"issuance_date" in metadata`. crtsh fires but no graph node has `issuance_date`
metadata. The agent reads cert issuances but stores `cert_serial`/`domain` nodes
without the issuance timestamp.

**Fix:** In `graph_mcp.add_node` or the crtsh/certspotter source, store
`metadata.issuance_date` when adding cert nodes from CT log responses.
**Δ-CAP estimate (c09):** PS 75→100 → +10 CAP points.

---

### P2 — rdap_origin pipeline completeness (F-PIVOT-MISS, c12)

`rdap_origin` checks for `rdap_ip` on IPs discovered from cert-CN Shodan search.
Currently the agent does the Shodan cert-CN search but does NOT consistently run
RDAP on the discovered origin IP. Adding cert-CN mandatory promotion (P0) should
open the path, but rdap_ip still needs to be added to the mandatory block.

**Fix:** In the cert-CN mandatory-promotion block, additionally add `rdap_ip(<origin_ip>)`
calls for origin IPs from the Shodan result. Alternative: add `rdap_ip` to
`_missing_mandatory_tools` for domain seeds where a non-CDN IP was discovered.
**Δ-CAP estimate (c12):** PS 75→100 → +8 CAP points (if EFF/RST/HYP stable).

---

### P3 — Pivot drain backlog starvation (F-BUDGET, c08)

c08 this run: BD=100, CTI calls=60

14+ lesson-learned blockers cite drain-budget exhaustion with large pending queues
(100+ pending pivots when drain rounds cap at 60 turns). High-value pivots like
`crtsh_subdomains`, `wayback`, and `virustotal_subdomains` are queued but never reached.

**Fix candidates (ordered by cost):**
1. **Per-depth turn budget:** allocate turn budget proportionally to node types in queue
   (not first-come-first-served). Low cost.
2. **Convergence-gated extension:** raise `BOUNCE_PIVOT_DRAIN_ROUNDS` from 3 to 5
   for hash-seed cases where hub-shaped investigation burns all turns on hash enrichment.
3. **Priority-bump high-value queue items:** `gaps_report()` already ranks by priority;
   wire its top-K output directly into the drain prompt to avoid random queue ordering.
**Δ-CAP estimate:** +0–10 across multiple cases; hard to quantify without fixture replay.

---

### P4 — OpenCTI structural attribution gap (F-SRC-TOKEN-DEAD / ops-action)

16+ lesson-learned blockers cite `opencti_lookup_indicator pivots skipped no_api_key`.
OpenCTI was permanently retired in commit `3c08c0b` (community instance requires auth).

**Ops-action:** No token refresh available. Long-term options:
1. Subscribe to a MISP instance with OpenCTI feeds (community license available).
2. Integrate MISP REST API as `mcp__cti__misp_*` tools (medium cost).
3. Accept the gap — 2026-06 runs show correct attribution via ThreatFox+OTX+VT alone.
**Δ-CAP estimate:** +5–15 on APT-attributed cases (c1, c2, c3) if working KG returns; 0 until then.
**Status:** deferred — ops dependency.

---

### P5 — Cert serial noise in rdap pivots (F-SCHEMA / F-PIVOT-QUERY)

Recurring lesson: `cert_serial` values stored as human-readable labels
(`"Let's Encrypt R12 / 569efec2..."`) cause IS_HEX_SERIAL noise-filter false-positives,
skipping RDAP lookups on valid cert serials.

**Fix:** In `graph_mcp.py::add_node`, when type=cert_serial, strip everything after
whitespace from value (keep only the hex part). Store the full label in
`metadata.subject_label`. This unblocks RDAP pivots on cert serials and de-noises `gaps_report`.
**Δ-CAP estimate:** small (+0–5); affects downstream cert-cluster pivots.

---

## Deferred (ops or infrastructure)

- **DNSDUMPSTER_API_KEY / CENSYS_API_ID**: Not in `.env.example` as required fields;
  add and wire them — would unlock domain enumeration and cert-cluster pivots.
- **Case 11 seed refresh**: Done per run by the nightly agent (see `eval/cases.py`).
- **Fixture-replay harness** (§4.C): hash seeds (c2, c3, c8) don't decay — snapshot
  their tool responses into `eval/fixtures/c0N/` for deterministic CAP replay.

---

## Ops-actions (not code bugs)

| Action | Priority | Notes |
|--------|----------|-------|
| OpenCTI token retired | Acknowledged | No refresh; structural gap; logged per run |
| c11 seed refresh | Per-run | Automated by nightly runner |
| DNSDUMPSTER_API_KEY | Low | Free API; add to .env.example |
| CENSYS_API_ID/SECRET | Medium | Cert cluster pivots; requires account |