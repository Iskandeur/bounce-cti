# Proposed Fixes — 2026-06-17 · commit 71e5fb1

Generated from: nightly eval run, Cases 2/3/8/9/12 + N1-N3, sequential.

---

## FIX-1 · c12 `_is_parked` over-gates on NS tag — CRITICAL (PS +25 on next c12 run)

**Symptom**: c12 (ClearFake, domain `921hapudyqwdvy.com`) scored PS=75 because
`shodan_cert_cn_search` never fired. Root cause: `agent_runner._is_parked()` (line ~855–893)
returned `True` for c12 because the two nameservers (`ns1.renewyourname.net`,
`ns2.renewyourname.net`) were tagged `parking`. The function short-circuits the
**entire followup phase** when any node has a `parking` tag — including the mandatory
`shodan_search('ssl.cert.subject.CN:<domain>')` hint that was specifically added for
cert-CN unmasking (the 71e5fb1 fix). The seed domain itself had:
- VT `malicious=15` / `suspicious=3`
- Tags: `clearfake_c2`, `c2`, `malicious`, `dga`
- `cross_investigation_lookup` found it in 10 prior investigations tagged `clearfake_c2`

So a clearly-malicious expired DGA domain had its entire followup skipped because its
registrar's parking nameservers were at a parking provider.

**Root cause**: `_is_parked` checks `"parking" in tags` for ALL nodes. NS nodes at
a registrar parking service get tagged `parking` during RDAP/DNS enrichment. The
function has no way to distinguish "the seed itself is parked/benign" from "the seed's
nameservers happen to be at a domain registrar's parking service."

**Fix** (high priority, ~10 lines):

```python
# In agent_runner._is_parked(), before the current early-return:
seed_node_tags = set()
for n in nodes:
    if n.get("value", "").lower() == inv.seed.lower() or "seed" in (n.get("tags") or []):
        seed_node_tags = set(t.lower() for t in (n.get("tags") or []))
        break

# Skip the parked short-circuit if the seed itself looks malicious:
MALICIOUS_OVERRIDE = {"malicious", "c2", "phishing", "botnet", "ransomware",
                      "dropper", "loader", "clearfake_c2", "cobalt_strike"}
if seed_node_tags & MALICIOUS_OVERRIDE:
    return False

for n in nodes:
    tags = [t.lower() for t in (n.get("tags") or [])]
    # ... existing parking/blackhole check, but only on non-NS nodes:
    if n.get("type") in ("ns",):
        continue  # NS tags don't indicate seed is parked
    if "parking" in tags or "blackhole" in tags:
        return True
```

**Expected impact**: c12 PS 75 → 100 (next run). The cert-CN shodan search would
then fire, finding `cert_cn:921hapudyqwdvy.com` → `ip:*yacolo` → `asn:AS203493`
(confirming Hetzner origin) — currently the only missing pivot in c12.

**Evidence that the fix would work**: The Hetzner origin IP (`135.181.211.230`)
was already found via VT resolutions in this run (VT historical data from 2023 campaign
era). The cert-CN pivot would have found it via the TLS certificate fingerprint chain,
which is the canonical method for the `shodan_cert_cn_search` rule.

---

## FIX-2 · c09 `ct_burst_window` adaptive hint — DEPLOYED (local, not yet on VPS)

**Symptom**: c09 (Tycoon 2FA, domain `rlcozx.es`) scored PS=75 because
`ct_burst_window` didn't fire. The scorer rule requires:
1. `crtsh_subdomains` or `certspotter_issuances` was called **AND**
2. any node has `issuance_date` or `burst` in metadata

Condition 1 was met (both tools were called). Condition 2 failed: `certspotter_issuances`
returned empty results for this domain, and `crtsh_subdomains` results were not
re-examined for burst date patterns — no `ct_burst_cohort` report node was added.

**Fix already in `backend/agent_runner.py`** (local, uncommitted — part of this commit):
The adaptive followup hint block detects when `crtsh_subdomains` was called on the seed
but no `ct_burst_cohort` node exists, and adds a targeted followup hint:

```python
# Added in _adaptive_followup_targets() before return targets[:20]:
if (crtsh_called_on_seed and not has_burst_node
        and domain_count >= 3 and key_burst not in seen_keys):
    targets.append(
        ("domain", seed_domain,
         [
             f'crtsh_subdomains("{seed_domain}")'
             "  # re-examine not_before dates; find the date"
             " where >=5 domains were issued (the burst date)",
             'add_node(type="report", value="ct_burst_cohort",'
             ' metadata={"issuance_date": "<burst_date>",'
             ' "burst_count": N,'
             ' "siblings": [<list of co-issued sibling domains>]})',
         ],
         "CT burst-window not documented: crtsh was called but no "
         "ct_burst_cohort node recorded. Extract the most common "
         "not_before date from crtsh results; if >=5 domains share it,"
         " add ct_burst_cohort with metadata.issuance_date=<date> "
         "(Tycoon-2FA / phishing-cluster temporal fingerprint)"))
    seen_keys.add(key_burst)
```

**Caveat**: The fix fires the followup hint correctly. Whether the agent successfully
adds a `ct_burst_cohort` node depends on whether `crtsh_subdomains(rlcozx.es)` returns
data with shared `not_before` dates. In this run, crtsh returned results but the agent
didn't identify a burst date cluster. The followup hint will prompt explicit extraction
of `not_before` dates. Effectiveness on live expired domains may remain ~50% (live
`certspotter_issuances` data is often absent for expired domains).

**Expected impact**: c09 PS 75 → 100 on future runs where crtsh returns burst-date
data for the seed domain. This is the most common case for active Tycoon-2FA PhaaS
campaigns.

---

## FIX-3 · c09 RQ=40 / missing marker — LOW PRIORITY

**Symptom**: c09 RQ=40 (vs 70 for other cases) because `marker_in_report=False`.
The missing markers are: `kit_fingerprint:turnstile`, `actor:storm-1747`,
`phishing_kit:tycoon 2fa`.

These are entity nodes that the agent did not add. The investigation correctly
identified Tycoon 2FA from OTX/URLscan but didn't add a `phishing_kit:tycoon 2fa`
or `actor:storm-1747` node to the graph.

**Fix**: No code change needed — these are agent prompt improvements. The
`KNOWN_BAD_MARKERS` table in `pivot_mapping.py` should include Tycoon 2FA
kit + STORM-1747 as known-bad markers with auto-tag heuristics, so `add_node`
auto-promotes when OTX or urlscan returns matching tags.

---

## FIX-4 · c03/c08 NR gaps — RESEARCH NEEDED

**Symptom**: c03 NR=47.1 (missing 9 nodes including 4 IPs and 5 domains from C2
infrastructure), c08 NR=50.0 (missing 2 domains from the GitLab stager chain).

Both cases had PS=100 (all pivot rules fired), so these are not pivot-routing gaps
but rather data availability gaps — the missing infrastructure is either:
- Behind auth-required sources (Netlas deep search, Shodan host:)
- Requires deeper pivot chaining beyond the current fan-out cap (8 high-priority pivots)
- VT resolutions capped at first-page results

**Proposed investigation**:
1. Check if `domain:gitlab.bzctoons.net` appeared in any Shodan/Netlas results as a
   related domain — if yes, the fan-out cap is suppressing it.
2. Check if the 4 missing c03 IPs appear in VT resolutions for the 4 known IPs — if
   yes, the VT page-2 results are needed.

No immediate code change; document for next EVAL run.

---

## Summary priority order

| Priority | Fix | Expected CAP gain | Effort |
|----------|-----|:-----------------:|--------|
| 1 (CRITICAL) | FIX-1: `_is_parked` NS tag exemption | +10 (c12 PS 75→100) | ~20 min |
| 2 (DEPLOYED) | FIX-2: ct_burst_window adaptive hint | +10 (c09 PS 75→100) | done |
| 3 (MEDIUM) | FIX-3: KNOWN_BAD_MARKERS for Tycoon 2FA | +0 CAP, +RQ | ~30 min |
| 4 (LOW) | FIX-4: NR gap investigation | +0 CAP | research |
