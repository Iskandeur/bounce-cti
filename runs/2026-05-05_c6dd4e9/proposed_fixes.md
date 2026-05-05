# Proposed fixes — 2026-05-05 · commit c6dd4e9

Failures ranked by (cases affected) × (expected per-case delta). Mechanical fixes preferred over prompt prose — the latter is read-and-ignored at a measurable rate (e.g., R14 still missed on Case 12 and the hypothesis-first arc skipped on 9/12 cases).

## P0 — F-HALLUCINATION

**Status: NO CHANGE NEEDED.** Heuristic + hand audit on the four largest graphs (cases 1, 4, 5, 8) found no fabricated nodes. R12 + R13 evidence rules continue to hold. The hard gate stays cleared.

---

## P1 — Mechanical `working_hypothesis` enforcement (9 cases affected)

**Diagnosis.** F-HYPOTHESIS-ABSENT in 9/12 cases. The system prompt prose ("Within your first ~8 tool calls, write a working_hypothesis report node…") is read but not enforced. The agent prioritises the mandatory-tools list and exits phase_main without committing to a category. Without a hypothesis node, the per-category playbooks (apt_targeted sibling-enum, traffer_or_tds vt_pdns deep-dive, etc.) never get triggered. This is the largest single behaviour drift this iteration.

**Fix.** Mirror the existing `phase3_report_write` fallback for `working_hypothesis`. After phase_main_exit, if no `working_hypothesis` report node exists in the graph, run a dedicated "phase 1.5" prompt that:
1. Reads the current graph (call `get_graph(compact=True)`).
2. Picks one of the documented categories: `apt_targeted | commodity_malware | traffer_or_tds | phishing_kit | infostealer | post_ex_framework | sinkholed | unclear`.
3. Writes `add_node("report", "working_hypothesis", metadata={category, confidence, reason, evidence, what_to_pursue_next})`.

Then **gate phase 2** on this hypothesis: include the chosen `category` and `what_to_pursue_next` verbatim in the followup prompt, so the agent's pivot decisions are anchored to the hypothesis it just committed.

**File**: `backend/agent_runner.py::run_investigation`. Add a `phase_hypothesis_write` block between `phase_main_exit` and the existing `phase2_needed` check, with helper `_has_working_hypothesis(inv_id)`.

**Expected uplift**: 9 cases × ~5 points each = ~3.8 points to mean. Critically unblocks the per-category playbooks the agent already has prose for — adding the apt_targeted sub-playbook (Case 1), the traffer_or_tds vt_pdns deep-dive (Case 7), the post_ex_framework banner-search (Case 5).

---

## P2 — `reverse_dns` → `dns_resolve` TXT/MX hint (1 high-impact case)

**Diagnosis.** F-PIVOT-MISS::dns_txt_mx_cross_ref on Case 10 (Contagious Interview). `reverse_dns(37.211.126.117)` returned `lianxinxiao.com` but the agent never called `dns_resolve(lianxinxiao.com, "TXT")` / `dns_resolve(lianxinxiao.com, "MX")`. The TXT/MX cross-reference is the **only** pivot that surfaces `blocknovas.com`, the gateway to the entire DPRK BlockNovas cluster. NR=7.7 (12 of 13 GT nodes invisible) without it.

**Fix.** Add a hint function `hint_for_reverse_dns(response, ip)` in `backend/hints.py`. When `reverse_dns` returns one or more hostnames, surface a `_pivot_hint` line for each: "PIVOT_HINT: reverse_dns surfaced '<hostname>'. For non-CDN hostnames, call dns_resolve('<hostname>', 'TXT') AND dns_resolve('<hostname>', 'MX'). TXT records often expose unique SPF/Google-site-verification IDs that cross-reference siblings (Contagious-Interview-class pivot). MX records reveal mail providers shared across an actor's front companies."

Wire it into `HINT_DISPATCH` and `with_hints` for `reverse_dns`. The `cti_mcp.py::reverse_dns` wrapper already supports the with_hints pattern (verify and add if missing).

**File**: `backend/hints.py` (new function + dispatch entry), `backend/mcp_servers/cti_mcp.py` (verify wrapper passes through with_hints).

**Expected uplift**: Case 10 NR 7.7 → ~30, PC 20 → 60, overall ~37.9 → ~52. ~1.2 points to mean.

---

## P3 — `cert_cn` shodan_search injection for all-CDN domain seeds (1 case, R14 enforcement)

**Diagnosis.** F-PIVOT-MISS::shodan_cert_cn on Case 12 (ClearFake). R14 in the system prompt mandates `shodan_search('ssl.cert.subject.CN:"<seed>"')` when the seed resolves to Cloudflare, but R14 has been ignored across two consecutive runs (Apr-20 + this one). The pivot is the **canonical** Cloudflare-defuse origin-unmask test. Prose enforcement has failed; mechanical enforcement is required.

**Fix.** In `backend/agent_runner.py::_adaptive_followup_targets`, add a branch for "seed domain whose IP nodes are ALL CDN-tagged":
- detect: seed_node has `tags=['seed']` and type domain; all `ip` nodes in graph have `cdn` tag.
- emit target: `("domain", seed_value, [f'shodan_search("ssl.cert.subject.CN:\"{seed_value}\"")', f'onyphe_datascan("tls.cert.subject.commonname:\"{seed_value}\"")'], "seed resolves only to CDN — origin unmask via cert CN required (R14)")`.

Then the existing followup prompt will surface these in the adaptive Phase 3 block, mechanically. The agent has already shown it follows that block reliably (Case 4 used 7 Phase 3 tools).

**File**: `backend/agent_runner.py::_adaptive_followup_targets` (add new branch).

**Expected uplift**: Case 12 NR 20 → 60+, PC 25 → 50+, overall 63 → 72+. ~1 point to mean. Also catches Case 11 (Smishing Triad — same pattern, when the seed isn't dead).

---

## P4 — Phase 1.5 reverse_whois enforcement when registrar is exposed (1 case but high-leverage)

**Diagnosis.** F-PIVOT-MISS::reverse_whois_email on Case 1 (Salt Typhoon). RDAP returned the registrar (`GMO Internet/Onamae.com`) but the registrant email was masked. The d1eeb63 sub-playbook for apt_targeted+privacy-masked is in the prompt but didn't fire because the working_hypothesis was never written (gated on P1 above).

**Fix.** P1 fixes this transitively: once the agent commits to `apt_targeted` after seeing 20 OTX pulses naming Salt Typhoon, the existing prompt sub-playbook activates and routes through whoxy_reverse + cert-SAN + NS-clustering.

**No standalone code change needed** — covered by P1.

---

## P5 — Mandatory `dns_resolve` for domain seeds (defer)

**Diagnosis.** Case 6 (LummaC2), Case 9 (Tycoon 2FA), Case 11 (Smishing) and Case 12 (ClearFake) would all benefit from explicit `dns_resolve` (TXT/MX/A) on the seed domain, in addition to the rdap call. Currently `_missing_mandatory_tools` for domain seeds has rdap_domain but not dns_resolve. The user prompt for domain seeds in `run_investigation` does include `dns_resolve` as STEP 1 but lists it alongside rdap as "/" (alternative).

**Fix.** Make `dns_resolve` mandatory for domain seeds. Add to `_missing_mandatory_tools` mandatory list for `seed_type == "domain"`.

**Defer** to next iteration: needs measurement against P1 first to avoid overcorrection (P1 alone may bring dns_resolve back into scope via the playbook).

---

## P6 — RQ marker mechanical extraction (carried over from Apr-20 P4)

**Diagnosis.** RQ < 70 in 11/12 cases. The phase_report_write block already extracts marker candidates from node metadata and injects them as a "MUST INCLUDE VERBATIM" block — verified in `agent_runner.py::run_investigation` lines 1916–1961. The model still paraphrases markers ~50% of the time.

**Fix.** Defer — the mechanical extraction already exists. The next-iteration improvement is to **also write markers directly into `report.metadata.discriminating_markers`** from the runner before the report-write phase, then have the report-write phase only confirm them. This eliminates the model from the verbatim-copy loop.

---

## What this iteration will land

- **P1 (mechanical working_hypothesis enforcement)** — touches only `agent_runner.py`. Largest expected uplift. Top priority.
- **P2 (reverse_dns hint for TXT/MX)** — `hints.py` + `cti_mcp.py` (small wrapper change). Unblocks Case 10.
- **P3 (cert_cn shodan_search adaptive followup)** — `agent_runner.py::_adaptive_followup_targets`. Unblocks Case 12 (and Case 11 when alive).

**Estimated combined uplift**: mean ~57.3 → ~62-65. Pass rate 0/12 → 2-3/12 (Cases 4, 8, 12 likely cross 70). Hypothesis presence 3/12 → 12/12 (mechanical).

**Deferred to next iteration**:
- P5 (dns_resolve mandatory for domain seeds) — measure interaction with P1 first.
- P6 (RQ marker direct-write from runner) — current mechanical extraction is in place, model paraphrasing is the residual loss.
- Per-category playbook strengthening for `traffer_or_tds` (Case 7) and `infostealer` (Case 6).
- Better Case 11 seed selection (live-feed snapshot fetch from sandbox-egress-friendly source).
- Phase 3 force-fire on cases that emerge with > 5 nodes but 0 Phase 3 tools used.
