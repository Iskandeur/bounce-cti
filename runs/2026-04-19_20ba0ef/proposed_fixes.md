# Proposed fixes — 2026-04-19 (commit 20ba0ef)

Priorities follow EVAL_PROTOCOL_V2 §6 (hallucination first, then highest-leverage
F-SRC-ABSENT, then system-prompt tunes).

---

## P0 — Case 1 misattribution (F-HALLUCINATION / F-CLUSTER-OVER) — trust-breaking

**Observation.** Case 1 (seed: `materialplies.com`, Salt Typhoon) produced a
report node titled *"APT34/OilRig & Saitama backdoor — co-resident IOCs on M247"*
and tagged `coinbase-wallet.co`, `yesbamk.in`, `o2vertragsservice.de` as
`phishing_lookalike` siblings of the seed based on co-residency on
`193.239.84.207` (M247 shared hosting). These are unrelated tenants; the APT34
attribution has no bearing on Salt Typhoon.

**Fix.** Add two guardrails in `backend/agent_runner.py` system prompt:
1. *"Do not create cluster edges between tenants of a shared-hosting IP unless
   you have ≥ 2 corroborating markers (cert SAN, cert SHA1, JARM, or identical
   registrant). Mere co-residency is never sufficient."*
2. *"Do not label a seed with an APT attribution from an OTX pulse that
   explicitly names a different APT than the one your current pivot chain has
   evidence for. Cite the pulse as context only; do not merge attributions."*

Also consider a post-run audit in `graph_store.py` that deletes edges of type
`co_resolves` between nodes whose only shared attribute is `/24` IP proximity.

---

## P1 — Premature termination (drives F-PIVOT-MISS across 10 of 12 cases)

**Observation.** Mean CTI-tool calls per case = **9.4**. Protocol budget is
**60**. Cases 2, 3, 7, 8 ran 4–6 CTI calls total and quit. The phase-followup
step never wrote a report for 6 of 12 cases. Agents are exiting well before the
pivot chain completes.

**Symptoms by case**:
- Case 2: no `shodan_host` / `onyphe_ip` on `91.235.234.202` ⇒ no JARM sibling discovery
- Case 3: no `virustotal_resolutions_domain` on `opmanager.pro` ⇒ no hosting IP ⇒ no SEO decoy cluster
- Case 7: no DNS resolve on `blackshelter.org` ⇒ no Keitaro IP `176.53.147.97`
- Case 10: no DNS TXT/MX on `lianxinxiao.com` ⇒ no `blocknovas.com` pivot (the whole point of the case)
- Case 12: 23 calls but no `shodan_search ssl.cert.subject.CN:"..."` ⇒ YACOLO-AS origins missed

**Fix.** In `agent_runner.py`:
1. Raise `max_turns` on phase_main only if tool-call count < 15 at the time of
   first `agent_result`. Prevents "I'm done" termination when the pivot chain is
   barely started.
2. Add a phase_main exit-check: if the graph has < 5 non-seed nodes OR no
   `report` node with `investigation_summary`, force the agent to continue with
   an explicit prompt: *"You stopped after N tool calls and the pivot chain is
   incomplete. Continue pivoting on the highest-value node you haven't
   explored yet."*
3. Add explicit pivot examples to the system prompt for each seed type. E.g.
   *"For a hash seed, always run `virustotal_file` → extract contacted-IPs →
   `shodan_host` on each → `threatfox_search` on each → `virustotal_resolutions_ip`
   on each. Do not skip steps."*

---

## P2 — F-REPORT: phase_followup completes but writes no summary (cases 4–9)

**Observation.** Cases 4, 5, 6, 7, 8, 9 all logged `phase_followup_exit` and
`phase2_done` but their graphs contain **zero** `report` nodes. phase_followup
is supposed to write `{type:report, value:investigation_summary}` per
`agent_runner.py:527`.

**Hypotheses**:
- phase_followup prompt doesn't mandate the write strongly enough
- agent writes a report but with a different `value`, so pdf_report filter misses it
- add_node tool silently failed (tag collision)

**Fix.** Instrument `run_investigation`'s followup phase: after it exits, query
the graph; if no investigation_summary exists, re-invoke claude with a
single-purpose prompt: *"Write ONE node: `{type:'report', value:'investigation_summary',
metadata:{summary, threat_assessment, per_seed_summaries, …}}`. Do not call
any other tool."* Fail-loud if that step also produces no report.

---

## P3 — F-SRC-ABSENT: reverse-WHOIS (Case 1 primary), Shodan cert-CN (Case 12)

**Observation.** Case 1 expects a reverse-WHOIS on `sdsdvxcdcbsgfe@protonmail.com`
as the discriminator pivot. The MCP catalog in `backend/mcp_servers/cti_mcp.py`
has no reverse-WHOIS tool. Similarly, Case 12's canonical Shodan cert-CN
query (`ssl.cert.subject.CN:"<seed>"`) can be constructed with the existing
`shodan_search` tool, but the agent did not emit it.

**Fix.**
1. Add `reverse_whois_email(email)` MCP tool backed by WhoisXML API or
   DomainTools (paid), or via crt.sh's registrant field if available. If budget
   is blocked, at minimum add a guidance note in the system prompt to approximate
   via `urlscan_search q.registrantEmail:"<email>"` and `mnemonic_pdns` keyword
   search.
2. Add an explicit example to the system prompt for cert-CN unmask:
   *"When the seed's A-record is a Cloudflare anycast IP (104.21.0.0/16,
   172.67.0.0/16, 172.64.0.0/13), do NOT stop. Query crt.sh for the cert, then
   call shodan_search with `ssl.cert.subject.CN:\"<seed_domain>\"` to find
   origin IPs."*

---

## Regression set for the next run

Per §6 regression discipline:
- **Smoke set (2, 3, 7)** — confirms premature-termination fix
- **Cases 1, 5** — confirms F-CLUSTER-OVER guardrail
- **Case 12** — confirms Shodan cert-CN pivot fires
- **Cases 4, 6, 9** — confirms phase_followup report-write fix
- **Full 12-case run** before any merge to `main`
