# Proposed fixes — 2026-04-19 (commit abca49b)

Priorities follow EVAL_PROTOCOL_V2 §6: hallucination first (already fixed),
then highest-leverage F-REPORT, then the two remaining phase-flow gaps.

---

## P0 — Report surface quality (F-REPORT on ~8 cases)

**Observation.** The agent runs the right pivots, but its `investigation_summary`
text skips naming the discriminating marker by exact value (JARM, cert-CN,
page title, registrant email) and fails to lift actor/family aliases that
sit in node metadata (threatfox malware_family, otx pulse adversary, urlhaus
tags, virustotal threat_names). RQ scores: 0 on cases 5, 7, 10; 40 on cases
1, 2, 6, 8, 12.

**Fix (applied in this commit).**
- Enhanced `STEP 8` (domain workflow) and the phase-3 `report_write` prompt
  in `backend/agent_runner.py` to force the summary to:
  1. Name the seed explicitly.
  2. Enumerate every actor alias, malware family, campaign label present in
     node metadata (threatfox `malware_family`, otx pulse `name`/`adversary`,
     urlhaus `tags`, virustotal `threat_names`, onyphe `threat_feeds`).
  3. Include the exact discriminating marker value, not an adjective —
     the JARM hex, cert subject CN string, favicon hash, page-title string,
     registrant email, or TDS URL pattern.
  4. Include at least 70 % of non-seed domain/ip/hash/email/url node values
     in `ioc_list`.
- Added a pre-write instruction to the phase-3 prompt: "scan graph-node
  metadata for ... before composing the summary".

## P1 — Phase-2 re-runs already-executed tools (Case 2, Case 7)

**Observation.** `phase2_needed` correctly flagged `threatfox_search` and
`otx_file` as missing, but the phase-2 agent replayed `virustotal_file` +
`malwarebazaar_hash` (already called in phase 1) instead.

**Fix (applied in this commit).**
- The phase-2 follow-up prompt in `run_investigation` now includes an
  explicit "ALREADY CALLED (DO NOT re-run any of these)" list derived from
  the captured CTI-tool set, plus an "ONLY call these" directive on the
  missing-tool block.

## P2 — DNS TXT/MX + Wayback pivots missing (Case 10 DPRK chain)

**Observation.** `lianxinxiao.com` seed never had `dns_resolve` called with
TXT/MX record types, so the `blocknovas.com` pivot (the whole point of the
case) never fired. Wayback is also unused.

**Fix (to apply in a follow-up commit if time permits).**
- Add explicit guidance to STEP 1c of the domain workflow:
  *"`dns_resolve` returns all configured record types, including TXT and
  MX. For each MX host: add_node(domain, ...), add_edge(seed→mx, uses_mx).
  For TXT strings containing domain references (e.g. SPF include:, DMARC
  rua=, SKI verification): extract the domain and add_node(domain)."*
- Add `wayback(seed)` as a mandatory call in STEP 2.5 alongside
  `urlhaus_host`. This catches seized/NDR'd domains (Contagious Interview
  case 10) and historical C2 phase-outs.

## P3 — NameSilo dnsowl NS false-defuse avoidance

**Observation (closed).** Scorer initially flagged `ns1-3.dnsowl.com` as
over-inclusion noise on Case 11 Smishing Triad. After protocol re-reading
(§4.4): Smishing Triad operators legitimately use NameSilo's free
`dnsowl.com` NS, so the NS nodes are genuine pivot targets, not noise.
Scorer corrected — no defuse-list change needed (would cause over-defuse
on real targets).

## Regression set for the next run

- **Smoke set (2, 7, 10)** — confirms phase-2 no-repeat fix and report
  marker surfacing
- **Cases 5, 6, 8, 12** — confirms actor/family name lifting into summary
- **Full 12-case run** before considering the launch gate.
