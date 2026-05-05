# Deltas — 2026-05-05 · commit c6dd4e9

Per-case missing nodes / edges, noise, pivot misses, hand-audit notes.

## Case 1 — Salt Typhoon

- NR 5/12 (41.7) — same as Apr baseline. Hits: seed + actor (`salt typhoon` via report metadata) + 3 malware names (`demodex`, `snappybee`, `ghostspider`).
- **Missing**: 5 sibling domains (`colourtinctem.com`, `solveblemten.com`, `dateupdata.com`, `infraredsen.com`, `pulseathermakf.com`) + 2 ProtonMail registrant emails.
- ER 0/3 (0.0). The registrant→domain edges depend on whoxy_reverse output, which was never called.
- PC 2/4 — `rdap_seed`, `vt_pdns_cluster` ✓. Missed: `reverse_whois_email`, `reverse_ip`.
- RQ 40 — actor name in report ✓ but only 1/9 IOCs and no marker hit (the registrant email).
- **Why**: agent extracted the registrar `GMO Internet/Onamae.com` from RDAP but the registrant email was masked behind privacy. No fallback NS-based or cert-SAN-based sibling enumeration fired. The d1eeb63 sub-playbook for apt_targeted-+-privacy-masked is in the prompt but didn't fire (working_hypothesis was never written, so the apt_targeted branch was unreachable).
- Code: `F-HYPOTHESIS-ABSENT`, `F-PIVOT-MISS::reverse_whois_email`, `F-NODE-RECALL::sibling_domain_enum`.

## Case 2 — MuddyRot

- NR 5/8 (62.5). Hits: seed hash + sibling hash prefix + `muddywater` actor + `muddyrot` + `bugsleep`.
- **Missing**: sibling hash `b8703744...`, live C2 `91.235.234.202`, down C2 `146.19.143.14`.
- PC 2/4 — `vt_file_seed`, `threatfox_muddywater` ✓. Missed: `shodan_or_onyphe_banner`, `jarm_search`.
- BD 100 (3 calls). RQ 40 — actor named, marker missed.
- **Why**: 3 cti calls only. Phase main exited before extracting the contacted IP from VT relationships, so no JARM/banner pivot. The `hint_for_virustotal_file` already includes a contacted-IP hint — verify it actually fired and the agent ignored it (it did fire; agent stopped early).
- Code: `F-EARLY-TERMINATION`, `F-PIVOT-MISS::contacted_ip_extraction`.

## Case 3 — Bumblebee → AdaptixC2 → Akira

- NR 5/14 (35.7). Same as baseline. Hits: seed + dropped DLL + `bumblebee` + `adaptixc2` + `akira`.
- **Missing**: `opmanager.pro`, DGA domains, all 3 SEO decoys, all 5 IPs (Bumblebee C2 / AdaptixC2 / exfil tier).
- ER 1/2 (50.0). Seed→opmanager edge missed; seed→dropped_dll edge ✓.
- PC 2/4 — `vt_file_seed`, `threatfox_adaptix` ✓. Missed: `vt_pdns_opmanager`, `reverse_ip_seo_decoy`.
- **Why**: 5 cti calls. Agent never pivoted on the contacted_domain `opmanager.pro` from VT response. Same root cause as case 2.

## Case 4 — Interlock

- NR 2/10 (20.0). Hits: seed IP + `interlock` malware. **All 4 backup IPs missed, all 4 ClickFix-staging domains missed.**
- ER null. PC 4/5 — strong (rdap, vt_pdns, threatfox, wayback ✓). Missed: `urlscan_clickfix_path`.
- BD 100 (31 calls — well-paced). RQ 40 — actor name ✓.
- **Best Phase 3 coverage of the run**: `abuseipdb_check`, `certspotter_serial`, `criminalip_ip`, `dom_fingerprints`, `netlas_jarm`, `whoxy_reverse`, `zoomeye_jarm`. Working_hypothesis ✓ (commodity_malware → commodity_malware (Interlock C2)).
- **Why backup IPs missed**: agent didn't extract the sibling IPs from threatfox `interlock` cluster results. `vt_pdns_seed` returned the historical resolutions but they were Cloudflare, not the backup tier.

## Case 5 — Eye Pyramid cross-brand

- NR 1/10 (10.0). Hit: only the seed IP. **All 3 ASNs missed, all 5 ransomware family names missed, framework "eye pyramid" missed.**
- ER null. PC 3/4 — ✓ rdap, shodan/onyphe, threatfox. Missed: `banner_sibling_search` (sibling IPs across ASNs).
- BD **50** — depth=4 in BFS, 37 calls, no budget_extension. Per V2.1 spec.
- RQ 40 — actor missed (no Eye Pyramid family node, no Rhysida/Vice/etc. in report metadata strings).
- Working_hypothesis ✓ (4 entries) but landed on `traffer_or_tds` — wrong category for Eye Pyramid (which is RaaS / cross-brand affiliate).
- **Why**: no sibling-IP enumeration via banner-hash search. The shodan/onyphe call returned but the cluster pivot wasn't followed up.

## Case 6 — LummaC2

- NR 2/5 (40.0). Same as baseline. Hits: seed + `lummac2`.
- **Missing**: cert SHA1 cluster, both mail-server siblings.
- PC 1/4 — only `rdap_seed`. Missed: urlscan/wayback, content_fingerprint, crtsh_sha1_cluster.
- BD 100 (7 calls). RQ 40.
- **Why**: 7 cti calls, no urlscan_search on the seed, no dom_fingerprints, no crtsh_query for SHA1 cert. The "About Cats" content fingerprint pivot — central to the LummaC2 case — never fired.
- Code: `F-PIVOT-MISS::content_fingerprint`, `F-PIVOT-MISS::crtsh_sha1_cluster`.

## Case 7 — SocGholish (regression)

- NR 1/12 (8.3). Same as Apr baseline. Hits: seed only.
- **Missing**: 4 TDS-front siblings, 2 stage-2 C2 subdomains, 2 stage-2 IPs, `socgholish` malware, `keitaro` tool.
- PC 3/5. RQ 0 — report blob too short / missing actor mention.
- BD 100 (7 calls).
- Working_hypothesis absent.
- **Why**: 7 cti calls only. The vt_resolutions_ip hint that was the centrepiece of d1eeb63 (Case 7 cap fix) didn't fire — the agent didn't get to vt_resolutions_ip on `176.53.147.97`. The agent's whole TDS-coresident pivot is gated on extracting the IP from `dns_resolve` first, then calling vt_resolutions_ip on that IP. Phase main exited before that chain.
- Code: `F-EARLY-TERMINATION`, `F-PIVOT-MISS::vt_resolutions_ip_followthrough`.
- **Hand audit**: the d1eeb63 hint fix WAS deployed (verified in `backend/hints.py`) — the issue is not the hint content, it's that the agent doesn't reach the trigger tool.

## Case 8 — Amadey/StealC

- NR 4/8 (50.0). Hits: seed hash + contacted IP + `amadey` + `stealc`.
- **Missing**: AS51381 ASN, `gitlab.bzctoons.net` subdomain, `bzctoons.net` apex (with apex-vs-subdomain tagging), `185.215.113.x` Amadey C2 hub.
- ER 1/2 (50.0). PC 2/4 — `vt_file_seed`, `threatfox_amadey` ✓.
- BD 100 (5 calls). RQ 40.
- **Why**: 5 cti calls. The `cert_san_apex` distinction (apex tagged clean, subdomain tagged dirty) requires a deliberate apex-domain analysis pass — never reached.

## Case 9 — Tycoon 2FA

- NR 1/3 (33.3). Hits: seed only. **Missing**: `tycoon 2fa` kit name, `storm-1747` actor.
- PC 2/4 — crtsh, vt_pdns ✓. Missed: `ct_burst_window`, `urlscan_kit_fingerprint`.
- BD 100 (8 calls). RQ 40.
- **Why**: agent ran crt.sh but didn't filter by issuance-date burst (2025-04-07). No URLScan kit-fingerprint pivot for Cloudflare Turnstile script + CSS filename.

## Case 10 — Contagious Interview (full regression)

- NR 1/13 (7.7). Hit: seed IP only. **Missing 12 of 13 GT nodes.**
- PC 1/5 — only `reverse_dns_seed` ✓. Missed: `dns_txt_mx_cross_ref`, `crtsh_blocknovas`, `wayback_seized`, `urlscan_front_companies`.
- BD 100 (8 calls). RQ 0.
- Working_hypothesis Y (2 entries, landed at `unclear`).
- **Why**: 8 cti calls. `reverse_dns(37.211.126.117)` returned `lianxinxiao.com` but `dns_resolve(lianxinxiao.com, "MX")` and `dns_resolve(lianxinxiao.com, "TXT")` were never called. The TXT/MX cross-reference is the ONLY pivot that surfaces `blocknovas.com`, the gateway to the entire DPRK cluster. Without it, the case is invisible.
- Code: `F-PIVOT-MISS::dns_txt_mx_cross_ref`. **Top single-case fix candidate.**

## Case 11 — Smishing Triad (seed-dead)

- NR 0/3 (0.0). All GT nodes (`registrar:namesilo`, `kit:lighthouse`, `actor:smishing triad`) missing from graph.
- PC 3/5 — rdap, crtsh, vt_pdns ✓ but each returned empty/404.
- BD 100 (7 calls). RQ 0.
- **Why**: chosen seed `usps.com-redeliveryinfo.top` returned no telemetry from any source. RDAP 404 on the .top registry, VT 'not found', OTX 0 pulses, threatfox empty, crtsh empty, onyphe empty. Per the protocol's freshness pre-check (§3) this seed should have been **SKIPped**. We did not gate it because the live freshness check (DNS/crt.sh) is blocked from the sandbox. The agent correctly recognized "no enrichment data available" and wrote a low-confidence summary.
- Code: `F-SEED-DEAD`. Not a code regression — a methodology issue with case 11 seed selection in network-isolated runs. **Recommendation**: cycle the seed list and pick from a vendor-published live-feed snapshot in the next iteration; if no such feed is accessible, mark case 11 SKIP per protocol.

## Case 12 — ClearFake (regression)

- NR 1/5 (20.0) vs baseline 40.0. Hits: seed only.
- **Missing**: cert_cn marker (extracted in baseline but missed this run), 2 ASNs, `keitaro` tool.
- PC 1/4 — only `crtsh_seed_cert`. Missed: `shodan_cert_cn` (R14), `rdap_origin`, `vt_pdns_origin`.
- BD 100 (8 calls). **RQ 70** — strongest report this run.
- **Why**: agent did the cert pivot via crt.sh but never executed `shodan_search('ssl.cert.subject.CN:"921hapudyqwdvy.com"')`. R14 still read-and-ignored. `cert_cn` node not added even though the seed's cert CN is the seed value (textbook anchor).
- Code: `F-PIVOT-MISS::shodan_cert_cn`.

---

## Cross-case patterns

- **Median 7 cti calls per case**. The agent's exit decision is driven by "I called the mandatory tools" rather than "I exhausted the pivot queue". The pivot queue (`pivot_tasks` table) is populated by add_node but the agent rarely drains it via `next_pivot()`. This is a known issue called out in `PIVOT_MAPPING.md` and the task brief.
- **Phase 3 tools used in 2/12 cases**. Adaptive-followup targets (`_adaptive_followup_targets`) only kick in if phase_main produces graph nodes that match the per-type rules. With 7-call phase_main, the graph is too small to trigger many targets. This is a chicken-and-egg: small phase_main → small adaptive followup → small phase 3 firing.
- **Working_hypothesis present in 3/12 cases**. The hypothesis-first arc is not gated mechanically. The system prompt prose says "Within your first ~8 tool calls, write a working_hypothesis report node" but the agent prioritises mandatory tools and skips this. Direct fix candidate.
- **vt_pdns hints fired**, but downstream graphing of co-resolvers happened only when the agent was actively in pivot mode (case 4) — when it's running the mandatory list, the hints get logged in the response and not acted on.
