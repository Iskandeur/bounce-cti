# Deltas — 2026-05-28 · commit ccee7e3

Per-case missing nodes / edges, noise, pivot misses, hand-audit notes.

## Case 1 — Salt Typhoon

- NR=46.7  (7/15 GT nodes hit)
  - Missing: domain:colourtinctem.com, domain:solveblemten.com, domain:dateupdata.com, domain:infraredsen.com, domain:pulseathermakf.com, email:sdsdvxcdcbsgfe@protonmail.com, email:oklmdsfhjnfdsifh@protonmail.co, actor:unc2286
- ER=0.0  (0/6 GT edges hit)
  - Missing edges: materialplies.com--registered_by-->sdsdvxcdcbsgfe@pro, colourtinctem.com--registered_by-->sdsdvxcdcbsgfe@pro, solveblemten.com--registered_by-->sdsdvxcdcbsgfe@pro, alpha--soa_mname_reuse-->beta, cluster--resolves_to-->hosting_ip, hosting_ip--overlaps_with-->unc4841
- PC=50.0  (2/4 pivot rules fired)
  - Pivot misses: reverse_whois_email, soa_mname_pivot
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=4, budget_extension_count=0)
- RQ=40  (actor_in_report=True, marker_in_report=False, node_pct=42.9%)
- Hypothesis: present=True category=apt_targeted history_len=3
- Phase 3 tools used: (none)
- Graph: 27 nodes / 36 edges

## Case 2 — MuddyRot

- NR=55.6  (5/9 GT nodes hit)
  - Missing: hash:b8703744, ip:91.235.234.202, ip:146.19.143.14, url:egnyte
- ER=0.0  (0/4 GT edges hit)
  - Missing edges: 94278fa01900fdbfb--contacts-->91.235.234.202, b8703744--same_family-->94278fa, 91.235.234.202--share_jarm-->146.19.143.14, 91.235.234.202--tagged-->muddywater
- PC=75.0  (3/4 pivot rules fired)
  - Pivot misses: shodan_or_onyphe_banner
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=48, budget_extension_count=0)
- RQ=40  (actor_in_report=True, marker_in_report=False, node_pct=66.7%)
- Hypothesis: present=True category=apt_targeted history_len=4
- Phase 3 tools used: ['abuseipdb_check', 'certspotter_serial', 'netlas_jarm', 'whoxy_reverse', 'zoomeye_jarm']
- Graph: 89 nodes / 104 edges

## Case 3 — Bumblebee→Akira

- NR=47.1  (8/17 GT nodes hit)
  - Missing: domain:opmanager, domain:ev2sirbd269o5j, domain:angryipscanner, domain:axiscamerastation, domain:ip-scanner, ip:188.40.187.145, ip:172.96.137.160, ip:193.242.184.150 ...
- ER=66.7  (2/3 GT edges hit)
  - Missing edges: 172.96.137.160--c2-->victim
- PC=100.0  (4/4 pivot rules fired)
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=0  (cti_calls=115, budget_extension_count=1)
- RQ=70  (actor_in_report=True, marker_in_report=True, node_pct=58.8%)
- Hypothesis: present=True category=commodity_malware history_len=3
- Phase 3 tools used: ['abuseipdb_check', 'certspotter_issuances', 'certspotter_serial', 'criminalip_domain', 'criminalip_ip', 'dom_fingerprints', 'netlas_jarm', 'netlas_search', 'zoomeye_jarm', 'zoomeye_search']
- Graph: 52 nodes / 55 edges

## Case 4 — Interlock

- NR=23.1  (3/13 GT nodes hit)
  - Missing: ip:49.12.69.80, ip:96.62.214.11, ip:188.34.195.44, ip:45.61.136.202, domain:microsoft-msteams, domain:microstteams, domain:advanceipscaner, domain:ecologilives ...
- ER=0.0  (0/2 GT edges hit)
  - Missing edges: 64.94.84.85--same_cluster-->49.12.69.80, advanceipscaner--delivery-->additional-check
- PC=100.0  (5/5 pivot rules fired)
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=0  (cti_calls=120, budget_extension_count=1)
- RQ=40  (actor_in_report=True, marker_in_report=False, node_pct=23.1%)
- Hypothesis: present=True category=commodity_malware history_len=3
- Phase 3 tools used: ['abuseipdb_check', 'certspotter_serial', 'criminalip_ip', 'netlas_jarm', 'netlas_search', 'openphish_check', 'whoxy_reverse', 'zoomeye_jarm']
- Graph: 77 nodes / 83 edges

## Case 5 — Eye Pyramid cross-brand

- NR=15.4  (2/13 GT nodes hit)
  - Missing: asn:as215540, asn:as215439, framework:eye pyramid, ransomware:rhysida, ransomware:vice society, ransomware:blackcat, ransomware:ransomhub, ransomware:fog ...
- ER=0.0  (0/2 GT edges hit)
  - Missing edges: 195.177.95.163--uses_infra-->rhysida, eye pyramid--uses_infra-->blackcat
- PC=100.0  (4/4 pivot rules fired)
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=56, budget_extension_count=2)
- RQ=0  (actor_in_report=False, marker_in_report=False, node_pct=15.4%)
- Hypothesis: present=True category=traffer_or_tds history_len=2
- Phase 3 tools used: ['abuseipdb_check', 'certspotter_issuances', 'certspotter_serial', 'criminalip_ip', 'netlas_jarm', 'whoxy_reverse', 'zoomeye_jarm']
- Graph: 165 nodes / 230 edges

## Case 6 — LummaC2 About-Cats

- NR=50.0  (3/6 GT nodes hit)
  - Missing: cert_sha1:80b9e0f6a81ab78ee4e01152958e13, domain:pinkipinevazzey, domain:fanlumpactiras
- ER=100.0  (2/2 GT edges hit)
- PC=75.0  (3/4 pivot rules fired)
  - Pivot misses: urlscan_or_wayback_seed
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=4, budget_extension_count=1)
- RQ=70  (actor_in_report=True, marker_in_report=True, node_pct=50.0%)
- Hypothesis: present=True category=commodity_malware history_len=2
- Phase 3 tools used: (none)
- Graph: 29 nodes / 27 edges

## Case 7 — SocGholish

- NR=41.7  (5/12 GT nodes hit)
  - Missing: ip:176.53.147.97, domain:packedbrick, domain:newgoodfoodmarket, domain:urban-orthodontics, domain:bestintownpro, ip:185.76.79.50, ip:166.88.182.126
- ER=0.0  (0/3 GT edges hit)
  - Missing edges: blackshelter.org--resolves_to-->176.53.147.97, rednosehorse--share_ip-->176.53.147.97, blackshelter--known_ioc-->socgholish
- PC=100.0  (5/5 pivot rules fired)
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=45, budget_extension_count=1)
- RQ=40  (actor_in_report=True, marker_in_report=False, node_pct=33.3%)
- Hypothesis: present=True category=socgholish_traffer_tds history_len=2
- Phase 3 tools used: ['abuseipdb_check', 'certspotter_issuances', 'certspotter_serial', 'criminalip_ip', 'dom_fingerprints', 'netlas_jarm', 'zoomeye_jarm']
- Graph: 167 nodes / 160 edges

## Case 8 — Amadey/StealC GitLab

- NR=50.0  (4/8 GT nodes hit)
  - Missing: ip:185.215.113, asn:as51381, domain:gitlab.bzctoons.net, domain:bzctoons.net
- ER=33.3  (1/3 GT edges hit)
  - Missing edges: 185.215.113--hosted_on_asn-->as51381, gitlab.bzctoons.ne--hosts_stager-->stealc
- PC=75.0  (3/4 pivot rules fired)
  - Pivot misses: rdap_ip
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=75  (cti_calls=86, budget_extension_count=1)
- RQ=70  (actor_in_report=True, marker_in_report=True, node_pct=50.0%)
- Hypothesis: present=True category=commodity_malware history_len=3
- Phase 3 tools used: ['abuseipdb_check', 'certspotter_issuances', 'certspotter_serial', 'criminalip_ip', 'dom_fingerprints', 'netlas_favicon', 'netlas_jarm', 'netlas_search', 'whoxy_reverse', 'zoomeye_favicon', 'zoomeye_jarm']
- Graph: 97 nodes / 126 edges

## Case 9 — Tycoon 2FA

- NR=50.0  (3/6 GT nodes hit)
  - Missing: kit_fingerprint:turnstile, actor:storm-1747, phishing_kit:tycoon 2fa
- ER=100.0  (1/1 GT edges hit)
- PC=75.0  (3/4 pivot rules fired)
  - Pivot misses: ct_burst_window
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=0  (cti_calls=127, budget_extension_count=1)
- RQ=40  (actor_in_report=True, marker_in_report=False, node_pct=50.0%)
- Hypothesis: present=True category=phishing_kit_cluster history_len=1
- Phase 3 tools used: ['certspotter_issuances', 'certspotter_serial', 'dom_fingerprints', 'netlas_jarm', 'netlas_search', 'whoxy_reverse', 'zoomeye_jarm']
- Graph: 79 nodes / 88 edges

## Case 10 — Contagious Interview

- NR=7.1  (1/14 GT nodes hit)
  - Missing: domain:lianxinxiao, domain:blocknovas, domain:angeloper, domain:softglide, domain:attisscmo, subdomain:gitlab.blocknovas, subdomain:status.blocknovas, subdomain:mail.blocknovas ...
- ER=0.0  (0/3 GT edges hit)
  - Missing edges: 37.211.126.117--resolves-->lianxinxiao, lianxinxiao--dns_txt_mx-->blocknovas, blocknovas--parent_of-->gitlab.blocknovas
- PC=40.0  (2/5 pivot rules fired)
  - Pivot misses: dns_txt_mx_cross_ref, crtsh_blocknovas, wayback_seized
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=18, budget_extension_count=0)
- RQ=0  (actor_in_report=False, marker_in_report=False, node_pct=7.1%)
- Hypothesis: present=True category=legitimate history_len=2
- Phase 3 tools used: ['abuseipdb_check', 'criminalip_ip', 'whoxy_reverse']
- Graph: 8 nodes / 8 edges

## Case 11 — Smishing Triad

- NR=0.0  (0/5 GT nodes hit)
  - Missing: registrar:namesilo, kit:lighthouse, actor:smishing triad, actor:wang duo yu, ip:104.21
- ER=n/a (no GT edges defined)
- PC=100.0  (5/5 pivot rules fired)
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=43, budget_extension_count=0)
- RQ=0  (actor_in_report=False, marker_in_report=False, node_pct=0.0%)
- Hypothesis: present=True category=smishing_hub history_len=3
- Phase 3 tools used: ['certspotter_issuances', 'dom_fingerprints', 'openphish_check', 'whoxy_reverse']
- Graph: 4 nodes / 1 edges

## Case 12 — ClearFake

- NR=62.5  (5/8 GT nodes hit)
  - Missing: ip:*yacolo, asn:as203493, tool:keitaro
- ER=100.0  (1/1 GT edges hit)
- PC=100.0  (4/4 pivot rules fired)
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=0  (cti_calls=94, budget_extension_count=2)
- RQ=70  (actor_in_report=True, marker_in_report=True, node_pct=66.7%)
- Hypothesis: present=True category=commodity_malware history_len=2
- Phase 3 tools used: ['abuseipdb_check', 'certspotter_issuances', 'certspotter_serial', 'criminalip_ip', 'dom_fingerprints', 'netlas_jarm', 'whoxy_reverse', 'zoomeye_jarm']
- Graph: 60 nodes / 77 edges

## Cross-case patterns

- Median CTI calls per case: 56.
- Working_hypothesis present in 12/12 cases.
- Phase 3 tools used in 10/12 cases.
- Short-call cases (≤ 8 CTI calls = early termination): [1, 6].
## Hand-audit narrative (hallucination second pass — cross-check spots)

The corpus-only hallucination heuristic flagged 3 `person` nodes; all cleared
on hand audit as legitimate RDAP data. Cross-check these if re-auditing:

- **c2 `person:Johnik Makedonskiy`** — `metadata.evidence` = "RDAP
  identitydigital.services registrant vcard for mazafakaerindahouse.info";
  carries `emails:[modafabiches@outlook.com]`, declared NYC address w/ invalid
  zip, tagged `false_persona`/`muddywater_operator_candidate`. Real registrant
  intel, not fabricated. (Also c2 `person:Ogwe Chibuike` — RDAP NameSilo vcard
  for brendysubs.com, `chibuike.ogwe.232986@unn.edu.ng`, tagged
  `false_flag_candidate`.)
- **c7 `person:Costel Savulescu`** — `source:rdap`, `evidence` = "RIPE RDAP
  ORG-CS1103-RIPE for 170.168.61.0/24", `asn:AS63023`.
- **c7 `person:Dmitrii Vladimirovich Malkov`** — `source:rdap`, `evidence` =
  "RIPE RDAP ORG-DVM4-RIPE for 176.53.146.0/23", `asn:AS48108`.

All four have explicit provenance metadata citing a specific RDAP object → 
traceable to a tool call per §4.6 → **not hallucinations**. The scorer's
`hallucination_check` was upgraded to clear suspects carrying
`evidence`/`source`/`sources_seen`/`provenance` metadata.

Largest graphs spot-checked for fabricated attribution (no provenance, value
absent from corpus): c7 (167n), c5 (165n), c8 (97n), c2 (89n) — none found.

## NR/marker cross-check spots (low-NR cases — decay vs bug)

- **c1**: live WHOIS shows benign 2026-04-03 GMO/Onamae re-registration; the
  malicious reverse-WHOIS cluster has decayed out of live data. Historical
  Salt-Typhoon attribution still recovered via tags. Decay, not bug (§3).
- **c2 / c7**: both missed their primary-marker IP (`91.235.234.202` /
  `176.53.147.97`) as a graph node despite finding the actor — recurring
  "key contacted/resolved IP not graphed" pattern. P1 (`dns_resolve`
  mandatory) targets the c7 instance; c2's is the VT-contacted-IP path.
- **c10**: seed IP lost its passive-DNS anchor to `lianxinxiao.com` (8 nodes).
  Exogenous decay — `dns_txt_mx_cross_ref` has no first-hop to fire against.
- **c11**: `ezpass-tollbill-pay.cc` not live (NXDOMAIN-class); 4 nodes, NR=0.
  Seed-selection limitation, not a Cloudflare-defuse failure (PC=100).
