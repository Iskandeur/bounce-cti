# Deltas — 2026-05-31 · commit 6e6aaeb

Per-case missing nodes / edges, noise, pivot misses, hand-audit notes.

## Case 1 — Salt Typhoon

- NR=53.3  (8/15 GT nodes hit)
  - Missing: domain:colourtinctem.com, domain:solveblemten.com, domain:dateupdata.com, domain:infraredsen.com, domain:pulseathermakf.com, email:oklmdsfhjnfdsifh@protonmail.co, actor:unc2286
- ER=16.7  (1/6 GT edges hit)
  - Missing edges: colourtinctem.com--registered_by-->sdsdvxcdcbsgfe@pro, solveblemten.com--registered_by-->sdsdvxcdcbsgfe@pro, alpha--soa_mname_reuse-->beta, cluster--resolves_to-->hosting_ip, hosting_ip--overlaps_with-->unc4841
- PC=75.0  (3/4 pivot rules fired)
  - Pivot misses: reverse_whois_email
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=4, budget_extension_count=0)
- RQ=70  (actor_in_report=True, marker_in_report=True, node_pct=50.0%, has_summary=True)
- Hypothesis: present=True category=apt_targeted history_len=1 final_category=apt_targeted valid=True
- Phase 3 tools used: (none)
- Graph: 24 nodes / 23 edges

## Case 2 — MuddyRot

- NR=55.6  (5/9 GT nodes hit)
  - Missing: hash:b8703744, ip:91.235.234.202, ip:146.19.143.14, url:egnyte
- ER=0.0  (0/4 GT edges hit)
  - Missing edges: 94278fa01900fdbfb--contacts-->91.235.234.202, b8703744--same_family-->94278fa, 91.235.234.202--share_jarm-->146.19.143.14, 91.235.234.202--tagged-->muddywater
- PC=100.0  (4/4 pivot rules fired)
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=49, budget_extension_count=0)
- RQ=40  (actor_in_report=True, marker_in_report=False, node_pct=55.6%, has_summary=True)
- Hypothesis: present=True category=apt_targeted history_len=1 final_category=apt_targeted valid=True
- Phase 3 tools used: ['abuseipdb_check', 'criminalip_ip', 'dom_fingerprints', 'netlas_jarm', 'zoomeye_jarm']
- Graph: 67 nodes / 122 edges

## Case 3 — Bumblebee→Akira

- NR=47.1  (8/17 GT nodes hit)
  - Missing: domain:opmanager, domain:ev2sirbd269o5j, domain:angryipscanner, domain:axiscamerastation, domain:ip-scanner, ip:188.40.187.145, ip:172.96.137.160, ip:193.242.184.150, ip:185.174.100.203
- ER=33.3  (1/3 GT edges hit)
  - Missing edges: 186b26df--contacts-->opmanager, 172.96.137.160--c2-->victim
- PC=100.0  (4/4 pivot rules fired)
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=75  (cti_calls=74, budget_extension_count=1)
- RQ=70  (actor_in_report=True, marker_in_report=True, node_pct=58.8%, has_summary=True)
- Hypothesis: present=True category=commodity_malware history_len=1 final_category=commodity_malware (loader-to-ransomware kill chain with affiliate-style operator behavior) valid=True
- Phase 3 tools used: ['abuseipdb_check', 'certspotter_issuances', 'certspotter_serial', 'criminalip_ip', 'dom_fingerprints', 'netlas_jarm', 'netlas_search', 'zoomeye_jarm']
- Graph: 48 nodes / 48 edges

## Case 4 — Interlock

- NR=23.1  (3/13 GT nodes hit)
  - Missing: ip:49.12.69.80, ip:96.62.214.11, ip:188.34.195.44, ip:45.61.136.202, domain:microsoft-msteams, domain:microstteams, domain:advanceipscaner, domain:ecologilives, url:additional-check, domain:trycloudflare
- ER=0.0  (0/2 GT edges hit)
  - Missing edges: 64.94.84.85--same_cluster-->49.12.69.80, advanceipscaner--delivery-->additional-check
- PC=100.0  (5/5 pivot rules fired)
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=75  (cti_calls=78, budget_extension_count=1)
- RQ=40  (actor_in_report=True, marker_in_report=False, node_pct=23.1%, has_summary=True)
- Hypothesis: present=True category=commodity_malware history_len=2 final_category=commodity_malware valid=True
- Phase 3 tools used: ['abuseipdb_check', 'certspotter_serial', 'criminalip_ip', 'dom_fingerprints', 'netlas_jarm', 'whoxy_reverse', 'zoomeye_jarm']
- Graph: 63 nodes / 82 edges

## Case 5 — Eye Pyramid cross-brand

- NR=15.4  (2/13 GT nodes hit)
  - Missing: asn:as215540, asn:as215439, framework:eye pyramid, ransomware:rhysida, ransomware:vice society, ransomware:blackcat, ransomware:ransomhub, ransomware:fog, malware:cobalt strike, malware:sliver ...
- ER=0.0  (0/2 GT edges hit)
  - Missing edges: 195.177.95.163--uses_infra-->rhysida, eye pyramid--uses_infra-->blackcat
- PC=100.0  (4/4 pivot rules fired)
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=45, budget_extension_count=1)
- RQ=0  (actor_in_report=False, marker_in_report=False, node_pct=15.4%, has_summary=True)
- Hypothesis: present=True category=commodity_malware history_len=3 final_category=phishing_kit_cluster_three_lir valid=True
- Phase 3 tools used: ['abuseipdb_check', 'certspotter_serial', 'criminalip_ip', 'netlas_jarm', 'whoxy_reverse', 'zoomeye_jarm']
- Graph: 73 nodes / 145 edges

## Case 6 — LummaC2 About-Cats

- NR=50.0  (3/6 GT nodes hit)
  - Missing: cert_sha1:80b9e0f6a81ab78ee4e01152958e13, domain:pinkipinevazzey, domain:fanlumpactiras
- ER=100.0  (2/2 GT edges hit)
- PC=25.0  (1/4 pivot rules fired)
  - Pivot misses: urlscan_or_wayback_seed, content_fingerprint_pivot, crtsh_seed
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=3, budget_extension_count=0)
- RQ=70  (actor_in_report=True, marker_in_report=True, node_pct=50.0%, has_summary=True)
- Hypothesis: present=True category=commodity_malware history_len=2 final_category=commodity_malware_seized valid=True
- Phase 3 tools used: (none)
- Graph: 26 nodes / 22 edges

## Case 7 — SocGholish

- NR=41.7  (5/12 GT nodes hit)
  - Missing: ip:176.53.147.97, domain:packedbrick, domain:newgoodfoodmarket, domain:urban-orthodontics, domain:bestintownpro, ip:185.76.79.50, ip:166.88.182.126
- ER=0.0  (0/3 GT edges hit)
  - Missing edges: blackshelter.org--resolves_to-->176.53.147.97, rednosehorse--share_ip-->176.53.147.97, blackshelter--known_ioc-->socgholish
- PC=100.0  (5/5 pivot rules fired)
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=48, budget_extension_count=1)
- RQ=40  (actor_in_report=True, marker_in_report=False, node_pct=41.7%, has_summary=True)
- Hypothesis: present=True category=commodity_malware history_len=2 final_category=traffer_or_tds valid=True
- Phase 3 tools used: ['abuseipdb_check', 'certspotter_issuances', 'certspotter_serial', 'criminalip_ip', 'dom_fingerprints', 'netlas_jarm', 'netlas_search', 'zoomeye_jarm']
- Graph: 91 nodes / 135 edges

## Case 8 — Amadey/StealC GitLab

- NR=50.0  (4/8 GT nodes hit)
  - Missing: ip:185.215.113, asn:as51381, domain:gitlab.bzctoons.net, domain:bzctoons.net
- ER=33.3  (1/3 GT edges hit)
  - Missing edges: 185.215.113--hosted_on_asn-->as51381, gitlab.bzctoons.ne--hosts_stager-->stealc
- PC=75.0  (3/4 pivot rules fired)
  - Pivot misses: cert_san_apex
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=0  (cti_calls=98, budget_extension_count=1)
- RQ=70  (actor_in_report=True, marker_in_report=True, node_pct=50.0%, has_summary=True)
- Hypothesis: present=True category=commodity_malware history_len=1 final_category=commodity_malware valid=True
- Phase 3 tools used: ['abuseipdb_check', 'criminalip_ip', 'dom_fingerprints', 'netlas_jarm', 'whoxy_reverse', 'zoomeye_jarm']
- Graph: 86 nodes / 108 edges

## Case 9 — Tycoon 2FA

- NR=66.7  (4/6 GT nodes hit)
  - Missing: kit_fingerprint:turnstile, actor:storm-1747
- ER=100.0  (1/1 GT edges hit)
- PC=75.0  (3/4 pivot rules fired)
  - Pivot misses: ct_burst_window
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=75  (cti_calls=79, budget_extension_count=1)
- RQ=70  (actor_in_report=True, marker_in_report=True, node_pct=66.7%, has_summary=True)
- Hypothesis: present=True category=phishing_kit_cluster history_len=2 final_category=phishing_kit_cluster (Tycoon 2FA PhaaS) valid=True
- Phase 3 tools used: ['certspotter_issuances', 'certspotter_serial', 'dom_fingerprints', 'netlas_jarm', 'netlas_search', 'zoomeye_jarm', 'zoomeye_search']
- Graph: 53 nodes / 45 edges

## Case 10 — Contagious Interview

- NR=7.1  (1/14 GT nodes hit)
  - Missing: domain:lianxinxiao, domain:blocknovas, domain:angeloper, domain:softglide, domain:attisscmo, subdomain:gitlab.blocknovas, subdomain:status.blocknovas, subdomain:mail.blocknovas, malware:beavertail, malware:invisibleferret ...
- ER=0.0  (0/3 GT edges hit)
  - Missing edges: 37.211.126.117--resolves-->lianxinxiao, lianxinxiao--dns_txt_mx-->blocknovas, blocknovas--parent_of-->gitlab.blocknovas
- PC=20.0  (1/5 pivot rules fired)
  - Pivot misses: dns_txt_mx_cross_ref, crtsh_blocknovas, wayback_seized, urlscan_front_companies
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=15, budget_extension_count=0)
- RQ=0  (actor_in_report=False, marker_in_report=False, node_pct=7.1%, has_summary=True)
- Hypothesis: present=True category=legitimate history_len=3 final_category=legitimate valid=True
- Phase 3 tools used: ['netlas_search']
- Graph: 7 nodes / 4 edges

## Case 11 — Smishing Triad

- NR=20.0  (1/5 GT nodes hit)
  - Missing: registrar:namesilo, kit:lighthouse, actor:wang duo yu, ip:104.21
- ER=n/a (no GT edges defined)
- PC=100.0  (5/5 pivot rules fired)
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=36, budget_extension_count=0)
- RQ=0  (actor_in_report=False, marker_in_report=False, node_pct=0.0%, has_summary=True)
- Hypothesis: present=True category=smishing_hub history_len=4 final_category=legitimate valid=True
- Phase 3 tools used: ['certspotter_issuances', 'dom_fingerprints']
- Graph: 4 nodes / 1 edges

## Case 12 — ClearFake

- NR=62.5  (5/8 GT nodes hit)
  - Missing: ip:*yacolo, asn:as203493, tool:keitaro
- ER=100.0  (1/1 GT edges hit)
- PC=50.0  (2/4 pivot rules fired)
  - Pivot misses: shodan_cert_cn_search, rdap_origin
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=11, budget_extension_count=1)
- RQ=70  (actor_in_report=True, marker_in_report=True, node_pct=66.7%, has_summary=True)
- Hypothesis: present=True category=traffer_or_tds history_len=2 final_category=traffer_or_tds valid=True
- Phase 3 tools used: (none)
- Graph: 48 nodes / 50 edges

## Cross-case patterns

- Median CTI calls per case: 48.
- Working_hypothesis present in 12/12 cases.
- Valid hypothesis (wh+history+final_cat) in 12/12 cases.
- Phase 3 tools used in 9/12 cases.
- Short-call cases (≤8 CTI calls): [1, 6] — check freshness/decay (Case 1/6/10/11 are known decay/dead-seed risks).