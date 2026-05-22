# Deltas — 2026-05-21 · commit e54dec1

Per-case missing nodes / edges, noise, pivot misses, hand-audit notes.

## Case 1 — Salt Typhoon

- NR=46.7  (7/15 GT nodes hit)
  - Missing: domain:colourtinctem.com, domain:solveblemten.com, domain:dateupdata.com, domain:infraredsen.com, domain:pulseathermakf.com, email:sdsdvxcdcbsgfe@protonmail.com, email:oklmdsfhjnfdsifh@protonmail.co, actor:unc2286
- ER=0.0  (0/6 GT edges hit)
  - Missing edges: materialplies.com--registered_by-->sdsdvxcdcbsgfe@pro, colourtinctem.com--registered_by-->sdsdvxcdcbsgfe@pro, solveblemten.com--registered_by-->sdsdvxcdcbsgfe@pro, alpha--soa_mname_reuse-->beta, cluster--resolves_to-->hosting_ip, hosting_ip--overlaps_with-->unc4841
- PC=50.0  (2/4 pivot rules fired)
  - Pivot misses: reverse_whois_email, soa_mname_pivot
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=0  (cti_calls=125, budget_extension_count=0)
- RQ=40  (actor_in_report=True, marker_in_report=False, node_pct=21.4%)
- Hypothesis: present=True category=apt_targeted history_len=3
- Phase 3 tools used: ['abuseipdb_check', 'certspotter_issuances', 'certspotter_serial', 'criminalip_ip', 'dom_fingerprints', 'netlas_jarm', 'netlas_search', 'zoomeye_jarm']
- Graph: 79 nodes / 103 edges

## Case 2 — MuddyRot

- NR=55.6  (5/9 GT nodes hit)
  - Missing: hash:b8703744, ip:91.235.234.202, ip:146.19.143.14, url:egnyte
- ER=0.0  (0/4 GT edges hit)
  - Missing edges: 94278fa01900fdbfb--contacts-->91.235.234.202, b8703744--same_family-->94278fa, 91.235.234.202--share_jarm-->146.19.143.14, 91.235.234.202--tagged-->muddywater
- PC=75.0  (3/4 pivot rules fired)
  - Pivot misses: shodan_or_onyphe_banner
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=25, budget_extension_count=0)
- RQ=40  (actor_in_report=True, marker_in_report=False, node_pct=66.7%)
- Hypothesis: present=True category=apt_targeted history_len=1
- Phase 3 tools used: ['dom_fingerprints']
- Graph: 15 nodes / 15 edges

## Case 3 — Bumblebee→Akira

- NR=35.3  (6/17 GT nodes hit)
  - Missing: hash:a6df0b49, domain:opmanager, domain:ev2sirbd269o5j, domain:2rxyt9urhq0bgj, domain:angryipscanner, domain:axiscamerastation, domain:ip-scanner, ip:188.40.187.145 ...
- ER=33.3  (1/3 GT edges hit)
  - Missing edges: 186b26df--drops-->a6df0b49, 172.96.137.160--c2-->victim
- PC=50.0  (2/4 pivot rules fired)
  - Pivot misses: vt_pdns_domain, reverse_ip_seo_decoy
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=12, budget_extension_count=0)
- RQ=70  (actor_in_report=True, marker_in_report=True, node_pct=47.1%)
- Hypothesis: present=True category=commodity_malware history_len=3
- Phase 3 tools used: (none)
- Graph: 30 nodes / 34 edges

## Case 4 — Interlock

- NR=23.1  (3/13 GT nodes hit)
  - Missing: ip:49.12.69.80, ip:96.62.214.11, ip:188.34.195.44, ip:45.61.136.202, domain:microsoft-msteams, domain:microstteams, domain:advanceipscaner, domain:ecologilives ...
- ER=0.0  (0/2 GT edges hit)
  - Missing edges: 64.94.84.85--same_cluster-->49.12.69.80, advanceipscaner--delivery-->additional-check
- PC=100.0  (5/5 pivot rules fired)
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=42, budget_extension_count=1)
- RQ=40  (actor_in_report=True, marker_in_report=False, node_pct=23.1%)
- Hypothesis: present=True category=commodity_malware history_len=1
- Phase 3 tools used: ['abuseipdb_check', 'certspotter_serial', 'criminalip_ip', 'dom_fingerprints', 'netlas_jarm', 'whoxy_reverse', 'zoomeye_jarm']
- Graph: 28 nodes / 29 edges

## Case 5 — Eye Pyramid cross-brand

- NR=7.7  (1/13 GT nodes hit)
  - Missing: asn:as214943, asn:as215540, asn:as215439, framework:eye pyramid, ransomware:rhysida, ransomware:vice society, ransomware:blackcat, ransomware:ransomhub ...
- ER=0.0  (0/2 GT edges hit)
  - Missing edges: 195.177.95.163--uses_infra-->rhysida, eye pyramid--uses_infra-->blackcat
- PC=25.0  (1/4 pivot rules fired)
  - Pivot misses: shodan_banner, banner_sibling_search, threatfox_multi
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=4, budget_extension_count=0)
- RQ=0  (actor_in_report=False, marker_in_report=False, node_pct=7.7%)
- Hypothesis: present=False category=(none) history_len=0
- Phase 3 tools used: (none)
- Graph: 1 nodes / 0 edges

## Case 6 — LummaC2 About-Cats

- NR=50.0  (3/6 GT nodes hit)
  - Missing: cert_sha1:80b9e0f6a81ab78ee4e01152958e13, domain:pinkipinevazzey, domain:fanlumpactiras
- ER=100.0  (2/2 GT edges hit)
- PC=25.0  (1/4 pivot rules fired)
  - Pivot misses: urlscan_or_wayback_seed, content_fingerprint_pivot, crtsh_seed
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=3, budget_extension_count=0)
- RQ=0  (actor_in_report=False, marker_in_report=False, node_pct=16.7%)
- Hypothesis: present=True category=commodity_malware history_len=0
- Phase 3 tools used: (none)
- Graph: 31 nodes / 33 edges

## Case 7 — SocGholish

- NR=50.0  (6/12 GT nodes hit)
  - Missing: domain:packedbrick, domain:newgoodfoodmarket, domain:urban-orthodontics, domain:bestintownpro, ip:185.76.79.50, ip:166.88.182.126
- ER=33.3  (1/3 GT edges hit)
  - Missing edges: blackshelter.org--resolves_to-->176.53.147.97, blackshelter--known_ioc-->socgholish
- PC=100.0  (5/5 pivot rules fired)
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=75  (cti_calls=65, budget_extension_count=1)
- RQ=70  (actor_in_report=True, marker_in_report=True, node_pct=50.0%)
- Hypothesis: present=True category=traffer_or_tds history_len=3
- Phase 3 tools used: ['abuseipdb_check', 'certspotter_issuances', 'certspotter_serial', 'criminalip_ip', 'dom_fingerprints', 'netlas_jarm', 'zoomeye_jarm']
- Graph: 68 nodes / 71 edges

## Case 8 — Amadey/StealC GitLab

- NR=50.0  (4/8 GT nodes hit)
  - Missing: ip:185.215.113, asn:as51381, domain:gitlab.bzctoons.net, domain:bzctoons.net
- ER=33.3  (1/3 GT edges hit)
  - Missing edges: 185.215.113--hosted_on_asn-->as51381, gitlab.bzctoons.ne--hosts_stager-->stealc
- PC=75.0  (3/4 pivot rules fired)
  - Pivot misses: cert_san_apex
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=9, budget_extension_count=0)
- RQ=70  (actor_in_report=True, marker_in_report=True, node_pct=50.0%)
- Hypothesis: present=True category=commodity_malware history_len=0
- Phase 3 tools used: (none)
- Graph: 12 nodes / 11 edges

## Case 9 — Tycoon 2FA

- NR=50.0  (3/6 GT nodes hit)
  - Missing: kit_fingerprint:turnstile, actor:storm-1747, phishing_kit:tycoon 2fa
- ER=100.0  (1/1 GT edges hit)
- PC=75.0  (3/4 pivot rules fired)
  - Pivot misses: ct_burst_window
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=24, budget_extension_count=0)
- RQ=40  (actor_in_report=True, marker_in_report=False, node_pct=50.0%)
- Hypothesis: present=True category=fronted_c2 history_len=2
- Phase 3 tools used: ['certspotter_issuances', 'certspotter_serial', 'dom_fingerprints', 'netlas_jarm', 'zoomeye_jarm']
- Graph: 31 nodes / 32 edges

## Case 10 — Contagious Interview

- NR=7.1  (1/14 GT nodes hit)
  - Missing: domain:lianxinxiao, domain:blocknovas, domain:angeloper, domain:softglide, domain:attisscmo, subdomain:gitlab.blocknovas, subdomain:status.blocknovas, subdomain:mail.blocknovas ...
- ER=0.0  (0/3 GT edges hit)
  - Missing edges: 37.211.126.117--resolves-->lianxinxiao, lianxinxiao--dns_txt_mx-->blocknovas, blocknovas--parent_of-->gitlab.blocknovas
- PC=0.0  (0/5 pivot rules fired)
  - Pivot misses: reverse_dns_seed, dns_txt_mx_cross_ref, crtsh_blocknovas, wayback_seized, urlscan_front_companies
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=2, budget_extension_count=0)
- RQ=0  (actor_in_report=False, marker_in_report=False, node_pct=7.1%)
- Hypothesis: present=False category=(none) history_len=0
- Phase 3 tools used: (none)
- Graph: 1 nodes / 0 edges

## Case 11 — Smishing Triad

- NR=0.0  (0/5 GT nodes hit)
  - Missing: registrar:namesilo, kit:lighthouse, actor:smishing triad, actor:wang duo yu, ip:104.21
- ER=n/a (no GT edges defined)
- PC=0.0  (0/5 pivot rules fired)
  - Pivot misses: rdap_seed, crtsh_seed, vt_pdns_seed, historical_origin_pivot, urlscan_dom_pivot
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=0, budget_extension_count=0)
- RQ=0  (actor_in_report=False, marker_in_report=False, node_pct=0.0%)
- Hypothesis: present=False category=(none) history_len=0
- Phase 3 tools used: (none)
- Graph: 0 nodes / 0 edges

## Case 12 — ClearFake

- NR=0.0  (0/8 GT nodes hit)
  - Missing: domain:921hapudyqwdvy.com, cert_cn:921hapudyqwdvy.com, ip:*yacolo, ip:*hetzner, asn:as203493, asn:as24940, tool:keitaro, malware:clearfake
- ER=0.0  (0/1 GT edges hit)
  - Missing edges: 921hapudyqwdvy--cert_cn-->921hapudyqwdvy
- PC=0.0  (0/4 pivot rules fired)
  - Pivot misses: dns_resolve_seed, crtsh_seed, shodan_cert_cn_search, rdap_origin
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=0, budget_extension_count=0)
- RQ=0  (actor_in_report=False, marker_in_report=False, node_pct=0.0%)
- Hypothesis: present=False category=(none) history_len=0
- Phase 3 tools used: (none)
- Graph: 0 nodes / 0 edges

## Cross-case patterns

- Median CTI calls per case: 12.
- Working_hypothesis present in 8/12 cases.
- Phase 3 tools used in 5/12 cases.
- Short-call cases (≤ 8 CTI calls = early termination): [5, 6, 10, 11, 12].