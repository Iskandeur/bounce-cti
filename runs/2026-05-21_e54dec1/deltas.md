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

- NR=0.0  (0/17 GT nodes hit)
  - Missing: hash:186b26df63df3b7334043b47659cba, hash:a6df0b49, domain:opmanager, domain:ev2sirbd269o5j, domain:2rxyt9urhq0bgj, domain:angryipscanner, domain:axiscamerastation, domain:ip-scanner ...
- ER=0.0  (0/3 GT edges hit)
  - Missing edges: 186b26df--drops-->a6df0b49, 186b26df--contacts-->opmanager, 172.96.137.160--c2-->victim
- PC=0.0  (0/4 pivot rules fired)
  - Pivot misses: virustotal_file, vt_pdns_domain, reverse_ip_seo_decoy, threatfox_ip
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=0, budget_extension_count=0)
- RQ=0  (actor_in_report=False, marker_in_report=False, node_pct=0.0%)
- Hypothesis: present=False category=(none) history_len=0
- Phase 3 tools used: (none)
- Graph: 0 nodes / 0 edges

## Case 4 — Interlock

- NR=0.0  (0/13 GT nodes hit)
  - Missing: ip:64.94.84.85, ip:49.12.69.80, ip:96.62.214.11, ip:188.34.195.44, ip:45.61.136.202, domain:microsoft-msteams, domain:microstteams, domain:advanceipscaner ...
- ER=0.0  (0/2 GT edges hit)
  - Missing edges: 64.94.84.85--same_cluster-->49.12.69.80, advanceipscaner--delivery-->additional-check
- PC=0.0  (0/5 pivot rules fired)
  - Pivot misses: rdap_seed, vt_pdns_ip, threatfox_ip, urlscan_path_keyword, wayback_or_urlscan_seed
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=0, budget_extension_count=0)
- RQ=0  (actor_in_report=False, marker_in_report=False, node_pct=0.0%)
- Hypothesis: present=False category=(none) history_len=0
- Phase 3 tools used: (none)
- Graph: 0 nodes / 0 edges

## Case 5 — Eye Pyramid cross-brand

- NR=0.0  (0/13 GT nodes hit)
  - Missing: ip:195.177.95.163, asn:as214943, asn:as215540, asn:as215439, framework:eye pyramid, ransomware:rhysida, ransomware:vice society, ransomware:blackcat ...
- ER=0.0  (0/2 GT edges hit)
  - Missing edges: 195.177.95.163--uses_infra-->rhysida, eye pyramid--uses_infra-->blackcat
- PC=0.0  (0/4 pivot rules fired)
  - Pivot misses: rdap_seed, shodan_banner, banner_sibling_search, threatfox_multi
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=0, budget_extension_count=0)
- RQ=0  (actor_in_report=False, marker_in_report=False, node_pct=0.0%)
- Hypothesis: present=False category=(none) history_len=0
- Phase 3 tools used: (none)
- Graph: 0 nodes / 0 edges

## Case 6 — LummaC2 About-Cats

- NR=0.0  (0/6 GT nodes hit)
  - Missing: domain:rugtou.shop, cert_sha1:80b9e0f6a81ab78ee4e01152958e13, domain:pinkipinevazzey, domain:fanlumpactiras, malware:lumma, malware:lummac2
- ER=0.0  (0/2 GT edges hit)
  - Missing edges: rugtou.shop--known_ioc-->lumma, rugtou.shop--registered_with-->namecheap
- PC=0.0  (0/4 pivot rules fired)
  - Pivot misses: rdap_seed, urlscan_or_wayback_seed, content_fingerprint_pivot, crtsh_seed
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=0, budget_extension_count=0)
- RQ=0  (actor_in_report=False, marker_in_report=False, node_pct=0.0%)
- Hypothesis: present=False category=(none) history_len=0
- Phase 3 tools used: (none)
- Graph: 0 nodes / 0 edges

## Case 7 — SocGholish

- NR=0.0  (0/12 GT nodes hit)
  - Missing: domain:blackshelter.org, ip:176.53.147.97, domain:rednosehorse, domain:blacksaltys, domain:packedbrick, domain:newgoodfoodmarket, domain:urban-orthodontics, domain:bestintownpro ...
- ER=0.0  (0/3 GT edges hit)
  - Missing edges: blackshelter.org--resolves_to-->176.53.147.97, rednosehorse--share_ip-->176.53.147.97, blackshelter--known_ioc-->socgholish
- PC=0.0  (0/5 pivot rules fired)
  - Pivot misses: dns_resolve_seed, vt_pdns_ip, wayback_or_urlscan_seed, vt_pdns_stage2, threatfox_stage2
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=0, budget_extension_count=0)
- RQ=0  (actor_in_report=False, marker_in_report=False, node_pct=0.0%)
- Hypothesis: present=False category=(none) history_len=0
- Phase 3 tools used: (none)
- Graph: 0 nodes / 0 edges

## Case 8 — Amadey/StealC GitLab

- NR=0.0  (0/8 GT nodes hit)
  - Missing: hash:aad0a60cb86e3a56bcd356c6559b92, ip:62.60.226.159, ip:185.215.113, asn:as51381, domain:gitlab.bzctoons.net, domain:bzctoons.net, malware:amadey, malware:stealc
- ER=0.0  (0/3 GT edges hit)
  - Missing edges: aad0a60c--contacts-->62.60.226.159, 185.215.113--hosted_on_asn-->as51381, gitlab.bzctoons.ne--hosts_stager-->stealc
- PC=0.0  (0/4 pivot rules fired)
  - Pivot misses: virustotal_file, rdap_ip, threatfox_asn, cert_san_apex
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=0, budget_extension_count=0)
- RQ=0  (actor_in_report=False, marker_in_report=False, node_pct=0.0%)
- Hypothesis: present=False category=(none) history_len=0
- Phase 3 tools used: (none)
- Graph: 0 nodes / 0 edges

## Case 9 — Tycoon 2FA

- NR=0.0  (0/6 GT nodes hit)
  - Missing: domain:rlcozx.es, kit_fingerprint:turnstile, kit_fingerprint:tycoon, actor:storm-1747, phishing_kit:tycoon, phishing_kit:tycoon 2fa
- ER=0.0  (0/1 GT edges hit)
  - Missing edges: rlcozx.es--known_ioc-->tycoon
- PC=0.0  (0/4 pivot rules fired)
  - Pivot misses: crtsh_seed, ct_burst_window, urlscan_kit_pivot, vt_pdns_seed
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=0, budget_extension_count=0)
- RQ=0  (actor_in_report=False, marker_in_report=False, node_pct=0.0%)
- Hypothesis: present=False category=(none) history_len=0
- Phase 3 tools used: (none)
- Graph: 0 nodes / 0 edges

## Case 10 — Contagious Interview

- NR=0.0  (0/14 GT nodes hit)
  - Missing: ip:37.211.126.117, domain:lianxinxiao, domain:blocknovas, domain:angeloper, domain:softglide, domain:attisscmo, subdomain:gitlab.blocknovas, subdomain:status.blocknovas ...
- ER=0.0  (0/3 GT edges hit)
  - Missing edges: 37.211.126.117--resolves-->lianxinxiao, lianxinxiao--dns_txt_mx-->blocknovas, blocknovas--parent_of-->gitlab.blocknovas
- PC=0.0  (0/5 pivot rules fired)
  - Pivot misses: reverse_dns_seed, dns_txt_mx_cross_ref, crtsh_blocknovas, wayback_seized, urlscan_front_companies
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=0, budget_extension_count=0)
- RQ=0  (actor_in_report=False, marker_in_report=False, node_pct=0.0%)
- Hypothesis: present=False category=(none) history_len=0
- Phase 3 tools used: (none)
- Graph: 0 nodes / 0 edges

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

- Median CTI calls per case: 0.
- Working_hypothesis present in 2/12 cases.
- Phase 3 tools used in 2/12 cases.
- Short-call cases (≤ 8 CTI calls = early termination): [3, 4, 5, 6, 7, 8, 9, 10, 11, 12].