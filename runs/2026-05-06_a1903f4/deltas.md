# Deltas — 2026-05-06 · commit a1903f4

Per-case missing nodes / edges, noise, pivot misses, hand-audit notes.

## Case 1 — Salt Typhoon

- NR=58.3  (7/15 GT nodes hit)
  - Missing: domain:colourtinctem.com, domain:solveblemten.com, domain:dateupdata.com, domain:infraredsen.com, domain:pulseathermakf.com, email:sdsdvxcdcbsgfe@protonmail.com, email:oklmdsfhjnfdsifh@protonmail.com, actor:unc2286
- ER=0.0  (0/6 GT edges hit)
  - Missing edges: materialplies.com--registered_by-->sdsdvxcdcbsgfe, colourtinctem.com--registered_by-->sdsdvxcdcbsgfe, solveblemten.com--registered_by-->sdsdvxcdcbsgfe, alpha--soa-->beta, --resolves_to-->, --overlaps-->
- PC=75.0  (3/4 pivot rules fired)
  - Pivot misses: reverse_whois_email
- DC=100.0  (over_inclusion=0, over_defuse=0)
- BD=100.0  (cti_calls=45, budget_extension_count=0)
- RQ=100.0  (actor_in_report=True, marker_in_report=True, node_pct=58.3%)
- Hypothesis: present=True category=apt_infrastructure history_len=0
- Phase 3 tools used: (none)
- Graph: 15 nodes / 13 edges

## Case 2 — MuddyRot

- NR=83.3  (5/9 GT nodes hit)
  - Missing: hash:b8703744, ip:91.235.234.202, ip:146.19.143.14, url:egnyte
- ER=0.0  (0/4 GT edges hit)
  - Missing edges: 94278fa01900fdbfb--contacts-->91.235.234.202, b8703744--same_family-->94278fa, 91.235.234.202--share_jarm-->146.19.143.14, 91.235.234.202--tagged-->muddywater
- PC=50.0  (2/4 pivot rules fired)
  - Pivot misses: shodan_or_onyphe_banner, jarm_search
- DC=100.0  (over_inclusion=0, over_defuse=0)
- BD=100.0  (cti_calls=7, budget_extension_count=0)
- RQ=100.0  (actor_in_report=True, marker_in_report=True, node_pct=83.3%)
- Hypothesis: present=False category=(none) history_len=0
- Phase 3 tools used: (none)
- Graph: 36 nodes / 30 edges

## Case 3 — Bumblebee→AdaptixC2→Akira

- NR=80.0  (8/16 GT nodes hit)
  - Missing: domain:ev2sirbd269o5j, domain:angryipscanner, domain:axiscamerastation, ip:188.40.187.145, ip:172.96.137.160, ip:193.242.184.150, ip:185.174.100.203, malware:akira
- ER=0.0  (0/3 GT edges hit)
  - Missing edges: 186b26df--drops-->a6df0b49, 186b26df--contacts-->opmanager, 172.96.137.160--c2-->victim
- PC=75.0  (3/4 pivot rules fired)
  - Pivot misses: reverse_ip_seo_decoy
- DC=100.0  (over_inclusion=0, over_defuse=0)
- BD=100.0  (cti_calls=52, budget_extension_count=0)
- RQ=100.0  (actor_in_report=True, marker_in_report=True, node_pct=80.0%)
- Hypothesis: present=False category=(none) history_len=0
- Phase 3 tools used: ['certspotter_serial']
- Graph: 28 nodes / 33 edges

## Case 4 — Interlock

- NR=30.0  (3/13 GT nodes hit)
  - Missing: ip:49.12.69.80, ip:96.62.214.11, ip:188.34.195.44, ip:45.61.136.202, domain:microsoft-msteams, domain:microstteams, domain:advanceipscaner, domain:ecologilives ...
- ER=0.0  (0/2 GT edges hit)
  - Missing edges: 64.94.84.85--same_cluster-->49.12.69.80, advanceipscaner--delivery-->additional-check
- PC=100.0  (5/5 pivot rules fired)
- DC=100.0  (over_inclusion=0, over_defuse=0)
- BD=100.0  (cti_calls=56, budget_extension_count=0)
- RQ=70.0  (actor_in_report=True, marker_in_report=True, node_pct=30.0%)
- Hypothesis: present=False category=(none) history_len=0
- Phase 3 tools used: ['abuseipdb_check', 'certspotter_serial', 'criminalip_ip']
- Graph: 22 nodes / 27 edges

## Case 5 — Eye Pyramid cross-brand

- NR=13.3  (2/13 GT nodes hit)
  - Missing: asn:as215540, asn:as215439, framework:eye pyramid, ransomware:rhysida, ransomware:vice society, ransomware:blackcat, ransomware:ransomhub, ransomware:fog ...
- ER=0.0  (0/2 GT edges hit)
  - Missing edges: 195.177.95.163--uses_infra-->rhysida, eye pyramid--uses_infra-->blackcat
- PC=75.0  (3/4 pivot rules fired)
  - Pivot misses: banner_sibling_search
- DC=100.0  (over_inclusion=0, over_defuse=0)
- BD=100.0  (cti_calls=37, budget_extension_count=0)
- RQ=40.0  (actor_in_report=False, marker_in_report=True, node_pct=13.3%)
- Hypothesis: present=False category=(none) history_len=0
- Phase 3 tools used: ['abuseipdb_check', 'criminalip_ip', 'dom_fingerprints', 'whoxy_reverse']
- Graph: 33 nodes / 47 edges

## Case 6 — LummaC2 About-Cats

- NR=8.0  (2/6 GT nodes hit)
  - Missing: cert_sha1:80b9e0f6a81ab78ee4e01152958e1322e6d7b6fa, cert_serial:(any), domain:pinkipinevazzey, domain:fanlumpactiras
- ER=0.0  (0/2 GT edges hit)
  - Missing edges: rugtou.shop--known_ioc-->lumma, rugtou.shop--registered_with-->namecheap
- PC=50.0  (2/4 pivot rules fired)
  - Pivot misses: urlscan_or_wayback_seed, content_fingerprint_pivot
- DC=100.0  (over_inclusion=0, over_defuse=0)
- BD=100.0  (cti_calls=47, budget_extension_count=0)
- RQ=70.0  (actor_in_report=True, marker_in_report=True, node_pct=8.0%)
- Hypothesis: present=False category=(none) history_len=0
- Phase 3 tools used: ['abuseipdb_check', 'criminalip_ip']
- Graph: 12 nodes / 12 edges

## Case 7 — SocGholish

- NR=37.5  (3/12 GT nodes hit)
  - Missing: domain:blacksaltys, domain:packedbrick, domain:newgoodfoodmarket, domain:urban-orthodontics, domain:bestintownpro, ip:185.76.79.50, ip:166.88.182.126, malware:socgholish ...
- ER=0.0  (0/3 GT edges hit)
  - Missing edges: blackshelter.org--resolves_to-->176.53.147.97, rednosehorse--share_ip-->176.53.147.97, blackshelter--known_ioc-->socgholish
- PC=100.0  (5/5 pivot rules fired)
- DC=100.0  (over_inclusion=0, over_defuse=0)
- BD=100.0  (cti_calls=30, budget_extension_count=0)
- RQ=40.0  (actor_in_report=False, marker_in_report=True, node_pct=37.5%)
- Hypothesis: present=False category=(none) history_len=0
- Phase 3 tools used: (none)
- Graph: 40 nodes / 37 edges

## Case 8 — Amadey/StealC GitLab

- NR=50.0  (4/8 GT nodes hit)
  - Missing: ip:185.215.113, asn:as51381, domain:gitlab.bzctoons.net, domain:bzctoons.net
- ER=20.0  (1/3 GT edges hit)
  - Missing edges: 185.215.113--hosted_on_asn-->as51381, gitlab.bzctoons.net--hosts_stager-->stealc
- PC=75.0  (3/4 pivot rules fired)
  - Pivot misses: cert_san_apex
- DC=100.0  (over_inclusion=0, over_defuse=0)
- BD=50.0  (cti_calls=78, budget_extension_count=0)
- RQ=100.0  (actor_in_report=True, marker_in_report=True, node_pct=50.0%)
- Hypothesis: present=False category=(none) history_len=0
- Phase 3 tools used: ['abuseipdb_check']
- Graph: 43 nodes / 67 edges

## Case 9 — Tycoon 2FA

- NR=20.0  (3/5 GT nodes hit)
  - Missing: kit_fingerprint:turnstile, actor:storm-1747
- ER=0.0  (0/1 GT edges hit)
  - Missing edges: rlcozx.es--known_ioc-->tycoon
- PC=75.0  (3/4 pivot rules fired)
  - Pivot misses: ct_burst_window
- DC=100.0  (over_inclusion=0, over_defuse=0)
- BD=100.0  (cti_calls=25, budget_extension_count=0)
- RQ=40.0  (actor_in_report=False, marker_in_report=True, node_pct=20.0%)
- Hypothesis: present=False category=(none) history_len=0
- Phase 3 tools used: (none)
- Graph: 57 nodes / 52 edges

## Case 10 — Contagious Interview

- NR=12.5  (1/14 GT nodes hit)
  - Missing: domain:lianxinxiao, domain:blocknovas, domain:angeloper, domain:softglide, domain:attisscmo, subdomain:gitlab.blocknovas, subdomain:status.blocknovas, subdomain:mail.blocknovas ...
- ER=0.0  (0/3 GT edges hit)
  - Missing edges: 37.211.126.117--resolves-->lianxinxiao, lianxinxiao--dns_txt_mx-->blocknovas, blocknovas--parent_of-->gitlab.blocknovas
- PC=0.0  (0/5 pivot rules fired)
  - Pivot misses: reverse_dns_seed, dns_txt_mx_cross_ref, crtsh_blocknovas, wayback_seized, urlscan_front_companies
- DC=100.0  (over_inclusion=0, over_defuse=0)
- BD=100.0  (cti_calls=18, budget_extension_count=0)
- RQ=0.0  (actor_in_report=False, marker_in_report=False, node_pct=12.5%)
- Hypothesis: present=False category=(none) history_len=0
- Phase 3 tools used: ['abuseipdb_check', 'criminalip_ip']
- Graph: 6 nodes / 4 edges

## Case 11 — Smishing Triad

- NR=0.0  (0/5 GT nodes hit)
  - Missing: registrar:namesilo, kit:lighthouse, actor:smishing triad, actor:wang duo yu, ip:104.21
- ER=n/a (no GT edges defined)
- PC=100.0  (5/5 pivot rules fired)
- DC=100.0  (over_inclusion=0, over_defuse=0)
- BD=50.0  (cti_calls=76, budget_extension_count=0)
- RQ=0.0  (actor_in_report=False, marker_in_report=False, node_pct=0.0%)
- Hypothesis: present=False category=(none) history_len=0
- Phase 3 tools used: ['certspotter_issuances', 'netlas_search', 'openphish_check', 'zoomeye_search']
- Graph: 2 nodes / 1 edges

## Case 12 — ClearFake

- NR=57.1  (4/6 GT nodes hit)
  - Missing: asn:as203493, tool:keitaro
- ER=0.0  (0/1 GT edges hit)
  - Missing edges: 921hapudyqwdvy--cert_cn-->921hapudyqwdvy
- PC=75.0  (3/4 pivot rules fired)
  - Pivot misses: rdap_origin
- DC=100.0  (over_inclusion=0, over_defuse=0)
- BD=50.0  (cti_calls=72, budget_extension_count=0)
- RQ=100.0  (actor_in_report=True, marker_in_report=True, node_pct=57.1%)
- Hypothesis: present=False category=(none) history_len=0
- Phase 3 tools used: ['abuseipdb_check', 'certspotter_serial', 'dom_fingerprints', 'netlas_jarm', 'zoomeye_jarm']
- Graph: 29 nodes / 31 edges

## Cross-case patterns

- Median CTI calls per case: 47.
- Working_hypothesis present in 1/12 cases.
- Phase 3 tools used in 8/12 cases.
- Short-call cases (≤ 8 CTI calls = early termination): [2].
