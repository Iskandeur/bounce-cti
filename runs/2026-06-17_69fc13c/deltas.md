# Deltas — 2026-06-17 · commit 69fc13c

Per-case missing nodes / edges, noise, pivot misses, hand-audit notes.

## Case 1 — ERROR

c01 not in this run's subset (no data)

## Case 2 — MuddyWater (Chaos/Stagecomp, 2026)

- NR=63.6  (7/11 GT nodes hit)
  - Missing: domain:uploadfiler, ip:172.86.126.208, ip:116.203.208.186, malware:chaos
- ER=33.3  (1/3 GT edges hit)
  - Missing edges: 3df9dcc45d2a3b1f--contacts-->uploadfiler, 24857fe82f454719--hosted_on-->172.86.126.208
- PC=100.0  (4/4 pivot rules fired)
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=46, budget_extension_count=0)
- RQ=70  (actor_in_report=True, marker_in_report=True, node_pct=63.6%, has_summary=True)
- Hypothesis: present=True category=apt_targeted history_len=1 final_category=apt_targeted valid=True
- Phase 3 tools used: ['abuseipdb_check', 'certspotter_serial', 'criminalip_ip', 'netlas_jarm', 'whoxy_reverse', 'zoomeye_jarm']
- Graph: 61 nodes / 84 edges

## Case 3 — Bumblebee→Akira

- NR=47.1  (8/17 GT nodes hit)
  - Missing: domain:opmanager, domain:ev2sirbd269o5j, domain:angryipscanner, domain:axiscamerastation, domain:ip-scanner, ip:188.40.187.145, ip:172.96.137.160, ip:193.242.184.150, ip:185.174.100.203
- ER=0.0  (0/3 GT edges hit)
  - Missing edges: 186b26df--drops-->a6df0b49, 186b26df--contacts-->opmanager, 172.96.137.160--c2-->victim
- PC=75.0  (3/4 pivot rules fired)
  - Pivot misses: reverse_ip_seo_decoy
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=12, budget_extension_count=0)
- RQ=70  (actor_in_report=True, marker_in_report=True, node_pct=52.9%, has_summary=True)
- Hypothesis: present=True category=commodity_malware history_len=1 final_category=commodity_malware valid=True
- Phase 3 tools used: (none)
- Graph: 28 nodes / 31 edges

## Case 4 — ERROR

c04 not in this run's subset (no data)

## Case 5 — ERROR

c05 not in this run's subset (no data)

## Case 6 — ERROR

c06 not in this run's subset (no data)

## Case 7 — ERROR

c07 not in this run's subset (no data)

## Case 8 — Amadey/StealC GitLab

- NR=50.0  (4/8 GT nodes hit)
  - Missing: ip:185.215.113, asn:as51381, domain:gitlab.bzctoons.net, domain:bzctoons.net
- ER=33.3  (1/3 GT edges hit)
  - Missing edges: 185.215.113--hosted_on_asn-->as51381, gitlab.bzctoons.ne--hosts_stager-->stealc
- PC=100.0  (4/4 pivot rules fired)
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=60, budget_extension_count=0)
- RQ=70  (actor_in_report=True, marker_in_report=True, node_pct=50.0%, has_summary=True)
- Hypothesis: present=True category=commodity_malware history_len=1 final_category=commodity_malware valid=True
- Phase 3 tools used: ['abuseipdb_check', 'certspotter_serial', 'criminalip_ip', 'dom_fingerprints', 'netlas_jarm', 'zoomeye_jarm']
- Graph: 39 nodes / 50 edges

## Case 9 — Tycoon 2FA

- NR=50.0  (3/6 GT nodes hit)
  - Missing: kit_fingerprint:turnstile, actor:storm-1747, phishing_kit:tycoon 2fa
- ER=100.0  (1/1 GT edges hit)
- PC=75.0  (3/4 pivot rules fired)
  - Pivot misses: ct_burst_window
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=33, budget_extension_count=0)
- RQ=40  (actor_in_report=True, marker_in_report=False, node_pct=50.0%, has_summary=True)
- Hypothesis: present=True category=phishing_kit_cluster history_len=2 final_category=phishing_kit_cluster valid=True
- Phase 3 tools used: ['certspotter_issuances', 'certspotter_serial', 'dom_fingerprints', 'netlas_jarm', 'openphish_check', 'zoomeye_jarm']
- Graph: 23 nodes / 20 edges

## Case 10 — ERROR

c10 not in this run's subset (no data)

## Case 11 — ERROR

c11 not in this run's subset (no data)

## Case 12 — ClearFake

- NR=50.0  (4/8 GT nodes hit)
  - Missing: cert_cn:921hapudyqwdvy.com, ip:*yacolo, asn:as203493, tool:keitaro
- ER=100.0  (1/1 GT edges hit)
- PC=75.0  (3/4 pivot rules fired)
  - Pivot misses: shodan_cert_cn_search
- DC=100  (over_inclusion=0, over_defuse=0)
- BD=100  (cti_calls=16, budget_extension_count=0)
- RQ=70  (actor_in_report=True, marker_in_report=True, node_pct=66.7%, has_summary=True)
- Hypothesis: present=True category=commodity_malware history_len=2 final_category=traffer_or_tds valid=True
- Phase 3 tools used: ['abuseipdb_check']
- Graph: 18 nodes / 20 edges

## Cross-case patterns

- Median CTI calls per case: 33.
- Working_hypothesis present in 5/5 cases.
- Valid hypothesis (wh+history+final_cat) in 5/5 cases.
- Phase 3 tools used in 4/5 cases.