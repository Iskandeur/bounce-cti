# Per-case deltas

## Case 1 — Reverse-WHOIS is the discriminator. If PC=0 on step 2, F-SRC-ABSENT.
- **status**: done, nodes=30, edges=33, cti_calls=12, depth=2, report=yes
- **NR** 11.1% (2/18) — missing: ['domain:colourtinctem.com', 'domain:solveblemten.com', 'domain:dateupdata.com', 'domain:infraredsen.com', 'domain:pulseathermakf.com', 'email:sdsdvxcdcbsgfe@protonmail.com', 'email:oklmdsfhjnfdsifh@protonmail.com', 'malware:Demodex', 'malware:SnappyBee', 'malware:GhostSpider']
- **ER** 0.0% (0/10) — missing: [('materialplies.com', 'sdsdvxcdcbsgfe@protonmail.com'), ('colourtinctem.com', 'sdsdvxcdcbsgfe@protonmail.com'), ('solveblemten.com', 'sdsdvxcdcbsgfe@protonmail.com')]
- **PC** 50.0% — missed: ['Reverse-WHOIS on registrant email', 'Reverse-IP on hosting']
- **DC** 100 — over-inclusions: []
- **BD** calls=12, depth=2
- **RQ** 40 — {'score': 40, 'mentions_actor': True, 'frac_nodes': 0.42, 'marker_hit': False, 'blob_len': 6332}
- **Failure codes**: ['F-SRC-ABSENT|F-PIVOT-MISS', 'F-REPORT']

## Case 2 — JARM/banner pivot is the discriminator.
- **status**: done, nodes=21, edges=31, cti_calls=4, depth=3, report=yes
- **NR** 33.3% (3/9) — missing: ['ip:91.235.234.202', 'ip:146.19.143.14']
- **ER** 0.0% (0/6) — missing: [('94278fa01900fdbfb58d2e373895c045c69c01915edc5349cd6f3e5b7130c472', '91.235.234.202')]
- **PC** 25.0% — missed: ['Shodan/Onyphe banner on C2', 'JARM/banner sibling search', 'ThreatFox muddywater tag']
- **DC** 100 — over-inclusions: []
- **BD** calls=4, depth=3
- **RQ** 70 — {'score': 70, 'mentions_actor': True, 'frac_nodes': 0.6, 'marker_hit': True, 'blob_len': 5401}
- **Failure codes**: ['F-PIVOT-MISS']

## Case 3 — Three tier distinction: loader C2, AdaptixC2, exfil.
- **status**: done, nodes=10, edges=14, cti_calls=6, depth=1, report=yes
- **NR** 26.7% (4/15) — missing: ['hash:a6df0b49a5ef9ffd6513bfe061fb60f6d2941a440038e2de8a7aeb1914945331', 'domain:opmanager.pro', 'domain:angryipscanner.org', 'domain:axiscamerastation.org', 'domain:ip-scanner.org', 'ip:109.205.195.211', 'ip:188.40.187.145', 'ip:172.96.137.160', 'ip:193.242.184.150', 'ip:185.174.100.203']
- **ER** 0.0% (0/11) — missing: [('186b26df63df3b7334043b47659cba4185c948629d857d47452cc1936f0aa5da', 'opmanager.pro'), ('186b26df63df3b7334043b47659cba4185c948629d857d47452cc1936f0aa5da', 'a6df0b49a5ef9ffd6513bfe061fb60f6d2941a440038e2de8a7aeb1914945331')]
- **PC** 50.0% — missed: ['pDNS on contacted domain', 'Reverse-IP on C2']
- **DC** 100 — over-inclusions: []
- **BD** calls=6, depth=1
- **RQ** 70 — {'score': 70, 'mentions_actor': True, 'frac_nodes': 0.29, 'marker_hit': True, 'blob_len': 5481}
- **Failure codes**: ['F-SRC-ABSENT|F-PIVOT-MISS']

## Case 4 — Cloudflare Tunnel defuse, distinct from fronting (11,12).
- **status**: done, nodes=6, edges=5, cti_calls=7, depth=0, report=NO
- **NR** 13.3% (2/15) — missing: ['ip:49.12.69.80', 'ip:96.62.214.11', 'ip:188.34.195.44', 'ip:45.61.136.202', 'domain:microsoft-msteams.com', 'domain:microstteams.com', 'domain:advanceipscaner.com', 'domain:ecologilives.com']
- **ER** 0.0% (0/8) — missing: []
- **PC** 20.0% — missed: ['RDAP seed', 'ThreatFox interlock tag', 'URLScan ClickFix path', 'Recover PS lure']
- **DC** 100 — over-inclusions: []
- **BD** calls=7, depth=0
- **RQ** 0 — {'score': 0, 'no_report': True}
- **Failure codes**: ['F-REPORT', 'F-PIVOT-MISS', 'F-SRC-ABSENT|F-PIVOT-MISS', 'F-REPORT']

## Case 5 — Multi-brand attribution on shared infra is the point.
- **status**: done, nodes=8, edges=7, cti_calls=7, depth=0, report=NO
- **NR** 4.5% (1/22) — missing: ['asn:AS214943', 'asn:AS215540', 'asn:AS215439', 'framework:Eye Pyramid', 'ransomware:Rhysida', 'ransomware:Vice Society', 'ransomware:BlackCat', 'ransomware:RansomHub', 'ransomware:Fog', 'malware:Cobalt Strike', 'malware:Sliver', 'malware:Rhadamanthys']
- **ER** 0.0% (0/12) — missing: []
- **PC** 25.0% — missed: ['RDAP/ASN', 'Banner-hash sibling search', 'ThreatFox cross-brand']
- **DC** 100 — over-inclusions: []
- **BD** calls=7, depth=0
- **RQ** 0 — {'score': 0, 'no_report': True}
- **Failure codes**: ['F-REPORT', 'F-PIVOT-MISS', 'F-SRC-ABSENT|F-PIVOT-MISS', 'F-REPORT']

## Case 6 — Content-fingerprint pivot + SSL SHA1 cluster.
- **status**: done, nodes=14, edges=13, cti_calls=7, depth=1, report=NO
- **NR** 3.4% (2/58) — missing: ['cert:80b9e0f6a81ab78ee4e01152958e1322e6d7b6fa', 'domain:pinkipinevazzey.pw', 'domain:fanlumpactiras.pw']
- **ER** 0.0% (0/15) — missing: []
- **PC** 50.0% — missed: ['RDAP Namecheap/inbox.eu', 'About Cats content fingerprint']
- **DC** 100 — over-inclusions: []
- **BD** calls=7, depth=1
- **RQ** 0 — {'score': 0, 'no_report': True}
- **Failure codes**: ['F-REPORT', 'F-SRC-ABSENT|F-PIVOT-MISS', 'F-REPORT']

## Case 7 — Two-tier: Keitaro front vs stage-2 C2 must stay distinct.
- **status**: done, nodes=51, edges=50, cti_calls=6, depth=1, report=NO
- **NR** 15.4% (2/13) — missing: ['domain:rednosehorse.com', 'domain:blacksaltys.com', 'domain:packedbrick.com', 'domain:newgoodfoodmarket.com', 'domain:virtual.urban-orthodontics.com', 'domain:msbdz.crm.bestintownpro.com', 'ip:185.76.79.50', 'ip:166.88.182.126', 'malware:SocGholish', 'tool:Keitaro']
- **ER** 12.5% (1/8) — missing: []
- **PC** 0.0% — missed: ['DNS A seed', 'Reverse DNS / pDNS on Keitaro', 'URLScan sibling TDS', 'Stage-2 DNS', 'ThreatFox SocGholish']
- **DC** 100 — over-inclusions: []
- **BD** calls=6, depth=1
- **RQ** 0 — {'score': 0, 'no_report': True}
- **Failure codes**: ['F-REPORT', 'F-PIVOT-MISS', 'F-SRC-ABSENT|F-PIVOT-MISS', 'F-REPORT']

## Case 8 — Apex vs subdomain scoping is the trap.
- **status**: done, nodes=6, edges=5, cti_calls=4, depth=0, report=NO
- **NR** 33.3% (4/12) — missing: ['asn:AS51381', 'domain:gitlab.bzctoons.net', 'domain:bzctoons.net']
- **ER** 14.3% (1/7) — missing: [('bzctoons.net', 'gitlab.bzctoons.net')]
- **PC** 25.0% — missed: ['RDAP/ASN', 'ThreatFox Amadey family', 'Cert SAN apex check']
- **DC** 100 — over-inclusions: []
- **BD** calls=4, depth=0
- **RQ** 0 — {'score': 0, 'no_report': True}
- **Failure codes**: ['F-REPORT', 'F-PIVOT-MISS', 'F-REPORT']

## Case 9 — CT issuance-date burst clustering.
- **status**: done, nodes=3, edges=2, cti_calls=7, depth=1, report=NO
- **NR** 4.0% (1/25) — missing: ['actor:Storm-1747', 'phishing_kit:Tycoon 2FA']
- **ER** 0.0% (0/12) — missing: []
- **PC** 50.0% — missed: ['CT burst-window', 'URLScan kit fingerprint']
- **DC** 100 — over-inclusions: []
- **BD** calls=7, depth=1
- **RQ** 0 — {'score': 0, 'no_report': True}
- **Failure codes**: ['F-REPORT', 'F-SRC-ABSENT|F-PIVOT-MISS', 'F-REPORT']

## Case 10 — DNS TXT/MX cross-ref is the signature pivot.
- **status**: done, nodes=8, edges=8, cti_calls=7, depth=2, report=yes
- **NR** 7.7% (1/13) — missing: ['domain:lianxinxiao.com', 'domain:blocknovas.com', 'domain:angeloper.com', 'domain:softglide.co', 'domain:attisscmo.com', 'domain:gitlab.blocknovas.com', 'domain:status.blocknovas.com', 'domain:mail.blocknovas.com', 'malware:BeaverTail', 'malware:InvisibleFerret', 'malware:OtterCookie', 'actor:Famous Chollima']
- **ER** 0.0% (0/9) — missing: [('37.211.126.117', 'lianxinxiao.com'), ('lianxinxiao.com', 'blocknovas.com')]
- **PC** 20.0% — missed: ['DNS A on C2 domain', 'DNS TXT/MX cross-ref', 'crt.sh blocknovas', 'Wayback seized']
- **DC** 100 — over-inclusions: []
- **BD** calls=7, depth=2
- **RQ** 40 — {'score': 40, 'mentions_actor': False, 'frac_nodes': 0.08, 'marker_hit': True, 'blob_len': 3011}
- **Failure codes**: ['F-PIVOT-MISS', 'F-SRC-ABSENT|F-PIVOT-MISS', 'F-REPORT']

## Case 11 — Primary Cloudflare origin-unmask test.
- **status**: done, nodes=27, edges=34, cti_calls=13, depth=2, report=yes
- **NR** 4.0% (2/50) — missing: ['actor:Smishing Triad', 'kit:Lighthouse']
- **ER** 0.0% (0/12) — missing: []
- **PC** 60.0% — missed: ['Origin banner (Tencent/Alibaba)', 'URLScan cross-brand DOM']
- **DC** 100 — over-inclusions: []
- **BD** calls=13, depth=2
- **RQ** 0 — {'score': 0, 'mentions_actor': False, 'frac_nodes': 0.5, 'marker_hit': False, 'blob_len': 5057}
- **Failure codes**: ['F-SRC-ABSENT|F-PIVOT-MISS', 'F-REPORT']

## Case 12 — Canonical cert-CN -> Shodan unmask.
- **status**: done, nodes=24, edges=23, cti_calls=23, depth=3, report=yes
- **NR** 25.0% (3/12) — missing: ['asn:AS203493', 'tool:Keitaro']
- **ER** 0.0% (0/7) — missing: []
- **PC** 25.0% — missed: ['Shodan cert-CN unmask', 'RDAP origins', 'pDNS on origins']
- **DC** 100 — over-inclusions: []
- **BD** calls=23, depth=3
- **RQ** 40 — {'score': 40, 'mentions_actor': False, 'frac_nodes': 0.6, 'marker_hit': True, 'blob_len': 4270}
- **Failure codes**: ['F-PIVOT-MISS', 'F-SRC-ABSENT|F-PIVOT-MISS', 'F-REPORT']
