# EVAL_PROTOCOL Scorecard — 2026-10-21 · commit 46dc9b0

**Run environment**
- Deployed `main` on the production VPS (HEAD `46dc9b0` at run start), production CLI 2.1.149.
- Model: `opus-5` (`claude-opus-5`, read from the `system/init` event of every phase; first run on the Claude 5 family)
- Mode: **nightly fresh subset** — cases 2, 3, 8, 9, 12 + negatives N1-N3, sequential one-by-one, each investigation created with `capture: true` from an admin session, default effort, default pivot drain.
- Run by Lupi (roadmap J4) next to the bare-model baseline of the same night, same model id: [`eval/baseline/2026-10-21/`](../../eval/baseline/2026-10-21/results.md).
- Note: an investigation of case 2 created on 2026-10-20 with `opus` ran on `claude-opus-4-7` (the production CLI's alias), so it is not part of this run.

## Capability scorecard (v3 — headline, decay-proof)

| Case | live | CAP | ΔCAP | PS | EFF | RST | HYP | REC | NR | MK |
|-----:|:----:|----:|-----:|---:|----:|----:|----:|----:|---:|---:|
| 2 | live | 90.0 | -10.0 | 100 | 60 | 100 | 100 | 65.2 | 64 | 100 |
| 3 | live | 100.0 | +0.0 | 100 | 100 | 100 | 100 | 66.7 | 47 | 100 |
| 8 | live | 89.6 | -10.4 | 100 | 58 | 100 | 100 | 58.3 | 50 | 100 |
| 9 | live | 89.9 | -0.1 | 100 | 60 | 100 | 100 | 83.3 | 67 | 100 |
| 12 | DECAY | 90.0 | +0.0 | 75 | 100 | 100 | 100 | n/a | 50 | 100 |
| N1 | – | 100 | – | – | – | 100 | – | – | – | – |
| N2 | – | 0 | – | – | – | 0 | – | – | – | – |
| N3 | – | 100 | – | – | – | 100 | – | – | – | – |

| Metric | Target | This run | Prior (2026-06-17 `71e5fb1`) |
|---|---|---|---|
| **CAP mean** (headline) | ≥75 → 85 | **91.9** (n=5) | 96.0 |
| Hallucination (mechanical check) | 0 hard gate | 0 ✅ | 0 |
| Restraint (negatives) | ≥ 80 | 100, 0, 100 | 100, 100, 100 |

## Scorecard (v2 legacy track — context only)

| Case | Status | NR   | ER   | PC   | DC  | BD  | RQ  | Overall | Calls | Hypothesis path |
|-----:|:------:|-----:|-----:|-----:|----:|----:|----:|--------:|------:|:----------------|
| 2 | done | 63.6 | 33.3 | 100.0 | 100 | 75 | 70 | 73.7 | 71 | Y (apt_targeted) |
| 3 | done | 47.1 | 66.7 | 100.0 | 100 | 100 | 70 | 80.6 | 55 | Y (commodity_malware) |
| 8 | done | 50.0 | 33.3 | 100.0 | 100 | 75 | 70 | 71.4 | 63 | Y (commodity_malware) |
| 9 | done | 66.7 | 100.0 | 100.0 | 100 | 75 | 70 | 85.3 | 62 | Y (phishing_kit_cluster) |
| 12 | done | 50.0 | 0.0 | 75.0 | 100 | 100 | 70 | 65.8 | 51 | Y (traffer_or_tds) |

## Per-case detail

- **C2** (`b898323343ea`): 70 nodes, 95 edges, 71 CTI calls; NR missing: domain:uploadfiler, ip:172.86.126.208, ip:116.203.208.186, malware:chaos; pivots missed: none.
- **C3** (`fb9a9fa590f0`): 53 nodes, 67 edges, 55 CTI calls; NR missing: domain:opmanager, domain:ev2sirbd269o5j, domain:angryipscanner, domain:axiscamerastation, domain:ip-scanner, ip:188.40.187.145, ip:172.96.137.160, ip:193.242.184.150, ip:185.174.100.203; pivots missed: none.
- **C8** (`e1e251399fb3`): 65 nodes, 69 edges, 63 CTI calls; NR missing: ip:185.215.113, asn:as51381, domain:gitlab.bzctoons.net, domain:bzctoons.net; pivots missed: none.
- **C9** (`099e7d56c7d0`): 41 nodes, 79 edges, 62 CTI calls; NR missing: kit_fingerprint:turnstile, actor:storm-1747; pivots missed: none.
- **C12** (`da273c8f45f0`): 36 nodes, 58 edges, 51 CTI calls; NR missing: cert_cn:921hapudyqwdvy.com, ip:*yacolo, asn:as203493, tool:keitaro; pivots missed: shodan_cert_cn_search.
- **N01** Cloudflare anycast (benign): 35 nodes, attribution none, 0 benign infrastructure node(s) tagged malicious.
- **N02** jsDelivr CDN (benign): 66 nodes, attribution ['ClearFake', 'ClickFix', 'ACRStealer'], 8 benign infrastructure node(s) tagged malicious.
- **N03** Wikipedia (benign): 57 nodes, attribution none, 0 benign infrastructure node(s) tagged malicious.

## Transcript integrity

`eval/stream_audit.py --since 2026-10-21T02:19Z` on the production database: 55 phases, none exited `rc=0` without its result event, 48 logged lines of 64 KiB or more kept whole, no loss event of the fixed reader. Exit code 0. CTI-call counts of this run are therefore not lower bounds.

## Restraint, read honestly

N2 (jsDelivr) fails: 8 benign infrastructure nodes are tagged malicious and ClearFake, ClickFix and ACRStealer are attributed. The bare model with web search fails the same case (RST 0); the memory-only arm does not.

## Attempts

Case 9 was run twice: the first investigation ended `error: interrupted` (service restart, not scored); the second is the one reported.
