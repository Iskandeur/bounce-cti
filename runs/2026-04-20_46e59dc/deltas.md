# Deltas vs prior run (2026-04-19_20ba0ef)

## Per-case overall deltas

| Case | Prior overall | This run overall | Δ | Status delta |
|-----:|---------:|---------:|---:|:-------------|
| 1  | 50.2 | 51.1 | **+0.9**  | NR slightly higher; F-CLUSTER-OVER hallucination GONE (was the critical finding) |
| 2  | 54.7 | 47.9 | −6.8 | Lost RQ; agent terminated phase_main with only 2 CTI calls (rate-limit pressure?) |
| 3  | 57.8 | 54.3 | −3.5 | RQ dropped from 70→40; node recall lower |
| 4  | 38.9 | 70.0 | **+31.1** | Edges + RQ both passed; first crossing of 70 threshold |
| 5  | 38.3 | 60.0 | +21.7 | ER 100; ASN nodes still missing |
| 6  | 42.2 | 67.5 | +25.3 | Cert SHA1 still missed; lummac2 + .pw siblings still missed |
| 7  | 38.0 | 48.1 | +10.1 | Pivot coverage up to 80%; node recall still low because GT lists very specific stage-2 hosts |
| 8  | 45.4 | 54.2 | +8.8  | apex/subdomain split still not done (`bzctoons.net` not surfaced) |
| 9  | 42.3 | 70.5 | **+28.2** | Tycoon 2FA case crossed threshold |
| 10 | 44.6 | 37.9 | −6.7 | DNS-TXT/MX cross-ref + Wayback never done — these are unique to Case 10 and have no fallback |
| 11 | 44.0 | 60.8 | +16.8 | Smishing Triad case improved despite different seed |
| 12 | 48.3 | 72.5 | **+24.2** | Cert-CN→Shodan still missed but ClearFake markers found |
| **mean** | **45.4** | **57.9** | **+12.5** | |

## Aggregate metrics

| Metric | Prior | Now | Δ |
|--------|------:|----:|--:|
| Overall mean | 45.4 | 57.9 | **+12.5** |
| Pass rate (≥70) | 0 % | 25 % | **+25 pp** |
| Hallucination rate | 1/12 (8.3 %) | 0/12 | **−1 case** |
| Defuse floor | 100 | 100 | 0 |
| Mean CTI calls/case | 7.6 | 7.0 | −0.6 |

## Hallucination hand-audit (this run)

I re-checked the same hot spots as last time (Cases 1, 5, 12) plus the cases with the largest graphs (7 and 8) since they had the greatest hallucination surface area:

- **Case 1** (`materialplies.com`, Salt Typhoon): Graph has 9 nodes — 1 actor (Salt Typhoon), 3 malware (DEMODEX, SNAPPYBEE, GHOSTSPIDER), 3 historical IPs (15.197.240.20, 160.16.200.77, 193.239.84.207), seed, report. The historical IPs are **not** clustered with sibling domains (prior run wrongly tagged unrelated co-residents on 193.239.84.207 as `phishing_lookalike`). Report attribution lists exactly the actors evidenced by the OTX pulses. ✅ **R12 + R13 prevented the prior failure.**
- **Case 5** (`195.177.95.163`, Eye Pyramid): Found `AS214961` (real — Onyphe `asn` field on the seed IP) and Lumma/Rhadamanthys malware tags from OTX/threatfox. Did not surface the canonical Eye Pyramid ASNs (AS214943/AS215540/AS215439). Not hallucinated, just incomplete.
- **Case 7** (`blackshelter.org`, SocGholish): Largest graph (30 nodes, 38 edges). Spot checks of `rednosehorse.com`, `blacksaltys.com`, `packedbrick.com` — they appeared in the graph as legitimate sibling SocGholish IOCs sourced from OTX/threatfox; not invented. ✅ Clean.
- **Case 8** (`aad0a60c…` Amadey hash): Largest hash graph (31 nodes, 41 edges). The IP `62.60.226.159` and `bzctoons.net`/`gitlab.bzctoons.net` were not surfaced — but the cluster of co-pivoted hashes and contacted IPs all have direct VT-communicating-files evidence in the event log. ✅ Clean.
- **Case 12** (`921hapudyqwdvy.com`, ClearFake): Same as last run — Cloudflare IPs correctly tagged `cdn`, Hetzner ASN legitimate, OTX `clearfake` report sourced. ✅ Clean.

**Verdict: no fabricated attributions in this run. R12 + R13 are working.** Heuristic check (suspect actor/malware nodes whose value never appears in event corpus) reports 0/12.

## What changed since the last run (commits between 20ba0ef and 46e59dc)

```
46e59dc … <this run's HEAD>
…
20ba0ef = prior run baseline
```

Top changes that drove the +12.5 mean:

1. **R12 NO CO-TENANCY CLUSTERING ON SHARED HOSTING** (`backend/agent_runner.py`)
   – stopped Case 1's APT34 misattribution. Cleared the hard hallucination gate.
2. **R13 NO CROSS-CAMPAIGN ATTRIBUTION MERGE** — backstop for R12; ensures stray OTX pulses about other actors don't relabel the seed.
3. **R14 CLOUDFLARE-FRONTED ORIGIN-UNMASK MANDATORY** — Case 12 now correctly graphs the seed cert/historical-A pair and mentions ClearFake; though it still doesn't fire the `ssl.cert.subject.CN:` Shodan query, the awareness is there in the report.
4. **Phase-3 report_write fallback** — every case now has an `investigation_summary` report node, so RQ is non-zero on more cases (vs. prior run where 6 cases had RQ=0 outright).

## Why we still don't pass

`F-EARLY-TERMINATION` and `F-PIVOT-MISS` (second-tier pivots like JARM-search, content-fingerprint, reverse-DNS, ct-burst, urlscan-clickfix) drive ~70% of the remaining gap. The agent calls the mandatory toolset and writes the report; it doesn't synthesize the next-hop pivot from what those mandatory tools returned. Proposed fixes target this in `proposed_fixes.md`.
