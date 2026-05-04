# EVAL_PROTOCOL Scorecard — 2026-05-04 · commit 76fbe4c (feat/hypothesis-first)

**Run environment**
- Branch: `feat/hypothesis-first` (1 commit on top of merged `feat/autonomy-engine`)
- Target: localhost (production VPS pre-merge)
- Model: `opus-4.7`
- Mode: targeted re-run on Case 1 (APT category — primary RE-EVALUATE test)
  and Case 7 (TDS retry — primary vt_pdns hint test)
- Validation purpose: confirm hypothesis-first loop + 2 new hints actually
  work end-to-end before considering a second merge to main.

## Scorecard

| Case | Status | NR | ER | PC | DC | BD | RQ | Overall | Calls | Hypothesis path |
|-----:|:------:|---:|---:|---:|---:|---:|---:|--------:|------:|:----------------|
| 1  | done | **46.2** | 50.0 | **80.0** | 100 | 100 | 70 | **74.4** | 40 | commodity_malware → **apt_targeted** (high) ✓ |
| 7  | done | **41.7** | 50.0 |  33.3 | 100 |  50 | 70 |   57.5  | 68 | unclear → commodity_malware → **traffer_or_tds** (high) ✓ |

## Aggregate vs prior runs

| Metric                | Case 1 v5 | Case 1 prior (Apr) | Δ      | Case 7 v5 | Case 7 v4 | Case 7 prior |
|-----------------------|----------:|-------------------:|-------:|----------:|----------:|-------------:|
| Overall               | **74.4**  |              51.1 | **+23.3** |    57.5   |    57.5   |        48.1   |
| NR                    |  46.2     |              41.7 |  +4.5  | **41.7**  |    25.0   |         8.3   |
| PC                    |  **80.0** |              25.0 | +55.0  |    33.3   |    50.0   |        80.0   |
| RQ                    |   70      |              40   | +30    |    70     |    70     |         0     |
| Calls                 |   40      |               9   | +31    |    68     |    74     |         9     |

**Key wins**:
- **Case 1 crosses 70 threshold for the FIRST time ever** (51.1 → 74.4, +23.3).
- Case 1 PC jumped 25 → 80: agent now calls whoxy_reverse, certspotter, etc. driven by the apt_targeted hypothesis.
- Case 7 NR jumped 25 → 41.7: vt_pdns hint worked — agent graphed `rednosehorse.com` and `blacksaltys.com` (TDS siblings).

## RE-EVALUATE behavioural verification

Both runs executed the hypothesis_history loop correctly — this is the
NEW behaviour the refactor was designed to produce.

### Case 1 — Salt Typhoon
```
hypothesis_history:
  1. category=commodity_malware  conf=medium
     reason=first-call observations: VT 16/91 malicious + multi-vendor
            malware/phishing categories + TLS cert "sinkhole"
  2. category=apt_targeted       conf=high
     reason=OTX returned 20 pulses naming materialplies.com explicitly,
            all attributed to Salt Typhoon

final_category: "apt_targeted (sinkholed) — Salt Typhoon / UNC4841 /
                Earth Estries (China MSS, telecom espionage)"
```

The agent started with a defensible commodity_malware guess (TLS literally
said "sinkhole" — a real signal), then RE-EVALUATEd to apt_targeted when
OTX returned actor attribution. Exactly the analyst behaviour the refactor
targets.

### Case 7 — SocGholish
```
hypothesis_history:
  1. category=unclear            conf=low
     reason=recently re-registered 2026-02-14, Dynadot+AWS Route53,
            insufficient context
  2. category=commodity_malware  conf=high
     reason=VT 17/91 malicious + 23,176 communicating files all named
            payload_1.hta + 50 OTX pulses
  3. category=traffer_or_tds     conf=high
     reason=VT crowdsourced IDS surfaced Proofpoint ET sid:2058047
            explicitly naming 'blackshelter.org' as Malicious TA2726
            TDS Domain

final_category: "traffer_or_tds"
```

Three-stage hypothesis evolution: started honest (`unclear`), narrowed via
VT detections (`commodity_malware`), then refined to the correct category
(`traffer_or_tds`) when Proofpoint ET signature provided ground-truth label.
This is exactly the iterative reasoning we wanted.

### Phase 3 + new hints — observed effect

Case 1 used: abuseipdb_check×2, criminalip_ip×2, certspotter_serial×1,
certspotter_issuances×1, netlas_jarm×1, zoomeye_jarm×1.

Case 7 used: abuseipdb_check×9, criminalip_ip×9, certspotter_serial×1,
certspotter_issuances×1, netlas_jarm×1, zoomeye_jarm×1.

The new vt_pdns hint surfaced co-resolvers in Case 7: agent graphed
`rednosehorse.blackshelter.org`, `emv1.blackshelter.org`, `directory.blackshelter.org`
+ found `blacksaltys.com` and `rednosehorse.com` as separate domain nodes
(present in discriminating_markers).

The new vt_file contacted_ip hint was not directly observable on these 2
cases (they're domain seeds, not hash) — needs Case 2/3/8 to validate.

## Failure modes still standing

| Code | Cases | Description | Notes |
|------|-------|-------------|-------|
| F-PIVOT-MISS::reverse_whois_email | 1 | Whoxy never called on `pwp-...@privacyguardian.org` (correctly filtered by hint) but ALSO not called on the actual ProtonMail registrant — likely RDAP returned only the privacy proxy address | Hint filter is correct; agent needs to extract the upstream cleartext email if RDAP exposes it (via different vCard entry or domain-history source) |
| F-NODE-RECALL::sibling_domain_enum | 1 | 0/5 Alpha+Beta sibling domains found despite apt_targeted hypothesis; whoxy alone wouldn't catch them either (registrant emails are the keys) | Need a "sibling enumeration via NS/cert SAN" pivot when registrant is privacy-protected |
| F-PIVOT-MISS::vt_resolutions_ip_followthrough | 7 | vt_resolutions_ip surfaced `rednosehorse.com` + `blacksaltys.com` (graphed!) but `packedbrick.com` and `newgoodfoodmarket.com` from same /24 missed | hint cap of "top 5 examples" may be the bottleneck; consider capping at 8 |
| F-BUDGET::no_extension_log | 7 | 68 calls without budget_extension event | R4 wording may need tightening; or runner-side enforcement |

## Verdict

**The hypothesis-first refactor delivers measurable behavioural change**:
- Case 1 +23.3 overall (first time crossing 70).
- Case 7 NR doubled (8.3 → 25 → 41.7) across two iterations.
- Both cases produce explicit hypothesis_history audit trails.
- RE-EVALUATE state actually fires (3 transitions on Case 7).

**Recommended next move**: USER REVIEW THE BRANCH, then merge to main.

Outstanding: the 5 sibling domains in Case 1 still missed (registrant
behind privacy proxy). That's a separate pivot gap (F-NODE-RECALL), not a
hypothesis-first regression. To be addressed in a follow-up that adds a
"sibling enumeration via NS-set or cert SAN" playbook for the apt_targeted
category when the registrant is privacy-masked.
