# Proposed fixes — 2026-04-20 · commit 46e59dc

Failures are listed in protocol §6 priority order. Each entry includes the rationale (linked to specific cases), the concrete code edit, and the expected uplift.

## P0 — F-HALLUCINATION

**Status: NO CHANGE NEEDED.** R12 (no co-tenancy clustering) and R13 (no cross-campaign attribution merge) added in the prior run held perfectly: 0/12 cases hallucinated this run vs. 1/12 prior. The hard gate is now cleared.

If we wanted to harden further: add an automated check at report-write time that scans report metadata for actor/malware names and verifies each one appears in the event corpus. Defer until we see another regression — the current evidence-based ruleset is working.

---

## P1 — F-EARLY-TERMINATION + F-PIVOT-MISS::rdap_seed (4 cases)

**Diagnosis.** `_missing_mandatory_tools` lists `crtsh_subdomains` for domains and `urlscan_search`/`shodan_host` for IPs but does **not** include `rdap_domain` / `rdap_ip` (the registrant + ASN extractor). RDAP is the cheapest first-hop pivot and is in STEP 1 of the workflow but never enforced by the followup loop. Cases 1, 4, 5, 6 missed it (33% of the run).

**Fix.** Add RDAP to the mandatory-tools list in `backend/agent_runner.py` (function `_missing_mandatory_tools`):

```python
# domain
mandatory = [
    ("rdap_domain",                    f'rdap_domain("{seed_value}")'),  # NEW
    ("virustotal_communicating_files", f'virustotal_communicating_files("domain", "{seed_value}")'),
    ("threatfox_search",               f'threatfox_search("{seed_value}")'),
    ("virustotal_resolutions_domain",  f'virustotal_resolutions_domain("{seed_value}")'),
    ("otx_domain",                     f'otx_domain("{seed_value}")'),
    ("crtsh_subdomains",               f'crtsh_subdomains("{seed_value}")'),
    ("onyphe_domain",                  f'onyphe_domain("{seed_value}")'),
]
# ip
mandatory = [
    ("rdap_ip",                        f'rdap_ip("{seed_value}")'),  # NEW
    ("reverse_dns",                    f'reverse_dns("{seed_value}")'),  # NEW (P2 below)
    ...
]
```

**Expected uplift.** PC for cases 1/4/5/6 each gains 1/N pivot, so PC moves from 25→50 (case 1), 60→80 (case 4), 50→75 (case 5), 25→50 (case 6) and case 1 NR may improve (RDAP returns the registrant email which is the discriminating marker). Mean overall: roughly +3 to +5 points. **Cost: trivial (4 added lines).**

---

## P2 — F-PIVOT-MISS::reverse_dns_seed + DNS-TXT/MX (Case 10)

**Diagnosis.** Case 10 (`37.211.126.117`, Famous Chollima/Contagious Interview) has the lowest overall (37.9). The reverse-DNS of the seed IP returns `lianxinxiao.com` which is the gateway to the entire BlockNovas cluster. Without `reverse_dns(seed)` the agent has no way to discover any of the GT domains. `dns_resolve` for TXT/MX would surface the front-company SMTP infrastructure.

**Fix.** Same edit as P1 — add `reverse_dns` to IP-mandatory list. Also add a followup hint: when `reverse_dns` returns at least one domain, the followup MUST `dns_resolve(<that_domain>, "MX")` and `dns_resolve(<that_domain>, "TXT")`.

```python
# ip
mandatory = [
    ("rdap_ip",     f'rdap_ip("{seed_value}")'),
    ("reverse_dns", f'reverse_dns("{seed_value}")'),
    ...
]
```

In the followup `extra_steps` for IP seeds, append:

```python
extra_steps.append(
    "If reverse_dns returned ≥ 1 domain, for each returned domain call "
    "dns_resolve(<domain>, 'MX') AND dns_resolve(<domain>, 'TXT'). "
    "TXT records often expose unique SPF/Google-site-verification IDs that "
    "let you cross-reference siblings via threatfox_search('<txt_value>'). "
    "MX records reveal mail providers shared across an actor's front companies."
)
```

**Expected uplift.** Case 10 NR jumps from 7.7→~30, PC from 20→60. Adds ~3 points to the mean.

---

## P3 — F-PIVOT-MISS::shodan_cert_cn (Case 12, R14 enforcement)

**Diagnosis.** R14 in the system prompt mandates the `shodan_search('ssl.cert.subject.CN:"<seed_fqdn>"')` query when the seed resolves to Cloudflare. Case 12 returned only Cloudflare IPs, the agent correctly tagged them `cdn`, called `crtsh_subdomains`, and stopped. The R14 query was never fired. The rule is read, the action isn't taken.

**Fix.** Mechanical enforcement in the followup phase. After `phase_main_exit`, if seed_type == "domain" AND every IP node tagged `cdn` AND no shodan_search call referenced "ssl.cert.subject.CN:", inject a phase 2.5 prompt that explicitly demands the unmask query.

```python
# In agent_runner.run_investigation, before the phase2_done check:
if seed_type == "domain":
    g_now = gs.get_graph(inv_id)
    ip_nodes = [n for n in g_now.get("nodes", []) if (n.get("type") or "").lower() == "ip"]
    all_cdn = ip_nodes and all("cdn" in (n.get("tags") or []) for n in ip_nodes)
    called_now = _get_called_cti_tools(inv_id)
    # Look for any shodan call with the unmask filter
    needs_unmask = all_cdn and not _shodan_called_with(inv_id, "ssl.cert.subject.CN:")
    if needs_unmask:
        unmask_prompt = (
            f"All IPs for {seed_value} are Cloudflare CDN endpoints. R14 "
            f"requires you to attempt the origin-unmask via cert CN:\n"
            f"  1. shodan_search('ssl.cert.subject.CN:\"{seed_value}\"')\n"
            f"  2. onyphe_datascan('tls.cert.subject.commonname:\"{seed_value}\"')\n"
            f"For each non-CDN IP returned, add_node(ip, ...) with source=shodan "
            f"and add_edge(seed→ip, candidate_origin)."
        )
        await _run_claude_phase(inv_id, unmask_prompt, _FOLLOWUP_SYSTEM_PROMPT,
                                model, env, mcp_cfg_path, phase="origin_unmask",
                                max_turns=8)
```

(`_shodan_called_with` is a small helper that scans `events.jsonl` for `mcp__cti__shodan_search` calls whose `input` contains the filter string.)

**Expected uplift.** Case 12 PC jumps from 25→50, and may surface real origin IPs which feed NR. Roughly +2 points to the mean. Also catches Case 11 (Smishing Triad — same Cloudflare-front pattern).

---

## P4 — F-REPORT (11 cases)

**Diagnosis.** RQ < 70 in 11/12 cases. The dominant gap is `marker_hit=False`: the report node's metadata doesn't contain the discriminating marker string verbatim (cert SHA1, JARM, registrant email, exact page title). The phase3_report_write prompt asks for them but the model paraphrases.

**Fix.** Make the marker requirement *mechanical*. Phase 3 already calls `get_graph()`. Extract every discriminating-shaped value from node metadata (cert serials, JARM hashes, favicon hashes, registrant emails) and inject them as a literal "MUST INCLUDE" list in the prompt:

```python
# Inside the phase3 block, before the report_prompt is built:
def _extract_marker_candidates(g) -> list[str]:
    out = []
    for n in g.get("nodes", []):
        md = n.get("metadata") or {}
        for k in ("cert_serial", "cert_sha1", "jarm", "favicon_hash",
                  "registrant_email", "http_title", "subject_cn"):
            v = md.get(k)
            if v and isinstance(v, str) and len(v) > 4:
                out.append(f"{k}={v}")
        # Also surface any tag that looks like a hash
        for t in (n.get("tags") or []):
            if isinstance(t, str) and re.match(r"^[a-f0-9]{32,}$", t):
                out.append(t)
    return out[:10]  # cap

g_now = gs.get_graph(inv_id)
markers = _extract_marker_candidates(g_now)
markers_block = (
    "\n  MARKERS YOU MUST INCLUDE VERBATIM in metadata.discriminating_markers:\n"
    + "\n".join(f"    - {m}" for m in markers)
    + "\n  Copy these EXACT strings — do NOT paraphrase or truncate.\n"
) if markers else ""
report_prompt = ... + markers_block + ...
```

**Expected uplift.** RQ moves from 0/40 to 70+ in 5–6 cases. Mean overall: +4 to +6 points.

---

## P5 — Optional / lower priority

- **F-PIVOT-MISS::content_fingerprint (Case 6) + ::ct_burst_window (Case 9)**: These need URLScan content-fingerprint queries and crt.sh issuance-date filters that aren't currently in any mandatory list. Would need new pivot-rules in the prompt's STEP 3/STEP 4 plus a tool wrapper that supports `min_entry_timestamp` / `max_entry_timestamp` on crt.sh. Defer until P1–P4 are landed and re-measured.
- **Reverse-WHOIS source (Case 1)**: Still no `reverse_whois_email` MCP tool. Would require adding a source. Two viable APIs: WhoisXMLAPI (paid, $99/mo) and DomainTools (paid). Without one, Case 1's NR ceiling is ~50.

---

## What this run will land

P1, P2, P4 are mechanical edits to `backend/agent_runner.py` only — no schema changes, no new dependencies, no frontend touch. Landing them in this commit. P3 needs a new helper and a new phase, leaving for a follow-up.

Expected improvement after landing P1+P2+P4: mean overall **62–66**, pass rate **40–55 %**.
