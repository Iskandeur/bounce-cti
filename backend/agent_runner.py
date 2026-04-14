"""Spawn Claude Code in headless mode to run an investigation."""
import asyncio
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path
from .config import CLAUDE_BIN
from . import graph_store as gs


def _log(inv_id: str, kind: str, msg):
    with gs.conn() as c:
        c.execute("INSERT INTO events(investigation_id, kind, payload, created_at) VALUES (?,?,?,?)",
                  (inv_id, kind, json.dumps({"kind": kind, "msg": msg}), time.time()))

ROOT = Path(__file__).resolve().parent.parent


def _get_called_cti_tools(inv_id: str) -> set:
    """Extract the set of CTI tool base names actually invoked during an investigation.

    Only counts tool_use blocks in assistant messages — ignores tool names that
    merely appear in the init event's available-tools list.
    """
    with gs.conn() as c:
        rows = c.execute(
            "SELECT payload FROM events WHERE investigation_id=?",
            (inv_id,)
        ).fetchall()
    tools = set()
    for (payload,) in rows:
        try:
            d = json.loads(payload)
        except (json.JSONDecodeError, TypeError):
            continue
        if d.get("kind") != "agent_assistant":
            continue
        for block in d.get("msg", {}).get("message", {}).get("content", []):
            if block.get("type") == "tool_use":
                name = block.get("name", "")
                if name.startswith("mcp__cti__"):
                    tools.add(name[len("mcp__cti__"):])
    return tools


def _is_parked(inv_id: str) -> bool:
    """Check if the investigation identified the seed as parked."""
    try:
        g = gs.get_graph(inv_id)
        for n in g.get("nodes", []):
            if "parking" in (n.get("tags") or []):
                return True
    except Exception:
        pass
    return False


def _missing_mandatory_tools(seed_type: str, seed_value: str, called: set) -> list:
    """Return list of call examples for mandatory tools not yet called."""
    missing = []
    if seed_type == "ip":
        mandatory = [
            ("virustotal_communicating_files", f'virustotal_communicating_files("ip", "{seed_value}")'),
            ("threatfox_search", f'threatfox_search("{seed_value}")'),
            ("virustotal_resolutions_ip", f'virustotal_resolutions_ip("{seed_value}")'),
            ("shodan_host", f'shodan_host("{seed_value}")'),
            ("onyphe_ip", f'onyphe_ip("{seed_value}")'),
            ("urlscan_search", f'urlscan_search("ip:{seed_value}")'),
            ("otx_ip", f'otx_ip("{seed_value}")'),
        ]
    elif seed_type == "domain":
        mandatory = [
            ("virustotal_communicating_files", f'virustotal_communicating_files("domain", "{seed_value}")'),
            ("threatfox_search", f'threatfox_search("{seed_value}")'),
            ("virustotal_resolutions_domain", f'virustotal_resolutions_domain("{seed_value}")'),
            ("otx_domain", f'otx_domain("{seed_value}")'),
            ("crtsh_subdomains", f'crtsh_subdomains("{seed_value}")'),
        ]
    else:  # hash
        mandatory = [
            ("virustotal_file", f'virustotal_file("{seed_value}")'),
            ("malwarebazaar_hash", f'malwarebazaar_hash("{seed_value}")'),
            ("threatfox_search", f'threatfox_search("{seed_value}")'),
            ("otx_file", f'otx_file("{seed_value}")'),
        ]
    for tool_name, call_example in mandatory:
        if tool_name not in called:
            missing.append(call_example)
    return missing


def _win_to_wsl(path: str) -> str:
    """C:\\Users\\foo → /mnt/c/Users/foo (no-op if already unix)."""
    s = str(path).replace("\\", "/")
    if len(s) >= 2 and s[1] == ":":
        return "/mnt/" + s[0].lower() + s[2:]
    return s


def _mcp_python() -> str:
    """Return the Python executable in a form that WSL claude can invoke.

    - On Windows (os.name=='nt'): convert to /mnt/c/... so WSL runs it via interop.
    - On WSL/Linux: use sys.executable directly.
    """
    exe = sys.executable
    if os.name == "nt":
        return _win_to_wsl(exe)
    return exe


def _mcp_launcher() -> str:
    """Absolute path to run_mcp.py.

    When on Windows: return the Windows path (C:\\...) because WSL interop
    executes python.exe with the Windows path as-is. The WSL→Win path test
    confirmed that Windows Python can open C:/... paths passed from WSL.
    When on Linux/WSL: return the unix path.
    """
    p = ROOT / "run_mcp.py"
    # Use forward slashes for the Windows path — python.exe accepts them
    return str(p).replace("\\", "/")


def _write_mcp_config(inv_id: str) -> Path:
    """Write a per-investigation mcp.json with correct paths for WSL claude.

    Uses run_mcp.py (a standalone launcher) so we don't need env-var PYTHONPATH tricks.
    The Python exe is converted to a WSL-accessible path when running on Windows.
    """
    python = _mcp_python()
    launcher = _mcp_launcher()

    # Pass minimal env: only what the MCP server actually needs.
    # run_mcp.py hard-codes the PYTHONPATH via os.path so no conversion needed.
    base_env = {
        k: v for k, v in os.environ.items()
        if k in ("HOME", "PATH", "TEMP", "TMP", "USERPROFILE", "APPDATA",
                 "LOCALAPPDATA", "SYSTEMROOT", "WINDIR", "COMSPEC",
                 "VIRTUAL_ENV", "CONDA_PREFIX", "CONDA_DEFAULT_ENV",
                 # API keys
                 "VIRUSTOTAL_API_KEY", "URLSCAN_API_KEY", "ONYPHE_API_KEY",
                 "SHODAN_API_KEY", "OTX_API_KEY")
    }
    # Load .env file values explicitly so they are available to MCP servers
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                if k.strip() and k.strip() not in base_env:
                    base_env[k.strip()] = v.strip()

    cfg = {
        "mcpServers": {
            "graph": {
                "command": python,
                "args": [launcher, "graph_mcp"],
                "env": {**base_env, "BOUNCE_INV_ID": inv_id},
            },
            "cti": {
                "command": python,
                "args": [launcher, "cti_mcp"],
                "env": base_env,
            },
        }
    }
    p = ROOT / "data" / f"mcp-{inv_id}.json"
    p.write_text(json.dumps(cfg, indent=2))
    return p

SYSTEM_PROMPT = """You are Bounce-CTI, an autonomous CTI investigation agent.
Your ONLY job is to call MCP tools to build an investigation graph. You have no filesystem access.

══════════════════════════════════════════════
ABSOLUTE RULES — never break these
══════════════════════════════════════════════
R1. EVERY piece of information you find MUST become a node and/or edge via add_node/add_edge.
    Never keep findings in your text. If you found it, graph it.
R2. ALWAYS call defuse(kind, value) before pivoting on any IP or NS.
    If should_stop_pivot=true → tag the node with the returned tags, add a note in metadata, then STOP pivoting on it. Still graph the node itself.
R3. Only use MCP tools (mcp__graph__* and mcp__cti__*). Do not attempt to read files, run commands, or search the web.
R4. Budget: max 80 tool calls total. If you hit the limit, stop and write the report node.
R5. ALWAYS set source= to the API name that produced the data (e.g. "virustotal", "crtsh", "rdap", "dns").
R6. ALWAYS add edges between nodes. A node with no edges is useless to the analyst.
R7. Steps marked MANDATORY must be executed. Do NOT skip threat intel (STEP 6), malware hash lookups (communicating_files), or the report node (STEP 8).
R8. JARM pivot rule: if you extract a JARM fingerprint from ANY source (VT, Onyphe, Shodan), you MUST call shodan_search("ssl.jarm:<jarm>") to find related infrastructure. This is one of the highest-value pivots.
R9. MANDATORY: virustotal_communicating_files MUST be called for EVERY investigation (domain or IP seed). This is the primary way to discover malware samples communicating with the indicator. Skipping it produces an incomplete investigation. Call it in STEP 3 a3 (domain) or STEP 4 a (IP).
R10. Execute ALL workflow steps in order. Do not stop early because the graph "looks complete". The investigation is only complete when the report node (STEP 8/7) is written.
R11. EVIDENCE-BASED CONCLUSIONS ONLY. The `threat_assessment` field MUST default to "benign".
    You may only assign "suspicious" / "likely_malicious" / "malicious" if at least ONE of these
    concrete, direct-evidence conditions is met, AND you cite the exact source+value in key_findings:
      • virustotal_*.last_analysis_stats.malicious > 0 (any flag count ≥ 1)
      • threatfox_search returned a record matching the seed or its infrastructure
      • otx_* returned a pulse directly referencing the seed or its infrastructure
      • urlhaus_host / urlhaus matched the seed
      • virustotal_communicating_files returned one or more samples with detection_ratio > 0
      • malwarebazaar_hash / _signature confirmed the seed as a known malicious sample
      • A directly-linked cert / JARM / favicon hit a node ALREADY tagged malicious by one of the above
    You are FORBIDDEN from assigning any non-benign label based on:
      ✗ the linguistic meaning or translation of a domain name
      ✗ the domain's age alone (recent registration ≠ malicious)
      ✗ the hosting provider or ASN (Hetzner/OVH/DigitalOcean/VPS ≠ malicious)
      ✗ the absence of threat-intel hits interpreted as "pre-operational / staging / early phase"
      ✗ pattern matching to a fraud genre ("looks like a lottery/crypto/pharma scam")
      ✗ generic TLD heuristics (.xyz/.top/.tk alone ≠ malicious)
    If NO direct-evidence condition is met, `threat_assessment` MUST be "benign".
    You may still note observations (recent registration, small VPS, etc.) as neutral facts in
    key_findings with sources, but they must NOT change threat_assessment on their own.

══════════════════════════════════════════════
PASSIVE FINGERPRINTING — ALWAYS SAFE, ALWAYS USEFUL
══════════════════════════════════════════════
shodan_host, onyphe_ip, onyphe_domain and virustotal_* are PASSIVE lookups: they query
pre-existing scanner databases/indexes. They do NOT touch the target server. Use them
freely on every investigation, including benign-looking seeds — they give you the concrete
technology fingerprint (open ports, HTTP banner, HTTP title, server header, TLS cert,
JARM, favicon hash, product/version) that lets you answer "what is actually running there?"
without any active probe.

For any IP node you encounter (seed or pivoted), you SHOULD capture into ip metadata:
  open_ports, http_title, http_server, http_banner (truncated), technologies[], jarm,
  favicon_hash (when present), asn, org, country
These fields are high-signal and cheap — do not skip them out of caution. The legal
constraint "no direct interaction with the target" does NOT apply here; the interaction
already happened long ago on behalf of a third-party scanner, and we are only reading
the recorded result.

══════════════════════════════════════════════
GRAPH SCHEMA — node types and edge relations
══════════════════════════════════════════════
Node types: domain, ip, ns, registrar, cert, asn, email, url, hash, jarm, favicon, country, report
Tags to use: seed, suspicious, benign, cdn, parking, sinkhole, dyndns, shared_hosting, c2, phishing, expired

COUNTRY NODE — USE SPARINGLY AND ONLY WHEN THE LINK IS UNAMBIGUOUS
A `country` node represents a jurisdiction/geolocation and MUST be created only when
the country is an authoritative attribute of the source record, not an inferred one.
  ✓ DO create+link a country node when you have a direct, authoritative source:
      • rdap_ip / virustotal_ip / shodan_host / onyphe_ip returns a `country` /
        `country_code` / `country_name` field for an IP or ASN — the ASN/IP is
        registered in that country.
      • rdap_domain returns a registrant `country` field — the registrant is in
        that country (link registrar OR registrant-email node, NOT the domain).
      • Any source returning an ISO-3166 alpha-2 code explicitly for the entity.
  ✗ DO NOT infer a country from:
      ✗ the TLD of a domain (.fr ≠ French operator; .io ≠ UK; ccTLDs are resold)
      ✗ the language of the page or domain name (French text ≠ French operator)
      ✗ the timezone of content or certificate NotBefore dates
      ✗ GeoIP of a CDN/anycast IP (the IP sits in many POPs)
      ✗ any chain of ≥ 2 inferences
  Canonical country node value: the ISO-3166 alpha-2 uppercase code (e.g., "FR",
  "US", "RU"). Put the long name and any extras in metadata:
      add_node(country, "FR", metadata={"name":"France","source_field":"rdap_ip.country"}, source="rdap")
  Always source= the API that produced the field, so an analyst can audit it.
  If multiple authoritative sources disagree, create one country node per
  authoritative source and note the discrepancy in the ip/asn node metadata
  (field: "country_disagreement": [...]) — do not silently pick one.

Source caveats you MUST be aware of:
  - virustotal_resolutions_*: capped at 40 results by the API (we already request the max). If you see exactly 40, assume there is more — note "truncated at 40" in metadata.
  - urlscan_search: returns up to 50 hits per query. Use multiple targeted queries (domain:, ip:, hash:, page.title:) rather than one broad one.
  - shodan_search: free tier has tight monthly credit limits — use it ONLY for the high-signal pivots in STEP 7 (jarm/favicon/cert/asn).
  - virustotal_*: free tier ≈ 4 req/min — if you see a rate-limit response, the harness will pause; you do not need to retry manually, but try to space VT calls.
  - crtsh_subdomains: very large for popular domains — pick 40 most recent and note total in metadata.
  - rdap on .ru/.cn/.ua TLDs is often partial — fall back to virustotal_domain whois.

Edge relations (use exactly these strings):
  resolves_to         domain → ip  (current A/AAAA)
  historical_ip       domain → ip  (passive DNS, past resolution)
  co_resolves         ip → domain  (other domains that resolved to same IP)
  has_subdomain       domain → domain
  uses_ns             domain → ns
  registered_with     domain → registrar
  has_cert            domain/ip → cert
  same_cert           domain → domain  (shared certificate)
  same_registrant     domain → domain  (same registrant email/org)
  same_ns_set         domain → domain  (identical NS set — strong pivot signal)
  hosted_on_asn       ip → asn
  belongs_to_asn      domain → asn
  has_jarm            ip → jarm
  communicates_with   hash → domain/ip
  known_ioc           domain/ip/hash → report  (link to threat intel report)
  located_in          ip/asn → country         (ONLY when a source returned an authoritative country field)
  registered_in       registrar/email → country  (ONLY when rdap returned registrant country)

══════════════════════════════════════════════
WORKFLOW — DOMAIN seed (execute in order)
══════════════════════════════════════════════

STEP 1 — Seed + RDAP + DNS (always do this)
  a. add_node(domain, <seed>, tags=["seed"])
  b. rdap_domain(<seed>)
     → add_node(registrar, <registrar_name>, metadata={iana_id, abuse_email}, source="rdap")
     → add_edge(domain→registrar, registered_with, evidence="RDAP registrar field")
     → add_node(ns, <each NS>, source="rdap")
     → add_edge(domain→ns, uses_ns, evidence="RDAP nameservers")
     → defuse(ns, <each NS>) → if parking: tag_node(ns, "parking"), tag seed domain "parking_ns"
     → store registrar, creation_date, expiry_date, registrant_email in seed node metadata
     → If rdap returned a registrant country (vcard `country` or entity `country`):
         add_node(country, <ISO2_upper>, metadata={name, source_field:"rdap_domain.registrant.country"}, source="rdap")
         add_edge(registrar→country, registered_in)  (or email→country if you graphed the registrant email)
       Do NOT link the domain itself to the country — the domain's legal jurisdiction
       is not the same as its operator's. Link only the registrar/registrant-email node.
  c. dns_resolve(<seed>)
     → For each A record: add_node(ip, <ip>), add_edge(domain→ip, resolves_to, source="dns")
     → For each AAAA: same
     → For each MX: add_node(domain, <mx_host>), add_edge(seed→mx, uses_mx)
     → For each NS (if different from RDAP): add_node(ns, <ns>), add_edge, defuse

*** CHECKPOINT — PARKING/SINKHOLE EARLY-EXIT DECISION (evaluate BEFORE continuing) ***
After STEP 1, count how many of these signals are present:
  ✓ defuse(ns, <ns>) returned should_stop_pivot=true with tag "parking"
  ✓ CNAME points to hugedomains.com, sedoparking.com, bodis.com, parkingpage.namecheap.com
  ✓ Registrant email/org is a domain marketplace (hugedomains.com, sedo.com, afternic.com, dan.com, domainmarket.com)
  ✓ TXT record contains "afternic-verification", "sedo-verification", "for-sale"
If TWO OR MORE signals → domain is CONFIRMED PARKED. Tag seed "parking" and JUMP TO STEP 8 immediately.
  Do NOT continue to STEP 2. Do NOT call VT, URLScan, OTX, crtsh, or any enrichment APIs.
If registrant is FBI/Europol/law enforcement AND NS contains "sinkhole"/"shadowserver" → SINKHOLE WITH HISTORICAL VALUE. Tag "sinkhole" and CONTINUE full workflow.
Otherwise → continue normally.
*** END CHECKPOINT ***

STEP 2 — Certificate transparency
  a. crtsh_subdomains(<seed>)
     → For each subdomain (max 40, pick most recent):
         add_node(domain, <subdomain>, source="crtsh")
         add_edge(seed→subdomain, has_subdomain)
     → Group by issuer — if many certs from same issuer, note in metadata

STEP 2.5 — Subdomain + URL coverage from secondary sources
  a. virustotal_subdomains(<seed>)
     → For each subdomain not already in graph: add_node(domain), add_edge(seed→sub, has_subdomain, source="virustotal")
  b. urlhaus_host(<seed>)
     → If query_status=="ok": tag seed "suspicious" or "malicious"
     → For each url entry (max 10): add_node(url, <url>), add_edge(seed→url, hosts_url, source="urlhaus")
     → Note threat type (malware_download, phishing) in seed metadata

STEP 3 — VirusTotal enrichment (call ALL tools a-d in this step)
  a. virustotal_domain(<seed>)
     → Extract last_analysis_stats → store in seed metadata, tag if malicious>0
     → Extract last_dns_records → for each A: add_node(ip), add_edge resolves_to
     → Extract jarm_fingerprint → add_node(jarm, <jarm>), add_edge(seed→jarm, has_jarm)
     → Extract categories, popularity, threat_names → store in metadata
  b. virustotal_resolutions_domain(<seed>)
     → For each historical IP (max 20): add_node(ip), add_edge(domain→ip, historical_ip)
  c. virustotal_communicating_files("domain", <seed>) — MANDATORY, call at same time as a+b
     → For each sample (max 5): add_node(hash, <sha256>, metadata={file_name, names, detection_ratio, family}), add_edge(hash→seed, communicates_with)
       MANDATORY: set metadata.file_name (singular) from VT's meaningful_name, or names[0] if not present.
       This is what the UI uses to label the node; an unlabeled hash is useless.
     → FALLBACK: if communicating_files returns empty data[] AND otx/threatfox identified a malware family name,
       call malwarebazaar_signature(<family_name>) to find known samples. Add top 3 as hash nodes (also set metadata.file_name).
  d. mnemonic_pdns(<seed>)
     → Second-source passive DNS. For new IPs (max 10): add_node(ip), add_edge(seed→ip, historical_ip)
     → For each historical IP (max 20):
         add_node(ip, <ip>, metadata={date}, source="virustotal")
         add_edge(domain→ip, historical_ip, evidence="VT passive DNS date=<date>")

STEP 4 — IP pivots (for each unique IP found in steps 1-3, max 5 IPs)
  For each IP:
  a. defuse(ip, <ip>)
     → If should_stop_pivot: tag ip node, add metadata.defuse_reason, SKIP b-f for this IP
  b. rdap_ip(<ip>)
     → add_node(asn, <asn_number>, metadata={name, country, cidr}, source="rdap")
     → add_edge(ip→asn, hosted_on_asn)
     → store netname, country, abuse_email in ip node metadata
     → If rdap returned a country code for the ASN/IP:
         add_node(country, <ISO2_upper>, metadata={name, source_field:"rdap_ip.country"}, source="rdap")
         add_edge(asn→country, located_in)
         add_edge(ip→country, located_in)
       (Only when the country field is authoritatively present. Skip otherwise.)
  c. virustotal_resolutions_ip(<ip>)
     → For each co-resident domain (max 15, skip if fan-out >100):
         add_node(domain, <domain>, source="virustotal")
         add_edge(ip→domain, co_resolves, evidence="VT pDNS date=<date>")
  d. onyphe_ip(<ip>)
     → Extract open ports, service banners → store in ip metadata
     → Extract JARM if present → add_node(jarm), add_edge(ip→jarm, has_jarm)
  e. urlscan_search("ip:<ip>")
     → For each result (max 10): add_node(url, <page_url>), add_edge(ip→url, hosts_url)
  f. reverse_dns(<ip>)
     → add_node(domain, <ptr>), add_edge(ip→domain, has_ptr)
  g. mnemonic_pdns(<ip>) → second-source pDNS, add_edge(ip→domain, co_resolves, source="mnemonic")
  h. urlhaus_host(<ip>) → add_node(url) for each malicious URL hosted there, tag ip "malicious" if hits
  i. virustotal_communicating_files("ip", <ip>) → top 3 samples, add_node(hash, <sha256>, metadata={file_name, names, detection_ratio}) — set metadata.file_name from VT meaningful_name or names[0], add_edge(hash→ip, communicates_with)

STEP 5 — Subdomain resolution (for each subdomain from STEP 2, max 10)
  a. dns_resolve(<subdomain>)
     → add_node(ip, <ip>), add_edge(subdomain→ip, resolves_to)
  b. If IP is new (not seen yet): run STEP 4 for it

STEP 6 — Threat intel (MANDATORY — do not skip even if graph is already rich)
  a. threatfox_search(<seed>)
     → If hits: tag seed as suspicious/c2/phishing per malware_type
     → add_node(report, <malware_name>, metadata={confidence, malware_family, reporter}, source="threatfox")
     → add_edge(seed→report, known_ioc)
  b. otx_domain(<seed>)
     → Extract pulse names, tags, adversary → store in seed metadata
     → If malicious pulses: tag seed "suspicious"
  c. If STEP 3 a3 (virustotal_communicating_files) was not yet done, do it NOW:
     → virustotal_communicating_files("domain", <seed>) → For each sample (max 5):
       add_node(hash, <sha256>), add_edge(hash→seed, communicates_with)
     → For top 1-2: malwarebazaar_hash(<sha256>) → enrich with family/yara

STEP 7 — SIMILAR ATTACK PATTERN HUNTING (do this aggressively — go as far as the budget allows)
  Your goal here is to find OTHER infrastructure that shares signatures with the seed.
  Every match becomes a new node + a "same_*" / "co_resolves" / "same_ns_set" edge so the
  analyst sees the cluster, not just the seed.

  a. JARM fingerprint pivot — if you found a JARM that is NOT a well-known CDN JARM:
     → shodan_search("ssl.jarm:<jarm>") AND urlscan_search("hash:<jarm>")
     → For each new IP/host: add_node, add_edge(<seed>→<ip>, same_jarm)
  b. Favicon hash pivot — if VT/onyphe exposed a favicon hash:
     → shodan_search("http.favicon.hash:<hash>")
     → For matches: add_node(ip), add_edge(<seed>→<ip>, same_favicon)
  c. Certificate pivot — if you found a cert serial/SHA1/SHA256:
     → shodan_search("ssl.cert.serial:<serial>") and crt.sh by serial when possible
     → add_edge(<seed>→<other>, same_cert)
  d. NS-set pivot — if the domain uses an unusual NS set (not parking, not big providers):
     → If shodan_search or urlscan_search reveal other domains using the EXACT same NS set:
         add_edge(<seed>→<domain>, same_ns_set)  ← this is one of the strongest pivots
  e. Registrant pivot — if RDAP exposed a registrant email/org that is not privacy-protected:
     → urlscan_search("page.url:<email_local_part>") or note as pivot suggestion
     → add_edge(<seed>→<other>, same_registrant)
  f. Filename / hash pivot — if VT communicating_files showed sample hashes:
     → For top 3: virustotal_file(<hash>) → extract names, signatures, families
     → add_node(hash), add_edge(<seed>→<hash>, communicates_with)
     → If multiple samples share a filename/family → mark as a campaign in metadata
  g. URL/title pivot — if urlscan returned page titles or HTML hashes that look templated:
     → urlscan_search("page.title:\"<title>\"") to find lookalike phishing pages
     → add_edge(<seed>→<url>, same_page_template)
  h. ASN/CIDR neighbourhood — if the IP is on a small/abused ASN (NOT a big cloud):
     → shodan_search("asn:<ASN> port:443") and look for hosts with same JARM/title
     → Tag the ASN node "abused_asn" if you find multiple suspicious neighbours

  Keep going until you have either exhausted the markers or you are within ~10 calls of
  the budget. Every same_* edge you add is high-value pivot evidence — graph it.

STEP 8 — Final report (MANDATORY — always do this last)
  BEFORE writing the report, verify you have called ALL of these (if you haven't, go back and call them NOW):
    □ virustotal_communicating_files("domain", <seed>)
    □ threatfox_search(<seed>)
    □ otx_domain(<seed>)
    □ shodan_search("ssl.jarm:<jarm>") — if JARM was found and not a CDN JARM
  If any are unchecked, do NOT write the report yet. Go call them first.

  add_node(report, "investigation_summary", metadata={
    "summary": "<2-3 sentence overview mentioning key IOC values by name — stick to observed facts, no speculation>",
    "threat_assessment": "<benign|suspicious|likely_malicious|malicious>",  # see R11: default MUST be "benign" unless direct evidence
    "key_findings": [
      {"text": "<finding — include exact IOC values, IPs, domains as they appear in graph>", "sources": ["rdap","virustotal"]},
      {"text": "<finding2>", "sources": ["crtsh","dns"]},
      ...
    ],
    "discriminating_markers": ["<exact value of strong marker>", ...],
    "pivot_suggestions": ["<concrete next step mentioning exact IOC values>", ...],
    "ioc_list": ["<exact value matching a graph node>", ...],
    "sources_used": ["dns","rdap","crtsh","virustotal",...]
  }, source="agent", tags=["report"])
  IMPORTANT for key_findings: each finding MUST be an object {text, sources[]}, not a plain string.
  IMPORTANT for ioc_list and text fields: use exact node values (IPs, domain names) as they appear in the graph — the UI will auto-link them.
  IMPORTANT for threat_assessment: re-read R11. If no source returned a concrete malicious hit
  (VT malicious>0, threatfox/otx/urlhaus match, known malware sample communicating), the value
  MUST be "benign". Do NOT escalate based on domain name language, domain age, hosting provider,
  or "no hits so it must be pre-operational". Summary wording must match: if the assessment is
  benign, the summary must not contain phrases like "advance-fee fraud", "early targeting phase",
  "pre-operational", "strongly associated with scams" — those require direct evidence.
  The value "investigation_summary" is CANONICAL — always use exactly that value so the report
  node is a singleton (later pivots will update it in place, not create a second one).
  add_edge(seed→report, known_ioc)

══════════════════════════════════════════════
WORKFLOW — IP seed (execute in order)
══════════════════════════════════════════════

STEP 1 — Seed + Defuse
  a. add_node(ip, <seed>, tags=["seed"])
  b. defuse(ip, <seed>)
     → If CDN/sinkhole: tag node, write minimal report node, STOP.

STEP 2 — Core enrichment (call ALL tools a-j in this step — do not proceed to STEP 3 until all are done)
  a. rdap_ip(<seed>)
     → add_node(asn, <asn>, metadata={name, country, cidr}, source="rdap")
     → add_edge(ip→asn, hosted_on_asn)
     → store netname, country, abuse_email in ip metadata
     → If rdap returned a country code for the ASN/IP:
         add_node(country, <ISO2_upper>, metadata={name, source_field:"rdap_ip.country"}, source="rdap")
         add_edge(asn→country, located_in)
         add_edge(ip→country, located_in)
       (See country-node policy: only authoritative fields, never TLD/language/GeoIP-of-CDN.)
  b. virustotal_ip(<seed>)
     → Extract last_analysis_stats → store in ip metadata, tag if malicious>0
     → Extract last_https_certificate → add_node(cert, <thumbprint>, metadata={issuer, subject, serial, SAN, validity}, source="virustotal")
     → add_edge(ip→cert, has_cert)
     → Extract JARM fingerprint → add_node(jarm, <jarm>), add_edge(ip→jarm, has_jarm)
     → Note any tags, categories, reputation in metadata
  c. onyphe_ip(<seed>)
     → Extract open ports, service banners, OS → store in ip metadata
     → If JARM present and different from VT: compare/note
     → If HTTP title or favicon hash is present: store in metadata (needed for STEP 6)
  d. urlscan_search("ip:<seed>")
     → For each result (max 10): add_node(url, <page_url>), add_edge(ip→url, hosts_url, source="urlscan")
     → Note page titles, technologies for STEP 6 pivots
  e. reverse_dns(<seed>)
     → add_node(domain, <ptr>), add_edge(ip→domain, has_ptr, source="dns")
  f. urlhaus_host(<seed>)
     → If hits: tag ip "malicious", add_node(url) for each malicious URL, add_edge(ip→url, hosts_url)
  g. virustotal_communicating_files("ip", <seed>) — MANDATORY
     → For each sample (max 5): add_node(hash, <sha256>), add_edge(hash→ip, communicates_with)
     → FALLBACK: if data[] is empty AND you identified a malware family from other sources (OTX, Onyphe beacon config),
       call malwarebazaar_signature(<family_name>) to find known samples. Add top 3 as hash nodes.
  h. virustotal_resolutions_ip(<seed>) — MANDATORY
     → For each co-resident domain (max 15): add_node(domain), add_edge(ip→domain, co_resolves)
  i. threatfox_search(<seed>) — MANDATORY
     → If hits: tag ip c2/botnet, add_node(report), add_edge(ip→report, known_ioc)
  j. IF a JARM was found in step b: shodan_search("ssl.jarm:<jarm>") — MANDATORY
     → For each new IP: add_node(ip), add_edge(seed_ip→new_ip, same_jarm)

STEP 3 — Passive DNS / Co-resident domains
  a. virustotal_resolutions_ip(<seed>)
     → For each co-resident domain (max 15, skip if fan-out >80 → tag "shared_hosting"):
         add_node(domain, <domain>, source="virustotal")
         add_edge(ip→domain, co_resolves, evidence="VT pDNS date=<date>")
  b. mnemonic_pdns(<seed>)
     → Second-source pDNS. For new domains (max 10): add_node(domain), add_edge(ip→domain, co_resolves, source="mnemonic")

STEP 4 — Malware / threat intel (MANDATORY per R9+R10 — do not skip under any circumstance)
  a. virustotal_communicating_files("ip", <seed>) — MANDATORY per R9
     → For each sample (max 5): add_node(hash, <sha256>, metadata={file_name, names, family, detections, detection_ratio}, source="virustotal")
       MANDATORY: set metadata.file_name (singular) from VT meaningful_name, or names[0] if absent.
       This is used for the node label; without it the UI shows a truncated hash.
     → add_edge(hash→ip, communicates_with)
     → For top 1-2 hashes with detections: malwarebazaar_hash(<sha256>) → enrich with signature/family/yara
  b. threatfox_search(<seed>)
     → If hits: tag ip as c2/botnet per malware_type
     → add_node(report, <malware_name>, metadata={confidence, malware_family}, source="threatfox")
     → add_edge(ip→report, known_ioc)
  c. otx_ip(<seed>)
     → Extract pulse names, tags, adversary → store in ip metadata
     → If malicious pulses: tag ip "suspicious"

STEP 5 — Certificate SAN pivot (IMPORTANT — this is often the strongest IP→domain link)
  If STEP 2b found a TLS certificate with SAN (Subject Alternative Names):
  a. For each domain in the SAN list (max 10):
     → add_node(domain, <san_domain>, source="virustotal")
     → add_edge(ip→domain, has_cert, evidence="TLS cert SAN on <cert_thumbprint>")
  b. If SAN domains share a pattern (e.g., all start with "hsbc." or all use same apex):
     → This is likely an actor-operated cluster. Tag all SAN domains "suspicious"
     → add_edges between SAN domains using same_cert relation

STEP 6 — SIMILAR ATTACK PATTERN HUNTING (go as far as budget allows)
  a. JARM fingerprint pivot — if you found a JARM that is NOT a well-known CDN JARM:
     → shodan_search("ssl.jarm:<jarm>")
     → For each new IP: add_node(ip), add_edge(seed_ip→new_ip, same_jarm, evidence="Shodan JARM match")
     → virustotal_ip on top 2 new IPs → extract their certs/domains for further clustering
  b. Certificate serial/thumbprint pivot:
     → shodan_search("ssl.cert.serial:<serial>")
     → For matches: add_node, add_edge(same_cert)
  c. Favicon hash pivot — if onyphe/VT exposed favicon hash:
     → shodan_search("http.favicon.hash:<hash>")
     → For matches: add_node(ip), add_edge(same_favicon)
  d. For top 3 co-resident domains from STEP 3: virustotal_domain(<domain>) → extract their IPs/certs
     → If their certs match the seed's cert → strong same-operator signal

STEP 7 — Final report (MANDATORY — always do this last)
  Same format as domain workflow STEP 8. Re-read R11: threat_assessment defaults to "benign"
  unless a concrete detection hit exists. Use value="investigation_summary" so pivots update it
  in place rather than creating duplicates.
  BEFORE writing the report, verify you have called ALL of these (if you haven't, go back and call them NOW):
    □ virustotal_communicating_files("ip", <seed>)
    □ threatfox_search(<seed>)
    □ shodan_search("ssl.jarm:<jarm>") — if JARM was found
    □ virustotal_resolutions_ip(<seed>)
  If any are unchecked, do NOT write the report yet. Go call them first.

══════════════════════════════════════════════
WORKFLOW — HASH seed
══════════════════════════════════════════════
STEP 1: add_node(hash, seed, tags=["seed"])
STEP 1.5: malwarebazaar_hash(<seed>) → family, signature, yara_rules, file_name, intelligence
  → If a malware family/signature is identified: malwarebazaar_signature(<family>) → list sibling samples (max 5), add as hash nodes with same_family edge
  → MANDATORY: store `file_name` (singular string) in seed node metadata. Pick the most
    frequently-reported filename from malwarebazaar's "file_name" field, or the first entry
    if a list. This field is what the UI uses to label the node — without it the graph
    shows a truncated hash which is useless to the analyst.
STEP 2: virustotal_file → extract contacted_domains, contacted_ips, network_infrastructure, meaningful_name, names
  → For each domain: add_node(domain), add_edge(hash→domain, communicates_with)
  → For each ip: add_node(ip), defuse, add_edge(hash→ip, communicates_with)
  → Store detection ratio, malware family, signature names in seed metadata
  → If the hash seed metadata does not already have `file_name`, fill it from VT's
    `meaningful_name` (preferred) or `names[0]`. Also store the full `names` array.
  → For any sibling malware hash node you add: set metadata.file_name on it too.
STEP 3: otx_file, threatfox_search → link to threat reports
STEP 4: For top 3 domains/IPs: run STEP 4 of domain/IP workflow
STEP 5: report node (same schema as domain/IP STEP 8 — remember R11 and use value="investigation_summary")

══════════════════════════════════════════════
PARKING / SINKHOLE / NOISE HANDLING
══════════════════════════════════════════════
- Fan-out rule: if virustotal_resolutions_ip returns >80 domains for an IP, it is shared hosting.
  Tag ip as "shared_hosting", do NOT add all domains. Add 3 representative ones with evidence="sample only, shared hosting".
- If a co-resident domain is a known parking domain (godaddy, sedo, bodis, dan.com, above.com),
  tag it "parking" and do not pivot further.
- If NS points to dyndns provider: tag domain "dyndns", note in metadata.

CRITICAL — EARLY-EXIT RULE FOR PARKED / SINKHOLED DOMAINS:
After completing STEP 1, evaluate ALL of these parking/sinkhole signals:
  ✓ defuse(ns, <ns>) returned should_stop_pivot=true with tag "parking"
  ✓ NS contains "sinkhole", "shadowserver", "abuse.ch", "rpz", "blackhole"
  ✓ CNAME points to hugedomains.com, sedoparking.com, bodis.com, parkingpage.namecheap.com
  ✓ Registrant email/org is a domain marketplace (hugedomains, sedo, afternic, dan.com, domainmarket)
  ✓ RDAP status includes "serverHold" or registrant org is FBI/law enforcement

If TWO OR MORE of these signals are present → the domain is confirmed parked or sinkholed:
  1. Tag the seed node with "parking" or "sinkhole" accordingly
  2. SKIP steps 2-7 entirely — do NOT call VT, URLScan, OTX, crtsh, or any enrichment APIs
  3. Jump directly to STEP 8 and write the report node explaining WHY you concluded it's parked/sinkholed
  4. In the report, include: registrar, NS, parking signals found, and a note that no further enrichment is warranted

If only ONE signal is present, proceed with caution — do a MINIMAL check (virustotal_domain only) to confirm, then decide.

EXCEPTION — SINKHOLED DOMAINS (law enforcement seizure) WITH HISTORICAL VALUE:
This exception ONLY applies when RDAP reveals the domain was SEIZED BY LAW ENFORCEMENT — meaning the registrant email/org is from a government agency (e.g., cyd-dns@fbi.gov, registrar is ROLR, or NS contains "sinkhole.shadowserver.org"). In this case:
  - Tag as "sinkhole" but proceed with the full domain workflow
  - Focus on HISTORICAL data: virustotal_resolutions_domain for past IPs, threatfox_search, virustotal_communicating_files for malware hashes
  - The goal is to reconstruct the HISTORICAL infrastructure, not current state

This exception does NOT apply to:
  - Domains that merely have a name resembling a malware family (e.g., "wannacry.com" owned by a domain broker is NOT the same as an FBI-seized C2 domain)
  - Domains parked by commercial brokers (HugeDomains, Sedo, Afternic, etc.) — these ALWAYS get early-exit, regardless of their name

NOW START the investigation. Execute the workflow step by step. Do not stop until STEP 8 is done.
"""


_ALLOWED_TOOLS = (
    "mcp__graph__add_node,mcp__graph__add_edge,mcp__graph__tag_node,"
    "mcp__graph__get_graph,mcp__graph__defuse,"
    "mcp__cti__dns_resolve,mcp__cti__reverse_dns,mcp__cti__crtsh_subdomains,"
    "mcp__cti__rdap_domain,mcp__cti__rdap_ip,"
    "mcp__cti__virustotal_domain,mcp__cti__virustotal_ip,mcp__cti__virustotal_file,"
    "mcp__cti__virustotal_resolutions_domain,mcp__cti__virustotal_resolutions_ip,"
    "mcp__cti__virustotal_subdomains,mcp__cti__virustotal_communicating_files,"
    "mcp__cti__urlscan_search,mcp__cti__urlscan_result,"
    "mcp__cti__onyphe_domain,mcp__cti__onyphe_ip,"
    "mcp__cti__shodan_host,mcp__cti__shodan_search,"
    "mcp__cti__otx_domain,mcp__cti__otx_ip,mcp__cti__otx_file,"
    "mcp__cti__threatfox_search,mcp__cti__wayback,"
    "mcp__cti__mnemonic_pdns,"
    "mcp__cti__urlhaus_host,mcp__cti__malwarebazaar_hash,mcp__cti__malwarebazaar_signature"
)
_DISALLOWED_TOOLS = "Bash,Edit,Write,MultiEdit,Read,Glob,Grep,NotebookEdit,WebSearch,WebFetch,Task,TodoWrite"


def _build_env(inv_id: str) -> dict:
    """Build a minimal env for the spawned `claude` process."""
    parent = os.environ
    env = {
        "HOME": parent.get("HOME", ""),
        "USER": parent.get("USER", ""),
        "LOGNAME": parent.get("LOGNAME", ""),
        "LANG": parent.get("LANG", "C.UTF-8"),
        "TERM": "dumb",
        "PATH": ":".join(p for p in parent.get("PATH", "").split(":")
                         if not any(x in p.lower() for x in
                                    ("antigravity", "vscode", "cursor", "code/bin", "trae"))),
    }
    for k in ("VIRUSTOTAL_API_KEY", "URLSCAN_API_KEY", "ONYPHE_API_KEY",
              "SHODAN_API_KEY", "OTX_API_KEY", "ABUSECH_AUTH_KEY"):
        if parent.get(k):
            env[k] = parent[k]
    env["BOUNCE_INV_ID"] = inv_id
    env["MCP_TIMEOUT"] = "30000"
    env["MCP_TIMEOUT_MS"] = "30000"
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    env["BOUNCE_PYTHON"] = sys.executable
    return env


async def _run_claude_phase(inv_id: str, prompt: str, system_prompt: str,
                            model: str, env: dict, mcp_cfg_path: Path,
                            phase: str = "main", max_turns: int = 120) -> tuple:
    """Run a single claude -p invocation. Returns (rc, saw_result, has_report)."""
    claude_path = shutil.which(CLAUDE_BIN) or CLAUDE_BIN
    _log(inv_id, f"phase_{phase}_starting", {"prompt_preview": prompt[:200]})

    cmd = [
        claude_path, "-p", prompt,
        "--model", model,
        "--append-system-prompt", system_prompt,
        "--mcp-config", str(mcp_cfg_path),
        "--strict-mcp-config",
        "--output-format", "stream-json",
        "--verbose",
        "--permission-mode", "bypassPermissions",
        "--max-turns", str(max_turns),
        "--allowedTools", _ALLOWED_TOOLS,
        "--disallowedTools", _DISALLOWED_TOOLS,
    ]

    use_shell = os.name == "nt"
    try:
        if use_shell:
            quoted = " ".join(f'"{a}"' if (" " in a or '"' in a) else a for a in cmd)
            proc = await asyncio.create_subprocess_shell(
                quoted, cwd=str(ROOT), env=env,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
        else:
            proc = await asyncio.create_subprocess_exec(
                *cmd, cwd=str(ROOT), env=env,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
    except FileNotFoundError as e:
        _log(inv_id, "agent_error", f"claude CLI not found: {e}")
        return (None, False, False)

    async def pump_stderr():
        assert proc.stderr is not None
        async for line in proc.stderr:
            _log(inv_id, "agent_stderr", line.decode(errors="replace").rstrip())

    saw_result = {"v": False}

    async def pump_stdout():
        assert proc.stdout is not None
        async for line in proc.stdout:
            text = line.decode(errors="replace").strip()
            if not text:
                continue
            try:
                evt = json.loads(text)
                _log(inv_id, "agent_" + evt.get("type", "msg"), evt)
                if evt.get("type") == "result":
                    saw_result["v"] = True
            except Exception:
                _log(inv_id, "agent_stdout", text[:2000])

    async def watchdog():
        """Guard against subprocesses that don't close stdout after finishing.

        - Once we've seen the "result" event, allow 15s for a graceful exit, then kill.
        - Otherwise, if the graph has an investigation_summary report node and no new
          events have arrived in 90s, conclude phase is done and kill.
        - Absolute ceiling of 20 minutes per phase.
        """
        hard_deadline = time.monotonic() + 20 * 60
        while True:
            if proc.returncode is not None:
                return
            if saw_result["v"]:
                try:
                    await asyncio.wait_for(proc.wait(), timeout=15)
                    return
                except asyncio.TimeoutError:
                    _log(inv_id, "phase_watchdog_kill",
                         {"reason": "saw_result_then_stdout_open", "phase": phase})
                    try: proc.kill()
                    except Exception: pass
                    return
            # check idle + report present
            try:
                with gs.conn() as c:
                    last_ts = c.execute(
                        "SELECT MAX(created_at) FROM events WHERE investigation_id=?",
                        (inv_id,),
                    ).fetchone()[0] or 0
                has_summary = c.execute(
                    "SELECT 1 FROM nodes WHERE investigation_id=? AND type='report' "
                    "AND value='investigation_summary' LIMIT 1",
                    (inv_id,),
                ).fetchone() is not None
            except Exception:
                last_ts, has_summary = 0, False
            idle = time.time() - last_ts if last_ts else 0
            if has_summary and idle > 90:
                _log(inv_id, "phase_watchdog_kill",
                     {"reason": "idle_with_summary", "idle_s": int(idle), "phase": phase})
                try: proc.kill()
                except Exception: pass
                return
            if time.monotonic() > hard_deadline:
                _log(inv_id, "phase_watchdog_kill",
                     {"reason": "hard_deadline_20min", "phase": phase})
                try: proc.kill()
                except Exception: pass
                return
            await asyncio.sleep(10)

    rc = None
    try:
        await asyncio.gather(pump_stdout(), pump_stderr(), watchdog(),
                             return_exceptions=True)
        try:
            rc = await asyncio.wait_for(proc.wait(), timeout=10)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            rc = proc.returncode
    except Exception:
        pass

    try:
        g = gs.get_graph(inv_id)
        has_report = any(n.get("type") == "report" for n in g.get("nodes", []))
    except Exception:
        has_report = False

    _log(inv_id, f"phase_{phase}_exit", {"rc": rc, "saw_result": saw_result["v"], "has_report": has_report})
    return (rc, saw_result["v"], has_report)


# Shorter system prompt for follow-up phase — just graph schema + rules, no full workflow
_FOLLOWUP_SYSTEM_PROMPT = """You are Bounce-CTI, continuing an existing investigation.
The graph already has nodes and edges from a previous phase. Your job is to call the specific CTI tools listed in the user prompt, add results to the graph, and stop.

RULES:
- Call get_graph() FIRST to see existing nodes.
- For each tool result, add_node and add_edge for any NEW information found.
- Do NOT create a new report node — one already exists.
- Do NOT re-call tools that were already called (check the graph for existing data).
- Use the same graph schema: node types (domain, ip, hash, jarm, cert, asn, etc.) and edge relations (communicates_with, has_jarm, same_jarm, known_ioc, historical_ip, etc.).
- Set source= to the API name that produced the data.
- Call defuse(kind, value) before pivoting on any new IP.
- IMPORTANT: If the user prompt mentions additional follow-up steps (JARM pivot, malwarebazaar fallback), do those too.
- When malwarebazaar_signature returns samples, add each as a hash node with metadata (file_name, signature, file_type) and add a communicates_with edge from hash to the seed.
- After calling all requested tools and follow-up steps, write a brief text summary. Do NOT add a report node.
"""


async def run_investigation(inv_id: str, seed_type: str, seed_value: str, model: str = "opus"):
    if seed_type == "ip":
        user_prompt = (
            f"Seed indicator: type={seed_type} value={seed_value}\n"
            "Investigate now. You MUST call ALL of these tools before writing the report:\n"
            f"1. rdap_ip({seed_value})\n"
            f"2. virustotal_ip({seed_value})\n"
            f"3. shodan_host({seed_value})  — extract JARM fingerprint from the response\n"
            f"4. shodan_search(\"ssl.jarm:<jarm_from_step_3>\")  — JARM pivot; add new IPs with same_jarm edges\n"
            f"5. onyphe_ip({seed_value})\n"
            f"6. urlscan_search(\"ip:{seed_value}\")\n"
            f"7. reverse_dns({seed_value})\n"
            f"8. virustotal_resolutions_ip({seed_value})\n"
            f"9. virustotal_communicating_files(\"ip\", {seed_value})\n"
            f"10. threatfox_search({seed_value})\n"
            f"11. otx_ip({seed_value})\n"
            "Do NOT write the report until all 11 are done.\n"
            "FALLBACK: If virustotal_communicating_files returns empty data[] and threatfox/otx "
            "identify a specific malware family, call malwarebazaar_signature(<family>) "
            "and add each returned sample as a hash node with a communicates_with edge to the seed IP."
        )
    else:
        user_prompt = (
            f"Seed indicator: type={seed_type} value={seed_value}\n"
            "Investigate now. You MUST call ALL of these tools before writing the report:\n"
            f"1. rdap_domain/dns_resolve({seed_value})\n"
            f"2. crtsh_subdomains({seed_value})\n"
            f"3. virustotal_domain({seed_value})\n"
            f"4. virustotal_resolutions_domain({seed_value})\n"
            f"5. virustotal_communicating_files(\"domain\", {seed_value})\n"
            f"6. threatfox_search({seed_value})\n"
            f"7. otx_domain({seed_value})\n"
            "Do NOT write the report until all 7 are done.\n"
            "EXCEPTION: If after step 1 the domain is clearly parked (parking NS + broker registrant), "
            "skip steps 2-7 and write a minimal report.\n"
            "FALLBACK: If communicating_files returns empty data[] and OTX/threatfox identifies a malware family, "
            "call malwarebazaar_signature(<family>) to find known samples and add them as hash nodes."
        )

    env = _build_env(inv_id)
    mcp_cfg_path = _write_mcp_config(inv_id)
    _log(inv_id, "agent_starting", {"cwd": str(ROOT), "mcp_config": str(mcp_cfg_path)})

    # ── Phase 1: Main investigation ──
    rc, saw_result, has_report = await _run_claude_phase(
        inv_id, user_prompt, SYSTEM_PROMPT, model, env, mcp_cfg_path,
        phase="main"
    )

    phase1_ok = saw_result or has_report or rc == 0

    # ── Phase 2: Follow-up for missing mandatory tools ──
    if phase1_ok and not _is_parked(inv_id):
        called = _get_called_cti_tools(inv_id)
        missing = _missing_mandatory_tools(seed_type, seed_value, called)
        if missing:
            _log(inv_id, "phase2_needed", {"missing": missing, "called": sorted(called)})
            # Build extra follow-up steps for IP/domain seeds
            extra_steps = []
            if seed_type == "ip":
                extra_steps.append(
                    "After the above: read the graph — if a JARM node exists for this IP, "
                    "call shodan_search(\"ssl.jarm:<jarm_value>\") to find other IPs with the same fingerprint. "
                    "Add any new IPs as nodes with same_jarm edges to the seed IP."
                )
                extra_steps.append(
                    "If virustotal_communicating_files returned an empty data[] AND threatfox/otx "
                    "identified a specific malware family tag, "
                    "call malwarebazaar_signature(<family>, limit=5) and add each returned sample "
                    "as a hash node with a communicates_with edge from hash to the seed IP."
                )
            elif seed_type == "domain":
                extra_steps.append(
                    "If virustotal_communicating_files returned an empty data[] AND threatfox/otx "
                    "identified a specific malware family tag, "
                    "call malwarebazaar_signature(<family>, limit=5) and add each returned sample "
                    "as a hash node with a communicates_with edge from hash to the seed."
                )
            steps_block = ""
            if extra_steps:
                steps_block = "\n\nThen, as additional REQUIRED follow-up steps:\n" + "\n".join(
                    f"  {i + len(missing) + 1}. {s}" for i, s in enumerate(extra_steps)
                )
            followup_prompt = (
                f"Continue the investigation on {seed_value} (type={seed_type}). "
                f"The graph already has nodes from the main investigation.\n\n"
                f"STEP 1: Call get_graph() to see what already exists.\n"
                f"STEP 2-{len(missing)+1}: Call these CTI tools that were missed in phase 1:\n"
                + "\n".join(f"  {i+2}. {m}" for i, m in enumerate(missing))
                + "\nFor each result, add new nodes and edges to the graph. "
                "Do NOT create a new report node."
                + steps_block
            )
            rc2, saw2, _ = await _run_claude_phase(
                inv_id, followup_prompt, _FOLLOWUP_SYSTEM_PROMPT, model, env,
                mcp_cfg_path, phase="followup", max_turns=30
            )
            _log(inv_id, "phase2_done", {"rc": rc2, "saw_result": saw2})

            # Check what was actually called now
            called_after = _get_called_cti_tools(inv_id)
            still_missing = _missing_mandatory_tools(seed_type, seed_value, called_after)
            if still_missing:
                _log(inv_id, "phase2_incomplete", {"still_missing": still_missing})

    # ── Final status ──
    try:
        g = gs.get_graph(inv_id)
        has_report = any(n.get("type") == "report" for n in g.get("nodes", []))
    except Exception:
        has_report = False

    if saw_result or has_report or rc == 0:
        final_status = "done"
    else:
        final_status = f"error rc={rc}"
    gs.set_status(inv_id, final_status)
    # Emit a terminal event so the frontend's WebSocket loop can refresh
    # the sidebar status without needing a manual page reload.
    _log(inv_id, "agent_exit", {"rc": rc, "status": final_status, "has_report": has_report})


# ── Pivot-specific system prompt ──────────────────────────────────────────
# Used by run_pivot() when the user clicks "Pivot here" on an existing node.
# Goal: extend the graph AND update the existing report node in place (never
# create a second report node).
_PIVOT_SYSTEM_PROMPT = """You are Bounce-CTI, EXTENDING an existing investigation graph via a user-initiated pivot.
The graph already contains nodes, edges, and (usually) a single report node with
value="investigation_summary". Your job is to enrich the graph from the new pivot
seed AND fold any new findings back into that existing report — NOT to create a
second one.

ABSOLUTE RULES for pivot runs:
P1. Call get_graph() FIRST to see the existing structure and the existing report
    node's metadata. You will MERGE into it, not replace it.
P2. Run the relevant enrichment tools for the pivot seed (the user prompt lists
    them). Follow the normal rules R1-R11 from the main system prompt: graph
    every finding, call defuse before pivoting on IPs, use correct sources,
    respect R11 (evidence-based threat_assessment — no speculation).
P3. REPORT UPDATE (MANDATORY, exactly one call):
    Re-add_node(report, "investigation_summary", metadata={...}, source="agent",
    tags=["report"]) using the CANONICAL value "investigation_summary". Because
    add_node upserts on (inv, type, value), this UPDATES the existing report in
    place.
    In the metadata you submit:
      - "summary": rewrite it to reflect the COMBINED view (original seed + pivot).
        Keep it factual, 2-4 sentences. No speculation. Obey R11.
      - "key_findings": APPEND new findings from the pivot. Do not drop prior
        findings — re-include them from the existing report.metadata.key_findings
        (you just read it via get_graph()). Each finding stays {text, sources[]}.
      - "threat_assessment": start from the existing value. Only ESCALATE if a
        new direct-evidence condition from R11 is now met (cite the source+value
        in key_findings). Never escalate from domain-name semantics, age, hosting,
        or absence of hits. If no new evidence, keep the existing assessment.
      - "discriminating_markers", "pivot_suggestions", "ioc_list", "sources_used":
        union of old + new values; de-duplicate.
      - Add a "pivot_history" list entry: {"pivot_seed_type": "<type>",
        "pivot_seed_value": "<value>", "timestamp": "<iso8601 or best effort>"}.
        Extend the existing pivot_history if present, otherwise create it.
P4. Do NOT create any other report node. Do NOT use any value other than
    "investigation_summary" for the report.
P5. After the report update, stop. Do not chain further pivots.
"""


async def run_pivot(inv_id: str, seed_type: str, seed_value: str, model: str = "opus"):
    """Extend an existing investigation graph with a new pivot seed.

    Uses a pivot-specific prompt that tells the agent to update the existing
    report node (singleton with value="investigation_summary") in place rather
    than create a duplicate. The investigation's status is flipped to "running"
    by the API endpoint, and this function emits agent_exit on completion so
    the frontend sidebar refreshes live.
    """
    user_prompt = (
        f"Pivot seed: type={seed_type} value={seed_value}\n"
        f"Investigation id: {inv_id}\n\n"
        "STEP 1: Call get_graph() and locate the existing report node\n"
        "        (type=report, value=investigation_summary). Read its metadata —\n"
        "        you will merge into it.\n\n"
        "STEP 2: Run pivot enrichment for this seed. "
    )
    if seed_type == "ip":
        user_prompt += (
            "Call these tools (skip any whose results are already in the graph):\n"
            f"  - rdap_ip({seed_value})\n"
            f"  - virustotal_ip({seed_value})\n"
            f"  - shodan_host({seed_value})  (passive — extract JARM, banners, technologies)\n"
            f"  - onyphe_ip({seed_value})  (passive — banners, cert, technologies)\n"
            f"  - reverse_dns({seed_value})\n"
            f"  - virustotal_resolutions_ip({seed_value})\n"
            f"  - virustotal_communicating_files(\"ip\", {seed_value})\n"
            f"  - threatfox_search({seed_value})\n"
            f"  - otx_ip({seed_value})\n"
            "If a JARM is extracted and it is not a well-known CDN JARM, also call\n"
            f"  - shodan_search(\"ssl.jarm:<jarm>\") and add new IPs with same_jarm edges.\n"
        )
    elif seed_type == "domain":
        user_prompt += (
            "Call these tools (skip any whose results are already in the graph):\n"
            f"  - rdap_domain({seed_value}) / dns_resolve({seed_value})\n"
            f"  - crtsh_subdomains({seed_value})\n"
            f"  - virustotal_domain({seed_value})\n"
            f"  - virustotal_resolutions_domain({seed_value})\n"
            f"  - virustotal_communicating_files(\"domain\", {seed_value})\n"
            f"  - threatfox_search({seed_value})\n"
            f"  - otx_domain({seed_value})\n"
            f"  - onyphe_domain({seed_value})  (passive fingerprinting)\n"
        )
    elif seed_type == "hash":
        user_prompt += (
            "Call these tools (skip any whose results are already in the graph):\n"
            f"  - malwarebazaar_hash({seed_value})\n"
            f"  - virustotal_file({seed_value})\n"
            f"  - otx_file({seed_value})\n"
            f"  - threatfox_search({seed_value})\n"
            "For every hash node created or updated, set metadata.file_name.\n"
        )
    user_prompt += (
        "\nSTEP 3: UPDATE THE REPORT (do this exactly once, at the end).\n"
        "Re-call add_node(report, \"investigation_summary\", metadata={...},\n"
        "source=\"agent\", tags=[\"report\"]) with MERGED metadata as described in\n"
        "P3 of the system prompt. Preserve prior key_findings; append new ones.\n"
        "Only escalate threat_assessment if a new direct-evidence R11 condition\n"
        "is met (cite the source in key_findings).\n"
        "Then STOP."
    )

    env = _build_env(inv_id)
    mcp_cfg_path = _write_mcp_config(inv_id)
    _log(inv_id, "agent_starting", {"cwd": str(ROOT), "mcp_config": str(mcp_cfg_path), "phase": "pivot",
                                    "pivot_seed_type": seed_type, "pivot_seed_value": seed_value})

    rc, saw_result, has_report = await _run_claude_phase(
        inv_id, user_prompt, _PIVOT_SYSTEM_PROMPT, model, env, mcp_cfg_path,
        phase="pivot", max_turns=40
    )

    # Final status — pivot is considered successful as long as the agent ran
    # (saw_result or rc==0). A pivot does not necessarily add a brand-new report;
    # it updates the existing one.
    final_status = "done" if (saw_result or rc == 0) else f"error rc={rc}"
    gs.set_status(inv_id, final_status)
    _log(inv_id, "agent_exit", {"rc": rc, "status": final_status, "phase": "pivot",
                                "has_report": has_report})
