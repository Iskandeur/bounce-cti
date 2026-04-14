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

══════════════════════════════════════════════
GRAPH SCHEMA — node types and edge relations
══════════════════════════════════════════════
Node types: domain, ip, ns, registrar, cert, asn, email, url, hash, jarm, favicon, report
Tags to use: seed, suspicious, benign, cdn, parking, sinkhole, dyndns, shared_hosting, c2, phishing, expired

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
     → For each sample (max 5): add_node(hash, <sha256>), add_edge(hash→seed, communicates_with)
     → FALLBACK: if communicating_files returns empty data[] AND otx/threatfox identified a malware family name,
       call malwarebazaar_signature(<family_name>) to find known samples. Add top 3 as hash nodes.
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
  i. virustotal_communicating_files("ip", <ip>) → top 3 samples, add_node(hash), add_edge(hash→ip, communicates_with)

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
    "summary": "<2-3 sentence overview mentioning key IOC values by name>",
    "threat_assessment": "<benign|suspicious|likely_malicious|malicious>",
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
     → For each sample (max 5): add_node(hash, <sha256>, metadata={names, family, detections}, source="virustotal")
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
  Same format as domain workflow STEP 8.
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
STEP 2: virustotal_file → extract contacted_domains, contacted_ips, network_infrastructure
  → For each domain: add_node(domain), add_edge(hash→domain, communicates_with)
  → For each ip: add_node(ip), defuse, add_edge(hash→ip, communicates_with)
  → Store detection ratio, malware family, signature names in seed metadata
STEP 3: otx_file, threatfox_search → link to threat reports
STEP 4: For top 3 domains/IPs: run STEP 4 of domain/IP workflow
STEP 5: report node

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
        gs.set_status(inv_id, "done")
    else:
        gs.set_status(inv_id, f"error rc={rc}")
