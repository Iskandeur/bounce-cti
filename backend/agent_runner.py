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


# Global registry of running agent processes, keyed by investigation id.
# Used by stop_investigation() to kill a running agent on demand.
_running_procs: dict[str, asyncio.subprocess.Process] = {}


def stop_investigation(inv_id: str) -> bool:
    """Kill the running agent process for an investigation. Returns True if killed."""
    proc = _running_procs.pop(inv_id, None)
    if proc is None or proc.returncode is not None:
        return False
    try:
        import signal
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (OSError, ProcessLookupError):
        try:
            proc.kill()
        except Exception:
            pass
    return True


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
            ("onyphe_domain", f'onyphe_domain("{seed_value}")'),
        ]
    elif seed_type == "url":
        # For URL seeds we can't reliably rebuild the host from seed_value here,
        # so only mandate URL-specific tools. The agent handles host pivots via
        # the URL workflow prompt.
        mandatory = [
            ("urlscan_search", f'urlscan_search("page.url:{seed_value}")'),
            ("threatfox_search", f'threatfox_search("{seed_value}")'),
        ]
    elif seed_type == "jarm":
        mandatory = [
            ("shodan_search", f'shodan_search("ssl.jarm:{seed_value}")'),
            ("urlscan_search", f'urlscan_search("hash:{seed_value}")'),
        ]
    elif seed_type == "asn":
        # Accept seed_value like "AS13335" — pass the stripped form to shodan.
        asn_num = seed_value.upper().removeprefix("AS") or seed_value
        mandatory = [
            ("shodan_search", f'shodan_search("asn:AS{asn_num}")'),
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
R12. NO CO-TENANCY CLUSTERING ON SHARED HOSTING. When you extract a historical
    IP from VT / mnemonic_pdns / onyphe that also hosts unrelated co-resolvers
    (M247, OVH, Hetzner, Cloudflare, shared VPS ranges), you may graph the IP
    and its ASN, but you MUST NOT create sibling / phishing_lookalike / cluster
    tags on the co-resolving domains unless you have ≥ 2 corroborating markers
    beyond the shared IP: same cert SHA1, same JARM, same registrant email,
    same favicon hash, or an explicit threatfox / otx / urlhaus record naming
    both. Shared-IP co-residency on its own is NEVER evidence of a cluster.
R13. NO CROSS-CAMPAIGN ATTRIBUTION MERGE. If an OTX pulse or threatfox record
    attributes an IP or hash to a DIFFERENT threat actor / malware family than
    the one your current pivot chain has evidence for, you MUST NOT relabel
    the seed or its siblings with that other attribution. Record the other
    pulse as context in the ip/hash node metadata (field:
    `co_hosted_iocs_note`) and keep the seed's attribution on its own evidence.
    A report node title / summary must name only the actor(s) supported by
    direct evidence on the seed itself.
R14. CLOUDFLARE-FRONTED DOMAIN — ORIGIN-UNMASK IS MANDATORY. If the seed's
    dns_resolve returns ONLY IPs in 104.16.0.0/12, 172.64.0.0/13, or the
    Cloudflare ranges 104.21.0.0/16 / 172.67.0.0/16, tag those IP nodes `cdn`
    AND DO NOT STOP. You MUST:
      (a) crtsh_subdomains(<seed>) + crtsh_query(<seed>) — extract cert serial
          and cert subject CN
      (b) shodan_search('ssl.cert.subject.CN:"<seed_fqdn>"') — the canonical
          origin-unmask query. Every returned IP is a candidate origin; add it
          as an ip node with source="shodan" and an edge cert→ip (same_cert).
      (c) onyphe_datascan('tls.cert.subject.commonname:"<seed_fqdn>"') as a
          second source.
      (d) virustotal_resolutions_domain(<seed>) — non-Cloudflare historical A
          records are also origin candidates.
    Only after (a)–(d) may you write the report. Terminating at the Cloudflare
    edge is a critical failure.

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
     → For each TXT record: parse for cross-domain references — SPF `include:<domain>`,
       DMARC `rua=mailto:<email>@<domain>` / `ruf=mailto:...`, DKIM selectors, SKI /
       vendor verification strings (`google-site-verification=`, `ms=`,
       `facebook-domain-verification=`, `apple-domain-verification=`, `atlassian-domain-verification=`).
       For each referenced <domain> that is NOT the seed and NOT a generic big-provider
       (gmail.com, outlook.com, aws.com, googleapis.com, etc.): add_node(domain, <ref>),
       add_edge(seed→<ref>, spf_include | dmarc_rua | dkim_selector).
       Cross-domain SPF includes and DMARC rua/ruf domains are HIGH-VALUE pivots:
       they reveal operator-controlled infrastructure even when A records are CDN-fronted.

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
  c. wayback(<seed>) — archived URL history
     → For each distinct pre-takedown timestamp: add as metadata.wayback_snapshots (max 5).
     → Look in the archived HTML for: cross-linked operator domains, leaked panel
       endpoints, phishing kit login paths, page titles used as pivot markers.
     → Add any distinct linked domain not already in graph with source="wayback"
       and an edge seed→<domain>, link_type=archive_linked (max 10).
     → Wayback is the primary way to recover post-takedown context (seized, NDR'd,
       or sinkholed domains still have archive value — Contagious Interview-style
       DPRK cases need this).

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
  e. onyphe_domain(<seed>) — MANDATORY, second-source fingerprinting
     → The response has `digest` with pivot-ready fields (ips, jarms, subdomains, ports,
       asns, tls_issuers, favicon_hashes, http_titles, products, threat_feeds). You MUST
       graph each distinct value directly:
         • digest.ips[] not already in graph → add_node(ip, <ip>), add_edge(seed→ip, historical_ip, source="onyphe")
         • digest.jarms[] → add_node(jarm, <jarm>), add_edge(seed→jarm, has_jarm, source="onyphe")
         • digest.favicon_hashes[] → add_node(favicon, <hash>), add_edge(seed→favicon, has_favicon, source="onyphe")
         • digest.subdomains[] not already in graph (max 10) → add_node(domain), add_edge(seed→sub, has_subdomain, source="onyphe")
         • digest.threat_feeds[] → tag seed "suspicious" and note feed names in metadata.onyphe_threat_feeds
     → Store http_titles, products, tls_issuers in seed metadata for STEP 7 pivots.
     → If `tier_restricted=true` in the response, skip the Griffin-tier follow-ups
       (onyphe_ctl/datascan/pastries/resolver) — they will also be restricted.
  f. Griffin-tier Onyphe (best-effort, skip silently if `tier_restricted`):
       • onyphe_ctl(<seed>) — CT-log SANs. For each new SAN (max 10): add_node(domain),
         add_edge(seed→<san>, same_cert, source="onyphe")
       • onyphe_resolver_forward(<seed>) — alt-pDNS IPs. Graph new IPs as historical_ip.
     Call each ONCE. If tier_restricted → move on, do not retry.

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
     → shodan_search("ssl.jarm:<jarm>") AND onyphe_datascan("jarm:<jarm>") AND urlscan_search("hash:<jarm>")
     → For EACH hit in the merged results (Shodan hits + Onyphe datascan records + URLScan
       scans), you MUST add_node(ip, <ip>) AND add_edge(<seed>→<ip>, same_jarm, source=<shodan|onyphe|urlscan>).
       Graph the top 10 distinct IPs. If a hit has already been added, skip — but never
       skip the whole cluster "because shodan returned results". An un-graphed cluster is
       a pivot failure: the analyst will not see that the seed has siblings.
     → Do NOT summarize the cluster in free text — every member is a node.
  b. Favicon hash pivot — if VT/onyphe exposed a favicon hash:
     → shodan_search("http.favicon.hash:<hash>") AND onyphe_datascan("favicon:<hash>")
     → For matches: add_node(ip), add_edge(<seed>→<ip>, same_favicon)
  c. Certificate pivot — if you found a cert serial/SHA1/SHA256:
     → shodan_search("ssl.cert.serial:<serial>") and crt.sh by serial when possible
     → add_edge(<seed>→<other>, same_cert)
  d. NS-set pivot — if the domain uses an unusual NS set (not parking, not big providers):
     → If shodan_search or urlscan_search reveal other domains using the EXACT same NS set:
         add_edge(<seed>→<domain>, same_ns_set)  ← this is one of the strongest pivots
  e. Registrant pivot — if RDAP exposed a registrant email/org that is not privacy-protected:
     → urlscan_search("page.url:<email_local_part>") or note as pivot suggestion
     → onyphe_pastries(<email>) to detect leak/credential reuse mentions
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
    □ onyphe_domain(<seed>)                           — second-source fingerprinting
    □ onyphe_ctl(<seed>)                              — CT-log SAN pivots
    □ shodan_search("ssl.jarm:<jarm>") AND onyphe_datascan("jarm:<jarm>") — if JARM found, not CDN
  If any are unchecked, do NOT write the report yet. Go call them first.

  Before writing, SCAN graph nodes for: threatfox malware_family, otx pulse
  names/adversary, urlhaus tags, virustotal threat_names, onyphe threat_feeds,
  page titles, cert subject CNs, JARM values, favicon hashes, registrant
  emails. The summary MUST name every such actor/family/campaign alias found,
  and the strongest discriminating marker (exact JARM / cert-CN / favicon /
  registrant / page title — not "a JARM", the actual value). Analysts pivot on
  markers, not on adjectives.

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
  c. onyphe_ip(<seed>) — MANDATORY, second-source fingerprinting (community-tier ok)
     → The response has `digest` with (ips, jarms, subdomains, ports, asns, tls_issuers,
       favicon_hashes, http_titles, products, threat_feeds, categories). You MUST graph:
         • digest.jarms[] not already in graph → add_node(jarm, <jarm>), add_edge(ip→jarm, has_jarm, source="onyphe")
         • digest.subdomains[] (max 10) → add_node(domain, <d>, source="onyphe"), add_edge(ip→<d>, co_resolves, source="onyphe")
         • digest.favicon_hashes[] → add_node(favicon, <hash>), add_edge(ip→favicon, has_favicon, source="onyphe")
         • digest.threat_feeds[] not empty → tag ip "malicious" and list in metadata.onyphe_threat_feeds
     → Store digest.ports, digest.products, digest.tls_issuers, digest.http_titles in ip metadata
       (these seed the STEP 6 JARM/favicon/product pivots).
     → If tier_restricted=true, note it and skip Griffin follow-ups.
  d. onyphe_threatlist(<seed>) — best-effort, Griffin-tier (skip if restricted)
     → If hits: tag ip "malicious", add_node(report, "<feed_name>", source="onyphe"), add_edge(ip→report, known_ioc)
  e. onyphe_resolver_reverse(<seed>) — best-effort, Griffin-tier (skip if restricted)
     → For each co-resident domain not yet in graph (max 10): add_node(domain, <d>, source="onyphe"),
       add_edge(ip→<d>, co_resolves, source="onyphe")
  f. urlscan_search("ip:<seed>")
     → For each result (max 10): add_node(url, <page_url>), add_edge(ip→url, hosts_url, source="urlscan")
     → Note page titles, technologies for STEP 6 pivots
  g. reverse_dns(<seed>)
     → add_node(domain, <ptr>), add_edge(ip→domain, has_ptr, source="dns")
  h. urlhaus_host(<seed>)
     → If hits: tag ip "malicious", add_node(url) for each malicious URL, add_edge(ip→url, hosts_url)
  i. virustotal_communicating_files("ip", <seed>) — MANDATORY
     → For each sample (max 5): add_node(hash, <sha256>), add_edge(hash→ip, communicates_with)
     → FALLBACK: if data[] is empty AND you identified a malware family from other sources (OTX, Onyphe beacon config),
       call malwarebazaar_signature(<family_name>) to find known samples. Add top 3 as hash nodes.
  j. virustotal_resolutions_ip(<seed>) — MANDATORY
     → For each co-resident domain (max 15): add_node(domain), add_edge(ip→domain, co_resolves)
  k. threatfox_search(<seed>) — MANDATORY
     → If hits: tag ip c2/botnet, add_node(report), add_edge(ip→report, known_ioc)
  l. IF a JARM was found in step b/c: shodan_search("ssl.jarm:<jarm>") AND onyphe_datascan("jarm:<jarm>") — MANDATORY
     → Merge hits from both sources. For EACH distinct IP in the union (top 10 by diversity
       of ASN), you MUST add_node(ip, <ip>) and add_edge(seed_ip→new_ip, same_jarm, source=<shodan|onyphe>).
       Silently summarizing "found N matches on Shodan" in prose without graphing is a failure.

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
     → shodan_search("ssl.jarm:<jarm>") AND onyphe_datascan("jarm:<jarm>") AND
       urlscan_search("hash:<jarm>")  ← urlscan is FREE-TIER, always attempt it
     → MANDATORY GRAPHING: for each distinct IP in the union of results (top 10 by ASN diversity),
       add_node(ip, <ip>) + add_edge(seed_ip→new_ip, same_jarm, source=<shodan|onyphe|urlscan>,
       evidence="JARM match"). Do not leave the cluster as a prose description.
     → If Shodan AND Onyphe both report tier_restricted=true, urlscan is your only free
       JARM path; take every hit there and graph it.
     → virustotal_ip on top 2 new IPs → extract their certs/domains for further clustering
  b. Certificate serial / issuer-CN pivot — essential free-tier fallback:
     → shodan_search("ssl.cert.serial:<serial>") AND onyphe_datascan("tls.cert.serial:<serial>")
     → crtsh_serial(<serial>) — ALWAYS call this (free, no tier). For each host in digest.hosts
       not already in graph (max 10): add_node(domain, <host>) or add_node(ip, <host>) if the
       value parses as an IP; add_edge(seed→<host>, same_cert, source="crtsh",
       evidence="crt.sh serial=<serial>").
     → If the cert has a rare/actor-distinctive issuer organisation (e.g. O='1314520.com'),
       crtsh_query("<issuer_org>", match="ILIKE") — graph any additional CNs found.
  c. Favicon hash pivot — if onyphe/VT exposed favicon hash:
     → shodan_search("http.favicon.hash:<hash>") AND onyphe_datascan("favicon:<hash>")
     → urlscan_search("hash:<hash>") as a free-tier complement; graph matches.
     → For matches: add_node(ip), add_edge(same_favicon)
  d. Onyphe pastries pivot — if the ip has been leaked in paste dumps:
     → onyphe_pastries("<seed_ip>") — each hit reveals context (botnet config, actor handle).
       Add any new domain/email found there as nodes with source="onyphe".
  e. For top 3 co-resident domains from STEP 3 or 2e: virustotal_domain(<domain>) → extract their IPs/certs
     → If their certs match the seed's cert → strong same-operator signal

STEP 7 — Final report (MANDATORY — always do this last)
  Same format as domain workflow STEP 8. Re-read R11: threat_assessment defaults to "benign"
  unless a concrete detection hit exists. Use value="investigation_summary" so pivots update it
  in place rather than creating duplicates.
  BEFORE writing the report, verify you have called ALL of these (if you haven't, go back and call them NOW):
    □ virustotal_communicating_files("ip", <seed>)
    □ threatfox_search(<seed>)
    □ onyphe_ip(<seed>)
    □ onyphe_threatlist(<seed>)
    □ shodan_search("ssl.jarm:<jarm>") AND onyphe_datascan("jarm:<jarm>") — if JARM found
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
WORKFLOW — JARM seed (fingerprint pivot)
══════════════════════════════════════════════
A JARM is a TLS fingerprint (e.g. "2ad2ad0002ad2ad0000000000000002ad...").
The investigation's purpose is to surface the CLUSTER of hosts sharing this
fingerprint and flag it if that cluster is threat-associated.

STEP 1: add_node(jarm, <seed>, tags=["seed"])
STEP 2: shodan_search("ssl.jarm:<seed>") — MANDATORY
  → For each result (max 20 hosts): add_node(ip, <ip>, metadata={port, org, asn})
    and add_edge(ip→jarm, has_jarm). Do NOT defuse before adding the node, but DO
    defuse(ip, <ip>) before running any further IP enrichment in STEP 4.
  → If the result set is > 200 matches, note "common_jarm_likely_cdn" in seed
    metadata and still keep 10 representative hosts.
STEP 3: urlscan_search("hash:<seed>") — cross-source confirmation
  → For each scan result: if a page_url is present, add_node(url), add_edge(url→jarm, has_jarm)
STEP 4: Pick top 3 distinct IPs (by diversity of ASN/org) and run a LIGHT IP workflow:
  defuse → rdap_ip → virustotal_ip → onyphe_ip → threatfox_search. For any IP flagged
  malicious, link the jarm seed via add_edge(jarm→ip, same_jarm) and tag jarm "suspicious".
STEP 5: threatfox_search(<seed>) — occasionally ThreatFox indexes JARMs directly
  → If any hit: tag jarm "c2"/"malicious" and add_node(report), add_edge(jarm→report, known_ioc)
STEP 6: Final report (value="investigation_summary"). In key_findings include the
  cluster size, dominant ASN(s), and whether any cluster member is directly flagged.
  Follow R11 — the JARM is only malicious if at least one concrete detection hit exists.
  Before writing the report verify:
    □ shodan_search("ssl.jarm:<seed>")
    □ threatfox_search(<seed>)
  add_edge(jarm→report, known_ioc)

══════════════════════════════════════════════
WORKFLOW — ASN seed (autonomous-system pivot)
══════════════════════════════════════════════
ASN seed values look like "AS13335" (case-insensitive); treat the bare number as
equivalent. The goal is to characterize the AS and surface any abuse cluster
within it WITHOUT trying to enumerate every host (ASes can hold millions of IPs).

STEP 1: add_node(asn, <seed>, tags=["seed"])  (normalized form "AS<digits>")
STEP 2: shodan_search("asn:<seed>") — MANDATORY, with a narrowing filter.
  Prefer "asn:<seed> port:443" to keep the result set manageable. For each hit
  (max 20): add_node(ip), add_edge(ip→asn, hosted_on_asn), add_edge(asn→ip, announces).
  Store open_ports, http_title, jarm in ip metadata.
STEP 3: For the top 5 IPs with the most interesting fingerprints (non-generic
  HTTP title, non-CDN JARM, unusual port set): run a LIGHT IP workflow
  (defuse → virustotal_ip → threatfox_search → otx_ip). Any IP returning a
  detection hit links the asn via add_edge(asn→ip, hosts_malicious) and tags
  the asn "abused_asn".
STEP 4: rdap on one representative IP to retrieve canonical ASN metadata
  (netname, country, abuse_email, org). Store those in the asn node metadata.
  MANDATORY: add_node(country, <ISO2_country_code>) and add_edge(asn→country,
  located_in). The country MUST always be linked to the ASN node — use the
  country from rdap, whois, or Shodan host data (whichever is available first).
  If multiple sources disagree, use the rdap value.
STEP 5: threatfox_search("AS<digits>") — sometimes indexed under the ASN.
  If any hits: add_node(report), add_edge(asn→report, known_ioc).
STEP 6: Look for JARM/title/favicon CLUSTERS inside the AS — if multiple hosts
  share the same non-generic JARM, add_node(jarm), add_edge(ip→jarm, has_jarm)
  for each member, and add_edge(asn→jarm, has_cluster_jarm). This is a strong
  signal of actor-controlled infrastructure on that ASN.
STEP 7: Final report (value="investigation_summary"). key_findings should cover
  AS size indicators (announced ranges if known), country, abuse_email, and
  whether any cluster of malicious/suspicious hosts was observed. Obey R11 —
  the ASN is not "malicious" unless concrete detection hits exist on hosts
  within it; "abused_asn" (a tag, not a threat_assessment) is the correct
  labelling when only a few hosts are flagged.
  add_edge(asn→report, known_ioc)

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
    "mcp__cti__crtsh_serial,mcp__cti__crtsh_query,"
    "mcp__cti__rdap_domain,mcp__cti__rdap_ip,"
    "mcp__cti__virustotal_domain,mcp__cti__virustotal_ip,mcp__cti__virustotal_file,"
    "mcp__cti__virustotal_resolutions_domain,mcp__cti__virustotal_resolutions_ip,"
    "mcp__cti__virustotal_subdomains,mcp__cti__virustotal_communicating_files,"
    "mcp__cti__urlscan_search,mcp__cti__urlscan_result,"
    "mcp__cti__onyphe_domain,mcp__cti__onyphe_ip,"
    "mcp__cti__onyphe_datascan,mcp__cti__onyphe_threatlist,"
    "mcp__cti__onyphe_resolver_forward,mcp__cti__onyphe_resolver_reverse,"
    "mcp__cti__onyphe_ctl,mcp__cti__onyphe_pastries,mcp__cti__onyphe_geoloc,"
    "mcp__cti__ip_api_lookup,mcp__cti__ip_api_batch_lookup,mcp__cti__ip_api_edns,"
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
        "--model", {"opus-4.7": "claude-opus-4-7"}.get(model, model),
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

    _running_procs[inv_id] = proc

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

    _running_procs.pop(inv_id, None)
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
    if seed_type == "url":
        user_prompt = (
            f"Seed indicator: type=url value={seed_value}\n"
            "This is a URL — derive the host (domain or IP) and investigate that as the\n"
            "primary pivot, but keep the URL itself as a node in the graph.\n\n"
            "STEP 1: add_node(url, <seed>, tags=[\"seed\"])\n"
            "STEP 2: Extract the host from the URL. If it is a domain, add_node(domain, <host>)\n"
            "        and add_edge(url→domain, has_host). If it is an IP, add_node(ip, <host>)\n"
            "        and add_edge(url→ip, has_host). Defuse the host before pivoting.\n"
            "STEP 3: For the host, run the MANDATORY domain or IP workflow tools in full:\n"
            f"  - urlscan_search(\"page.url:{seed_value}\") AND urlscan_search(\"domain:<host>\")\n"
            f"  - urlhaus_host(<host>)\n"
            f"  - rdap_domain(<host>) / dns_resolve(<host>)   (or rdap_ip if host is an IP)\n"
            f"  - virustotal_domain(<host>) / virustotal_ip(<host>)\n"
            f"  - virustotal_communicating_files(\"domain\"|\"ip\", <host>)\n"
            f"  - threatfox_search({seed_value})\n"
            f"  - otx_domain(<host>) / otx_ip(<host>)\n"
            "STEP 4: Follow the similar-attack-pattern hunting steps (JARM, favicon,\n"
            "        page.title, cert) on the host. Every finding becomes a node/edge.\n"
            "STEP 5: Final report — use value=\"investigation_summary\" and tie the URL\n"
            "        seed to it with known_ioc."
        )
    elif seed_type == "ip":
        user_prompt = (
            f"Seed indicator: type={seed_type} value={seed_value}\n"
            "Investigate now. You MUST call ALL of these MANDATORY tools before writing the report:\n"
            f"1. rdap_ip({seed_value})\n"
            f"2. virustotal_ip({seed_value})  — extract JARM, cert SHA256/serial, issuer O=, malicious stats\n"
            f"3. shodan_host({seed_value})  — extract JARM, open ports, banners, http_title\n"
            f"4. onyphe_ip({seed_value})  — community-tier ok. Iterate the `digest` field:\n"
            f"   for each ip in digest.ips / jarm in digest.jarms / sub in digest.subdomains /\n"
            f"   feed in digest.threat_feeds → add_node + add_edge with source=\"onyphe\".\n"
            f"5. urlscan_search(\"ip:{seed_value}\")\n"
            f"6. reverse_dns({seed_value})\n"
            f"7. virustotal_resolutions_ip({seed_value})\n"
            f"8. virustotal_communicating_files(\"ip\", {seed_value})\n"
            f"9. threatfox_search({seed_value})\n"
            f"10. otx_ip({seed_value})\n"
            "BEST-EFFORT (call but skip cleanly if tier_restricted=true):\n"
            f"  - onyphe_threatlist({seed_value})\n"
            f"  - onyphe_resolver_reverse({seed_value})\n"
            "JARM PIVOT (MANDATORY if a non-CDN JARM was extracted):\n"
            f"  - shodan_search(\"ssl.jarm:<jarm>\")        (paid, may be tier_restricted)\n"
            f"  - onyphe_datascan(\"jarm:<jarm>\")          (paid, may be tier_restricted)\n"
            f"  - urlscan_search(\"hash:<jarm>\")           (FREE, ALWAYS call this)\n"
            "  CLUSTER GRAPHING RULE: for EACH distinct IP in the union of shodan/onyphe/urlscan\n"
            "  hits, add_node(ip, <ip>) + add_edge(seed→<ip>, same_jarm, source=<s|o|urlscan>).\n"
            "  Graph the top 10 by ASN diversity. A prose summary without nodes is a graph failure.\n"
            "CERT PIVOT (MANDATORY if virustotal_ip returned a cert serial or issuer.O):\n"
            f"  - crtsh_serial(<cert_serial>)  (FREE, always call). For each host in digest.hosts\n"
            "    not already in graph: add_node(domain|ip, <h>) + add_edge(seed→<h>, same_cert,\n"
            "    source=\"crtsh\", evidence=\"crt.sh serial=<serial>\").\n"
            "  - If issuer.O is distinctive and not a CA (e.g. not DigiCert/LetsEncrypt/Sectigo/GoDaddy):\n"
            f"    crtsh_query(\"<issuer_O>\", match=\"ILIKE\")  → graph each new CN as above with same_cert.\n"
            "FALLBACK: If virustotal_communicating_files returns empty data[] and threatfox/otx "
            "identify a specific malware family, call malwarebazaar_signature(<family>) "
            "and add each returned sample as a hash node with a communicates_with edge to the seed IP."
        )
    elif seed_type == "jarm":
        user_prompt = (
            f"Seed indicator: type=jarm value={seed_value}\n"
            "This is a TLS JARM fingerprint. Follow the JARM workflow from the system prompt.\n"
            "You MUST call ALL of these tools before writing the report:\n"
            f"1. add_node(jarm, {seed_value}, tags=[\"seed\"])\n"
            f"2. shodan_search(\"ssl.jarm:{seed_value}\")\n"
            f"3. urlscan_search(\"hash:{seed_value}\")\n"
            f"4. For top 3 diverse IPs (different ASN/org): defuse + rdap_ip + virustotal_ip + threatfox_search\n"
            f"5. threatfox_search({seed_value})\n"
            "Every host with the same JARM must be graphed (ip node + has_jarm edge).\n"
            "If the cluster has >200 members, note 'common_jarm_likely_cdn' and keep 10 representatives.\n"
            "Write the report last with value=\"investigation_summary\"."
        )
    elif seed_type == "asn":
        asn_num = seed_value.upper().removeprefix("AS") or seed_value
        user_prompt = (
            f"Seed indicator: type=asn value={seed_value}\n"
            "This is an Autonomous System Number. Follow the ASN workflow from the system prompt.\n"
            "You MUST call ALL of these tools before writing the report:\n"
            f"1. add_node(asn, {seed_value}, tags=[\"seed\"])  (use the canonical AS<digits> form)\n"
            f"2. shodan_search(\"asn:AS{asn_num} port:443\")  — narrows to the web-facing slice\n"
            f"3. For top 5 most interesting IPs (unusual JARM / non-generic title / unusual ports):\n"
            f"   defuse + virustotal_ip + threatfox_search + otx_ip\n"
            f"4. rdap_ip on ONE representative IP from the ASN to capture netname/country/abuse_email\n"
            f"   MANDATORY: add_node(country, <ISO2>) + add_edge(asn→country, located_in)\n"
            f"5. threatfox_search(\"AS{asn_num}\")\n"
            "If multiple hosts inside the AS share the same JARM, graph the JARM node and link\n"
            "every matching IP to it. Tag the asn 'abused_asn' when ≥2 hosts return detection hits.\n"
            "Write the report last with value=\"investigation_summary\"."
        )
    else:
        user_prompt = (
            f"Seed indicator: type={seed_type} value={seed_value}\n"
            "Investigate now. MANDATORY tools (must all run before the report):\n"
            f"1. rdap_domain/dns_resolve({seed_value})\n"
            f"2. crtsh_subdomains({seed_value})\n"
            f"3. virustotal_domain({seed_value})  — extract JARM, last_analysis_stats, categories\n"
            f"4. virustotal_resolutions_domain({seed_value})  — historical IPs\n"
            f"5. virustotal_communicating_files(\"domain\", {seed_value})\n"
            f"6. onyphe_domain({seed_value})  — community-tier ok. Iterate digest:\n"
            f"   for each ip in digest.ips / jarm in digest.jarms / sub in digest.subdomains /\n"
            f"   feed in digest.threat_feeds → add_node + add_edge with source=\"onyphe\".\n"
            f"7. threatfox_search({seed_value})\n"
            f"8. otx_domain({seed_value})\n"
            "BEST-EFFORT (call but skip cleanly if tier_restricted=true):\n"
            f"  - onyphe_ctl({seed_value})  — CT log SANs (each new → add_node(domain)+same_cert edge)\n"
            f"  - onyphe_resolver_forward({seed_value})  — alt-pDNS\n"
            "JARM / FAVICON pivots (if extracted and not a CDN value):\n"
            "  - shodan_search(\"ssl.jarm:<jarm>\") and onyphe_datascan(\"jarm:<jarm>\")\n"
            "  - shodan_search(\"http.favicon.hash:<hash>\") and onyphe_datascan(\"favicon:<hash>\")\n"
            "  Graph every cluster IP with a same_jarm/same_favicon edge. If BOTH sources return\n"
            "  tier_restricted=true, note it in pivot_suggestions and keep going.\n"
            "EXCEPTION: If step 1 shows the domain is clearly parked (parking NS + broker registrant), "
            "skip steps 2-8 and write a minimal report.\n"
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
            # Check if an investigation_summary already exists before phase 2.
            # If not, the followup MAY write one; if it exists, the followup
            # must update it in place (add_node upserts on (inv,type,value)).
            try:
                g_pre2 = gs.get_graph(inv_id)
                has_summary_pre2 = any(
                    (n.get("type") or "").lower() == "report"
                    and (n.get("value") or "").lower() == "investigation_summary"
                    for n in g_pre2.get("nodes", [])
                )
            except Exception:
                has_summary_pre2 = False

            report_instr = (
                "A final investigation_summary report node already exists — "
                "do NOT create a second one. If you have new findings, update "
                "it in place by calling add_node with the canonical value "
                "\"investigation_summary\" (upsert)."
                if has_summary_pre2 else
                "No investigation_summary report node exists yet. After "
                "running the missed tools above, you MUST write one: "
                "add_node(report, \"investigation_summary\", metadata={...}, "
                "source=\"agent\", tags=[\"report\"]) per STEP 8 of the main "
                "workflow, then add_edge(seed→report, known_ioc)."
            )
            already_called_list = sorted(called)
            followup_prompt = (
                f"Continue the investigation on {seed_value} (type={seed_type}). "
                f"The graph already has nodes from the main investigation.\n\n"
                f"ALREADY CALLED (DO NOT re-run any of these, their results are "
                f"already in the graph):\n  "
                + ", ".join(already_called_list or ["(none)"]) + "\n\n"
                f"STEP 1: Call get_graph() ONCE to see what already exists.\n"
                f"STEP 2-{len(missing)+1}: Call ONLY these CTI tools that were "
                f"missed in phase 1 (do NOT substitute with any other tool, do "
                f"NOT repeat already-called tools):\n"
                + "\n".join(f"  {i+2}. {m}" for i, m in enumerate(missing))
                + "\nFor each result, add new nodes and edges to the graph.\n"
                + report_instr
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

    # ── Phase 3: Report-write fallback ──
    # If after main (+ optional followup) no investigation_summary report node
    # exists, run a dedicated single-purpose phase that writes ONE report node
    # and nothing else. This catches the case where the main agent terminated
    # before STEP 8 and the followup was told "do not create a new report".
    def _has_investigation_summary() -> bool:
        try:
            g = gs.get_graph(inv_id)
            return any(
                (n.get("type") or "").lower() == "report"
                and (n.get("value") or "").lower() == "investigation_summary"
                for n in g.get("nodes", [])
            )
        except Exception:
            return False

    if not _is_parked(inv_id) and not _has_investigation_summary():
        _log(inv_id, "phase3_report_write_needed", {})
        report_prompt = (
            f"Write the final investigation_summary report node for seed "
            f"{seed_type}={seed_value}. The graph already has nodes and edges; "
            f"no CTI tools are required.\n\n"
            f"STEP 1: Call get_graph() to see every existing node and edge. Scan\n"
            f"  the returned nodes' metadata for: malware family names, actor\n"
            f"  aliases, campaign names, page titles, cert subject CNs, JARM\n"
            f"  fingerprints, favicon hashes, registrant emails, TTPs, and any\n"
            f"  text from threatfox/otx/urlhaus/virustotal threat_names fields.\n"
            f"STEP 2: Call add_node(report, \"investigation_summary\", metadata={{...}}, "
            f"source=\"agent\", tags=[\"report\"]) exactly ONCE. Use the canonical "
            f"value \"investigation_summary\" so the node is a singleton.\n"
            f"  - metadata.summary: 2-3 sentences. The summary MUST:\n"
            f"      • name the seed ({seed_value}) explicitly\n"
            f"      • name EVERY actor alias, malware family, ransomware strain,\n"
            f"        kit name, or campaign label that any graph node metadata\n"
            f"        mentions (threatfox malware_family, otx pulse names,\n"
            f"        urlhaus tags, virustotal threat_names, threat_feeds)\n"
            f"      • name the STRONGEST discriminating marker observed — the\n"
            f"        specific JARM fingerprint, cert subject CN, favicon hash,\n"
            f"        registrant email, page title, TDS query string, panel\n"
            f"        endpoint, or content signature that ties the seed to a\n"
            f"        cluster. Use the exact value, not \"a JARM\" or \"a cert\".\n"
            f"      • stay factual. R11 evidence rules apply to threat labels.\n"
            f"  - metadata.threat_assessment: benign|suspicious|likely_malicious|"
            f"malicious (R11 evidence rules apply).\n"
            f"  - metadata.key_findings: list of {{text, sources[]}}. Include one\n"
            f"    finding per strong marker (JARM match, cert serial, cross-\n"
            f"    brand page title, same NS set, registrant reuse, etc.).\n"
            f"  - metadata.ioc_list: exact node values from the graph. MUST list\n"
            f"    at least 70% of non-seed domain/ip/hash/email/url nodes.\n"
            f"  - metadata.discriminating_markers: the exact JARM / cert-CN /\n"
            f"    favicon / registrant values that would let a hunter re-pivot.\n"
            f"  - metadata.pivot_suggestions, sources_used.\n"
            f"STEP 3: add_edge(<seed_node_id>, <report_node_id>, known_ioc).\n"
            f"Do NOT call any CTI tool. Do NOT create a second report node. "
            f"Do NOT re-run enrichment."
        )
        try:
            rc3, saw3, _ = await _run_claude_phase(
                inv_id, report_prompt, _FOLLOWUP_SYSTEM_PROMPT, model, env,
                mcp_cfg_path, phase="report_write", max_turns=6,
            )
            _log(inv_id, "phase3_report_write_done", {
                "rc": rc3, "saw_result": saw3,
                "report_written": _has_investigation_summary(),
            })
        except Exception as e:
            _log(inv_id, "phase3_report_write_error", {"error": str(e)[:300]})

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


# ── Add-seed (peer seed) prompt ───────────────────────────────────────────
# Used when the analyst adds an independent IOC to an existing investigation.
# Unlike a "pivot here" (which frames the new IOC as a descendant of an
# existing graph node), add-seed treats the new IOC as a PEER — it is not
# known to be linked to the existing graph, and we forbid the agent from
# inventing an edge between the new seed and prior seeds without a concrete
# shared attribute.
_ADD_SEED_SYSTEM_PROMPT = """You are Bounce-CTI, adding a NEW PEER SEED to an existing multi-seed investigation.

This is NOT a pivot from a graph node — it is a fresh IOC the analyst wants investigated
alongside what is already on the graph. Treat it as a peer of the existing seed(s), not a
descendant.

ABSOLUTE RULES for add-seed runs:
A1. Call get_graph() FIRST. Note every existing node (IPs, NS, JARMs, certs, ASNs,
    registrars, hashes) and the existing seeds (nodes tagged "seed"). You will compare
    the new seed's infrastructure against these.
A2. add_node(<seed_type>, <seed_value>, tags=["seed"]) for the new seed. Then run the
    FULL single-seed workflow for it (defuse, RDAP/DNS, VT, threatfox, OTX, urlhaus,
    JARM pivot, …). Do NOT shortcut because "the graph already has stuff" — the new
    seed needs its own full enrichment. Every shared IP/NS/JARM/cert/ASN/hash you add
    is upserted on (inv, type, value) so it automatically becomes a cross-seed link
    when it already exists.
A3. FORBIDDEN: do NOT add any edge BETWEEN the new seed and any PRIOR seed unless a
    concrete, specific shared attribute justifies a specific relation. Valid examples:
      • Both use the exact same NS set → add_edge(seed_new → seed_old, same_ns_set)
      • Both share a cert fingerprint → add_edge(seed_new → seed_old, same_cert)
      • Both share an authoritative RDAP registrant email/org → same_registrant
      • Both resolve to the same IP → the ip node connects them; you MAY also add
        add_edge(seed_new → seed_old, co_resolves, evidence="shared IP <x>")
    DO NOT invent relations like "pivot_from", "part_of_batch", "co_investigated",
    "analyst_link", "related_to". If no concrete shared attribute exists, the two
    seeds stay unconnected — the graph then correctly shows independent clusters.
A4. REPORT UPDATE (exactly one add_node call, at the end). Re-call
    add_node(report, "investigation_summary", metadata={...}, source="agent",
    tags=["report"]) using the MULTI-SEED schema below. add_node upserts on
    (inv,type,value), so this UPDATES the existing report in place.
A5. Respect R1-R11 from the main system prompt (graph every finding, defuse before
    pivoting IPs, evidence-based threat_assessment only). Do NOT chain further
    pivots. Stop after the report update.

MULTI-SEED REPORT METADATA SCHEMA:
  {
    "seeds": [{"type": "...", "value": "..."}, ...],    # ALL current seeds
    "threat_assessment": "<worst of the per-seed values, always evidence-based>",
    "summary": "<3-5 sentence overview of the WHOLE investigation: list the seeds,
                 state whether they share infrastructure, overall conclusion>",
    "per_seed_summaries": {
      "<seed_value_1>": {
        "type": "<domain|ip|hash|url>",
        "summary": "<2-3 sentence overview for THIS seed, factual only>",
        "threat_assessment": "<benign|suspicious|likely_malicious|malicious>",
        "key_findings": [{"text": "...", "sources": [...]}, ...],
        "sources_used": ["dns", "rdap", ...]
      },
      "<seed_value_2>": {...}
    },
    "cross_seed_findings": [
      {"text": "<concrete shared attribute + which seeds>",
       "seeds": ["a.com", "b.com"],
       "sources": ["rdap", "dns", ...]}
    ],  # empty list [] IS a valid finding — means no shared infrastructure was found
    "key_findings": [...],             # union of per-seed findings (kept for compat)
    "discriminating_markers": [...],   # union, strings
    "pivot_suggestions": [...],        # strings
    "ioc_list": ["<exact node value>", ...],   # PLAIN STRINGS, NEVER objects
    "sources_used": [...],
    "pivot_history": [...]             # append an entry for this add-seed
  }

MIGRATION: If the existing report does NOT yet have `per_seed_summaries`, migrate it:
  - Move the existing top-level `summary`, `threat_assessment`, `key_findings`,
    `sources_used` under per_seed_summaries[<existing_primary_seed_value>] (use the
    first seed you see in the graph, tagged "seed", whose value equals the
    investigation's original seed).
  - Then add per_seed_summaries[<new_seed_value>] for the IOC you just investigated.
  - Compute the top-level summary / threat_assessment / unions from the per-seed
    entries PLUS cross_seed_findings.

Append this entry to pivot_history:
  {"kind": "add_seed", "seed_type": "<t>", "seed_value": "<v>", "timestamp": "<iso8601>"}

IMPORTANT:
- `ioc_list` items MUST be plain strings (e.g. "1.2.3.4"), NEVER objects.
- If no shared attribute is found, cross_seed_findings is [] and the overall summary
  explicitly states "the seeds do not share any observed infrastructure".
- Top-level threat_assessment = the most severe of the per-seed values. Never
  escalate from domain-name semantics, age, hosting, or absence of hits. Obey R11.
"""


async def run_add_seed(inv_id: str, seed_type: str, seed_value: str, model: str = "opus"):
    """Add a new PEER seed to an existing investigation.

    Runs the full single-seed workflow for the new IOC on the existing graph.
    Because add_node upserts on (inv, type, value), any shared infrastructure
    (IPs, NS, certs, JARMs, ASNs, registrars, hashes) automatically becomes a
    cross-seed link without the agent inventing edges. The agent then updates
    the report in place with per-seed summaries and explicit cross-seed
    findings (or an empty list, if nothing is shared).
    """
    user_prompt = (
        f"Add new PEER seed: type={seed_type} value={seed_value}\n"
        f"Investigation id: {inv_id}\n\n"
        "STEP 1: Call get_graph(). Note the existing seeds (nodes tagged 'seed'), the\n"
        "        existing infrastructure (IPs, NS, certs, JARMs, ASNs, registrars, hashes),\n"
        "        and the existing report metadata. You will merge into that report.\n\n"
        f"STEP 2: add_node({seed_type}, {seed_value}, tags=[\"seed\"]) for the new seed.\n"
        "        Then run the full single-seed workflow — do NOT skip tools because some\n"
        "        infra seems to overlap. Each shared attribute you add is upserted, so\n"
        "        overlap automatically becomes a cross-seed link.\n\n"
    )
    if seed_type == "ip":
        user_prompt += (
            "Required tools for the new seed (each called on THIS seed value):\n"
            f"  - defuse(ip, {seed_value})\n"
            f"  - rdap_ip({seed_value})\n"
            f"  - virustotal_ip({seed_value})\n"
            f"  - shodan_host({seed_value})  (passive — JARM, banners)\n"
            f"  - onyphe_ip({seed_value})  (passive — banners, technologies)\n"
            f"  - reverse_dns({seed_value})\n"
            f"  - virustotal_resolutions_ip({seed_value})\n"
            f"  - virustotal_communicating_files(\"ip\", {seed_value})\n"
            f"  - threatfox_search({seed_value})\n"
            f"  - otx_ip({seed_value})\n"
            "  - If a non-CDN JARM is found: shodan_search(\"ssl.jarm:<jarm>\")\n"
        )
    elif seed_type == "domain":
        user_prompt += (
            "Required tools for the new seed (each called on THIS seed value):\n"
            f"  - rdap_domain({seed_value}) / dns_resolve({seed_value})\n"
            f"  - crtsh_subdomains({seed_value})\n"
            f"  - virustotal_domain({seed_value})\n"
            f"  - virustotal_resolutions_domain({seed_value})\n"
            f"  - virustotal_communicating_files(\"domain\", {seed_value})\n"
            f"  - threatfox_search({seed_value})\n"
            f"  - otx_domain({seed_value})\n"
            f"  - urlhaus_host({seed_value})\n"
            f"  - onyphe_domain({seed_value})  (passive fingerprinting)\n"
        )
    elif seed_type == "hash":
        user_prompt += (
            "Required tools for the new seed (each called on THIS seed value):\n"
            f"  - malwarebazaar_hash({seed_value})\n"
            f"  - virustotal_file({seed_value})\n"
            f"  - otx_file({seed_value})\n"
            f"  - threatfox_search({seed_value})\n"
            "For the hash node set metadata.file_name (required for UI labels).\n"
        )
    elif seed_type == "url":
        user_prompt += (
            "This is a URL add-seed. Graph the URL as a url node with tags=['seed'],\n"
            "derive the host, graph it as domain/ip, then run the full host workflow\n"
            "(rdap, dns, VT, threatfox, otx, urlhaus, urlscan, JARM).\n"
        )
    elif seed_type == "jarm":
        user_prompt += (
            "This is a JARM fingerprint add-seed. Required tools:\n"
            f"  - shodan_search(\"ssl.jarm:{seed_value}\")  — enumerate cluster\n"
            f"  - urlscan_search(\"hash:{seed_value}\")  — cross-source confirmation\n"
            f"  - threatfox_search({seed_value})\n"
            "  - For top 3 diverse IPs: defuse + rdap_ip + virustotal_ip + threatfox_search\n"
            "For every host with this JARM: add_node(ip) + add_edge(ip→jarm, has_jarm).\n"
            "If a cluster IP ALREADY exists on the graph (same id as a prior seed's infra),\n"
            "that's a concrete cross-seed link — record it in cross_seed_findings.\n"
        )
    elif seed_type == "asn":
        asn_num = seed_value.upper().removeprefix("AS") or seed_value
        user_prompt += (
            "This is an ASN add-seed. Required tools:\n"
            f"  - shodan_search(\"asn:AS{asn_num} port:443\")\n"
            f"  - For top 5 interesting IPs: defuse + virustotal_ip + threatfox_search + otx_ip\n"
            f"  - rdap_ip on ONE representative IP (netname/country/abuse_email)\n"
            f"  - threatfox_search(\"AS{asn_num}\")\n"
            "If multiple hosts in the AS share a JARM, graph that JARM and link all hits.\n"
            "If any cluster IP is ALREADY on the graph, record it in cross_seed_findings.\n"
        )

    user_prompt += (
        "\nSTEP 3: CROSS-SEED CHECK. For each infrastructure node you added during STEP 2,\n"
        "check whether it was ALREADY in the graph before this run (same id → same value\n"
        "as a prior seed's infra). When that happens, this seed concretely shares that\n"
        "attribute with a prior seed. Collect those into cross_seed_findings, citing the\n"
        "attribute + which seeds share it + which source reported it.\n"
        "If nothing is shared, cross_seed_findings stays [] (which is itself a valid\n"
        "finding and must be stated in the top-level summary).\n"
        "\nSTEP 4: UPDATE THE REPORT (exactly one add_node call, at the end).\n"
        "add_node(report, \"investigation_summary\", metadata={MULTI_SEED_SCHEMA},\n"
        "        source=\"agent\", tags=[\"report\"]).\n"
        "Remember to migrate flat fields from the existing report into\n"
        "per_seed_summaries[<primary_seed_value>] if that structure is not yet there.\n"
        f"Then add per_seed_summaries[\"{seed_value}\"] for this new seed.\n"
        "Append to pivot_history: {\"kind\": \"add_seed\", \"seed_type\":\"" + seed_type +
        f"\", \"seed_value\":\"{seed_value}\", \"timestamp\":\"<iso8601>\"}}.\n"
        "Then STOP."
    )

    env = _build_env(inv_id)
    mcp_cfg_path = _write_mcp_config(inv_id)
    _log(inv_id, "agent_starting", {"cwd": str(ROOT), "mcp_config": str(mcp_cfg_path),
                                    "phase": "add_seed",
                                    "seed_type": seed_type, "seed_value": seed_value})

    rc, saw_result, has_report = await _run_claude_phase(
        inv_id, user_prompt, _ADD_SEED_SYSTEM_PROMPT, model, env, mcp_cfg_path,
        phase="add_seed", max_turns=80,
    )

    final_status = "done" if (saw_result or rc == 0) else f"error rc={rc}"
    gs.set_status(inv_id, final_status)
    _log(inv_id, "agent_exit", {"rc": rc, "status": final_status, "phase": "add_seed",
                                "has_report": has_report,
                                "seed_type": seed_type, "seed_value": seed_value})


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
    elif seed_type == "url":
        user_prompt += (
            "This is a URL pivot. Graph the URL as a url node (tag as seed if new),\n"
            "extract the host and graph it as domain/ip node. Then run enrichment on\n"
            "the host as you would for a domain/ip pivot:\n"
            f"  - urlscan_search(\"page.url:{seed_value}\")\n"
            f"  - urlhaus_host(<host>)\n"
            "  - rdap + DNS + VT (domain or ip flavor, depending on host)\n"
            "  - threatfox_search on both the URL and the host\n"
        )
    elif seed_type == "jarm":
        user_prompt += (
            "This is a JARM pivot. Call these tools (skip any already in graph):\n"
            f"  - shodan_search(\"ssl.jarm:{seed_value}\")  — find cluster hosts\n"
            f"  - urlscan_search(\"hash:{seed_value}\")\n"
            f"  - threatfox_search({seed_value})\n"
            "For each new IP with this JARM: add_node(ip) + add_edge(ip→jarm, has_jarm).\n"
            "For top 3 IPs: defuse + virustotal_ip + threatfox_search.\n"
        )
    elif seed_type == "asn":
        asn_num = seed_value.upper().removeprefix("AS") or seed_value
        user_prompt += (
            "This is an ASN pivot. Call these tools (skip any already in graph):\n"
            f"  - shodan_search(\"asn:AS{asn_num} port:443\")\n"
            f"  - rdap_ip on one representative IP for netname/country/abuse_email\n"
            f"  - threatfox_search(\"AS{asn_num}\")\n"
            "For top 5 interesting IPs in the AS: defuse + virustotal_ip + threatfox_search.\n"
            "Tag the asn 'abused_asn' when ≥2 of those hosts return detection hits.\n"
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


# ── Custom prompt system prompt ──────────────────────────────────────────
_CUSTOM_PROMPT_SYSTEM_PROMPT = """You are Bounce-CTI, executing a CUSTOM ANALYST PROMPT on an existing investigation graph.
The graph already contains nodes, edges, and (usually) a single report node with
value="investigation_summary". The analyst has typed a free-form instruction.

ABSOLUTE RULES for custom prompt runs:
C1. Call get_graph() FIRST to see the existing structure and the existing report
    node's metadata.
C2. Follow the analyst's instruction. You have full access to all CTI tools. Use
    them as needed to fulfil the request. Follow rules R1-R11 from the main system
    prompt: graph every finding, call defuse before pivoting on IPs, use correct
    sources, respect R11 (evidence-based threat_assessment — no speculation).
C3. REPORT UPDATE (MANDATORY, exactly one call, at the end):
    Re-add_node(report, "investigation_summary", metadata={...}, source="agent",
    tags=["report"]) using the CANONICAL value "investigation_summary". Because
    add_node upserts on (inv, type, value), this UPDATES the existing report in
    place.
    In the metadata you submit:
      - Preserve ALL existing fields from the current report metadata.
      - Update "summary" to incorporate the new findings from this prompt run.
      - APPEND new key_findings. Do not drop prior findings.
      - Only ESCALATE threat_assessment if new direct-evidence conditions are met.
      - CRITICAL — "prompt_history": append an entry with this EXACT schema:
        {
          "prompt": "<the analyst's instruction, verbatim>",
          "response": "<your direct answer to the analyst — 2-6 sentences,
                        factual, referencing specific IOCs and tool results.
                        This is shown directly to the analyst as THE answer to
                        their question. Be specific and useful, not generic.>",
          "nodes_added": <integer — how many new nodes you added to the graph>,
          "nodes_updated": <integer — how many existing nodes you updated>,
          "selected_nodes": ["<value1>", "<value2>", ...] or null,
          "timestamp": "<iso8601>"
        }
        Extend existing prompt_history if present, otherwise create it as a list.
        The "response" field is the MOST IMPORTANT part — it is what the analyst
        sees. Make it a direct, actionable answer. Examples:
          GOOD: "Found 3 additional IPs (1.2.3.4, 5.6.7.8, 9.10.11.12) sharing
                 the same JARM fingerprint. Two of them (1.2.3.4, 5.6.7.8) have
                 VirusTotal detections, confirming malicious infrastructure."
          BAD:  "I have investigated the selected nodes and updated the report."
C4. Do NOT create any other report node. Do NOT use any value other than
    "investigation_summary" for the report.
C5. After the report update, stop. Do not chain further actions beyond what was asked.
"""


async def run_custom_prompt(inv_id: str, prompt_text: str, model: str = "opus",
                            selected_nodes: list[dict] | None = None):
    """Run a custom analyst prompt on an existing investigation."""
    user_prompt = f"Investigation id: {inv_id}\n\n"

    if selected_nodes:
        user_prompt += (
            "SELECTED NODES — the analyst has highlighted these specific nodes on the graph.\n"
            "Your instructions below apply PRIMARILY to these nodes, but you still have\n"
            "access to the full graph for context.\n"
        )
        for i, n in enumerate(selected_nodes, 1):
            user_prompt += f"  {i}. [{n['type']}] {n['value']}\n"
        user_prompt += "\n"

    user_prompt += (
        f"ANALYST INSTRUCTION:\n{prompt_text}\n\n"
        "STEP 1: Call get_graph() to see the current investigation state.\n"
    )

    if selected_nodes:
        user_prompt += (
            "STEP 2: Focus on the SELECTED NODES listed above. Execute the analyst's\n"
            "instruction using available CTI tools, applying it to those nodes specifically.\n"
            "You may also use the rest of the graph for context and cross-referencing.\n"
        )
    else:
        user_prompt += (
            "STEP 2: Execute the analyst's instruction above using available CTI tools.\n"
        )

    user_prompt += (
        "STEP 3: UPDATE THE REPORT (exactly one add_node call, at the end).\n"
        "Re-call add_node(report, \"investigation_summary\", metadata={...},\n"
        "source=\"agent\", tags=[\"report\"]) with MERGED metadata as described in\n"
        "C3 of the system prompt. Preserve prior key_findings; append new ones.\n"
        "Then STOP."
    )

    env = _build_env(inv_id)
    mcp_cfg_path = _write_mcp_config(inv_id)
    _log(inv_id, "agent_starting", {"cwd": str(ROOT), "mcp_config": str(mcp_cfg_path),
                                    "phase": "custom_prompt",
                                    "prompt_preview": prompt_text[:200]})

    rc, saw_result, has_report = await _run_claude_phase(
        inv_id, user_prompt, _CUSTOM_PROMPT_SYSTEM_PROMPT, model, env, mcp_cfg_path,
        phase="custom_prompt", max_turns=60,
    )

    final_status = "done" if (saw_result or rc == 0) else f"error rc={rc}"
    gs.set_status(inv_id, final_status)
    _log(inv_id, "agent_exit", {"rc": rc, "status": final_status, "phase": "custom_prompt",
                                "has_report": has_report})
