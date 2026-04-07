"""Spawn Claude Code in headless mode to run an investigation."""
import asyncio
import json
import os
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


def _write_mcp_config(inv_id: str) -> Path:
    """Write a per-investigation mcp.json with absolute paths and env vars baked in."""
    cfg = {
        "mcpServers": {
            "graph": {
                "command": sys.executable,
                "args": ["-m", "backend.mcp_servers.graph_mcp"],
                "env": {
                    "BOUNCE_INV_ID": inv_id,
                    "PYTHONPATH": str(ROOT),
                },
            },
            "cti": {
                "command": sys.executable,
                "args": ["-m", "backend.mcp_servers.cti_mcp"],
                "env": {
                    "PYTHONPATH": str(ROOT),
                },
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
R4. Budget: max 60 tool calls total. If you hit the limit, stop and write the report node.
R5. ALWAYS set source= to the API name that produced the data (e.g. "virustotal", "crtsh", "rdap", "dns").
R6. ALWAYS add edges between nodes. A node with no edges is useless to the analyst.

══════════════════════════════════════════════
GRAPH SCHEMA — node types and edge relations
══════════════════════════════════════════════
Node types: domain, ip, ns, registrar, cert, asn, email, url, hash, jarm, favicon, report
Tags to use: seed, suspicious, benign, cdn, parking, sinkhole, dyndns, shared_hosting, c2, phishing, expired

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

STEP 2 — Certificate transparency
  a. crtsh_subdomains(<seed>)
     → For each subdomain (max 40, pick most recent):
         add_node(domain, <subdomain>, source="crtsh")
         add_edge(seed→subdomain, has_subdomain)
     → Group by issuer — if many certs from same issuer, note in metadata

STEP 3 — VirusTotal enrichment
  a. virustotal_domain(<seed>)
     → Extract last_analysis_stats → store in seed metadata, tag if malicious>0
     → Extract last_dns_records → for each A: add_node(ip), add_edge resolves_to
     → Extract jarm_fingerprint → add_node(jarm, <jarm>), add_edge(seed→jarm, has_jarm)
     → Extract categories, popularity, threat_names → store in metadata
  b. virustotal_resolutions_domain(<seed>)
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

STEP 5 — Subdomain resolution (for each subdomain from STEP 2, max 10)
  a. dns_resolve(<subdomain>)
     → add_node(ip, <ip>), add_edge(subdomain→ip, resolves_to)
  b. If IP is new (not seen yet): run STEP 4 for it

STEP 6 — Threat intel
  a. threatfox_search(<seed>)
     → If hits: tag seed as suspicious/c2/phishing per malware_type
     → add_node(report, <malware_name>, metadata={confidence, malware_family, reporter}, source="threatfox")
     → add_edge(seed→report, known_ioc)
  b. otx_domain(<seed>)
     → Extract pulse names, tags, adversary → store in seed metadata
     → If malicious pulses: tag seed "suspicious"

STEP 7 — Strong discriminating pivots (only if you found these markers)
  IF you found a JARM fingerprint that is NOT a well-known CDN JARM:
    → shodan_search("ssl.jarm:<jarm>") → add co-infrastructure nodes
  IF you found a certificate serial/thumbprint:
    → shodan_search("ssl.cert.serial:<serial>") → add matching hosts
  IF VT favicon hash exists:
    → shodan_search("http.favicon.hash:<hash>") → add matching hosts
  IF registrant email found in RDAP:
    → virustotal_resolutions_domain(<other_domain_by_same_registrant>) if you find any

STEP 8 — Final report (MANDATORY — always do this last)
  add_node(report, "investigation_summary", metadata={
    "summary": "<2-3 sentence overview>",
    "threat_assessment": "<benign|suspicious|likely_malicious|malicious>",
    "key_findings": ["<finding1>", "<finding2>", ...],
    "discriminating_markers": ["<marker1>", ...],
    "pivot_suggestions": ["<what an analyst should investigate next>", ...],
    "ioc_list": ["<ioc1>", ...],
    "sources_used": ["dns","rdap","crtsh","virustotal",...]
  }, source="agent", tags=["report"])
  add_edge(seed→report, known_ioc)

══════════════════════════════════════════════
WORKFLOW — IP seed
══════════════════════════════════════════════
STEP 1: add_node(ip, seed, tags=["seed"]) → defuse(ip, seed)
  If CDN/sinkhole: tag and write report node, STOP.
STEP 2: rdap_ip, virustotal_ip, onyphe_ip, shodan_host, urlscan_search("ip:<seed>")
  → Graph ASN, open ports, banners, categories
STEP 3: virustotal_resolutions_ip → co-resident domains (max 15)
  → For each: add_node(domain), add_edge(ip→domain, co_resolves)
  → dns_resolve top 5 domains → add their IPs
STEP 4: reverse_dns, threatfox_search
STEP 5: report node

══════════════════════════════════════════════
WORKFLOW — HASH seed
══════════════════════════════════════════════
STEP 1: add_node(hash, seed, tags=["seed"])
STEP 2: virustotal_file → extract contacted_domains, contacted_ips, network_infrastructure
  → For each domain: add_node(domain), add_edge(hash→domain, communicates_with)
  → For each ip: add_node(ip), defuse, add_edge(hash→ip, communicates_with)
  → Store detection ratio, malware family, signature names in seed metadata
STEP 3: otx_file, threatfox_search → link to threat reports
STEP 4: For top 3 domains/IPs: run STEP 4 of domain/IP workflow
STEP 5: report node

══════════════════════════════════════════════
PARKING / NOISE HANDLING
══════════════════════════════════════════════
- Fan-out rule: if virustotal_resolutions_ip returns >80 domains for an IP, it is shared hosting.
  Tag ip as "shared_hosting", do NOT add all domains. Add 3 representative ones with evidence="sample only, shared hosting".
- If a co-resident domain is a known parking domain (godaddy, sedo, bodis, dan.com, above.com),
  tag it "parking" and do not pivot further.
- If NS points to dyndns provider: tag domain "dyndns", note in metadata.

NOW START the investigation. Execute the workflow step by step. Do not stop until STEP 8 is done.
"""


async def run_investigation(inv_id: str, seed_type: str, seed_value: str):
    user_prompt = f"Seed indicator: type={seed_type} value={seed_value}\nInvestigate now."
    env = os.environ.copy()
    env["BOUNCE_INV_ID"] = inv_id
    # Make sure the MCP servers (spawned by claude as child processes) can import the backend package
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    # Ensure the same python interpreter is used for MCP servers
    env["BOUNCE_PYTHON"] = sys.executable

    claude_path = shutil.which(CLAUDE_BIN) or CLAUDE_BIN
    mcp_cfg_path = _write_mcp_config(inv_id)
    _log(inv_id, "agent_starting", {"claude": claude_path, "cwd": str(ROOT), "mcp_config": str(mcp_cfg_path)})

    cmd = [
        claude_path, "-p", user_prompt,
        "--model", "sonnet",
        "--append-system-prompt", SYSTEM_PROMPT,
        "--mcp-config", str(mcp_cfg_path),
        "--strict-mcp-config",
        "--output-format", "stream-json",
        "--verbose",
        "--permission-mode", "bypassPermissions",
        # Whitelist only MCP tools — block all filesystem/shell tools
        "--allowedTools",
        "mcp__graph__add_node,mcp__graph__add_edge,mcp__graph__tag_node,"
        "mcp__graph__get_graph,mcp__graph__defuse,"
        "mcp__cti__dns_resolve,mcp__cti__reverse_dns,mcp__cti__crtsh_subdomains,"
        "mcp__cti__rdap_domain,mcp__cti__rdap_ip,"
        "mcp__cti__virustotal_domain,mcp__cti__virustotal_ip,mcp__cti__virustotal_file,"
        "mcp__cti__virustotal_resolutions_domain,mcp__cti__virustotal_resolutions_ip,"
        "mcp__cti__urlscan_search,mcp__cti__onyphe_domain,mcp__cti__onyphe_ip,"
        "mcp__cti__shodan_host,mcp__cti__shodan_search,"
        "mcp__cti__otx_domain,mcp__cti__otx_ip,mcp__cti__otx_file,"
        "mcp__cti__threatfox_search,mcp__cti__wayback",
        "--disallowedTools",
        "Bash,Edit,Write,MultiEdit,Read,Glob,Grep,NotebookEdit,WebSearch,WebFetch,Task,TodoWrite",
    ]

    # On Windows, .CMD shims must be launched via the shell
    use_shell = os.name == "nt"
    try:
        if use_shell:
            # Quote args carefully for cmd.exe
            quoted = " ".join(f'"{a}"' if (" " in a or '"' in a) else a for a in cmd)
            proc = await asyncio.create_subprocess_shell(
                quoted, cwd=str(ROOT), env=env,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
        else:
            proc = await asyncio.create_subprocess_exec(
                *cmd, cwd=str(ROOT), env=env,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
    except FileNotFoundError as e:
        _log(inv_id, "agent_error", f"claude CLI not found: {e}")
        gs.set_status(inv_id, "error: claude CLI not found")
        return

    async def pump_stderr():
        assert proc.stderr is not None
        async for line in proc.stderr:
            _log(inv_id, "agent_stderr", line.decode(errors="replace").rstrip())

    async def pump_stdout():
        assert proc.stdout is not None
        async for line in proc.stdout:
            text = line.decode(errors="replace").strip()
            if not text:
                continue
            try:
                evt = json.loads(text)
                _log(inv_id, "agent_" + evt.get("type", "msg"), evt)
            except Exception:
                _log(inv_id, "agent_stdout", text[:2000])

    await asyncio.gather(pump_stdout(), pump_stderr())
    rc = await proc.wait()
    _log(inv_id, "agent_exit", {"rc": rc})
    gs.set_status(inv_id, "done" if rc == 0 else f"error rc={rc}")
