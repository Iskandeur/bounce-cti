"""Spawn Claude Code in headless mode to run an investigation."""
import asyncio
import json
import os
from pathlib import Path
from .config import CLAUDE_BIN
from . import graph_store as gs

ROOT = Path(__file__).resolve().parent.parent
MCP_CONFIG = ROOT / "mcp.json"

SYSTEM_PROMPT = """You are Bounce-CTI, an autonomous CTI investigation agent.

GOAL: starting from a single seed indicator (domain, IP, or file hash), build the
richest possible infrastructure graph for an analyst, while filtering noise.

HARD RULES:
1. Every fact you discover MUST be written to the graph via add_node / add_edge.
   Never keep findings only in your reasoning. Always set `source` to the API used.
2. Before pivoting on an IP or nameserver, ALWAYS call `defuse(kind, value)`.
   If `should_stop_pivot` is true, tag the node and DO NOT enumerate its co-residents.
3. Prefer DISCRIMINATING pivots (favicon hash, JARM, JA3, certificate serial,
   exact HTML title, registrant email, full NS set, GA tracker) over weak pivots
   (shared IP, shared ASN). Weak pivots only when you have nothing else.
4. Budget: at most ~3 pivot hops from the seed, ~30 API calls total. Stop early
   if you find a clear cluster. If a query returns >50 candidates, sample/rank
   instead of expanding all.
5. Always cite provenance via the `source` field and put raw evidence in `evidence`.
6. Tag nodes you classify: cdn, parking, sinkhole, dyndns, shared_hosting,
   suspicious, benign, c2, phishing.

WORKFLOW for a seed domain:
- rdap_domain + dns_resolve -> add registrar, NS, A/AAAA, MX nodes & edges
- defuse each NS; tag parking ones
- crtsh_subdomains -> add subdomain nodes (sample top 30 by recency)
- virustotal_domain + virustotal_resolutions_domain -> historical IPs
- For each NEW resolved IP: defuse(ip). If clean: rdap_ip, shodan_host (if key),
  onyphe_ip, virustotal_resolutions_ip -> co-resident domains (cap to 20).
- urlscan_search domain:<seed> -> screenshots, related infra
- threatfox_search seed -> known malware ties
- For each strong marker found (favicon hash, JARM, cert serial), do one
  shodan_search to find matching infra.

WORKFLOW for a seed IP:
- defuse first. If CDN/sinkhole, tag and stop.
- rdap_ip, shodan_host, onyphe_ip, virustotal_ip, virustotal_resolutions_ip
- Pivot on co-resident domains (cap 20), reverse_dns, urlscan ip:<seed>

WORKFLOW for a seed hash:
- virustotal_file, otx_file, threatfox_search
- Add domains/IPs from VT contacted_domains/contacted_ips as nodes & edges

OUTPUT: at the end, write a final summary node of type "report" with a
metadata field containing {summary, key_findings, confidence, ioc_list}.
"""


async def run_investigation(inv_id: str, seed_type: str, seed_value: str):
    user_prompt = f"Seed indicator: type={seed_type} value={seed_value}\nInvestigate now."
    env = os.environ.copy()
    env["BOUNCE_INV_ID"] = inv_id
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")

    cmd = [
        CLAUDE_BIN, "-p", user_prompt,
        "--append-system-prompt", SYSTEM_PROMPT,
        "--mcp-config", str(MCP_CONFIG),
        "--output-format", "stream-json",
        "--verbose",
        "--permission-mode", "acceptEdits",
        "--allowedTools",
        "mcp__graph__add_node,mcp__graph__add_edge,mcp__graph__tag_node,mcp__graph__get_graph,mcp__graph__defuse,"
        "mcp__cti__dns_resolve,mcp__cti__reverse_dns,mcp__cti__crtsh_subdomains,"
        "mcp__cti__rdap_domain,mcp__cti__rdap_ip,"
        "mcp__cti__virustotal_domain,mcp__cti__virustotal_ip,mcp__cti__virustotal_file,"
        "mcp__cti__virustotal_resolutions_domain,mcp__cti__virustotal_resolutions_ip,"
        "mcp__cti__urlscan_search,mcp__cti__onyphe_domain,mcp__cti__onyphe_ip,"
        "mcp__cti__shodan_host,mcp__cti__shodan_search,"
        "mcp__cti__otx_domain,mcp__cti__otx_ip,mcp__cti__otx_file,"
        "mcp__cti__threatfox_search,mcp__cti__wayback",
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=str(ROOT), env=env,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        gs.set_status(inv_id, "error: claude CLI not found")
        return

    assert proc.stdout is not None
    async for line in proc.stdout:
        try:
            evt = json.loads(line.decode().strip())
            # mirror agent events into the events table for the WS to surface
            with gs.conn() as c:
                c.execute("INSERT INTO events(investigation_id, kind, payload, created_at) VALUES (?,?,?,?)",
                          (inv_id, "agent_" + evt.get("type", "msg"),
                           json.dumps({"kind": "agent_" + evt.get("type", "msg"), "data": evt}),
                           __import__("time").time()))
        except Exception:
            pass
    rc = await proc.wait()
    gs.set_status(inv_id, "done" if rc == 0 else f"error rc={rc}")
