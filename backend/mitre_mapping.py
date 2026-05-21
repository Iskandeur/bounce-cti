"""MITRE ATT&CK technique mapping (heuristic).

A pragmatic, deterministic mapper that takes the investigation graph
(nodes + edges + tags + metadata) and proposes a set of candidate ATT&CK
technique IDs the agent can cite in the report. The agent then validates
each candidate against the actual evidence and produces the final
``mitre_attack_mapping`` block on the report node.

This module deliberately holds a small hand-curated subset of the ATT&CK
matrix — the techniques we can ACTUALLY infer from public CTI source
output. The full ATT&CK matrix has 200+ enterprise techniques; we don't
pretend to cover them all from passive intel alone. Mappings are
explicit, conservative, and each comes with a short rationale string the
agent must echo back in the report so the analyst can audit the chain
of reasoning.

The mapper runs in two passes:

  1. Tag-based: ``mappings_for_tag(tag)`` returns the candidate techniques
     declared by a node tag (e.g. ``powershell_dropper`` →
     T1059.001 + T1027). Tags live on every node and are the lowest-
     friction signal we already collect.
  2. Import-based (PE-only): ``mappings_for_pe_imports(dlls)`` peeks at
     a sample's static-analysis import-DLL list and adds techniques the
     imports imply (e.g. ``wininet.dll`` → T1071.001 web protocols).

Output of ``map_graph(graph)`` is a list of::

    {
      "technique_id": "T1059.001",
      "technique_name": "PowerShell",
      "tactics": ["execution"],
      "rationale": "Tag `powershell_dropper` on command_line node",
      "evidence_node_ids": ["sha1...", ...],
      "confidence": "high|medium|low",
    }

with duplicates merged on technique_id (rationales + evidence_node_ids
concatenated) and confidence escalated to the highest seen value.
"""
from __future__ import annotations

from typing import Iterable

# ── Technique catalog (subset) ────────────────────────────────────────────
# Each entry: (technique_id, name, [tactic, ...]). Tactic names match the
# ATT&CK Enterprise framework. Kept terse — full descriptions live on
# attack.mitre.org and are linked from the UI.
TECHNIQUES: dict[str, dict] = {
    "T1059.001": {"name": "PowerShell", "tactics": ["execution"]},
    "T1059.003": {"name": "Windows Command Shell", "tactics": ["execution"]},
    "T1059.004": {"name": "Unix Shell", "tactics": ["execution"]},
    "T1059.005": {"name": "Visual Basic", "tactics": ["execution"]},
    "T1059.006": {"name": "Python", "tactics": ["execution"]},
    "T1059.007": {"name": "JavaScript", "tactics": ["execution"]},
    "T1027":     {"name": "Obfuscated Files or Information", "tactics": ["defense-evasion"]},
    "T1027.002": {"name": "Software Packing", "tactics": ["defense-evasion"]},
    "T1218":     {"name": "System Binary Proxy Execution (LOLBins)", "tactics": ["defense-evasion"]},
    "T1218.001": {"name": "Compiled HTML File (HTA)", "tactics": ["defense-evasion"]},
    "T1218.005": {"name": "Mshta", "tactics": ["defense-evasion"]},
    "T1218.010": {"name": "Regsvr32", "tactics": ["defense-evasion"]},
    "T1218.011": {"name": "Rundll32", "tactics": ["defense-evasion"]},
    "T1140":     {"name": "Deobfuscate/Decode Files or Information", "tactics": ["defense-evasion"]},
    "T1071":     {"name": "Application Layer Protocol", "tactics": ["command-and-control"]},
    "T1071.001": {"name": "Web Protocols", "tactics": ["command-and-control"]},
    "T1071.004": {"name": "DNS", "tactics": ["command-and-control"]},
    "T1090":     {"name": "Proxy", "tactics": ["command-and-control"]},
    "T1573":     {"name": "Encrypted Channel", "tactics": ["command-and-control"]},
    "T1568":     {"name": "Dynamic Resolution", "tactics": ["command-and-control"]},
    "T1568.002": {"name": "Domain Generation Algorithms", "tactics": ["command-and-control"]},
    "T1583":     {"name": "Acquire Infrastructure", "tactics": ["resource-development"]},
    "T1583.001": {"name": "Domains", "tactics": ["resource-development"]},
    "T1583.004": {"name": "Server", "tactics": ["resource-development"]},
    "T1584":     {"name": "Compromise Infrastructure", "tactics": ["resource-development"]},
    "T1584.001": {"name": "Domains", "tactics": ["resource-development"]},
    "T1566":     {"name": "Phishing", "tactics": ["initial-access"]},
    "T1566.001": {"name": "Spearphishing Attachment", "tactics": ["initial-access"]},
    "T1566.002": {"name": "Spearphishing Link", "tactics": ["initial-access"]},
    "T1105":     {"name": "Ingress Tool Transfer", "tactics": ["command-and-control"]},
    "T1041":     {"name": "Exfiltration Over C2 Channel", "tactics": ["exfiltration"]},
    "T1486":     {"name": "Data Encrypted for Impact (Ransomware)", "tactics": ["impact"]},
    "T1078":     {"name": "Valid Accounts", "tactics": ["defense-evasion", "persistence"]},
    "T1110":     {"name": "Brute Force", "tactics": ["credential-access"]},
    "T1110.001": {"name": "Password Guessing", "tactics": ["credential-access"]},
    "T1497":     {"name": "Virtualization/Sandbox Evasion", "tactics": ["defense-evasion"]},
    "T1547":     {"name": "Boot or Logon Autostart Execution", "tactics": ["persistence"]},
    "T1547.001": {"name": "Registry Run Keys / Startup Folder", "tactics": ["persistence"]},
    "T1574":     {"name": "Hijack Execution Flow", "tactics": ["persistence", "privilege-escalation"]},
    "T1620":     {"name": "Reflective Code Loading", "tactics": ["defense-evasion"]},
    "T1056":     {"name": "Input Capture", "tactics": ["credential-access", "collection"]},
    "T1003":     {"name": "OS Credential Dumping", "tactics": ["credential-access"]},
    "T1018":     {"name": "Remote System Discovery", "tactics": ["discovery"]},
    "T1082":     {"name": "System Information Discovery", "tactics": ["discovery"]},
}


# ── Tag → technique map ───────────────────────────────────────────────────
# Tags are the lowest-friction signal: the agent already attaches them to
# nodes based on tool output and heuristics. We keep the mapping intentional
# (no fishy auto-pivots like "any malicious tag → ransomware") so the rationale
# the UI shows stays defensible.
_TAG_MAP: dict[str, list[tuple[str, str]]] = {
    # (technique_id, rationale)
    "powershell_dropper":   [("T1059.001", "PowerShell dropper indicated by tag"),
                              ("T1027",     "Likely obfuscated PowerShell payload"),
                              ("T1105",     "Dropper implies ingress tool transfer")],
    "bash_dropper":         [("T1059.004", "Unix shell dropper indicated by tag"),
                              ("T1105",     "Dropper implies ingress tool transfer")],
    "living_off_the_land":  [("T1218",     "LOLBin usage indicated by tag")],
    "lolbins":              [("T1218",     "LOLBin usage indicated by tag")],
    "base64_loader":        [("T1027",     "Base64-obfuscated payload"),
                              ("T1140",     "Base64 decoding step expected at runtime")],
    "hta_dropper":          [("T1218.001", "HTA-based execution"),
                              ("T1059.005", "Likely VBS/JS inside HTA")],
    "mshta_dropper":        [("T1218.005", "mshta.exe proxy execution")],
    "certutil_download":    [("T1105",     "certutil used for ingress download"),
                              ("T1218",     "certutil as LOLBin")],
    "bitsadmin":            [("T1105",     "bitsadmin used for ingress download"),
                              ("T1218",     "bitsadmin as LOLBin")],
    "curl_pipe_bash":       [("T1059.004", "Unix shell via curl|bash pattern"),
                              ("T1105",     "curl-based ingress")],
    "iex_download":         [("T1059.001", "PowerShell IEX download pattern"),
                              ("T1105",     "Download cradle for ingress")],
    "obfuscated_script":    [("T1027",     "Obfuscation observed in script body")],
    "regsvr32_proxy":       [("T1218.010", "regsvr32 proxy execution")],
    "rundll32_proxy":       [("T1218.011", "rundll32 proxy execution")],
    "persistence_registry": [("T1547.001", "Registry Run-key persistence")],
    "ransomware":           [("T1486",     "Ransomware family detected")],
    "phishing":             [("T1566",     "Phishing indicator")],
    "phishing_attachment":  [("T1566.001", "Phishing with attachment")],
    "phishing_link":        [("T1566.002", "Phishing with link")],
    "c2":                   [("T1071",     "C2 infrastructure indicator")],
    "c2_https":             [("T1071.001", "HTTPS C2"),
                              ("T1573",     "Encrypted C2 channel")],
    "c2_dns":               [("T1071.004", "DNS C2 indicator")],
    "dga":                  [("T1568.002", "DGA-like domain pattern")],
    "actor_infra":          [("T1583",     "Actor-controlled infrastructure")],
    "compromised_infra":    [("T1584",     "Compromised infrastructure")],
    "packed_or_encrypted":  [("T1027.002", "Packed binary (high section entropy)"),
                              ("T1027",     "Obfuscation via packing")],
    "credential_stealer":   [("T1056",     "Credential capture"),
                              ("T1003",     "OS credential access")],
}


# ── PE-import → technique map ─────────────────────────────────────────────
# Triggered when sample_analysis.parse_pe extracts an import-DLL list.
# Single-DLL signals are weak; we mark them as "medium" confidence and
# expect the agent to upgrade to "high" only when corroborated by other
# evidence in the report body.
_IMPORT_MAP: dict[str, list[tuple[str, str]]] = {
    "wininet.dll":  [("T1071.001", "wininet import → HTTP/HTTPS C2")],
    "winhttp.dll":  [("T1071.001", "winhttp import → HTTP/HTTPS C2")],
    "ws2_32.dll":   [("T1071",     "WinSock import → raw network I/O")],
    "wsock32.dll":  [("T1071",     "WinSock import → raw network I/O")],
    "dnsapi.dll":   [("T1071.004", "DNS API import → DNS-based C2 or beaconing")],
    "crypt32.dll":  [("T1573",     "crypt32 import → encrypted channel")],
    "advapi32.dll": [("T1547.001", "advapi32 import → registry access (persistence?)")],
    "ntdll.dll":    [("T1620",     "ntdll direct syscalls → possible reflective loading")],
}


def mappings_for_tag(tag: str) -> list[tuple[str, str]]:
    return _TAG_MAP.get(tag, [])


def mappings_for_pe_imports(dlls: Iterable[str]) -> list[tuple[str, str]]:
    seen: list[tuple[str, str]] = []
    for d in (dlls or []):
        seen += _IMPORT_MAP.get((d or "").lower(), [])
    return seen


def _confidence_for(rationale_count: int, has_pe_evidence: bool) -> str:
    """Promote confidence when multiple independent signals point at the
    same technique (e.g. tag + PE import + family label)."""
    if rationale_count >= 3 or (rationale_count >= 2 and has_pe_evidence):
        return "high"
    if rationale_count == 2:
        return "medium"
    return "low"


def map_graph(graph: dict) -> list[dict]:
    """Run the heuristic ATT&CK mapper across a full investigation graph.

    Returns a list of unique technique entries with merged rationales /
    evidence node IDs. The agent uses this as a STARTING POINT — it must
    validate each candidate against the evidence text and either keep,
    drop, or refine it on the final report.
    """
    nodes = graph.get("nodes") or []
    candidates: dict[str, dict] = {}

    def _add(tech_id: str, rationale: str, node_id: str, pe_evidence: bool):
        if tech_id not in TECHNIQUES:
            return
        ent = candidates.setdefault(tech_id, {
            "technique_id": tech_id,
            "technique_name": TECHNIQUES[tech_id]["name"],
            "tactics": TECHNIQUES[tech_id]["tactics"],
            "rationales": [],
            "evidence_node_ids": [],
            "_pe_evidence": False,
        })
        if rationale not in ent["rationales"]:
            ent["rationales"].append(rationale)
        if node_id and node_id not in ent["evidence_node_ids"]:
            ent["evidence_node_ids"].append(node_id)
        if pe_evidence:
            ent["_pe_evidence"] = True

    for n in nodes:
        if n.get("type") == "report":
            continue
        tags = n.get("tags") or []
        for t in tags:
            for tech_id, rationale in mappings_for_tag(t):
                _add(tech_id, rationale, n.get("id"), False)
        # PE import lift via static_analysis on hash nodes
        md = n.get("metadata") or {}
        sa = md.get("static_analysis") or {}
        pe = sa.get("pe") or {}
        dlls = pe.get("import_dlls") or []
        for tech_id, rationale in mappings_for_pe_imports(dlls):
            _add(tech_id, rationale, n.get("id"), True)

    out: list[dict] = []
    for tech_id, ent in candidates.items():
        ent["confidence"] = _confidence_for(len(ent["rationales"]),
                                              ent.pop("_pe_evidence"))
        out.append(ent)
    # Sort by confidence then by technique_id for stable display
    rank = {"high": 0, "medium": 1, "low": 2}
    out.sort(key=lambda e: (rank.get(e["confidence"], 3), e["technique_id"]))
    return out
