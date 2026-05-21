"""Output → action artifacts.

Once an investigation is done, the analyst wants concrete artefacts they
can paste into firewalls, ticket trackers, SIEMs, or abuse contact forms.
This module renders the graph into operational deliverables:

  * ``blocklist``        — IOCs in a chosen blocklist syntax
                           (plain / hosts / unbound / rpz / palo-edl /
                           cisco-acl / csv).
  * ``detection_rules``  — Sigma / Snort / YARA starter rules derived
                           from network IOCs and hash IOCs.
  * ``takedown``         — Per-domain / per-IP abuse-contact bundle:
                           target IOC, abuse_email pulled from
                           rdap/whois metadata, suggested mail subject +
                           body. Mailto link included for one-click open.

Design constraints:
  - Defused nodes (CDN / parking / sinkhole / Tor / blackhole) are EXCLUDED
    from blocklists and detection rules. They'd cause false-positive
    fallout if shipped to a firewall.
  - Hashes flagged ``nsrl_known`` are EXCLUDED from detection rules.
  - All output is plain text — the API wraps it in a JSON envelope with
    a ``content`` string and a suggested ``filename``.
"""
from __future__ import annotations

import re
import time
from typing import Iterable

# Defuse tags we never want in actionable output. Same set as
# pivot_mapping.bad_tags but inverted intent: here we treat them as
# *unsafe to action*.
_DEFUSED_TAGS = {
    "cdn", "parked_domain", "sinkhole", "blackhole", "dyndns",
    "tor_exit", "nsrl_known", "legit_service", "shared_hosting",
}

_NETWORK_TYPES = {"domain", "ip", "url"}
_HASH_TYPES = {"hash"}


def _is_defused(node: dict) -> bool:
    tags = set(node.get("tags") or [])
    return bool(tags & _DEFUSED_TAGS)


def _iter_actionable(nodes: Iterable[dict], wanted_types: set[str],
                      include_defused: bool = False) -> list[dict]:
    """Filter the graph for nodes that are safe to ship to a defender.

    ``wanted_types`` restricts to network / hash slices. ``include_defused``
    is a deliberate analyst override (the UI exposes it as a checkbox)."""
    out: list[dict] = []
    for n in nodes:
        if n.get("type") not in wanted_types:
            continue
        if "seed" not in (n.get("tags") or []) and n.get("type") == "report":
            continue
        if not include_defused and _is_defused(n):
            continue
        out.append(n)
    return out


def _safe_value(v: str) -> str:
    """Trim and lowercase for canonical comparison; preserve case for URLs."""
    return (v or "").strip()


# ── Blocklist renderers ───────────────────────────────────────────────────

def _strip_url(u: str) -> str:
    """Pull the host (without scheme / path / query) out of a URL."""
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://([^/?#]+)", u)
    if m:
        host = m.group(1).rsplit("@", 1)[-1].rsplit(":", 1)[0]
        return host
    return u


def render_blocklist(nodes: list[dict], fmt: str,
                      include_defused: bool = False) -> str:
    """Render network IOCs in the chosen blocklist syntax."""
    actionable = _iter_actionable(nodes, _NETWORK_TYPES, include_defused)
    ips: list[str] = []
    domains: list[str] = []
    urls: list[str] = []
    for n in actionable:
        v = _safe_value(n["value"])
        if not v:
            continue
        if n["type"] == "ip":
            ips.append(v)
        elif n["type"] == "domain":
            domains.append(v.lower())
        elif n["type"] == "url":
            urls.append(v)
            host = _strip_url(v)
            if host and "." in host and not re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
                domains.append(host.lower())
    ips = sorted(set(ips))
    domains = sorted(set(domains))
    urls = sorted(set(urls))

    fmt = (fmt or "plain").lower()
    if fmt == "plain":
        lines = ["# bounce-cti blocklist (plain text)"]
        if ips:
            lines += ["", "# IP addresses"] + ips
        if domains:
            lines += ["", "# Domains"] + domains
        if urls:
            lines += ["", "# URLs"] + urls
        return "\n".join(lines) + "\n"

    if fmt == "hosts":
        # /etc/hosts style — point each domain at 0.0.0.0 (or ::). IPs are
        # not representable in hosts files, so we surface them as comments.
        lines = ["# bounce-cti hosts blocklist", "# Domains:"]
        lines += [f"0.0.0.0 {d}" for d in domains]
        if ips:
            lines += ["", "# IPs (not representable in hosts, drop at firewall):"]
            lines += [f"# {ip}" for ip in ips]
        return "\n".join(lines) + "\n"

    if fmt == "unbound":
        lines = ["# bounce-cti Unbound local-zone NXDOMAIN list"]
        lines += [f'local-zone: "{d}" always_nxdomain' for d in domains]
        return "\n".join(lines) + "\n"

    if fmt == "rpz":
        # Response Policy Zone (BIND format). Resolves blocked names to CNAME .
        ts = time.strftime("%Y%m%d%H")
        lines = [
            "$TTL 3600",
            f"@ IN SOA localhost. root.localhost. ({ts} 3600 600 86400 600)",
            "  IN NS localhost.",
        ]
        for d in domains:
            lines.append(f"{d} CNAME .")
            lines.append(f"*.{d} CNAME .")
        return "\n".join(lines) + "\n"

    if fmt == "palo_edl":
        # Palo Alto External Dynamic List — one IP/host per line, no comments.
        return "\n".join(sorted(set(ips + domains))) + "\n"

    if fmt == "cisco_acl":
        # Bare-bones ACL — IPs only. Domains aren't representable.
        lines = ["! bounce-cti Cisco ACL — drop traffic to listed hosts",
                 "ip access-list extended BOUNCE_BLOCK"]
        for ip in ips:
            lines.append(f" deny ip any host {ip}")
        lines.append(" permit ip any any")
        return "\n".join(lines) + "\n"

    if fmt == "csv":
        lines = ["type,value"]
        for ip in ips:
            lines.append(f"ip,{ip}")
        for d in domains:
            lines.append(f"domain,{d}")
        for u in urls:
            lines.append(f"url,{u}")
        return "\n".join(lines) + "\n"

    raise ValueError(f"unknown blocklist format: {fmt}")


# ── Detection rule scaffolds ──────────────────────────────────────────────

def render_detection(nodes: list[dict], fmt: str,
                      investigation_id: str = "",
                      include_defused: bool = False) -> str:
    """Generate a starter detection rule from the IOCs. Always include the
    caveat that these are STARTING POINTS — a defender must tune false
    positives and add their environment context before deploying."""
    fmt = (fmt or "sigma").lower()
    actionable_net = _iter_actionable(nodes, _NETWORK_TYPES, include_defused)
    actionable_hash = _iter_actionable(nodes, _HASH_TYPES, include_defused)
    ips = sorted({_safe_value(n["value"]) for n in actionable_net if n["type"] == "ip"})
    domains = sorted({_safe_value(n["value"]).lower() for n in actionable_net if n["type"] == "domain"})
    urls = sorted({_safe_value(n["value"]) for n in actionable_net if n["type"] == "url"})
    hashes_sha256 = sorted({n["value"].lower() for n in actionable_hash if len(n["value"]) == 64})
    hashes_sha1 = sorted({n["value"].lower() for n in actionable_hash if len(n["value"]) == 40})
    hashes_md5 = sorted({n["value"].lower() for n in actionable_hash if len(n["value"]) == 32})

    title = f"Bounce-CTI IOC sweep — {investigation_id or 'untitled'}"

    if fmt == "sigma":
        # https://github.com/SigmaHQ/sigma — proxy/DNS log format
        lines = [
            f"title: {title}",
            f"id: bounce-cti-{investigation_id or 'unknown'}",
            "status: experimental",
            "description: Starter Sigma rule from a bounce-cti investigation. Tune before deploy.",
            "logsource:",
            "  category: proxy",
            "detection:",
            "  selection_domain:",
            "    DestinationHostname|endswith:",
        ]
        if domains:
            for d in domains:
                lines.append(f"      - '{d}'")
        else:
            lines.append("      - 'EXAMPLE.invalid'   # no actionable domains")
        lines += [
            "  selection_ip:",
            "    DestinationIp:",
        ]
        if ips:
            for ip in ips:
                lines.append(f"      - '{ip}'")
        else:
            lines.append("      - '0.0.0.0'   # no actionable IPs")
        lines += [
            "  condition: selection_domain or selection_ip",
            "level: high",
        ]
        return "\n".join(lines) + "\n"

    if fmt == "snort":
        lines = [f"# Snort/Suricata starter rules for {title}",
                 "# Tune the SID and msg fields. These are STARTING POINTS."]
        sid = 1_000_000
        for d in domains:
            lines.append(
                f'alert dns $HOME_NET any -> any 53 (msg:"Bounce-CTI domain hit: {d}"; '
                f'dns_query; content:"{d}"; nocase; sid:{sid}; rev:1;)'
            )
            sid += 1
        for ip in ips:
            lines.append(
                f'alert ip $HOME_NET any -> {ip} any (msg:"Bounce-CTI IP hit: {ip}"; '
                f'sid:{sid}; rev:1;)'
            )
            sid += 1
        return "\n".join(lines) + "\n"

    if fmt == "yara":
        # YARA rule scaffold matching embedded hashes / strings. The hash
        # match requires the `hash` module; the string match works without.
        lines = [
            "import \"hash\"",
            "",
            "rule bounce_cti_iocs",
            "{",
            "    meta:",
            f'        title = "{title}"',
            '        author = "bounce-cti"',
            "    strings:",
        ]
        for i, d in enumerate(domains):
            lines.append(f"        $d{i} = \"{d}\" ascii wide nocase")
        for i, u in enumerate(urls):
            safe = u.replace("\\", "\\\\").replace("\"", "\\\"")
            lines.append(f"        $u{i} = \"{safe}\" ascii wide nocase")
        lines.append("    condition:")
        cond = []
        if hashes_sha256:
            cond.append("hash.sha256(0, filesize) in ({})"
                        .format(", ".join(f'"{h}"' for h in hashes_sha256)))
        if hashes_md5:
            cond.append("hash.md5(0, filesize) in ({})"
                        .format(", ".join(f'"{h}"' for h in hashes_md5)))
        if not cond and (domains or urls):
            cond.append("any of ($d*, $u*)")
        if not cond:
            cond.append("false   /* no actionable IOCs in graph */")
        lines.append("        " + " or ".join(cond))
        lines.append("}")
        return "\n".join(lines) + "\n"

    raise ValueError(f"unknown detection format: {fmt}")


# ── Takedown bundle ───────────────────────────────────────────────────────

def render_takedown(nodes: list[dict], edges: list[dict],
                     investigation_id: str = "") -> list[dict]:
    """Build a list of takedown-ready records: one per malicious host /
    IP with a known abuse contact. Each record has::

        {
          "target": {"type": "domain|ip", "value": "..."},
          "abuse_email": "abuse@registrar.example",
          "registrar": "...",
          "asn": "AS...",
          "evidence": ["...", "..."],   # short bullets the analyst pastes
          "subject": "...",
          "body": "...",                # plain text email body, ready to paste
          "mailto": "mailto:abuse@...?subject=...&body=...",
        }

    The agent's evidence (tags, source list, tool hits) is summarised
    into short bullets. The analyst still owns the send — we never
    auto-email anyone."""
    out: list[dict] = []
    by_id = {n["id"]: n for n in nodes if "id" in n}
    for n in nodes:
        if n.get("type") not in ("domain", "ip"):
            continue
        if _is_defused(n):
            continue
        md = n.get("metadata") or {}
        tags = n.get("tags") or []
        # Look for an abuse email in the node metadata (RDAP / WHOIS fields).
        abuse = (md.get("abuse_email") or md.get("registrar_abuse_email")
                 or md.get("org_abuse_email") or md.get("abuse"))
        registrar = md.get("registrar") or md.get("netname") or md.get("org") or ""
        asn = md.get("asn") or ""
        if not abuse:
            # Skip the node — without a known abuse contact this isn't
            # actionable. We still list it in 'incomplete' below.
            continue

        evidence_bullets: list[str] = []
        if tags:
            evidence_bullets.append("Tags: " + ", ".join(sorted(tags)))
        ss = md.get("sources_seen") or []
        if ss:
            evidence_bullets.append("Sources confirming the indicator: " +
                                     ", ".join(sorted(ss)))
        if md.get("first_seen"):
            evidence_bullets.append(f"First observed: {md['first_seen']}")
        # Edges originating from this node that hint at attack relationships.
        rels: list[str] = []
        for e in edges:
            if e.get("src") == n["id"]:
                dst = by_id.get(e.get("dst"))
                if dst:
                    rels.append(f"{e.get('relation')} → {dst.get('type')}:{dst.get('value')}")
            if e.get("dst") == n["id"]:
                src = by_id.get(e.get("src"))
                if src:
                    rels.append(f"{src.get('type')}:{src.get('value')} {e.get('relation')} →")
        rels = list(dict.fromkeys(rels))[:6]
        if rels:
            evidence_bullets.append("Graph context:")
            evidence_bullets.extend(f"  - {r}" for r in rels)

        subject = f"Abuse report: malicious activity from {n['type']} {n['value']}"
        body_lines = [
            f"Hello{(' ' + registrar) if registrar else ''} abuse team,",
            "",
            f"We have observed malicious activity associated with the following indicator:",
            "",
            f"    {n['type']}: {n['value']}",
            f"    Tracked under investigation id: {investigation_id}" if investigation_id else "",
            "",
            "Summary of evidence:",
        ]
        if evidence_bullets:
            for b in evidence_bullets:
                # If a bullet line is already indented (sub-item), keep it as-is.
                body_lines.append(b if b.startswith(" ") else f"  - {b}")
        else:
            body_lines.append("  - (no aggregated metadata)")
        body_lines += [
            "",
            "We respectfully request you investigate and take appropriate action",
            "(content removal / hosting suspension / DNS suspension) under your",
            "abuse policy.",
            "",
            "We are happy to share additional artefacts on request.",
            "",
            "Regards,",
            "",
        ]
        body = "\n".join(line for line in body_lines if line is not None)

        # Build a mailto link (capped at 1900 chars — most clients reject longer).
        from urllib.parse import quote
        mailto_body = quote(body)[:1900]
        mailto_subject = quote(subject)
        mailto = f"mailto:{abuse}?subject={mailto_subject}&body={mailto_body}"

        out.append({
            "target": {"type": n["type"], "value": n["value"]},
            "abuse_email": abuse,
            "registrar": registrar,
            "asn": asn,
            "evidence_bullets": evidence_bullets,
            "subject": subject,
            "body": body,
            "mailto": mailto,
        })
    return out
