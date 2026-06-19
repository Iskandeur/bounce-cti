"""OSINT identity dossier export.

The CTI deliverables (STIX, blocklist, detection rules, takedown bundles in
``action_exports.py``) are infrastructure-centric and make little sense for an
OSINT investigation, whose subject is an *identity* — a person, handle, email,
phone or wallet — and whose value is the **footprint**: the accounts, linked
identifiers and connections discovered around the seed.

This module renders that footprint as a Markdown **identity dossier**:

  * header — subject, investigation, counts,
  * summary — from the ``investigation_summary`` report node,
  * identities & accounts — usernames / social profiles,
  * identifiers — emails, phones (w/ carrier/line-type), wallets (w/ chain/
    balance), domains,
  * connections — the graph edges in plain language,
  * key findings + provenance.

Pure functions only (no DB, no I/O) so the API route stays thin and the layout
is unit-testable. Output is Markdown text; the API wraps it in the usual
``{content, filename}`` envelope.
"""
from __future__ import annotations

import time
from typing import Iterable

# Node types that carry identity/footprint meaning in an OSINT dossier, in the
# order we want them to appear. Infra types (ip/asn/cert/…) are summarised under
# "infrastructure" rather than given their own section.
_IDENTITY_SECTIONS = [
    ("username", "Usernames & handles"),
    ("email", "Emails"),
    ("phone", "Phone numbers"),
    ("wallet_address", "Crypto wallets"),
    ("person", "People"),
    ("domain", "Domains"),
    ("url", "URLs"),
]
_INFRA_TYPES = {"ip", "asn", "ns", "cert", "registrar", "jarm", "favicon",
                "ja3", "ja3s", "country"}


def _code(v) -> str:
    """Render a value inside a markdown code span, neutralising backticks."""
    return "`" + str(v).replace("`", "ˋ") + "`"


def _tag_suffix(node: dict) -> str:
    tags = [t for t in (node.get("tags") or []) if t != "seed"]
    return f" — _{', '.join(tags)}_" if tags else ""


def _phone_detail(md: dict) -> str:
    bits = [md.get(k) for k in ("region", "country", "carrier", "line_type") if md.get(k)]
    return f" — {' · '.join(str(b) for b in bits)}" if bits else ""


def _wallet_detail(md: dict) -> str:
    bits = []
    if md.get("chain"):
        bits.append(str(md["chain"]).upper())
    for k, label in (("balance_btc", "BTC"), ("balance_eth", "ETH")):
        if md.get(k) is not None:
            bits.append(f"{md[k]} {label}")
    if md.get("tx_count") is not None:
        bits.append(f"{md['tx_count']} tx")
    return f" — {' · '.join(bits)}" if bits else ""


def _username_detail(md: dict) -> str:
    bits = []
    if md.get("platform"):
        bits.append(str(md["platform"]))
    if md.get("url"):
        bits.append(str(md["url"]))
    if md.get("name"):
        bits.append(str(md["name"]))
    return f" — {' · '.join(bits)}" if bits else ""


_DETAIL = {"phone": _phone_detail, "wallet_address": _wallet_detail,
           "username": _username_detail}


def _by_type(nodes: Iterable[dict], t: str) -> list[dict]:
    out = [n for n in nodes if n.get("type") == t]
    out.sort(key=lambda n: str(n.get("value", "")).lower())
    return out


def render_dossier(graph: dict, inv: dict) -> str:
    """Render an OSINT identity dossier (Markdown) from the graph + investigation
    row. Pure — no DB access."""
    nodes = graph.get("nodes", []) or []
    edges = graph.get("edges", []) or []

    report = {}
    for n in nodes:
        if n.get("type") == "report" and n.get("value") == "investigation_summary":
            report = n.get("metadata", {}) or {}
            break

    seed_value = inv.get("seed_value", "?")
    seed_type = inv.get("seed_type", "unknown")
    title = inv.get("title") or ""
    non_report = [n for n in nodes if n.get("type") != "report"]

    L: list[str] = []
    L.append(f"# OSINT Dossier — {seed_value}")
    L.append("")
    L.append(f"**Subject:** {_code(seed_value)} ({seed_type})  ")
    if title:
        L.append(f"**Title:** {title}  ")
    L.append(f"**Investigation:** {_code(inv.get('id', '?'))}  ")
    L.append(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}  ")
    L.append(f"**Footprint:** {len(non_report)} nodes · {len(edges)} connections")
    L.append("")

    # ── Summary ──
    L.append("## Summary")
    L.append("")
    L.append(report.get("summary") or "_No summary was produced for this investigation._")
    if report.get("threat_assessment"):
        L.append("")
        L.append(f"**Assessment:** {report['threat_assessment']}")
    L.append("")

    # ── Identities & identifiers ──
    for t, heading in _IDENTITY_SECTIONS:
        items = _by_type(non_report, t)
        if not items:
            continue
        L.append(f"## {heading} ({len(items)})")
        L.append("")
        detail = _DETAIL.get(t)
        for n in items:
            line = f"- {_code(n.get('value', ''))}"
            if detail:
                line += detail(n.get("metadata", {}) or {})
            line += _tag_suffix(n)
            L.append(line)
        L.append("")

    # ── Infrastructure (compact) ──
    infra = [n for n in non_report if n.get("type") in _INFRA_TYPES]
    if infra:
        L.append(f"## Infrastructure ({len(infra)})")
        L.append("")
        for n in sorted(infra, key=lambda n: (n.get("type", ""), str(n.get("value", "")))):
            L.append(f"- ({n.get('type')}) {_code(n.get('value', ''))}{_tag_suffix(n)}")
        L.append("")

    # ── Connections ──
    if edges:
        by_id = {n.get("id"): n.get("value") for n in nodes}
        L.append(f"## Connections ({len(edges)})")
        L.append("")
        for e in edges[:80]:
            src = by_id.get(e.get("source"), e.get("source"))
            dst = by_id.get(e.get("target"), e.get("target"))
            rel = e.get("relation", "linked")
            L.append(f"- {_code(src)} —[{rel}]→ {_code(dst)}")
        if len(edges) > 80:
            L.append(f"- _…and {len(edges) - 80} more connections_")
        L.append("")

    # ── Key findings ──
    kf = report.get("key_findings") or []
    if kf:
        L.append("## Key findings")
        L.append("")
        for f in kf:
            if isinstance(f, dict):
                f = f.get("finding") or f.get("text") or str(f)
            L.append(f"- {f}")
        L.append("")

    # ── Provenance ──
    sources = set()
    for n in non_report:
        md = n.get("metadata", {}) or {}
        if md.get("source"):
            sources.add(str(md["source"]))
        for s in (md.get("sources_seen") or []):
            sources.add(str(s))
    if sources:
        L.append("## Provenance")
        L.append("")
        L.append("Sources observed across the graph: "
                 + ", ".join(sorted(sources)) + ".")
        L.append("")

    L.append("---")
    L.append("*Generated by Bounce OSINT. Public-source intelligence — verify "
             "before acting; identity correlation can produce false positives.*")
    return "\n".join(L)
