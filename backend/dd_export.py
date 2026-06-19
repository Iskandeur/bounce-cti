"""KYB (Due-Diligence) dossier export.

The DD counterpart to ``osint_export`` / ``action_exports``: an investigation in
the ``dd`` vertical is about a LEGAL ENTITY and its group, and the deliverable a
compliance analyst wants is a **KYB dossier** — subject identity, corporate
hierarchy, officers / persons-with-significant-control, and (the headline)
**sanctions exposure** — with the legal caveats baked in.

Pure ``render_kyb_dossier(graph, inv)`` (no DB, no I/O) → Markdown, unit-tested;
the API route wraps it in the usual ``{content, filename}`` envelope.

Two non-negotiable disclaimers are always emitted: ownership shown is ESTIMATED
(not authoritative UBO/RBE), and sanctions hits are CANDIDATES for human review.
"""
from __future__ import annotations

import time

_PARENT_RELS = {"parent_of", "subsidiary_of", "owns", "owned_by", "ultimate_parent_of"}
_PERSON_RELS = {"officer_of", "significant_control_of", "director_of", "psc_of"}
# Tags / metadata that flag a sanctions match (the agent tags `sanctioned`).
_SANCTION_TAGS = {"sanctioned", "sanctions_hit"}


def _code(v) -> str:
    return "`" + str(v).replace("`", "ˋ") + "`"


def _tags(n: dict) -> list[str]:
    return [t for t in (n.get("tags") or []) if t != "seed"]


def _company_detail(md: dict) -> str:
    bits = []
    if md.get("lei"):
        bits.append(f"LEI {md['lei']}")
    for k in ("jurisdiction", "status", "country"):
        if md.get(k):
            bits.append(str(md[k]))
    if md.get("incorporated"):
        bits.append(f"inc. {md['incorporated']}")
    return " · ".join(bits)


def _person_detail(md: dict) -> str:
    bits = []
    for k in ("role", "nationality", "dob"):
        if md.get(k):
            bits.append(str(md[k]))
    noc = md.get("natures_of_control")
    if noc:
        bits.append(", ".join(noc) if isinstance(noc, list) else str(noc))
    return " · ".join(bits)


def _sanction_detail(n: dict) -> str:
    md = n.get("metadata", {}) or {}
    bits = []
    for k in ("sanctions_list", "list", "programs", "programmes", "sanctions_program",
              "sanctions_ref", "ref"):
        v = md.get(k)
        if v:
            bits.append(", ".join(v) if isinstance(v, list) else str(v))
    return " · ".join(dict.fromkeys(bits))  # dedupe, keep order


def _by_type(nodes, t):
    out = [n for n in nodes if n.get("type") == t]
    out.sort(key=lambda n: str(n.get("value", "")).lower())
    return out


def render_kyb_dossier(graph: dict, inv: dict) -> str:
    """Render a KYB / Due-Diligence dossier (Markdown). Pure — no DB access."""
    nodes = graph.get("nodes", []) or []
    edges = graph.get("edges", []) or []
    by_id = {n.get("id"): n for n in nodes}

    report = {}
    for n in nodes:
        if n.get("type") == "report" and n.get("value") == "investigation_summary":
            report = n.get("metadata", {}) or {}
            break

    seed_value = inv.get("seed_value", "?")
    companies = _by_type(nodes, "company")
    people = _by_type(nodes, "person")
    non_report = [n for n in nodes if n.get("type") != "report"]
    sanctioned = [n for n in non_report
                  if set(n.get("tags") or []) & _SANCTION_TAGS]

    L: list[str] = []
    L.append(f"# KYB Dossier — {seed_value}")
    L.append("")
    L.append(f"**Subject:** {_code(seed_value)} (company)  ")
    if inv.get("title"):
        L.append(f"**Title:** {inv['title']}  ")
    L.append(f"**Investigation:** {_code(inv.get('id', '?'))}  ")
    L.append(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}  ")
    L.append(f"**Graph:** {len(companies)} companies · {len(people)} people · "
             f"{len(edges)} relations")
    L.append("")

    # Headline: sanctions exposure first — it's what KYB is for.
    L.append("## ⚠️ Sanctions exposure")
    L.append("")
    if sanctioned:
        L.append(f"**{len(sanctioned)} flagged node(s)** — candidate matches, verify before acting:")
        L.append("")
        for n in sanctioned:
            det = _sanction_detail(n)
            L.append(f"- {_code(n.get('value', ''))} ({n.get('type')})"
                     + (f" — {det}" if det else ""))
    else:
        L.append("_No sanctions match was recorded on any node._")
    L.append("")

    # Summary
    L.append("## Summary")
    L.append("")
    L.append(report.get("summary") or "_No summary was produced for this investigation._")
    L.append("")

    # Companies
    if companies:
        L.append(f"## Companies ({len(companies)})")
        L.append("")
        for n in companies:
            det = _company_detail(n.get("metadata", {}) or {})
            flag = " — **SANCTIONED**" if set(n.get("tags") or []) & _SANCTION_TAGS else ""
            extra = _tags(n)
            extra = [t for t in extra if t not in _SANCTION_TAGS]
            L.append(f"- {_code(n.get('value', ''))}" + (f" — {det}" if det else "")
                     + flag + (f" _({', '.join(extra)})_" if extra else ""))
        L.append("")

    # Corporate hierarchy (parent/subsidiary edges)
    hier = [e for e in edges if (e.get("relation") in _PARENT_RELS)]
    if hier:
        L.append("## Corporate hierarchy (estimated)")
        L.append("")
        for e in hier:
            s = (by_id.get(e.get("source")) or {}).get("value", e.get("source"))
            t = (by_id.get(e.get("target")) or {}).get("value", e.get("target"))
            L.append(f"- {_code(s)} —[{e.get('relation')}]→ {_code(t)}")
        L.append("")

    # Officers / PSC
    if people:
        L.append(f"## Officers & significant control ({len(people)})")
        L.append("")
        for n in people:
            det = _person_detail(n.get("metadata", {}) or {})
            flag = " — **SANCTIONED**" if set(n.get("tags") or []) & _SANCTION_TAGS else ""
            L.append(f"- {_code(n.get('value', ''))}" + (f" — {det}" if det else "") + flag)
        L.append("")

    # Provenance
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
        L.append("Sources observed: " + ", ".join(sorted(sources)) + ".")
        L.append("")

    L.append("---")
    L.append("*Generated by Bounce DD (KYB). **Ownership shown is ESTIMATED** "
             "corporate hierarchy / registry-declared control — NOT authoritative "
             "beneficial ownership (UBO/RBE), and not a substitute for a registry "
             "consultation by an obligated entity. **Sanctions matches are "
             "candidates for human review** (name collisions occur), not automated "
             "determinations. Public-source intelligence; not legal advice.*")
    return "\n".join(L)
