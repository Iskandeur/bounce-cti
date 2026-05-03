"""Pivot hints — context-aware suggestions injected into tool responses.

The agent reads tool responses and adapts. By embedding short, specific
"PIVOT_HINT:" lines in the response, we nudge the agent toward the next
high-value pivot AT THE MOMENT it has the data, instead of relying on its
recall of "which tools exist".

This is the "system 1" path: data triggers reaction. No hard-coded sequence;
each hint is conditional on what the source actually returned.

Each hint function:
  - Takes the source's response dict + the queried value (for context).
  - Returns a list[str] of "PIVOT_HINT:" lines.
  - Returns [] if nothing useful was found.
  - Never raises (best-effort; missing fields are silently skipped).
"""
from __future__ import annotations

import re
from typing import Any

# ── helpers ────────────────────────────────────────────────────────────

_PRIVACY_EMAIL_PATTERNS = (
    "privacy", "redacted", "whoisproxy", "whoisguard", "domainsbyproxy",
    "perfectprivacy", "withheldforprivacy", "anonymize", "registrar.contact",
    "abuse@", "noreply@", "support@", "admin@",
)

_WELL_KNOWN_CDN_JARMS = {
    # Common Cloudflare JARMs (truncated, not exhaustive — used to skip noise)
    "27d40d40d00040d0",  # generic CF prefix
}


def _is_private_email(email: str) -> bool:
    if not email:
        return True
    el = email.lower()
    return any(p in el for p in _PRIVACY_EMAIL_PATTERNS)


def _flatten_strings(obj: Any, out: list[str], max_depth: int = 5) -> None:
    if max_depth < 0 or not obj:
        return
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, list):
        for x in obj:
            _flatten_strings(x, out, max_depth - 1)
    elif isinstance(obj, dict):
        for v in obj.values():
            _flatten_strings(v, out, max_depth - 1)


# ── per-source hint functions ──────────────────────────────────────────

def hint_for_rdap_domain(response: dict, domain: str) -> list[str]:
    if not isinstance(response, dict):
        return []
    hints: list[str] = []

    # Registrant email pivot (whoxy)
    entities = response.get("entities") or []
    if isinstance(entities, list):
        for ent in entities:
            if not isinstance(ent, dict):
                continue
            vc = ent.get("vcardArray")
            items = vc[1] if isinstance(vc, list) and len(vc) >= 2 and isinstance(vc[1], list) else []
            for it in items:
                if isinstance(it, list) and len(it) >= 4 and it[0] == "email":
                    email = it[3] if isinstance(it[3], str) else ""
                    if email and not _is_private_email(email):
                        hints.append(
                            f"PIVOT_HINT: registrant email '{email}' is NOT privacy-protected — "
                            f"call whoxy_reverse(email='{email}') to enumerate sibling domains by same registrant. "
                            "This is the canonical reverse-WHOIS pivot (Salt-Typhoon-class clusters)."
                        )
                        break
            if hints:
                break

    # Creation date → CT-burst pivot via CertSpotter
    events = response.get("events") or []
    if isinstance(events, list):
        for ev in events:
            if isinstance(ev, dict) and ev.get("eventAction") == "registration":
                date = ev.get("eventDate", "?")
                hints.append(
                    f"PIVOT_HINT: domain registered {date} — for richer CT history than crt.sh, "
                    f"call certspotter_issuances(domain='{domain}', include_subdomains=True). "
                    "Especially useful when crt.sh times out or the domain is too young."
                )
                break
    return hints


def hint_for_rdap_ip(response: dict, ip: str) -> list[str]:
    if not isinstance(response, dict):
        return []
    hints: list[str] = []

    # Always offer abuseipdb + criminalip on a real IP node
    hints.append(
        f"PIVOT_HINT: cheap IP-reputation pivots for {ip}: "
        f"abuseipdb_check('{ip}') (1000/day free) and criminalip_ip('{ip}'). "
        "Both cross-corroborate a vt_ip score with independent telemetry."
    )
    return hints


def hint_for_virustotal_domain(response: dict, domain: str) -> list[str]:
    if not isinstance(response, dict):
        return []
    data = response.get("data") if isinstance(response.get("data"), dict) else response
    attrs = (data or {}).get("attributes") or {}
    hints: list[str] = []

    # JARM pivot
    jarm = attrs.get("jarm") or attrs.get("jarm_fingerprint")
    if jarm and len(jarm) > 16:
        hints.append(
            f"PIVOT_HINT: JARM '{jarm}' present — call netlas_jarm('{jarm}') AND "
            f"zoomeye_jarm('{jarm}') in addition to shodan_search('ssl.jarm:{jarm}'). "
            "Multi-source coverage catches origins one scanner misses."
        )

    # Cert serial pivot
    cert = attrs.get("last_https_certificate") or {}
    serial = cert.get("serial_number") if isinstance(cert, dict) else None
    if serial:
        hints.append(
            f"PIVOT_HINT: TLS cert serial '{serial[:24]}...' present — "
            f"call certspotter_serial('{serial}') for cluster of every host that presented this serial. "
            "Strong cluster signal for reused / Cobalt Strike default certs."
        )

    # Page title for dom_fingerprints
    last_dns = attrs.get("last_https_certificate") or {}
    if attrs.get("last_analysis_stats", {}).get("malicious", 0) >= 1:
        hints.append(
            f"PIVOT_HINT: VT flags this domain malicious — call dom_fingerprints(url='https://{domain}/') "
            "to extract favicon mmh3 / page title hash / tracking IDs / form actions for cluster pivots."
        )
    return hints


def hint_for_virustotal_ip(response: dict, ip: str) -> list[str]:
    if not isinstance(response, dict):
        return []
    data = response.get("data") if isinstance(response.get("data"), dict) else response
    attrs = (data or {}).get("attributes") or {}
    hints: list[str] = []

    jarm = attrs.get("jarm") or attrs.get("jarm_fingerprint")
    if jarm and len(jarm) > 16:
        hints.append(
            f"PIVOT_HINT: JARM '{jarm}' on this IP — call netlas_jarm('{jarm}') AND "
            f"zoomeye_jarm('{jarm}') to find sibling IPs sharing the same TLS fingerprint."
        )

    # IP reputation cross-source
    hints.append(
        f"PIVOT_HINT: cheap IP-reputation cross-checks: abuseipdb_check('{ip}') and "
        f"criminalip_ip('{ip}'). Use BOTH alongside virustotal_ip — different telemetry sources."
    )
    return hints


def hint_for_urlscan_result(response: dict, uuid_or_url: str) -> list[str]:
    if not isinstance(response, dict):
        return []
    hints: list[str] = []

    # Try to find a uuid for dom_fingerprints
    task = response.get("task") or {}
    uuid = task.get("uuid") if isinstance(task, dict) else None
    if not uuid and isinstance(response.get("uuid"), str):
        uuid = response["uuid"]
    if uuid:
        hints.append(
            f"PIVOT_HINT: urlscan UUID '{uuid}' available — call dom_fingerprints(urlscan_uuid='{uuid}') "
            "to extract favicon mmh3 hash, page title SHA1, marketing tracking IDs (GA/GTM/FB Pixel/Yandex/"
            "Hotjar/Clarity/TikTok), form actions, and crypto wallet addresses (drainer kits). "
            "Each tracking ID and favicon hash becomes a new graph node + auto-pivot."
        )
    return hints


def hint_for_urlscan_search(response: dict, query: str) -> list[str]:
    if not isinstance(response, dict):
        return []
    results = response.get("results") or []
    if not isinstance(results, list) or not results:
        return []
    # Only surface hint if at least one scan looks relevant
    first = results[0] if results else {}
    task = first.get("task") if isinstance(first, dict) else None
    uuid = task.get("uuid") if isinstance(task, dict) else None
    if not uuid:
        return []
    return [
        f"PIVOT_HINT: top urlscan UUID is '{uuid}' — feed it to dom_fingerprints(urlscan_uuid='{uuid}') "
        "to extract DOM markers (favicon mmh3, title, tracking IDs, form actions, wallets)."
    ]


def hint_for_dns_resolve(response: dict, domain: str) -> list[str]:
    if not isinstance(response, dict):
        return []
    hints: list[str] = []

    # MX or TXT cross-reference (Contagious-Interview-class pivot)
    mx = response.get("MX") or response.get("mx") or []
    if isinstance(mx, list) and mx:
        # Look for MX hostnames pointing to a different apex
        for entry in mx:
            host = entry if isinstance(entry, str) else (entry.get("exchange") if isinstance(entry, dict) else None)
            if host and isinstance(host, str):
                host_clean = host.rstrip(".").lower()
                if host_clean and not host_clean.endswith(domain.lower()):
                    hints.append(
                        f"PIVOT_HINT: MX '{host_clean}' points to a DIFFERENT apex than '{domain}' — "
                        f"call dns_resolve('{host_clean}') and rdap_domain('{host_clean}') to map operator "
                        "infrastructure (TXT/MX cross-reference is the canonical Contagious-Interview pivot)."
                    )
                    break

    # TXT for cross-reference
    txts: list[str] = []
    raw_txt = response.get("TXT") or response.get("txt") or []
    if isinstance(raw_txt, list):
        for r in raw_txt:
            if isinstance(r, str):
                txts.append(r)
    for txt in txts:
        # SPF include
        m = re.search(r"include:([\w\.\-]+)", txt)
        if m:
            ref = m.group(1).lower()
            if ref and not ref.endswith(domain.lower()) and not ref.endswith(("googleapis.com", "amazonses.com", "outlook.com", "google.com", "_spf.salesforce.com")):
                hints.append(
                    f"PIVOT_HINT: SPF include='{ref}' references a non-generic domain — "
                    f"add_node(domain, '{ref}', source='spf_include') and call dns_resolve + rdap_domain on it."
                )
                break
    return hints


# Dispatch table for cti_mcp wrappers to call.
HINT_DISPATCH = {
    "rdap_domain": hint_for_rdap_domain,
    "rdap_ip": hint_for_rdap_ip,
    "virustotal_domain": hint_for_virustotal_domain,
    "virustotal_ip": hint_for_virustotal_ip,
    "urlscan_result": hint_for_urlscan_result,
    "urlscan_search": hint_for_urlscan_search,
    "dns_resolve": hint_for_dns_resolve,
}


def with_hints(tool_name: str, response: Any, primary_arg: str) -> Any:
    """Wrap a source response with `_pivot_hints` if the dispatch knows the tool.
    Returns the response unchanged if the tool isn't registered or response
    isn't a dict (best-effort, never raises)."""
    fn = HINT_DISPATCH.get(tool_name)
    if not fn or not isinstance(response, dict):
        return response
    try:
        hints = fn(response, primary_arg)
    except Exception:
        return response
    if hints:
        # Avoid clobbering existing keys; merge into a list.
        existing = response.get("_pivot_hints")
        if isinstance(existing, list):
            response["_pivot_hints"] = existing + hints
        else:
            response["_pivot_hints"] = hints
    return response
