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
)

# Generic local-parts that indicate an institutional / registrar mailbox,
# never an actual registrant. Match the LEFT side of the @ exactly.
_INSTITUTIONAL_LOCAL_PARTS = frozenset((
    "abuse", "noreply", "no-reply", "support", "admin", "info",
    "hostmaster", "postmaster", "webmaster", "billing", "contact",
    "domains", "domain", "registrar", "whois", "tech", "compliance",
    "security", "dns", "service", "help",
))

# Domain endings that strongly suggest the email belongs to a registrar /
# registry / WHOIS-management service (not to an actual customer registrant).
_REGISTRAR_EMAIL_ENDINGS = (
    "namesilo.com", "namecheap.com", "godaddy.com", "google.com",
    "googledomains.com", "dynadot.com", "porkbun.com", "tucows.com",
    "enom.com", "hover.com", "gandi.net", "ovh.com", "ovh.net",
    "ionos.com", "1and1.com", "dreamhost.com", "bluehost.com",
    "hostinger.com", "register.com", "name.com", "internet.bs",
    "inwx.com", "csc.com", "markmonitor.com", "safenames.net",
    "easydns.com", "dnimble.com", "openprovider.com",
)

_WELL_KNOWN_CDN_JARMS = {
    # Common Cloudflare JARMs (truncated, not exhaustive — used to skip noise)
    "27d40d40d00040d0",  # generic CF prefix
}


def _is_private_email(email: str) -> bool:
    """Return True if the email is privacy-masked, an institutional/abuse
    inbox, or belongs to a known registrar service. We use this to suppress
    pivot hints that would point the agent at a non-registrant email
    (false-positive whoxy_reverse calls)."""
    if not email or "@" not in email:
        return True
    el = email.lower().strip()
    # Substring match on common privacy-mask vocabulary
    if any(p in el for p in _PRIVACY_EMAIL_PATTERNS):
        return True
    # Split local@domain
    try:
        local, domain = el.split("@", 1)
    except ValueError:
        return True
    # Generic institutional local-part
    if local in _INSTITUTIONAL_LOCAL_PARTS:
        return True
    # Domain belongs to a known registrar service
    if any(domain == d or domain.endswith("." + d) for d in _REGISTRAR_EMAIL_ENDINGS):
        return True
    return False


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


def hint_for_virustotal_file(response: dict, file_hash: str) -> list[str]:
    """vt_file is the entry point for hash investigations. The agent often
    stops at "VT says malicious", graphs the hash, and never extracts the
    contacted IPs/domains in the response — so no shodan/JARM pivot fires.
    Fix: explicitly point to contacted infra fields when present.
    """
    if not isinstance(response, dict):
        return []
    data = response.get("data") if isinstance(response.get("data"), dict) else response
    attrs = (data or {}).get("attributes") or {}
    rels = (data or {}).get("relationships") or {}
    hints: list[str] = []

    # Detection ratio + family suggest commodity_malware hypothesis
    stats = attrs.get("last_analysis_stats") or {}
    mal = stats.get("malicious", 0) if isinstance(stats, dict) else 0
    threat_label = attrs.get("popular_threat_classification") or {}
    family = threat_label.get("suggested_threat_label") if isinstance(threat_label, dict) else None
    if mal >= 1:
        if family:
            hints.append(
                f"PIVOT_HINT: VT family label '{family}' ({mal} engines flag malicious). "
                f"Consider malwarebazaar_signature('{family.split('.')[0]}') AND "
                f"threatfox_search('{file_hash}') to enumerate the campaign cluster."
            )
        else:
            hints.append(
                f"PIVOT_HINT: VT flags this hash malicious ({mal} engines) but no family "
                "label — call malwarebazaar_hash() and otx_file() for family attribution."
            )

    # Contacted infrastructure — usually under relationships.contacted_*
    contacted = []
    for kind in ("contacted_ips", "contacted_domains", "contacted_urls"):
        block = rels.get(kind) if isinstance(rels, dict) else None
        items = (block or {}).get("data") if isinstance(block, dict) else None
        if isinstance(items, list):
            for it in items[:3]:  # cap to top 3
                if isinstance(it, dict) and it.get("id"):
                    contacted.append((kind.replace("contacted_", "").rstrip("s"), it["id"]))
    if contacted:
        bits = ", ".join(f"{kind}={val}" for kind, val in contacted)
        hints.append(
            f"PIVOT_HINT: VT-contacted infra: {bits}. For each: "
            "add_node + run the per-type playbook (rdap_ip + reverse_dns + "
            "shodan_host on IPs; rdap_domain + virustotal_domain on domains). "
            "Hash investigations that stop at 'VT verdict' miss the C2 cluster."
        )
    return hints


def hint_for_virustotal_resolutions_ip(response: dict, ip: str) -> list[str]:
    """vt_resolutions_ip returns co-resident domains. Empirically, the agent
    sometimes graphs only the malicious-flagged ones and skips the rest, even
    when they're part of a TDS cluster (Case 7 SocGholish failure mode).
    Hint: enumerate the top co-resolvers explicitly.
    """
    if not isinstance(response, dict):
        return []
    data = response.get("data") if isinstance(response.get("data"), list) else None
    if not data or not isinstance(data, list):
        return []
    # VT pDNS items have attributes.host_name
    co_resolvers: list[str] = []
    for item in data[:15]:  # peek deeper than the surface 5
        attrs = item.get("attributes") if isinstance(item, dict) else None
        host = (attrs or {}).get("host_name") if isinstance(attrs, dict) else None
        if host and host not in co_resolvers:
            co_resolvers.append(host)
    if not co_resolvers:
        return []
    examples = ", ".join(co_resolvers[:8])  # bumped from 5 to 8 (Case 7 fix)
    return [
        f"PIVOT_HINT: VT pDNS shows {len(co_resolvers)}+ co-resolvers on {ip} "
        f"(top 8: {examples}). For shared-hosting IPs (>80 co-residents), "
        "tag 'shared_hosting' and graph 3 representatives only. For small clusters "
        "(< 30 co-residents — likely intentional, e.g. TDS / Keitaro / phishing-kit "
        "infra), graph EACH listed co-resolver as a domain node with a co_resolves "
        "edge from the IP. The cap is generous on purpose — prefer over-graphing here."
    ]


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


def hint_for_reverse_dns(response: dict, ip: str) -> list[str]:
    """reverse_dns surfaces PTR hostnames. The Contagious-Interview pivot is
    "reverse_dns(ip) -> hostname X -> dns_resolve(X, 'TXT'/'MX') -> uncovers
    a sibling apex via SPF include or shared MX". The agent often graphs the
    PTR result and stops; force the next step explicitly.
    """
    if not isinstance(response, dict):
        return []
    hosts = response.get("hostnames") or []
    if not isinstance(hosts, list) or not hosts:
        return []
    # Filter out CDN-style PTR records (cloudflare/google/aws default PTRs)
    interesting: list[str] = []
    skip_substrings = ("cloudfront", "amazonaws", "googleusercontent",
                       "fastly", "akamai", "azure-edge", "googleapis",
                       "cloudflare", "1e100.net", "akamaitechnologies")
    for h in hosts:
        if not isinstance(h, str):
            continue
        hl = h.lower().rstrip(".")
        if any(s in hl for s in skip_substrings):
            continue
        interesting.append(hl)
    if not interesting:
        return []
    examples = ", ".join(interesting[:3])
    return [
        f"PIVOT_HINT: reverse_dns surfaced {len(interesting)} non-CDN hostname(s) "
        f"on {ip} (top 3: {examples}). For EACH non-CDN hostname (cap 3): "
        f"(a) add_node(domain, <hostname>) + add_edge(seed_ip→domain, ptr_record); "
        f"(b) call dns_resolve(<hostname>) — its TXT records often expose unique "
        f"SPF/Google-site-verification IDs that cross-reference siblings, and "
        f"its MX records reveal mail providers shared across an actor's front "
        f"companies (canonical Contagious-Interview / DPRK-front pivot — "
        f"lianxinxiao.com → blocknovas.com via TXT cross-ref). "
        f"(c) rdap_domain(<hostname>) for registrar/registrant context."
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
    "virustotal_file": hint_for_virustotal_file,
    "virustotal_resolutions_ip": hint_for_virustotal_resolutions_ip,
    "urlscan_result": hint_for_urlscan_result,
    "urlscan_search": hint_for_urlscan_search,
    "dns_resolve": hint_for_dns_resolve,
    "reverse_dns": hint_for_reverse_dns,
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
