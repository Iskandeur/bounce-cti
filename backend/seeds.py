"""Seed registry — single source of truth for per-seed-type behaviour.

Historically the agent runner carried five parallel ``if seed_type == …``
ladders (mandatory-tool lists + per-type prompt blocks in
``run_investigation`` / ``run_add_seed`` / ``run_pivot``). Adding a seed type
meant editing all of them. This module centralises that knowledge so a seed
type is defined in *one* place.

The refactor is strictly behaviour-preserving: every string produced here is
byte-identical to the literal it replaced (guarded by golden tests in
``backend/tests``). ``vertical`` selection (cti / osint / dd) builds on top of
this registry in later steps; for now every entry belongs to the CTI pool.
"""
from __future__ import annotations

from typing import Callable


def _asn_num(seed_value: str) -> str:
    """Canonical AS number digits (``AS13335`` → ``13335``), tolerating a bare
    number. Mirrors the derivation the agent-runner ladders used."""
    return seed_value.upper().removeprefix("AS") or seed_value


# ── Mandatory-tool specs ──────────────────────────────────────────────────
# Each entry maps a seed type to a builder that, given the seed value, returns
# the ordered list of ``(tool_name, call_example)`` the agent must have called
# before writing its report. ``_missing_mandatory_tools`` filters this against
# the set of tools actually invoked.

def _mandatory_ip(v: str) -> list[tuple[str, str]]:
    return [
        ("rdap_ip", f'rdap_ip("{v}")'),
        ("reverse_dns", f'reverse_dns("{v}")'),
        ("virustotal_communicating_files", f'virustotal_communicating_files("ip", "{v}")'),
        ("threatfox_search", f'threatfox_search("{v}")'),
        ("virustotal_resolutions_ip", f'virustotal_resolutions_ip("{v}")'),
        ("shodan_host", f'shodan_host("{v}")'),
        ("onyphe_ip", f'onyphe_ip("{v}")'),
        ("urlscan_search", f'urlscan_search("ip:{v}")'),
        ("otx_ip", f'otx_ip("{v}")'),
    ]


def _mandatory_domain(v: str) -> list[tuple[str, str]]:
    return [
        ("rdap_domain", f'rdap_domain("{v}")'),
        # Live A-record resolution of the seed. Was NOT mandatory before — Case 7
        # (SocGholish) missed its primary marker 176.53.147.97 (the shared
        # Keitaro-front IP and co-residency anchor) because the seed's own A
        # record was never graphed. Also feeds the all-CDN origin-unmask branch
        # in _adaptive_followup_targets for Cases 11/12 (the CDN IP node lets the
        # cert-CN unmask fire reliably). One cheap call.
        ("dns_resolve", f'dns_resolve("{v}")'),
        ("virustotal_communicating_files", f'virustotal_communicating_files("domain", "{v}")'),
        ("threatfox_search", f'threatfox_search("{v}")'),
        ("virustotal_resolutions_domain", f'virustotal_resolutions_domain("{v}")'),
        ("otx_domain", f'otx_domain("{v}")'),
        ("crtsh_subdomains", f'crtsh_subdomains("{v}")'),
        ("onyphe_domain", f'onyphe_domain("{v}")'),
        # Added 2026-05-21 — Cases 6 (LummaC2 About-Cats), 9 (Tycoon 2FA), 11
        # (Smishing Triad) all hit F-PIVOT-MISS::urlscan_or_wayback_seed because
        # urlscan_search wasn't mandatory. Without it the content-fingerprint
        # cluster never expands and NR collapses.
        ("urlscan_search", f'urlscan_search("domain:{v}")'),
        # Wayback is the canonical fallback when the live seed is dead or
        # sinkholed (Cases 6 partial sinkhole, 10 BlockNovas FBI seizure, 11
        # NameSilo bulk-cycle). Historical content is graphable.
        ("wayback", f'wayback("{v}")'),
    ]


def _mandatory_url(v: str) -> list[tuple[str, str]]:
    # For URL seeds we can't reliably rebuild the host from seed_value here, so
    # only mandate URL-specific tools. The agent handles host pivots via the URL
    # workflow prompt.
    return [
        ("urlscan_search", f'urlscan_search("page.url:{v}")'),
        ("threatfox_search", f'threatfox_search("{v}")'),
    ]


def _mandatory_jarm(v: str) -> list[tuple[str, str]]:
    return [
        ("shodan_search", f'shodan_search("ssl.jarm:{v}")'),
        ("urlscan_search", f'urlscan_search("hash:{v}")'),
    ]


def _mandatory_asn(v: str) -> list[tuple[str, str]]:
    # Accept seed_value like "AS13335" — pass the stripped form to shodan.
    return [
        ("shodan_search", f'shodan_search("asn:AS{_asn_num(v)}")'),
    ]


def _mandatory_hash(v: str) -> list[tuple[str, str]]:
    return [
        ("virustotal_file", f'virustotal_file("{v}")'),
        ("malwarebazaar_hash", f'malwarebazaar_hash("{v}")'),
        ("threatfox_search", f'threatfox_search("{v}")'),
        ("otx_file", f'otx_file("{v}")'),
    ]


def _mandatory_executable_name(v: str) -> list[tuple[str, str]]:
    return [
        ("malwarebazaar_filename", f'malwarebazaar_filename("{v}")'),
        ("threatfox_search", f'threatfox_search("{v}")'),
    ]


def _mandatory_email(v: str) -> list[tuple[str, str]]:
    return [
        ("emailrep_check", f'emailrep_check("{v}")'),
        ("whoxy_reverse", f'whoxy_reverse(email="{v}")'),
        ("pulsedive_indicator", f'pulsedive_indicator("{v}")'),
        ("opencti_lookup_indicator", f'opencti_lookup_indicator("{v}")'),
        ("threatfox_search", f'threatfox_search("{v}")'),
    ]


def _mandatory_wallet_address(v: str) -> list[tuple[str, str]]:
    return [
        ("threatfox_search", f'threatfox_search("{v}")'),
        ("pulsedive_indicator", f'pulsedive_indicator("{v}")'),
        ("opencti_lookup_indicator", f'opencti_lookup_indicator("{v}")'),
    ]


def _mandatory_username(v: str) -> list[tuple[str, str]]:
    return [
        ("threatfox_search", f'threatfox_search("{v}")'),
        ("pulsedive_indicator", f'pulsedive_indicator("{v}")'),
        ("opencti_lookup_indicator", f'opencti_lookup_indicator("{v}")'),
    ]


def _mandatory_phone(v: str) -> list[tuple[str, str]]:
    return [
        ("phone_lookup", f'phone_lookup("{v}")'),
        ("threatfox_search", f'threatfox_search("{v}")'),
        ("opencti_lookup_indicator", f'opencti_lookup_indicator("{v}")'),
    ]


def _mandatory_company(v: str) -> list[tuple[str, str]]:
    # DD pool (mcp__dd__*). GLEIF = identity + hierarchy; sanctions screening
    # is the core KYB check.
    return [
        ("gleif_lookup", f'gleif_lookup("{v}")'),
        ("sanctions_screen", f'sanctions_screen("{v}")'),
    ]


# Registry of mandatory-tool builders. Seed types absent here (command_line and
# any unknown type) have no IOC-level mandatory tools — their prompt drives the
# per-IOC pivots once embedded indicators are graphed.
_MANDATORY: dict[str, Callable[[str], list[tuple[str, str]]]] = {
    "ip": _mandatory_ip,
    "domain": _mandatory_domain,
    "url": _mandatory_url,
    "jarm": _mandatory_jarm,
    "asn": _mandatory_asn,
    "hash": _mandatory_hash,
    "executable_name": _mandatory_executable_name,
    "email": _mandatory_email,
    "wallet_address": _mandatory_wallet_address,
    "username": _mandatory_username,
    "phone": _mandatory_phone,
    "company": _mandatory_company,
}


def mandatory_tools(seed_type: str, seed_value: str) -> list[tuple[str, str]]:
    """Ordered ``(tool_name, call_example)`` pairs the agent must call for this
    seed type, or ``[]`` for types with no IOC-level mandatory tools."""
    builder = _MANDATORY.get(seed_type)
    return builder(seed_value) if builder else []


# Seed types the platform recognises (CTI pool). Used for validation and to
# enumerate the registry in tests. ``command_line`` has a workflow prompt but
# no mandatory IOC tools, so it is registered but absent from ``_MANDATORY``.
KNOWN_SEED_TYPES: tuple[str, ...] = (
    "ip", "domain", "url", "jarm", "asn", "hash", "executable_name",
    "email", "wallet_address", "username", "phone", "company", "command_line",
)


# ── Main-investigation prompts ────────────────────────────────────────────
# The per-seed-type user prompt for the main investigation phase. Extracted
# verbatim from the run_investigation if/elif ladder. ``domain`` and ``hash``
# (and any unknown type) intentionally fall through to the generic domain-style
# workflow, exactly as the original ``else`` branch did. The SOURCE REPORT
# (report_context) prepend stays in agent_runner — it depends on a separate
# parameter and is shared across seed types.

def investigation_prompt(seed_type: str, seed_value: str) -> str:
    """Return the main-phase user prompt for a seed (sans report_context)."""
    if seed_type == "url":
        return (
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
        return (
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
        return (
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
        return (
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
    elif seed_type == "executable_name":
        return (
            f"Seed indicator: type=executable_name value={seed_value}\n"
            "This is JUST the filename of a malicious binary — the analyst does\n"
            "NOT have the file itself and does NOT have its hash. Your job is to\n"
            "find sample(s) ever reported under this filename and attribute the\n"
            "family from there. There is no fingerprint to pivot on yet — the\n"
            "filename is the only signal.\n\n"
            f"STEP 1: add_node(executable_name, {seed_value}, tags=[\"seed\"], "
            f"metadata={{\"extension\": \"<ext>\"}})\n"
            f"STEP 2: malwarebazaar_filename({seed_value})  — primary pivot. "
            "For EACH sample returned (up to the top 10, prioritising distinct\n"
            f"  sha256/signature/file_type triplets):\n"
            "  - add_node(hash, <sha256_hash>, metadata={file_name, file_type, "
            "signature, first_seen}, source=\"malwarebazaar\")\n"
            f"  - add_edge(<hash> → executable_name node, observed_as, "
            f"source=\"malwarebazaar\", evidence=\"reported with filename "
            f"{seed_value} on MalwareBazaar\")\n"
            "  - If `signature` is set on the sample, that is the malware family\n"
            "    — copy it onto the executable_name node as a tag (e.g. "
            "    'family:agenttesla', 'family:lummac2') and add an `attributed_to`\n"
            "    relation in the report's metadata.\n"
            f"STEP 3: For the top 3 sample hashes (by recency / family diversity), "
            "run the full hash workflow:\n"
            "  - virustotal_file(<h>)  — extract names[], meaningful_name, "
            "first_submission, family from popular_threat_classification\n"
            "  - malwarebazaar_hash(<h>)  — yara/cape tags, C2 list\n"
            "  - otx_file(<h>)  — pulse / actor attribution\n"
            "  - threatfox_search(<h>)  — IOCs linked to that sample\n"
            "  Graph every C2 / contacted_url / contacted_domain / "
            "contacted_ip the sample reveals (add_node + communicates_with edge).\n"
            f"STEP 4: threatfox_search({seed_value})  — sometimes ThreatFox\n"
            "  entries reference filenames as IOCs (especially for droppers).\n"
            f"STEP 5: opencti_lookup_indicator({seed_value})  — community KG\n"
            "  may have the filename indexed against an actor / campaign.\n"
            "STEP 6: If no sample is found in MalwareBazaar AND threatfox finds\n"
            "  no hit, the filename may be too generic ('update.exe', "
            "  'svchost.exe', 'taskmgr.exe') — note that explicitly in the\n"
            "  report's metadata under `attribution_status: \"filename_too_"
            "generic\"` and STILL write a short investigation_summary.\n"
            "STEP 7: Final report — value=\"investigation_summary\", linking the\n"
            "  executable_name node with known_ioc. The summary MUST state:\n"
            "  - how many samples were found,\n"
            "  - the dominant malware family (if any),\n"
            "  - the most distinctive C2 / network IOC each family contacts,\n"
            "  - whether the filename is generic / shared across families.\n"
            "EXCEPTION: If malwarebazaar_filename returns zero samples and the\n"
            "  filename matches a known legitimate binary (svchost, explorer,\n"
            "  notepad, chrome, msedge…), tag the seed `generic_filename` and\n"
            "  keep the report minimal — explain that the name alone is not a\n"
            "  meaningful pivot."
        )
    elif seed_type == "email":
        return (
            f"Seed indicator: type=email value={seed_value}\n"
            "This is an email address — most often a malware/phishing registrant\n"
            "contact, a C2 beacon target, an exfil drop, or a paste-site author.\n"
            "Your job is to find every domain registered with this email, every\n"
            "reputation signal, and any threat-intel mention.\n\n"
            f"STEP 1: add_node(email, {seed_value}, tags=[\"seed\"])\n"
            f"STEP 2: emailrep_check({seed_value})  — reputation, disposable flag,\n"
            "        spammer / malicious tags. Copy `details.profiles` onto the node\n"
            "        metadata when present (linked social profiles).\n"
            f"STEP 3: whoxy_reverse(email=\"{seed_value}\")  — every domain ever\n"
            "        registered with this email. For each returned domain (top 25\n"
            "        prioritising recency / TLD diversity):\n"
            "          - add_node(domain, <d>)\n"
            "          - add_edge(email→domain, registered, source=\"whoxy\")\n"
            "        Tag the email `bulk_registrant` if ≥20 domains are returned.\n"
            f"STEP 4: pulsedive_indicator({seed_value}) — risk-scored corroboration.\n"
            f"STEP 5: opencti_lookup_indicator({seed_value}) — community KG hits.\n"
            f"STEP 6: threatfox_search({seed_value}) — listed as IOC?\n"
            "STEP 7: For the TOP 3 domains discovered in STEP 3 (most recently\n"
            "        registered or most-suspect TLD), run the full domain workflow\n"
            "        (rdap, dns, VT, urlhaus, threatfox, otx) so the cluster has\n"
            "        concrete infrastructure to pivot from.\n"
            "STEP 8: Final report — value=\"investigation_summary\". The summary\n"
            "        MUST state: how many domains the email registered, whether the\n"
            "        email is disposable / reputation-flagged, and the dominant\n"
            "        malware family or campaign (if attributable)."
        )
    elif seed_type == "wallet_address":
        return (
            f"Seed indicator: type=wallet_address value={seed_value}\n"
            "This is a cryptocurrency wallet address — most often a ransomware\n"
            "payment target, a scam-collection wallet, or a market vendor wallet.\n"
            "We do not (yet) query block explorers — your job is to surface every\n"
            "PUBLIC threat-intel mention of this address and graph the surrounding\n"
            "infrastructure so analysts can attribute the campaign.\n\n"
            f"STEP 1: add_node(wallet_address, {seed_value}, tags=[\"seed\"], "
            f"metadata={{\"chain\": \"<btc|eth|xmr|...>\"}})\n"
            "        Set the chain in metadata based on the address format:\n"
            "          - 0x + 40 hex   → ethereum (also BSC, Polygon — flag both)\n"
            "          - bc1/tb1       → bitcoin (bech32)\n"
            "          - 1 / 3 + b58   → bitcoin (legacy P2PKH / P2SH)\n"
            "          - 4 / 8 + b58   → monero\n"
            f"STEP 2: threatfox_search({seed_value}) — abuse.ch lists wallets in\n"
            "        ransomware IOC bundles. Every matching threat_type / malware\n"
            "        field becomes a tag on the wallet_address node.\n"
            f"STEP 3: pulsedive_indicator({seed_value}) — risk + linked indicators.\n"
            f"STEP 4: opencti_lookup_indicator({seed_value}) — community KG.\n"
            f"STEP 5: urlscan_search(\"{seed_value}\") — sometimes the address shows\n"
            "        up in scanned phishing page DOM (donate buttons, ransom notes).\n"
            "        For each matching page graph it as a url node and tie back to\n"
            "        the wallet with an embedded_in edge.\n"
            "STEP 6: Final report — value=\"investigation_summary\". The summary\n"
            "        MUST state: the chain, whether the wallet has any direct\n"
            "        threat-feed listing, and the campaign / malware family it is\n"
            "        attributed to (if known). If NONE of the sources return a\n"
            "        hit, set metadata.attribution_status=\"unattributed\" and keep\n"
            "        the report minimal. Without block-explorer access we cannot\n"
            "        chain-trace — note that explicitly in `limitations`."
        )
    elif seed_type == "username":
        return (
            f"Seed indicator: type=username value={seed_value}\n"
            "This is an actor handle / alias — could be a forum username, a\n"
            "Telegram/X/GitHub handle, a malware-builder identifier, or a paste-\n"
            "site author. Treat it as an opaque identifier and surface every\n"
            "public mention in the threat-intel sources we have.\n\n"
            f"STEP 1: add_node(username, {seed_value}, tags=[\"seed\"])\n"
            f"STEP 2: threatfox_search({seed_value}) — sometimes lists known actor handles.\n"
            f"STEP 3: pulsedive_indicator({seed_value}) — corroboration.\n"
            f"STEP 4: opencti_lookup_indicator({seed_value}) — community KG.\n"
            f"STEP 5: urlscan_search(\"{seed_value}\") — the handle may appear in\n"
            "        page text on phishing kits or open-dir listings.\n"
            "STEP 6: For every domain / IP / hash mentioned in returned records,\n"
            "        graph it (add_node + uses_handle edge from the infrastructure\n"
            "        back to the username node).\n"
            "STEP 7: Final report — value=\"investigation_summary\". The summary\n"
            "        MUST state: which actor / campaign the handle attributes to\n"
            "        (if any), how many concrete IOCs were tied to it, and what\n"
            "        platforms / forums the handle has been observed on. If no\n"
            "        public source mentions the handle, set\n"
            "        metadata.attribution_status=\"no_public_record\" and keep\n"
            "        the report minimal — the handle alone is not actionable."
        )
    elif seed_type == "phone":
        return (
            f"Seed indicator: type=phone value={seed_value}\n"
            "This is a phone number — could be a scam/fraud callback number, a\n"
            "Telegram/WhatsApp contact for a vendor, a phishing SMS sender, or an\n"
            "actor's registration/2FA number. Supply E.164 (+countrycode…). Your\n"
            "job is to qualify the number and surface every public mention.\n\n"
            f"STEP 1: add_node(phone, {seed_value}, tags=[\"seed\"])\n"
            f"STEP 2: phone_lookup({seed_value}) — offline libphonenumber metadata.\n"
            "        Copy onto the node metadata: country/region, carrier, line_type\n"
            "        (mobile/fixed/voip/toll_free), and validity. A VoIP / invalid /\n"
            "        toll-free number is a strong burner/spoofing signal — tag it\n"
            "        (e.g. `voip_line`, `invalid_number`).\n"
            f"STEP 3: threatfox_search({seed_value}) — listed in any IOC bundle?\n"
            f"STEP 4: opencti_lookup_indicator({seed_value}) — community KG mention.\n"
            f"STEP 5: urlscan_search(\"{seed_value}\") — the number may appear in\n"
            "        scanned scam/phishing page DOM (callback widgets, contact info).\n"
            "        Graph each matching page as a url node tied back with embedded_in.\n"
            "STEP 6: For every domain / email / username co-mentioned with the number\n"
            "        in returned records, graph it (add_node + uses_contact edge).\n"
            "STEP 7: Final report — value=\"investigation_summary\". The summary MUST\n"
            "        state: the country/carrier/line type, whether the number is a\n"
            "        likely burner (VoIP/invalid), and which campaign / actor it\n"
            "        attributes to (if any). If no public source mentions it, set\n"
            "        metadata.attribution_status=\"no_public_record\" and keep the\n"
            "        report minimal — the line metadata alone is the deliverable."
        )
    elif seed_type == "company":
        return (
            f"Seed indicator: type=company value={seed_value}\n"
            "This is a COMPANY / legal entity (Due-Diligence / KYB). Your job is\n"
            "factual identity verification + corporate hierarchy from authoritative\n"
            "registry data — NOT threat attribution, NOT adverse media.\n\n"
            f"STEP 1: add_node(company, {seed_value}, tags=[\"seed\"])\n"
            f"STEP 2: gleif_lookup(\"{seed_value}\") — resolve identity (legal name,\n"
            "        LEI, jurisdiction, status, address). If a name search returns\n"
            "        several matches, pick the best and note the alternatives.\n"
            "        CANONICALISE: set metadata.lei / jurisdiction / status ON THE\n"
            "        SEED node and treat it as the entity — if the official legal\n"
            "        name differs from the seed text, record it as an alias; do NOT\n"
            "        create a second company node for the same LEI (avoids the\n"
            "        'Danone' vs 'DANONE SA' duplicate-hub problem).\n"
            "STEP 3: If an LEI is found, gleif_lookup(\"<LEI>\") to pull Level-2\n"
            "        relationships. For each direct/ultimate parent and each direct\n"
            "        child: add_node(company, <name>, metadata={\"lei\": <lei>}) and\n"
            "        add_edge with relation `subsidiary_of` (child→parent) or\n"
            "        `parent_of` (parent→child), source=\"gleif\".\n"
            "STEP 4: REGISTRY by JURISDICTION (route to the matching one; don't\n"
            "        call a country's registry for entities outside it):\n"
            "        - GB → companies_house_lookup (officers + PSC → `person` nodes,\n"
            "          relation `officer_of` / `significant_control_of`; needs key,\n"
            "          skip if available=false). PSC = ESTIMATED control, not UBO.\n"
            "        - US → edgar_lookup (CIK / tickers / SIC + former names as\n"
            "          aliases; skip if found=false).\n"
            "        - FR → recherche_entreprises_lookup (SIREN + dirigeants →\n"
            "          `person` nodes via officer_of; a dirigeant of kind=company →\n"
            "          graph as a company). Skip if found=false.\n"
            "        For other jurisdictions (NL/DE/PL/SG/…) no registry connector\n"
            "        exists yet — note the gap, don't force a wrong-country call.\n"
            "STEP 5: sanctions_screen_batch([...]) — pass EVERY company + person\n"
            "        name in the graph in ONE call (don't screen one-by-one). For\n"
            "        each name in `flagged`: tag that node `sanctioned`, record the\n"
            "        programme(s) + list + ref. A hit is a CANDIDATE match for human\n"
            "        review (name collisions happen), not an automated determination.\n"
            "STEP 6: Final report — value=\"investigation_summary\". State the\n"
            "        verified identity, the group structure (ultimate parent +\n"
            "        subsidiaries), and the confidence/limits. MANDATORY caveat in\n"
            "        `limitations`: ownership shown is ESTIMATED/INFERRED corporate\n"
            "        hierarchy (GLEIF Level-2), NOT authoritative beneficial\n"
            "        ownership (UBO/RBE), and not a substitute for a registry\n"
            "        consultation by an obligated entity. Do NOT include adverse\n"
            "        media or any criminal/wrongdoing claim about a natural person."
        )
    elif seed_type == "command_line":
        return (
            f"Seed indicator: type=command_line value={seed_value}\n"
            "This is a malicious command line / script / dropper snippet pasted "
            "by the analyst. The raw text is in the SOURCE REPORT block above — "
            "read it carefully BEFORE anything else.\n\n"
            f"STEP 1: add_node(command_line, {seed_value}, tags=[\"seed\"], "
            f"metadata={{\"preview\": \"<first line>\", \"interpretation\": "
            f"\"<one sentence: what does this command do>\"}})\n"
            "STEP 2: Categorise the command. Pick one and add it as a tag:\n"
            "  - powershell_dropper | bash_dropper | living_off_the_land | "
            "lolbins | base64_loader | hta_dropper | mshta_dropper | "
            "certutil_download | bitsadmin | curl_pipe_bash | iex_download | "
            "obfuscated_script\n"
            "STEP 3: Identify EVERY embedded indicator and graph it as its own node:\n"
            "  - URLs (curl/wget/Invoke-WebRequest/DownloadString targets) → "
            "add_node(url, <url>), add_edge(command_line→url, embedded_in_command)\n"
            "  - IPs / domains → add_node + same edge\n"
            "  - Hashes → add_node(hash, <h>) + same edge\n"
            "  - Base64 blobs that decode to URLs/IPs → decode mentally, add the\n"
            "    decoded indicator as a node + edge with evidence=\"decoded from\n"
            "    base64 within command line\".\n"
            "  - LOLBin names (rundll32, mshta, regsvr32, certutil, bitsadmin,\n"
            "    msbuild, installutil, …) → tag the command_line node with the\n"
            "    lolbin name; no separate node needed.\n"
            "STEP 4: For each embedded URL / domain / IP, run its standard\n"
            "  workflow (urlscan_search + urlhaus_host + virustotal_* + threatfox_search).\n"
            "STEP 5: If a binary hash is referenced or downloaded, run\n"
            "  virustotal_file(<h>) + malwarebazaar_hash(<h>) + otx_file(<h>) to\n"
            "  identify the family.\n"
            "STEP 6: Final report — value=\"investigation_summary\", linking the\n"
            "  command_line node with known_ioc. The summary MUST describe what\n"
            "  the command does AND which family / actor the embedded infrastructure\n"
            "  belongs to (if attributable)."
        )
    else:
        return (
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



# ── Add-seed prompt blocks ────────────────────────────────────────────────
# The per-seed-type body appended to the run_add_seed prompt (between the shared
# STEP 1/2 preamble and the shared STEP 3/4 cross-seed/report suffix, both of
# which stay in agent_runner). Unknown seed types append nothing (""), exactly
# as the original ladder did.

def add_seed_block(seed_type: str, seed_value: str) -> str:
    """Return the per-seed-type body for run_add_seed, or "" for unknown types."""
    if seed_type == "ip":
        return (
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
        return (
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
        return (
            "Required tools for the new seed (each called on THIS seed value):\n"
            f"  - malwarebazaar_hash({seed_value})\n"
            f"  - virustotal_file({seed_value})\n"
            f"  - otx_file({seed_value})\n"
            f"  - threatfox_search({seed_value})\n"
            "For the hash node set metadata.file_name (required for UI labels).\n"
        )
    elif seed_type == "executable_name":
        return (
            "This is a filename-only add-seed (no binary, no hash). Required:\n"
            f"  - malwarebazaar_filename({seed_value})  — top samples → graph each\n"
            "    as a hash node with an `observed_as` edge to the executable_name.\n"
            "    Top 3 samples: also virustotal_file + otx_file + malwarebazaar_hash\n"
            "    to pull family / C2 / file_name set.\n"
            f"  - threatfox_search({seed_value})\n"
            "If any returned sample's sha256 / family / C2 ALREADY exists on the\n"
            "graph (from a prior seed), that's a concrete cross-seed link — record\n"
            "it in cross_seed_findings.\n"
        )
    elif seed_type == "url":
        return (
            "This is a URL add-seed. Graph the URL as a url node with tags=['seed'],\n"
            "derive the host, graph it as domain/ip, then run the full host workflow\n"
            "(rdap, dns, VT, threatfox, otx, urlhaus, urlscan, JARM).\n"
        )
    elif seed_type == "jarm":
        return (
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
        asn_num = _asn_num(seed_value)
        return (
            "This is an ASN add-seed. Required tools:\n"
            f"  - shodan_search(\"asn:AS{asn_num} port:443\")\n"
            f"  - For top 5 interesting IPs: defuse + virustotal_ip + threatfox_search + otx_ip\n"
            f"  - rdap_ip on ONE representative IP (netname/country/abuse_email)\n"
            f"  - threatfox_search(\"AS{asn_num}\")\n"
            "If multiple hosts in the AS share a JARM, graph that JARM and link all hits.\n"
            "If any cluster IP is ALREADY on the graph, record it in cross_seed_findings.\n"
        )
    elif seed_type == "email":
        return (
            "This is an email add-seed. Required tools:\n"
            f"  - emailrep_check({seed_value})\n"
            f"  - whoxy_reverse(email=\"{seed_value}\")  — every reverse-WHOIS domain hit\n"
            "    becomes a domain node + registered edge from the email.\n"
            f"  - pulsedive_indicator({seed_value})\n"
            f"  - opencti_lookup_indicator({seed_value})\n"
            f"  - threatfox_search({seed_value})\n"
            "If any returned domain ALREADY exists on the graph, that's a concrete\n"
            "cross-seed link — record it in cross_seed_findings.\n"
        )
    elif seed_type == "wallet_address":
        return (
            "This is a wallet_address add-seed. Required tools:\n"
            f"  - threatfox_search({seed_value})\n"
            f"  - pulsedive_indicator({seed_value})\n"
            f"  - opencti_lookup_indicator({seed_value})\n"
            f"  - urlscan_search(\"{seed_value}\")  — phishing page DOM may include it\n"
            "Set metadata.chain on the wallet node (btc / eth / xmr / …).\n"
        )
    elif seed_type == "username":
        return (
            "This is a username add-seed. Required tools:\n"
            f"  - threatfox_search({seed_value})\n"
            f"  - pulsedive_indicator({seed_value})\n"
            f"  - opencti_lookup_indicator({seed_value})\n"
            f"  - urlscan_search(\"{seed_value}\")\n"
            "Every domain / IP / hash co-mentioned with the handle becomes a node\n"
            "with a uses_handle edge to the username.\n"
        )
    elif seed_type == "phone":
        return (
            "This is a phone add-seed (supply E.164 +countrycode…). Required tools:\n"
            f"  - phone_lookup({seed_value})  — set metadata.country/carrier/line_type\n"
            f"  - threatfox_search({seed_value})\n"
            f"  - opencti_lookup_indicator({seed_value})\n"
            f"  - urlscan_search(\"{seed_value}\")\n"
            "Tag the node `voip_line` / `invalid_number` when the lookup says so.\n"
            "Every domain / email / username co-mentioned becomes a node with a\n"
            "uses_contact edge to the phone.\n"
        )
    elif seed_type == "company":
        return (
            "This is a company add-seed (Due-Diligence). Required tools:\n"
            f"  - gleif_lookup(\"{seed_value}\")  — identity + Level-2 hierarchy\n"
            f"  - companies_house_lookup(\"{seed_value}\")  — UK officers/PSC →\n"
            "    person nodes (best-effort; skip if no key). Screen each person.\n"
            f"  - edgar_lookup(\"{seed_value}\")  — US-listed issuers (CIK/tickers/\n"
            "    SIC/former names; best-effort, skip if found=false).\n"
            f"  - recherche_entreprises_lookup(\"{seed_value}\")  — FR company +\n"
            "    dirigeants → person nodes (best-effort; no key). Screen each.\n"
            f"  - sanctions_screen(\"{seed_value}\")  — OFAC/EU/UK; tag `sanctioned`\n"
            "    on a hit (candidate match for review, not a determination).\n"
            "Graph each parent/subsidiary as a company node with a\n"
            "subsidiary_of / parent_of edge. Set metadata.lei/jurisdiction/status.\n"
            "Ownership is ESTIMATED corporate hierarchy, NOT beneficial ownership.\n"
            "No adverse-media / criminal claims about natural persons.\n"
        )
    return ""


# ── Pivot prompt blocks ───────────────────────────────────────────────────
# The per-seed-type body appended to the run_pivot prompt (between the shared
# STEP 1/2 preamble and the shared STEP 3 report-merge suffix, both of which
# stay in agent_runner). Unknown seed types append nothing ("").

def pivot_block(seed_type: str, seed_value: str) -> str:
    """Return the per-seed-type body for run_pivot, or "" for unknown types."""
    if seed_type == "ip":
        return (
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
        return (
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
        return (
            "Call these tools (skip any whose results are already in the graph):\n"
            f"  - malwarebazaar_hash({seed_value})\n"
            f"  - virustotal_file({seed_value})\n"
            f"  - otx_file({seed_value})\n"
            f"  - threatfox_search({seed_value})\n"
            "For every hash node created or updated, set metadata.file_name.\n"
        )
    elif seed_type == "executable_name":
        return (
            "This is a filename-only pivot (no binary, no hash). Required:\n"
            f"  - malwarebazaar_filename({seed_value})  — graph each returned\n"
            "    sample's sha256 as a hash node + observed_as edge to the\n"
            "    executable_name. Top 3 samples: also virustotal_file +\n"
            "    malwarebazaar_hash + otx_file to pull family + C2.\n"
            f"  - threatfox_search({seed_value})\n"
        )
    elif seed_type == "url":
        return (
            "This is a URL pivot. Graph the URL as a url node (tag as seed if new),\n"
            "extract the host and graph it as domain/ip node. Then run enrichment on\n"
            "the host as you would for a domain/ip pivot:\n"
            f"  - urlscan_search(\"page.url:{seed_value}\")\n"
            f"  - urlhaus_host(<host>)\n"
            "  - rdap + DNS + VT (domain or ip flavor, depending on host)\n"
            "  - threatfox_search on both the URL and the host\n"
        )
    elif seed_type == "jarm":
        return (
            "This is a JARM pivot. Call these tools (skip any already in graph):\n"
            f"  - shodan_search(\"ssl.jarm:{seed_value}\")  — find cluster hosts\n"
            f"  - urlscan_search(\"hash:{seed_value}\")\n"
            f"  - threatfox_search({seed_value})\n"
            "For each new IP with this JARM: add_node(ip) + add_edge(ip→jarm, has_jarm).\n"
            "For top 3 IPs: defuse + virustotal_ip + threatfox_search.\n"
        )
    elif seed_type == "asn":
        asn_num = _asn_num(seed_value)
        return (
            "This is an ASN pivot. Call these tools (skip any already in graph):\n"
            f"  - shodan_search(\"asn:AS{asn_num} port:443\")\n"
            f"  - rdap_ip on one representative IP for netname/country/abuse_email\n"
            f"  - threatfox_search(\"AS{asn_num}\")\n"
            "For top 5 interesting IPs in the AS: defuse + virustotal_ip + threatfox_search.\n"
            "Tag the asn 'abused_asn' when ≥2 of those hosts return detection hits.\n"
        )
    elif seed_type == "email":
        return (
            "This is an email pivot. Call these tools (skip any already in graph):\n"
            f"  - emailrep_check({seed_value})\n"
            f"  - whoxy_reverse(email=\"{seed_value}\")\n"
            f"  - pulsedive_indicator({seed_value})\n"
            f"  - opencti_lookup_indicator({seed_value})\n"
            f"  - threatfox_search({seed_value})\n"
            "For each new domain returned by whoxy: add_node + registered edge.\n"
        )
    elif seed_type == "wallet_address":
        return (
            "This is a wallet_address pivot. Call these tools (skip already-graphed):\n"
            f"  - threatfox_search({seed_value})\n"
            f"  - pulsedive_indicator({seed_value})\n"
            f"  - opencti_lookup_indicator({seed_value})\n"
            f"  - urlscan_search(\"{seed_value}\")\n"
        )
    elif seed_type == "username":
        return (
            "This is a username pivot. Call these tools (skip already-graphed):\n"
            f"  - threatfox_search({seed_value})\n"
            f"  - pulsedive_indicator({seed_value})\n"
            f"  - opencti_lookup_indicator({seed_value})\n"
            f"  - urlscan_search(\"{seed_value}\")\n"
        )
    elif seed_type == "phone":
        return (
            "This is a phone pivot (E.164). Call these tools (skip already-graphed):\n"
            f"  - phone_lookup({seed_value})\n"
            f"  - threatfox_search({seed_value})\n"
            f"  - opencti_lookup_indicator({seed_value})\n"
            f"  - urlscan_search(\"{seed_value}\")\n"
        )
    elif seed_type == "company":
        return (
            "This is a company pivot (Due-Diligence). Call (skip already-graphed):\n"
            f"  - gleif_lookup(\"{seed_value}\")\n"
            f"  - companies_house_lookup(\"{seed_value}\")  — UK officers/PSC (key)\n"
            f"  - edgar_lookup(\"{seed_value}\")  — US-listed issuers (no key)\n"
            f"  - recherche_entreprises_lookup(\"{seed_value}\")  — FR company + dirigeants\n"
            f"  - sanctions_screen(\"{seed_value}\")  — tag `sanctioned` on a hit\n"
            "Graph parents/subsidiaries as company nodes (subsidiary_of/parent_of).\n"
            "Graph officers/PSC as person nodes and sanctions_screen each.\n"
            "Ownership = ESTIMATED hierarchy, not beneficial ownership.\n"
        )
    return ""


# ── Follow-up phase extra steps ───────────────────────────────────────────
# Per-seed-type additional REQUIRED follow-up steps appended in the
# run_investigation follow-up phase. The numbering/join stays in agent_runner
# (it depends on the count of already-missing mandatory tools); only the
# per-type step text lives here. These are constant strings (no interpolation).

def followup_extra_steps(seed_type: str) -> list[str]:
    """Return the per-seed-type follow-up step strings, or [] for other types."""
    if seed_type == "ip":
        return [
            "After the above: read the graph — if a JARM node exists for this IP, "
            "call shodan_search(\"ssl.jarm:<jarm_value>\") to find other IPs with the same fingerprint. "
            "Add any new IPs as nodes with same_jarm edges to the seed IP.",
            "If virustotal_communicating_files returned an empty data[] AND threatfox/otx "
            "identified a specific malware family tag, "
            "call malwarebazaar_signature(<family>, limit=5) and add each returned sample "
            "as a hash node with a communicates_with edge from hash to the seed IP.",
            "If reverse_dns returned ≥ 1 domain, for EACH returned domain (top 3): "
            "(a) dns_resolve(<domain>, 'MX') and dns_resolve(<domain>, 'TXT') — add each "
            "discovered MX hostname and TXT record value to the seed/domain metadata; "
            "(b) crtsh_subdomains(<domain>) to enumerate sister hostnames; "
            "(c) wayback(<domain>) to check for historical takedown/seizure notices. "
            "Add every discovered hostname as a new domain node with edge "
            "(seed_ip → domain, resolves_to) and (domain → wayback_snapshot, has_archive).",
        ]
    elif seed_type == "domain":
        return [
            "If virustotal_communicating_files returned an empty data[] AND threatfox/otx "
            "identified a specific malware family tag, "
            "call malwarebazaar_signature(<family>, limit=5) and add each returned sample "
            "as a hash node with a communicates_with edge from hash to the seed.",
        ]
    return []
