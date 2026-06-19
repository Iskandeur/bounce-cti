"""Pivot mapping: given a node type, return the list of pivots that should
be enqueued for it. Used by the auto-enqueue logic in ``graph_mcp.add_node``
and by the ``requeue_missing`` exhaustion-check pass.

A pivot is identified by its MCP tool name (e.g. ``"virustotal_domain"``) so
the agent can read a queue entry and call the tool directly with no
translation step.

Priority scale (lower = more important, drained first):
  1 -- foundational / no-API-key documentation pivots (rdap, dns_resolve)
  2 -- high-signal infrastructure pivots (cert, fingerprint, primary scanner)
  3 -- enrichment pivots (passive DNS, secondary scanners, threat lists)
  4 -- low-yield pivots (wayback, generic searches)
  5 -- exotic / edge cases

When a node is "defused" (CDN, sinkhole, parking, dyndns), only ``doc_only``
pivots are enqueued as 'pending'; the rest get inserted as 'skipped' with
``skip_reason='defused'`` so they remain visible in the coverage matrix.

When a pivot's source has no API key configured, it is inserted as 'skipped'
with ``skip_reason='no_api_key'`` so it surfaces in ``gaps_report``.

The rule table (``_PIVOT_RULES``) is keyed by canonical node type and shared
across verticals. ``pivots_for`` returns ``[]`` for unregistered types, and
other verticals (OSINT / DD) add their node-type pivots via ``register_pivots``
at import time rather than editing this module — so CTI types and OSINT/DD types
coexist in one uniform lookup.
"""
from __future__ import annotations

import os
import re
from typing import Callable, Optional

# (pivot_op, priority, key_source_required_or_None, doc_only)
_PIVOT_RULES: dict[str, list[tuple[str, int, Optional[str], bool]]] = {
    "domain": [
        ("rdap_domain", 1, None, True),
        ("whois_domain", 2, None, True),
        ("dns_resolve", 1, None, True),
        ("crtsh_subdomains", 2, None, False),
        ("virustotal_domain", 2, "vt", False),
        ("virustotal_subdomains", 3, "vt", False),
        ("virustotal_resolutions_domain", 3, "vt", False),
        ("urlscan_search", 3, None, False),
        ("wayback", 4, None, False),
        ("otx_domain", 3, "otx", False),
        ("onyphe_domain", 3, "onyphe", False),
        ("threatfox_search", 4, None, False),
        ("urlhaus_host", 4, None, False),
        ("mnemonic_pdns", 3, None, False),
        ("certspotter_issuances", 3, "certspotter", False),
        ("dom_fingerprints", 3, None, False),
        ("opencti_lookup_indicator", 3, "opencti", False),
        # Tier 1/2 additions (2026-05-21)
        ("dnsdumpster_domain", 3, "dnsdumpster", False),
        ("hackertarget_hosts", 3, None, False),
        ("leakix_host", 3, None, False),  # key optional — works anonymous too
        ("pulsedive_indicator", 3, "pulsedive", False),
        ("dnstwist_permutations", 4, None, False),
        ("phishtank_check", 4, None, False),
    ],
    "ip": [
        ("rdap_ip", 1, None, True),
        ("whois_ip", 2, None, True),
        ("reverse_dns", 1, None, True),
        ("virustotal_ip", 2, "vt", False),
        ("virustotal_resolutions_ip", 3, "vt", False),
        ("virustotal_communicating_files", 3, "vt", False),
        ("shodan_host", 2, "shodan", False),
        ("onyphe_ip", 3, "onyphe", False),
        ("otx_ip", 3, "otx", False),
        ("ip_api_lookup", 4, None, False),
        ("mnemonic_pdns", 3, None, False),
        ("threatfox_search", 4, None, False),
        ("urlhaus_host", 4, None, False),
        ("abuseipdb_check", 3, "abuseipdb", False),
        ("criminalip_ip", 3, "criminalip", False),
        ("opencti_lookup_indicator", 3, "opencti", False),
        # Tier 1/2 additions (2026-05-21)
        ("hackertarget_reverse_ip", 3, None, False),
        ("leakix_host", 3, None, False),
        ("pulsedive_indicator", 3, "pulsedive", False),
        ("censys_host", 3, "censys", False),
        ("alienvault_reputation", 4, None, False),
        ("tor_exit_check", 4, None, True),  # doc-only: always cheap, always safe
        ("project_honeypot_check", 4, None, False),
    ],
    "hash": [
        ("virustotal_file", 1, "vt", False),
        ("otx_file", 2, "otx", False),
        ("malwarebazaar_hash", 2, None, False),
        ("opencti_lookup_indicator", 3, "opencti", False),
        # Tier 1/2 additions (2026-05-21)
        ("circl_hash_lookup", 1, None, True),  # doc-only: defuses NSRL hits
    ],
    "executable_name": [
        # MalwareBazaar's get_filename query is the one free pivot that turns
        # a bare filename into concrete sample hashes. The hash nodes the agent
        # creates from the result then enqueue their own VT/OTX/threatfox/MB
        # pivots, so the standard hash workflow takes over from there.
        ("malwarebazaar_filename", 2, None, False),
        ("threatfox_search", 3, None, False),
        ("opencti_lookup_indicator", 3, "opencti", False),
    ],
    "url": [
        ("urlscan_search", 2, None, False),
        ("wayback", 3, None, False),
        ("dom_fingerprints", 2, None, False),
        ("website_extract", 3, None, False),  # links/emails/social — free, no key
        ("opencti_lookup_indicator", 3, "opencti", False),
        # Tier 1/2 additions (2026-05-21)
        ("phishtank_check", 3, None, False),
        ("pulsedive_indicator", 4, "pulsedive", False),
    ],
    "jarm": [
        ("onyphe_datascan", 2, "onyphe", False),
        ("shodan_search", 2, "shodan", False),
        ("netlas_jarm", 2, "netlas", False),
        ("zoomeye_jarm", 3, "zoomeye", False),
    ],
    "asn": [
        ("whois_ip", 1, None, True),
        ("onyphe_datascan", 4, "onyphe", False),
        ("shodan_search", 4, "shodan", False),
        ("netlas_search", 5, "netlas", False),
    ],
    "cert_serial": [
        ("crtsh_serial", 2, None, False),
        ("certspotter_serial", 3, "certspotter", False),
    ],
    "cert": [
        ("crtsh_query", 3, None, False),
    ],
    "email": [
        ("gravatar_email", 2, None, False),  # free, no key — email → linked accounts
        ("whoxy_reverse", 3, "whoxy", False),
        ("emailrep_check", 3, None, False),  # key optional
        ("pulsedive_indicator", 3, "pulsedive", False),
        ("opencti_lookup_indicator", 3, "opencti", False),
        ("threatfox_search", 4, None, False),
    ],
    "phone": [
        ("phone_lookup", 2, None, False),  # offline libphonenumber, no key
        ("threatfox_search", 2, None, False),
        ("opencti_lookup_indicator", 3, "opencti", False),
        ("urlscan_search", 4, None, False),
    ],
    "wallet_address": [
        ("threatfox_search", 2, None, False),
        ("wallet_enrich", 2, None, False),  # BTC free; ETH needs key (graceful)
        ("pulsedive_indicator", 3, "pulsedive", False),
        ("opencti_lookup_indicator", 3, "opencti", False),
        ("urlscan_search", 4, None, False),
    ],
    "username": [
        ("username_enumerate", 2, None, False),
        ("github_profile", 3, None, False),  # free, no key — identity enrichment
        ("threatfox_search", 2, None, False),
        ("pulsedive_indicator", 3, "pulsedive", False),
        ("opencti_lookup_indicator", 3, "opencti", False),
        ("urlscan_search", 4, None, False),
    ],
    "favicon_hash": [
        ("shodan_search", 2, "shodan", False),
        ("netlas_favicon", 2, "netlas", False),
        ("zoomeye_favicon", 3, "zoomeye", False),
    ],
    "tracking_id": [
        ("urlscan_search", 3, None, False),
    ],
    "ns": [
        ("crtsh_subdomains", 5, None, False),
    ],
    # title_hash, form_action, js_hash: no pivots (used as connectors /
    # evidence only). The auto-enqueue will skip them silently. wallet_address
    # used to live here but now gets ThreatFox / Pulsedive / OpenCTI lookups
    # since it can also be a seed type.
}

# Type aliases — different names for the same conceptual node type. When
# the agent calls add_node(favicon, ...) we want the same pivots as
# add_node(favicon_hash, ...). Resolved at lookup time in pivots_for().
_TYPE_ALIASES: dict[str, str] = {
    "favicon": "favicon_hash",          # prompt legacy name
    "cert_sha1": "cert_serial",         # CT-cluster pivot is the same
    "cert_sha256": "cert_serial",
    "cert_thumbprint": "cert_serial",
    "ja3": "jarm",                       # different fingerprint, same scanner pivots
    "ja3s": "jarm",
}

# Cloud / CDN ASN list — nodes with these ASNs are non-discriminating
# infrastructure (multi-tenant). Used by the convergence check, not the
# pivot mapper itself.
CLOUD_ASNS: set[str] = {
    "AS14618",   # AWS US East
    "AS16509",   # AWS Global
    "AS15169",   # Google
    "AS13335",   # Cloudflare
    "AS8075",    # Microsoft / Azure
    "AS32934",   # Facebook / Meta
    "AS16276",   # OVH
    "AS14061",   # DigitalOcean
    "AS20473",   # Choopa / Vultr
    "AS24940",   # Hetzner
    "AS396982",  # Google Cloud
    "AS54113",   # Fastly
    "AS20940",   # Akamai International
    "AS16625",   # Akamai
    "AS46606",   # Unified Layer
}

# Fan-out caps per parent node, applied at auto-enqueue time.
MAX_HIGH_PRIO_PER_NODE = 8   # priority <= 3
MAX_LOW_PRIO_PER_NODE = 4    # priority >= 4

# Per-hop cap on net-new domain/ip nodes (reset every DRAIN_QUEUE entry).
MAX_NEW_NODES_PER_HOP = 30

# Global pending-queue ceiling. Every eval retrospective showed the queue
# ballooning (478, 610, 1328, 2035 pending) because breadth-first fan-out adds
# ~15-50 pivots per new node and a single subdomain-enumeration call can 10x the
# queue in one turn. Once pending exceeds this ceiling, newly auto-enqueued
# pivots are parked as `deferred` (skip_reason='queue_ceiling') instead of
# `pending`, so the drain budget is spent on the work already queued rather than
# an ever-growing backlog. `requeue_missing` can still promote them later.
MAX_PENDING_QUEUE = int(os.environ.get("BOUNCE_PIVOT_QUEUE_MAX", "300"))


# ── Noise pre-filters (suppress structurally-doomed fan-out at enqueue time) ──

# Shared SaaS / cloud-platform parent domains: enumerating subdomains or running
# whois/crtsh on these is pure noise (the tenant doesn't control the apex). Seen
# wasting fan-out on *.azurewebsites.net (14/18 nodes on one case), *.onlyoffice.com.
_CLOUD_PLATFORM_SUFFIXES: tuple[str, ...] = (
    ".azurewebsites.net", ".cloudapp.azure.com", ".web.core.windows.net",
    ".blob.core.windows.net", ".trafficmanager.net",
    ".amazonaws.com", ".elb.amazonaws.com", ".s3.amazonaws.com",
    ".cloudfront.net", ".herokuapp.com", ".herokudns.com",
    ".onlyoffice.com", ".sharepoint.com", ".onmicrosoft.com",
    ".netlify.app", ".pages.dev", ".workers.dev", ".github.io",
    ".firebaseapp.com", ".web.app", ".appspot.com", ".run.app",
    ".vercel.app", ".cloudfunctions.net", ".azureedge.net",
    ".wixsite.com", ".weebly.com", ".squarespace.com", ".myshopify.com",
)
# Subdomain-enumeration / whois pivots that are wasteful on shared-SaaS parents.
_CLOUD_PLATFORM_SUPPRESSED_OPS: frozenset[str] = frozenset({
    "crtsh_subdomains", "virustotal_subdomains", "dnstwist_permutations",
    "dnsdumpster_domain", "whois_domain", "certspotter_issuances",
})


def cloud_platform_domain(value: str) -> bool:
    """True if the domain is a shared SaaS / cloud-platform host where
    subdomain enumeration and whois are non-discriminating noise."""
    v = (value or "").strip().lower().rstrip(".")
    return any(v.endswith(suf) or ("." + v).endswith(suf) for suf in _CLOUD_PLATFORM_SUFFIXES)


# Role / functional mailboxes: never a registrant, so reverse-WHOIS / EmailRep /
# OpenCTI on them burns paid quota for nothing (e.g. abuse@qatar.net.qa is a
# carrier abuse desk, not an operator identity).
_ROLE_MAILBOX_LOCALPARTS: frozenset[str] = frozenset({
    "abuse", "noc", "security", "hostmaster", "postmaster", "admin",
    "administrator", "webmaster", "support", "info", "dns", "registrar",
    "soc", "cert", "csirt", "helpdesk", "contact", "privacy", "legal",
})
_EMAIL_PIVOT_OPS: frozenset[str] = frozenset({
    "whoxy_reverse", "emailrep_check", "opencti_lookup_indicator",
})


def is_role_mailbox(email: str) -> bool:
    """True for functional/role mailboxes (abuse@, noc@, security@, ...) that
    are never a discriminating registrant identity."""
    e = (email or "").strip().lower()
    if "@" not in e:
        return False
    return e.split("@", 1)[0] in _ROLE_MAILBOX_LOCALPARTS


_RE_HEX_SERIAL = re.compile(r"^(0x)?[0-9a-f:\s]{6,}$")


def is_hex_serial(value: str) -> bool:
    """True if a cert_serial value looks like a hex DER serial. Label strings
    (e.g. 'sevenfeet_software_ab_codesign') break crtsh_serial / certspotter_serial
    lookups, so we skip those pivots rather than fire a doomed query."""
    v = (value or "").strip().lower()
    if not _RE_HEX_SERIAL.match(v):
        return False
    # Require at least 6 actual hex digits (reject e.g. ':::::: ' edge cases).
    hexchars = [ch for ch in v if ch in "0123456789abcdef"]
    return len(hexchars) >= 6


# Pivot ops that only make sense on a hex DER serial.
_SERIAL_OPS: frozenset[str] = frozenset({"crtsh_serial", "certspotter_serial"})


# Known threat-actor handles. When the agent tags a node with one of these
# (based on its own evidence), graph_mcp promotes it to a first-class
# `threat_actor` node + `attributed_to` edge so attribution is queryable rather
# than buried in a tag. Promotion preserves provenance (the source tag), so it
# is normalisation of the agent's own finding — not new attribution.
ACTOR_HANDLES: dict[str, str] = {
    "unc1549": "UNC1549", "nimbus_manticore": "Nimbus Manticore",
    "muddywater": "MuddyWater", "salt_typhoon": "Salt Typhoon",
    "earth_estries": "Earth Estries", "unc2286": "UNC2286",
    "unc4841": "UNC4841", "famous_chollima": "Famous Chollima",
    "unc5342": "UNC5342", "contagious_interview": "Contagious Interview",
    "lazarus": "Lazarus", "apt33": "APT33", "apt28": "APT28",
    "apt29": "APT29", "storm-1747": "Storm-1747",
    "smishing_triad": "Smishing Triad", "wang_duo_yu": "Wang Duo Yu",
    "socgholish": "SocGholish", "ta569": "TA569", "mustard_tempest": "Mustard Tempest",
    "ta450": "TA450", "interlock": "Interlock",
}


def actor_handle_for_tag(tag: str) -> Optional[str]:
    """Return the canonical actor display-name if `tag` is a known handle."""
    return ACTOR_HANDLES.get((tag or "").strip().lower().replace(" ", "_"))


# Known phishing-kit / PhaaS handles — the kit analogue of ACTOR_HANDLES (the
# tooling, not the operator). When the agent tags a node with one of these
# (based on its own OTX / urlscan / community-KG evidence), graph_mcp promotes
# it to a first-class `phishing_kit` node + `uses_kit` edge so the kit
# attribution is queryable rather than buried in a tag. Like ACTOR_HANDLES this
# is normalisation of the agent's own finding (the tag is its evidence), not new
# attribution. Kept to UNAMBIGUOUS adversary-in-the-middle / PhaaS kit names —
# deliberately excludes dual-use tech (e.g. Cloudflare Turnstile, which benign
# sites also use) to avoid false promotion (2026-06-17 eval FIX-3: c09 Tycoon
# 2FA identified but never graphed, RQ stuck at 40).
KIT_HANDLES: dict[str, str] = {
    "tycoon_2fa": "Tycoon 2FA", "tycoon": "Tycoon 2FA",
    "evilproxy": "EvilProxy", "evilginx": "Evilginx", "evilginx2": "Evilginx",
    "mamba_2fa": "Mamba 2FA", "sneaky_2fa": "Sneaky 2FA",
    "rockstar_2fa": "Rockstar 2FA", "greatness": "Greatness",
    "dadsec": "DadSec", "naked_pages": "NakedPages", "nakedpages": "NakedPages",
    "caffeine": "Caffeine", "w3ll": "W3LL",
}


def kit_handle_for_tag(tag: str) -> Optional[str]:
    """Return the canonical phishing-kit display-name if `tag` is a known kit."""
    return KIT_HANDLES.get((tag or "").strip().lower().replace(" ", "_"))


# Known-bad positive markers — the inverse of defuse_lists. When a node's value
# exactly matches one of these publicly-documented tool DEFAULTS, auto-tag it so
# the agent doesn't have to recall the fingerprint from memory. Kept deliberately
# CONSERVATIVE (exact match on fully-public defaults only) to avoid false
# attribution — operators should extend this from verified threat-intel, not
# partial hashes. Keyed by node_type → {lowercased exact value: (tag, note)}.
KNOWN_BAD_MARKERS: dict[str, dict[str, tuple[str, str]]] = {
    # Cobalt Strike's default self-signed TLS cert serial (0x8BB00EE) — one of
    # the most widely published C2 defaults; an unmodified team-server tell.
    "cert_serial": {
        "146473198": ("cobalt_strike_default_cert",
                      "Cobalt Strike default TLS cert serial 0x8BB00EE (unmodified team server)"),
    },
}


def known_bad_marker(node_type: str, value: str) -> Optional[tuple[str, str]]:
    """Return (tag, note) if value is a documented known-bad default for this
    node type, else None."""
    table = KNOWN_BAD_MARKERS.get(canonical_type(node_type))
    if not table:
        return None
    return table.get((value or "").strip().lower())


# Reverse map: pivot_op -> the key-pool source it needs (None if keyless).
_OP_KEY_SOURCE: dict[str, str] = {}
for _rules in _PIVOT_RULES.values():
    for _op, _prio, _key_req, _doc in _rules:
        if _key_req and _op not in _OP_KEY_SOURCE:
            _OP_KEY_SOURCE[_op] = _key_req


def key_source_for_op(op: str) -> Optional[str]:
    """Return the key-pool source name a pivot op needs (e.g. 'shodan'), or
    None if the op needs no API key."""
    return _OP_KEY_SOURCE.get(op)


def canonical_type(node_type: str) -> str:
    """Map an agent-provided node type to the canonical key used in
    _PIVOT_RULES (e.g. 'favicon' -> 'favicon_hash')."""
    if not node_type:
        return ""
    t = node_type.strip().lower()
    return _TYPE_ALIASES.get(t, t)


def pivots_for(node_type: str, node_value: str, *,
               has_key: Callable[[str], bool],
               defused: bool = False) -> list[tuple[str, int, Optional[str]]]:
    """Return ``[(pivot_op, priority, skip_reason_or_None)]`` for a node.

    - If ``defused``, non-doc pivots are returned with ``skip_reason='defused'``.
    - If a pivot's source lacks any key (``has_key(src)`` False), returned
      with ``skip_reason='no_api_key'``.
    - Otherwise, ``skip_reason`` is ``None`` (the caller enqueues as pending).
    """
    rules = _PIVOT_RULES.get(canonical_type(node_type), [])
    out: list[tuple[str, int, Optional[str]]] = []
    for op, prio, key_required, doc_only in rules:
        if defused and not doc_only:
            out.append((op, prio, "defused"))
            continue
        if key_required and not has_key(key_required):
            out.append((op, prio, "no_api_key"))
            continue
        out.append((op, prio, None))
    return out


# Pivot-rule tuple shape, shared by _PIVOT_RULES and register_pivots:
#   (pivot_op, priority, key_source_required_or_None, doc_only)
PivotRule = tuple[str, int, Optional[str], bool]


def register_pivots(node_type: str, rules: list[PivotRule], *, replace: bool = False) -> None:
    """Register pivot rules for a node type — the extension point for other
    verticals (OSINT / DD source modules add their node-type pivots here at
    import time instead of editing the _PIVOT_RULES monolith).

    The table is keyed by canonical node type and shared across verticals, so
    OSINT/DD types coexist with the CTI ones and ``pivots_for`` works uniformly.
    Rules are appended (deduping by pivot_op, first registration wins) unless
    ``replace=True``. Tuple shape is validated to fail fast on bad entries.
    """
    for r in rules:
        if not (isinstance(r, tuple) and len(r) == 4
                and isinstance(r[0], str) and isinstance(r[1], int)
                and (r[2] is None or isinstance(r[2], str)) and isinstance(r[3], bool)):
            raise ValueError(f"invalid pivot rule for {node_type!r}: {r!r} "
                             "(expected (op:str, priority:int, key_source:str|None, doc_only:bool))")
    key = canonical_type(node_type)
    if replace or key not in _PIVOT_RULES:
        _PIVOT_RULES[key] = list(rules)
        return
    existing_ops = {op for op, _, _, _ in _PIVOT_RULES[key]}
    for r in rules:
        if r[0] not in existing_ops:
            _PIVOT_RULES[key].append(r)
            existing_ops.add(r[0])


def known_pivot_types() -> tuple[str, ...]:
    """Canonical node types that currently have pivot rules registered."""
    return tuple(_PIVOT_RULES)


def discriminating_marker(node_type: str, tags: list[str] | None,
                           metadata: dict | None) -> bool:
    """Return True if this node counts as a "discriminating fingerprint" for
    the convergence criterion. See PIVOT_MAPPING.md §4."""
    tags = tags or []
    metadata = metadata or {}

    # Always discriminating
    if node_type in ("jarm", "ja3", "ja3s", "favicon_hash", "cert_serial",
                      "tracking_id", "wallet_address", "email", "phone", "person"):
        return True

    # Defused tags neutralise the marker. `blackhole` joins the list — a
    # null-routed IP cannot identify infrastructure. `sinkhole` stays here
    # too (sinkhole IPs are shared by hundreds of historical victims, so
    # they don't fingerprint a single operator on their own).
    bad_tags = {"cdn", "parking", "sinkhole", "blackhole", "dyndns", "tor_exit",
                  "nsrl_known"}
    if any(t in bad_tags for t in tags):
        return False

    if node_type == "ip":
        return True
    if node_type == "domain":
        return True
    if node_type == "ns":
        return True
    if node_type == "asn":
        # Only discriminating if not a cloud ASN
        # node_value would be like "AS12345"; we accept it via metadata too
        return True  # caller handles cloud check via CLOUD_ASNS

    # title_hash, form_action, js_hash, report, etc.: not discriminating alone
    return False
