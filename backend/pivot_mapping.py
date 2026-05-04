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
"""
from __future__ import annotations

from typing import Callable, Optional

# (pivot_op, priority, key_source_required_or_None, doc_only)
_PIVOT_RULES: dict[str, list[tuple[str, int, Optional[str], bool]]] = {
    "domain": [
        ("rdap_domain", 1, None, True),
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
    ],
    "ip": [
        ("rdap_ip", 1, None, True),
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
    ],
    "hash": [
        ("virustotal_file", 1, "vt", False),
        ("otx_file", 2, "otx", False),
        ("malwarebazaar_hash", 2, None, False),
    ],
    "url": [
        ("urlscan_search", 2, None, False),
        ("wayback", 3, None, False),
        ("dom_fingerprints", 2, None, False),
    ],
    "jarm": [
        ("onyphe_datascan", 2, "onyphe", False),
        ("shodan_search", 2, "shodan", False),
        ("netlas_jarm", 2, "netlas", False),
        ("zoomeye_jarm", 3, "zoomeye", False),
    ],
    "asn": [
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
        ("whoxy_reverse", 3, "whoxy", False),
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
    # title_hash, form_action, wallet_address, js_hash: no pivots (used as
    # connectors/evidence only). The auto-enqueue will skip them silently.
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


def discriminating_marker(node_type: str, tags: list[str] | None,
                           metadata: dict | None) -> bool:
    """Return True if this node counts as a "discriminating fingerprint" for
    the convergence criterion. See PIVOT_MAPPING.md §4."""
    tags = tags or []
    metadata = metadata or {}

    # Always discriminating
    if node_type in ("jarm", "favicon_hash", "cert_serial", "tracking_id",
                      "wallet_address", "email"):
        return True

    # Defused tags neutralise the marker
    bad_tags = {"cdn", "parking", "sinkhole", "dyndns"}
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
