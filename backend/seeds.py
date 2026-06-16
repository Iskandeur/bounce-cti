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
    "email", "wallet_address", "username", "command_line",
)
