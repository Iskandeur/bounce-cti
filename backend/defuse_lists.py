"""Hardcoded defusing lists. Extend as needed."""
import ipaddress

CDN_RANGES = [
    "104.16.0.0/12",   # Cloudflare
    "172.64.0.0/13",
    "162.158.0.0/15",
    "131.0.72.0/22",
    "151.101.0.0/16",  # Fastly
    "23.235.32.0/20",
    "199.232.0.0/16",
    "23.32.0.0/11",    # Akamai
    "104.64.0.0/10",
    "13.32.0.0/15",    # CloudFront
    "13.224.0.0/14",
    "52.84.0.0/15",
    "143.204.0.0/16",
    "34.96.0.0/12",    # GCP LB
    "35.190.0.0/17",
]
_CDN_NETS = [ipaddress.ip_network(c) for c in CDN_RANGES]

PARKING_NS = {
    "ns1.sedoparking.com", "ns2.sedoparking.com",
    "ns1.bodis.com", "ns2.bodis.com",
    "ns1.above.com", "ns2.above.com",
    "ns1.dan.com", "ns2.dan.com",
    "ns1.parkingcrew.net", "ns2.parkingcrew.net",
    "ns1.uniregistrymarket.link", "ns2.uniregistrymarket.link",
    # HugeDomains / NameBright / Afternic marketplace
    "nsg1.namebrightdns.com", "nsg2.namebrightdns.com",
    "ns1.hugedomains.com", "ns2.hugedomains.com",
    # Sav.com / ParkLogic / other common parking providers
    "ns1.afternic.com", "ns2.afternic.com",
    "ns1.undeveloped.com", "ns2.undeveloped.com",
    "ns1.parklogic.com", "ns2.parklogic.com",
}

# Registrant orgs/emails that confirm a domain is parked/for-sale
PARKING_REGISTRANTS = {
    "hugedomains.com", "domainmarket.com", "afternic.com",
    "sedo.com", "bodis.com", "dan.com", "undeveloped.com",
    "parklogic.com", "godaddy.com parking",
}

DYNDNS_TLDS = {
    "duckdns.org", "no-ip.com", "no-ip.org", "no-ip.biz", "ddns.net",
    "freedns.afraid.org", "dynu.com", "ydns.io", "dynv6.net", "myftp.org",
    "hopto.org", "zapto.org", "serveftp.com", "myvnc.com",
}

# CNAME targets that confirm domain is parked
PARKING_CNAMES = {
    "hugedomains.com", "traff-https.hugedomains.com", "traff-3.hugedomains.com",
    "parkingpage.namecheap.com", "sedoparking.com", "bodis.com",
    "above.com", "parklogic.com", "afternic.com",
}

# Nameserver substrings that confirm a sinkhole / takedown handler.
# Match is case-insensitive substring on the lowered NS hostname.
SINKHOLE_NS_PATTERNS = [
    "sinkhole.", "sinkholed.", ".shadowserver.org", ".abuse.ch",
    "rpz.", "blackhole.", ".spamhaus.org", "sinkhole.cyber.gc.ca",
    ".sinkhole.team-cymru.com", "sinkhole.dyn.com", "sinkhole.lacnic.net",
    "ns1.csof.net", "ns2.csof.net",  # Microsoft DCU sinkhole NS
    "sinkhole.akamai.com", "fbisinkhole",
]

# Known sinkhole IPs — these belong to security vendors / LE / academic
# monitoring teams. A live DNS resolution onto one of these IPs means the
# domain has been taken over for passive measurement.
KNOWN_SINKHOLES = {
    # Shadowserver Foundation
    "184.105.139.67", "184.105.139.68", "184.105.139.69",
    # Microsoft DCU
    "204.13.200.103", "204.13.248.95",
    # OpenDNS / Cisco Umbrella block page
    "146.112.61.106",
    # Spamhaus DBL "drop" address
    "192.42.116.41",
    # Common 1990s-era catch-all / Microsoft sinkhole legacy
    "199.16.156.41",
    "8.7.198.45",
    # abuse.ch URLhaus sinkhole
    "104.244.14.252",
    # Team Cymru DNS sinkhole
    "38.102.150.27",
    # Conficker Working Group / Microsoft historical
    "207.46.90.16",
    # FBI / DoJ historical takedown landings
    "104.236.213.202",
    "199.83.131.182",
}

# Reserved / unroutable IPs that indicate a deliberate null route
# ("blackhole"). Distinct from a sinkhole — a blackhole means the domain
# has been parked at an unresolvable address rather than monitored.
BLACKHOLE_IPS = {
    "0.0.0.0", "127.0.0.1", "127.0.0.2", "127.0.53.53",
    "::", "::1", "::ffff:0.0.0.0",
}
BLACKHOLE_RANGES = [
    "0.0.0.0/8",        # reserved "this network"
    "127.0.0.0/8",      # loopback
    "240.0.0.0/4",      # reserved future use
    "192.0.2.0/24",     # TEST-NET-1
    "198.51.100.0/24",  # TEST-NET-2
    "203.0.113.0/24",   # TEST-NET-3
]
_BLACKHOLE_NETS = [ipaddress.ip_network(c) for c in BLACKHOLE_RANGES]

# Registrant-side markers that indicate a law-enforcement / vendor
# takedown rather than a commercial parking. When ANY of these match the
# RDAP registrant email/org/registrar, the domain is `sinkholed` with
# HISTORICAL VALUE — the agent should preserve passive residue rather
# than early-exit.
LE_REGISTRANT_PATTERNS = [
    # Email host substrings
    "@fbi.gov", "@ic3.gov", "@dhs.gov", "@cisa.dhs.gov",
    "@usss.dhs.gov", "@justice.gov", "@dc3.mil",
    "@europol.europa.eu", "@interpol.int", "@ncfta.net",
    "@shadowserver.org", "@spamhaus.org", "@abuse.ch",
    "@microsoft.com",        # DCU takedown registrant
    # Org / handle substrings
    "federal bureau of investigation", "fbi cyber division",
    "u.s. department of justice", "europol", "microsoft corporation",
    "shadowserver foundation", "spamhaus", "team cymru",
    # Registrar markers (RDAP `registrar` field)
    "rolr", "registrar of last resort",
]


def ip_in_cdn(ip: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net in _CDN_NETS:
        if addr in net:
            return str(net)
    return None


def is_dyndns_domain(domain: str) -> bool:
    d = domain.lower().strip(".")
    return any(d == t or d.endswith("." + t) for t in DYNDNS_TLDS)


def is_parking_ns(ns: str) -> bool:
    return ns.lower().strip(".") in PARKING_NS


def is_sinkhole_ns(ns: str) -> bool:
    ns_l = ns.lower().strip(".")
    return any(p in ns_l for p in SINKHOLE_NS_PATTERNS)


def is_sinkhole(ip: str) -> bool:
    return ip in KNOWN_SINKHOLES


def is_blackhole(ip: str) -> bool:
    """Reserved / null-routed IP — domain points there to be unresolvable,
    not to be monitored. Differs from a sinkhole semantically."""
    if ip in BLACKHOLE_IPS:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _BLACKHOLE_NETS)


def le_registrant_match(text: str) -> str | None:
    """Return the matching LE-pattern substring if `text` (a registrant
    email, org name, or registrar string) looks like a law-enforcement
    or vendor takedown handler. Used to flag `le_seized` sinkholes that
    should be investigated for historical residue rather than early-exit."""
    if not text:
        return None
    t = text.lower()
    for p in LE_REGISTRANT_PATTERNS:
        if p in t:
            return p
    return None


def defuse_check(kind: str, value: str, *,
                 registrant: str | None = None,
                 registrar: str | None = None) -> dict:
    """Return dict with tags + reasons + sinkhole_kind. kind in {ip, domain, ns}.

    Optional `registrant`/`registrar` (RDAP fields, free-form strings) are
    inspected for LE-takedown markers — when matched, the result carries
    ``sinkhole_kind="le_seized"`` which signals the agent to preserve
    historical residue rather than early-exit.

    Result schema:
      {
        "tags":             list[str],         # cdn|parking|sinkhole|dyndns|blackhole
        "reasons":          list[str],         # one human line per signal
        "sinkhole_kind":    str | None,        # le_seized|monitoring|blackhole|None
        "should_stop_pivot": bool,             # True only when *commercial* defuse
                                               # — LE seizures explicitly stay false
                                               # so the agent keeps mining residue.
      }
    """
    tags: list[str] = []
    reasons: list[str] = []
    sinkhole_kind: str | None = None
    if kind == "ip":
        cdn = ip_in_cdn(value)
        if cdn:
            tags.append("cdn")
            reasons.append(f"IP in CDN range {cdn}")
        if is_blackhole(value):
            tags.append("blackhole")
            sinkhole_kind = "blackhole"
            reasons.append(f"IP {value} is a reserved / null-routed address — domain is intentionally unresolvable")
        elif is_sinkhole(value):
            tags.append("sinkhole")
            sinkhole_kind = "monitoring"
            reasons.append(f"IP {value} is a known monitoring sinkhole (vendor / LE / academic)")
    elif kind == "domain":
        if is_dyndns_domain(value):
            tags.append("dyndns")
            reasons.append("Dynamic DNS provider TLD")
    elif kind == "ns":
        if is_parking_ns(value):
            tags.append("parking")
            reasons.append("Known parking nameserver")
        if is_sinkhole_ns(value):
            tags.append("sinkhole")
            sinkhole_kind = sinkhole_kind or "monitoring"
            reasons.append(f"NS {value} matches a known sinkhole/takedown pattern")

    # Registrant-side LE takedown — applies to any kind, even when the IP
    # itself isn't on our list. RDAP often surfaces the seizure before the
    # DNS records do.
    for src in (registrant, registrar):
        match = le_registrant_match(src or "")
        if match:
            if "sinkhole" not in tags:
                tags.append("sinkhole")
            sinkhole_kind = "le_seized"
            reasons.append(
                f"Registrant/registrar string contains LE-takedown marker '{match}' — "
                f"treat as law-enforcement sinkhole with HISTORICAL VALUE"
            )
            break

    # Commercial-defuse short-circuit: parking / dyndns / cdn / blackhole stop the
    # pivot. Monitoring sinkholes also stop NEW pivots (no live infra to chase) but
    # historical pivots remain valuable. LE-seizures explicitly DO NOT stop —
    # the agent must continue mining passive residue (VT historical resolutions,
    # crtsh history, wayback, threatfox).
    commercial_defuse = bool(set(tags) & {"cdn", "parking", "dyndns", "blackhole"})
    monitoring_sinkhole = sinkhole_kind == "monitoring"
    should_stop_pivot = commercial_defuse or monitoring_sinkhole
    if sinkhole_kind == "le_seized":
        should_stop_pivot = False

    return {
        "tags": tags,
        "reasons": reasons,
        "sinkhole_kind": sinkhole_kind,
        "should_stop_pivot": should_stop_pivot,
    }
