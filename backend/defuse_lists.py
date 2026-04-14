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

# Sinkhole nameserver patterns (substring match)
SINKHOLE_NS_PATTERNS = [
    "sinkhole.", "sinkholed.", ".shadowserver.org", ".abuse.ch",
    "rpz.", "blackhole.",
]

KNOWN_SINKHOLES = {
    "204.13.200.103",  # Microsoft sinkhole
    "199.16.156.41",
    "8.7.198.45",
    "146.112.61.106",  # OpenDNS
}


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


def defuse_check(kind: str, value: str) -> dict:
    """Return dict with tags + reason. kind in {ip, domain, ns}."""
    tags = []
    reasons = []
    if kind == "ip":
        cdn = ip_in_cdn(value)
        if cdn:
            tags.append("cdn")
            reasons.append(f"IP in CDN range {cdn}")
        if is_sinkhole(value):
            tags.append("sinkhole")
            reasons.append("Known sinkhole IP")
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
            reasons.append("Known sinkhole nameserver")
    return {"tags": tags, "reasons": reasons, "should_stop_pivot": bool(tags)}
