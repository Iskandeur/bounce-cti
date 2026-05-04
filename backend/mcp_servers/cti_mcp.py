"""MCP server exposing CTI source lookups to the agent."""
from mcp.server.fastmcp import FastMCP
import importlib

from ..hints import with_hints

mcp = FastMCP("bounce-cti")

# Lazy source-module loader. Top-level imports of all sources add ~1.5s to
# server startup, which under the new claude-code (>=2.1) harness is enough
# to push us past the MCP connection deadline (graph connects, cti times out
# as 'pending'). Each source is imported on first use instead.
_src_cache = {}
def _src(name: str):
    m = _src_cache.get(name)
    if m is None:
        m = importlib.import_module(f"backend.sources.{name}")
        _src_cache[name] = m
    return m


@mcp.tool()
async def dns_resolve(domain: str) -> dict:
    """Resolve A/AAAA/MX/NS/TXT/CNAME/SOA records for a domain."""
    return with_hints("dns_resolve", await _src("dns_tools").resolve_all(domain), domain)


@mcp.tool()
async def reverse_dns(ip: str) -> list[str]:
    """PTR lookup for an IP."""
    return await _src("dns_tools").reverse_dns(ip)


@mcp.tool()
async def crtsh_subdomains(domain: str) -> list[dict]:
    """Query crt.sh for certificates / subdomains of a domain (great for enumeration)."""
    return await _src("crtsh").subdomains_for(domain)


@mcp.tool()
async def crtsh_serial(serial: str) -> dict:
    """crt.sh lookup by cert serial number (hex). Free-tier equivalent of
    shodan_search(\"ssl.cert.serial:<serial>\") — surfaces other hosts that
    presented the same serial (common for reused self-signed Cobalt Strike
    staging certs). Returns {digest:{hosts,issuers,serial_count,...}, rows}.
    """
    return await _src("crtsh").by_serial(serial)


@mcp.tool()
async def crtsh_query(q: str, match: str = "ILIKE") -> dict:
    """crt.sh generic search. Use for pivots on a distinctive issuer/subject
    organisation (e.g. O='1314520.com'), or any free-form CT log query.
    `match` accepts ILIKE/LIKE/=. Returns the same digest shape as crtsh_serial.
    """
    return await _src("crtsh").by_query(q, match=match)


@mcp.tool()
async def rdap_domain(domain: str) -> dict:
    """RDAP lookup for a domain (registrar, registrant, dates, nameservers)."""
    return with_hints("rdap_domain", await _src("rdap").rdap_domain(domain), domain)


@mcp.tool()
async def rdap_ip(ip: str) -> dict:
    """RDAP lookup for an IP (ASN, netname, country, abuse contact)."""
    return with_hints("rdap_ip", await _src("rdap").rdap_ip(ip), ip)


@mcp.tool()
async def virustotal_domain(domain: str) -> dict:
    """VirusTotal v3 domain report."""
    return with_hints("virustotal_domain", await _src("virustotal").vt_domain(domain), domain)


@mcp.tool()
async def virustotal_ip(ip: str) -> dict:
    """VirusTotal v3 IP report."""
    return with_hints("virustotal_ip", await _src("virustotal").vt_ip(ip), ip)


@mcp.tool()
async def virustotal_file(hash: str) -> dict:
    """VirusTotal v3 file report by md5/sha1/sha256."""
    return with_hints("virustotal_file", await _src("virustotal").vt_file(hash), hash)


@mcp.tool()
async def virustotal_resolutions_domain(domain: str) -> dict:
    """Historical passive DNS resolutions for a domain (VT)."""
    return await _src("virustotal").vt_domain_resolutions(domain)


@mcp.tool()
async def virustotal_resolutions_ip(ip: str) -> dict:
    """Historical passive DNS resolutions for an IP (VT) — co-resident domains."""
    return with_hints("virustotal_resolutions_ip", await _src("virustotal").vt_ip_resolutions(ip), ip)


@mcp.tool()
async def virustotal_subdomains(domain: str) -> dict:
    """VirusTotal known subdomains for a domain (max 40). Complements crt.sh."""
    return await _src("virustotal").vt_subdomains(domain)


@mcp.tool()
async def virustotal_communicating_files(kind: str, value: str) -> dict:
    """Files (samples) that talked to a domain or IP. kind ∈ {'domain','ip'}.
    Opens a hash-pivot dimension from a network IOC (max 20)."""
    return await _src("virustotal").vt_communicating_files(kind, value)


@mcp.tool()
async def urlscan_search(query: str) -> dict:
    """URLScan.io search. Examples: domain:example.com, ip:1.2.3.4, hash:<jarm>, page.title:"login"."""
    return with_hints("urlscan_search", await _src("urlscan").urlscan_search(query), query)


@mcp.tool()
async def urlscan_result(uuid: str) -> dict:
    """Fetch full urlscan result by submission UUID (DOM hash, JARM, cert, network)."""
    return with_hints("urlscan_result", await _src("urlscan").urlscan_result(uuid), uuid)


@mcp.tool()
async def mnemonic_pdns(query: str) -> dict:
    """Mnemonic Passive DNS — historical resolutions for a domain or IP.
    Different vantage point from VT — use it as a second opinion."""
    return await _src("mnemonic").pdns_query(query)


@mcp.tool()
async def urlhaus_host(host: str) -> dict:
    """abuse.ch URLhaus — malicious URLs ever observed on a host (domain or IP)."""
    return await _src("abusech").urlhaus_host(host)


@mcp.tool()
async def malwarebazaar_hash(hash: str) -> dict:
    """abuse.ch MalwareBazaar — sample lookup by md5/sha1/sha256."""
    return await _src("abusech").mb_hash(hash)


@mcp.tool()
async def malwarebazaar_signature(signature: str, limit: int = 10) -> dict:
    """abuse.ch MalwareBazaar — list samples for a malware family/signature.

    Response is trimmed per-sample (hash fields, file_name/type, first_seen, tags).
    Default limit=10 to stay under MCP tool-result token caps.
    """
    return await _src("abusech").mb_signature(signature, limit=limit)


@mcp.tool()
async def onyphe_domain(domain: str) -> dict:
    """Onyphe summary for a domain."""
    return await _src("onyphe").onyphe_summary_domain(domain)


@mcp.tool()
async def onyphe_ip(ip: str) -> dict:
    """Onyphe summary for an IP."""
    return await _src("onyphe").onyphe_summary_ip(ip)


@mcp.tool()
async def onyphe_datascan(query: str) -> dict:
    """Onyphe Griffin datascan — run a raw Onyphe query against banners/HTTP/TLS
    indices (e.g. `ip:1.2.3.4`, `jarm:<jarm>`, `product:nginx os:Linux`).
    Returns scan records — read them like you would shodan hits."""
    return await _src("onyphe").onyphe_datascan(query)


@mcp.tool()
async def onyphe_threatlist(ip: str) -> dict:
    """Onyphe threatlist — curated malicious-IP feed hits (C2, scanners, abuse)."""
    return await _src("onyphe").onyphe_threatlist(ip)


@mcp.tool()
async def onyphe_resolver_forward(domain: str) -> dict:
    """Onyphe forward DNS resolver history for a domain."""
    return await _src("onyphe").onyphe_resolver_forward(domain)


@mcp.tool()
async def onyphe_resolver_reverse(ip: str) -> dict:
    """Onyphe reverse DNS resolver history for an IP (passive DNS)."""
    return await _src("onyphe").onyphe_resolver_reverse(ip)


@mcp.tool()
async def onyphe_ctl(domain: str) -> dict:
    """Onyphe Certificate Transparency Logs — SAN pivots for a domain."""
    return await _src("onyphe").onyphe_ctl(domain)


@mcp.tool()
async def onyphe_pastries(query: str) -> dict:
    """Onyphe pastries — paste-site mentions for an IOC (domain/IP/email)."""
    return await _src("onyphe").onyphe_pastries(query)


@mcp.tool()
async def onyphe_geoloc(ip: str) -> dict:
    """Onyphe geolocation for an IP — authoritative country/city."""
    return await _src("onyphe").onyphe_geoloc(ip)


@mcp.tool()
async def ip_api_lookup(ip: str) -> dict:
    """ip-api.com geolocation lookup (country, ASN, ISP, proxy/hosting hints).
    Free tier, no key needed. Good second opinion next to rdap/virustotal."""
    return await _src("ip_api").ip_api_single(ip)


@mcp.tool()
async def ip_api_batch_lookup(ips: list[str]) -> dict:
    """Batch geolocation lookup for up to 100 IPs at once via ip-api.com.
    Returns {results: [{query, country, as, ...}, ...]}. Use this when you
    pivoted to many IPs and need to classify them cheaply."""
    return await _src("ip_api").ip_api_batch(ips)


@mcp.tool()
async def ip_api_edns(ip: str) -> dict:
    """ip-api.com EDNS-aware geolocation — shows the CDN edge that answered
    the client-subnet query (helpful to distinguish anycast POPs)."""
    return await _src("ip_api").ip_api_edns(ip)


@mcp.tool()
async def shodan_host(ip: str) -> dict:
    """Shodan host info (open ports, banners, vulns)."""
    return await _src("shodan").shodan_host(ip)


@mcp.tool()
async def shodan_search(query: str) -> dict:
    """Shodan search query (e.g. http.favicon.hash:-12345, ssl.cert.serial:..., http.title:...)."""
    return await _src("shodan").shodan_search(query)


@mcp.tool()
async def otx_domain(domain: str) -> dict:
    """AlienVault OTX domain general report."""
    return await _src("otx").otx_domain(domain)


@mcp.tool()
async def otx_ip(ip: str) -> dict:
    """AlienVault OTX IP general report."""
    return await _src("otx").otx_ip(ip)


@mcp.tool()
async def otx_file(hash: str) -> dict:
    """AlienVault OTX file general report."""
    return await _src("otx").otx_file(hash)


@mcp.tool()
async def threatfox_search(ioc: str | None = None, query: str | None = None) -> dict:
    """ThreatFox (abuse.ch) IOC lookup — links indicators to malware families/campaigns.

    Accepts either `ioc` or `query` (alias) for convenience.
    """
    value = ioc or query or ""
    return await _src("threatfox").threatfox_search(value)


@mcp.tool()
async def wayback(url: str) -> dict:
    """Wayback Machine availability for a URL/domain."""
    return await _src("wayback").wayback_snapshots(url)


# ── Phase 3 sources (added 2026-05-03) ─────────────────────────────────

@mcp.tool()
async def abuseipdb_check(ip: str, max_age_days: int = 90) -> dict:
    """AbuseIPDB report for an IP: confidence score, country, ISP, total
    reports, last report date, categories. Free 1000 req/day."""
    return await _src("abuseipdb").check_ip(ip, max_age_days=max_age_days)


@mcp.tool()
async def certspotter_issuances(domain: str, include_subdomains: bool = True) -> dict:
    """CertSpotter (SSLMate) — certs issued for a domain. Each issuance has
    dns_names, issuer, validity, cert hashes. Free 100 req/day."""
    return await _src("certspotter").issuances_for_domain(domain, include_subdomains=include_subdomains)


@mcp.tool()
async def certspotter_serial(serial: str) -> dict:
    """CertSpotter lookup by cert serial (hex). Cross-host reuse detection
    (Cobalt Strike default certs etc.)."""
    return await _src("certspotter").issuances_for_serial(serial)


@mcp.tool()
async def netlas_search(query: str, size: int = 20) -> dict:
    """Netlas host search (Lucene-like). Examples:
      domain:evil.com
      ip:1.2.3.4
      jarm:<jarm_fingerprint>
      http.favicon.hash:<int>
      asn:AS12345
    Free 50 req/day."""
    return await _src("netlas").host_search(query, size=size)


@mcp.tool()
async def netlas_jarm(jarm: str, size: int = 20) -> dict:
    """Netlas — find hosts by JARM fingerprint."""
    return await _src("netlas").jarm_search(jarm, size=size)


@mcp.tool()
async def netlas_favicon(favicon_hash: str, size: int = 20) -> dict:
    """Netlas — find hosts by favicon mmh3 hash (Shodan-compat int)."""
    return await _src("netlas").favicon_search(favicon_hash, size=size)


@mcp.tool()
async def whoxy_reverse(email: str | None = None, name: str | None = None,
                         keyword: str | None = None, page: int = 1) -> dict:
    """Whoxy reverse WHOIS — list domains registered by an email, a name,
    or matching a keyword. Free tier: 1500 lifetime requests."""
    if email:
        return await _src("whoxy").reverse_by_email(email, page=page)
    if name:
        return await _src("whoxy").reverse_by_name(name, page=page)
    if keyword:
        return await _src("whoxy").reverse_by_keyword(keyword, page=page)
    return {"error": "whoxy_reverse: pass at least one of email, name, keyword"}


@mcp.tool()
async def zoomeye_search(query: str, page: int = 1) -> dict:
    """ZoomEye host search. Examples: ip:"1.2.3.4", hostname:"x.com",
    iconhash:"<mmh3>", ssl.jarm:"<jarm>". Free 10k/month."""
    return await _src("zoomeye").host_search(query, page=page)


@mcp.tool()
async def zoomeye_jarm(jarm: str, page: int = 1) -> dict:
    """ZoomEye — find hosts by JARM fingerprint."""
    return await _src("zoomeye").jarm_search(jarm, page=page)


@mcp.tool()
async def zoomeye_favicon(favicon_hash: str, page: int = 1) -> dict:
    """ZoomEye — find hosts by favicon mmh3 hash (Shodan-compat int)."""
    return await _src("zoomeye").favicon_search(favicon_hash, page=page)


@mcp.tool()
async def criminalip_ip(ip: str, full: bool = False) -> dict:
    """CriminalIP IP report: ASN, geo, ports, scoring, malicious flags.
    Free ~50 req/day."""
    return await _src("criminalip").ip_report(ip, full=full)


@mcp.tool()
async def criminalip_domain(domain: str) -> dict:
    """CriminalIP domain scan: scoring, related malware, hosting."""
    return await _src("criminalip").domain_report(domain)


@mcp.tool()
async def openphish_check(url: str | None = None, host: str | None = None) -> dict:
    """OpenPhish community feed — corroborate phishing classification.
    Pass `url` for exact match or `host` for substring match. No auth."""
    if url:
        return await _src("openphish").check_url(url)
    if host:
        return await _src("openphish").check_host(host)
    return {"error": "openphish_check: pass either url or host"}


@mcp.tool()
async def dom_fingerprints(url: str | None = None,
                            urlscan_uuid: str | None = None) -> dict:
    """Extract high-signal DOM fingerprints from a page: favicon mmh3 hash
    (Shodan-compat), title SHA1, marketing tracking IDs (GA, GA4, GTM, FB
    Pixel, Yandex, Hotjar, Adobe DTM, MS Clarity, TikTok), form action URLs
    (often the phishing backend), inline-script SHA1s, crypto wallet
    addresses (BTC bech32, ETH, XMR — drainer kits).

    Pass either `url` (live fetch + favicon) or `urlscan_uuid` (uses urlscan's
    public DOM endpoint, no extra fetch). Cached for 24h."""
    if url:
        return await _src("fingerprints").extract_from_url(url)
    if urlscan_uuid:
        return await _src("fingerprints").extract_from_urlscan(urlscan_uuid)
    return {"error": "dom_fingerprints: pass either url or urlscan_uuid"}


if __name__ == "__main__":
    mcp.run()
