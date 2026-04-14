"""MCP server exposing CTI source lookups to the agent."""
from mcp.server.fastmcp import FastMCP
import importlib

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
    return await _src("dns_tools").resolve_all(domain)


@mcp.tool()
async def reverse_dns(ip: str) -> list[str]:
    """PTR lookup for an IP."""
    return await _src("dns_tools").reverse_dns(ip)


@mcp.tool()
async def crtsh_subdomains(domain: str) -> list[dict]:
    """Query crt.sh for certificates / subdomains of a domain (great for enumeration)."""
    return await _src("crtsh").subdomains_for(domain)


@mcp.tool()
async def rdap_domain(domain: str) -> dict:
    """RDAP lookup for a domain (registrar, registrant, dates, nameservers)."""
    return await _src("rdap").rdap_domain(domain)


@mcp.tool()
async def rdap_ip(ip: str) -> dict:
    """RDAP lookup for an IP (ASN, netname, country, abuse contact)."""
    return await _src("rdap").rdap_ip(ip)


@mcp.tool()
async def virustotal_domain(domain: str) -> dict:
    """VirusTotal v3 domain report."""
    return await _src("virustotal").vt_domain(domain)


@mcp.tool()
async def virustotal_ip(ip: str) -> dict:
    """VirusTotal v3 IP report."""
    return await _src("virustotal").vt_ip(ip)


@mcp.tool()
async def virustotal_file(hash: str) -> dict:
    """VirusTotal v3 file report by md5/sha1/sha256."""
    return await _src("virustotal").vt_file(hash)


@mcp.tool()
async def virustotal_resolutions_domain(domain: str) -> dict:
    """Historical passive DNS resolutions for a domain (VT)."""
    return await _src("virustotal").vt_domain_resolutions(domain)


@mcp.tool()
async def virustotal_resolutions_ip(ip: str) -> dict:
    """Historical passive DNS resolutions for an IP (VT) — co-resident domains."""
    return await _src("virustotal").vt_ip_resolutions(ip)


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
    return await _src("urlscan").urlscan_search(query)


@mcp.tool()
async def urlscan_result(uuid: str) -> dict:
    """Fetch full urlscan result by submission UUID (DOM hash, JARM, cert, network)."""
    return await _src("urlscan").urlscan_result(uuid)


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


if __name__ == "__main__":
    mcp.run()
