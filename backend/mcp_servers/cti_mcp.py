"""MCP server exposing CTI source lookups to the agent."""
from mcp.server.fastmcp import FastMCP

from ..sources import crtsh, rdap, dns_tools, virustotal, urlscan, onyphe, shodan, otx, threatfox, wayback

mcp = FastMCP("bounce-cti")


@mcp.tool()
async def dns_resolve(domain: str) -> dict:
    """Resolve A/AAAA/MX/NS/TXT/CNAME/SOA records for a domain."""
    return await dns_tools.resolve_all(domain)


@mcp.tool()
async def reverse_dns(ip: str) -> list[str]:
    """PTR lookup for an IP."""
    return await dns_tools.reverse_dns(ip)


@mcp.tool()
async def crtsh_subdomains(domain: str) -> list[dict]:
    """Query crt.sh for certificates / subdomains of a domain (great for enumeration)."""
    return await crtsh.subdomains_for(domain)


@mcp.tool()
async def rdap_domain(domain: str) -> dict:
    """RDAP lookup for a domain (registrar, registrant, dates, nameservers)."""
    return await rdap.rdap_domain(domain)


@mcp.tool()
async def rdap_ip(ip: str) -> dict:
    """RDAP lookup for an IP (ASN, netname, country, abuse contact)."""
    return await rdap.rdap_ip(ip)


@mcp.tool()
async def virustotal_domain(domain: str) -> dict:
    """VirusTotal v3 domain report."""
    return await virustotal.vt_domain(domain)


@mcp.tool()
async def virustotal_ip(ip: str) -> dict:
    """VirusTotal v3 IP report."""
    return await virustotal.vt_ip(ip)


@mcp.tool()
async def virustotal_file(hash: str) -> dict:
    """VirusTotal v3 file report by md5/sha1/sha256."""
    return await virustotal.vt_file(hash)


@mcp.tool()
async def virustotal_resolutions_domain(domain: str) -> dict:
    """Historical passive DNS resolutions for a domain (VT)."""
    return await virustotal.vt_domain_resolutions(domain)


@mcp.tool()
async def virustotal_resolutions_ip(ip: str) -> dict:
    """Historical passive DNS resolutions for an IP (VT) — co-resident domains."""
    return await virustotal.vt_ip_resolutions(ip)


@mcp.tool()
async def urlscan_search(query: str) -> dict:
    """URLScan.io search. Examples: domain:example.com, ip:1.2.3.4, hash:..."""
    return await urlscan.urlscan_search(query)


@mcp.tool()
async def onyphe_domain(domain: str) -> dict:
    """Onyphe summary for a domain."""
    return await onyphe.onyphe_summary_domain(domain)


@mcp.tool()
async def onyphe_ip(ip: str) -> dict:
    """Onyphe summary for an IP."""
    return await onyphe.onyphe_summary_ip(ip)


@mcp.tool()
async def shodan_host(ip: str) -> dict:
    """Shodan host info (open ports, banners, vulns)."""
    return await shodan.shodan_host(ip)


@mcp.tool()
async def shodan_search(query: str) -> dict:
    """Shodan search query (e.g. http.favicon.hash:-12345, ssl.cert.serial:..., http.title:...)."""
    return await shodan.shodan_search(query)


@mcp.tool()
async def otx_domain(domain: str) -> dict:
    """AlienVault OTX domain general report."""
    return await otx.otx_domain(domain)


@mcp.tool()
async def otx_ip(ip: str) -> dict:
    """AlienVault OTX IP general report."""
    return await otx.otx_ip(ip)


@mcp.tool()
async def otx_file(hash: str) -> dict:
    """AlienVault OTX file general report."""
    return await otx.otx_file(hash)


@mcp.tool()
async def threatfox_search(ioc: str) -> dict:
    """ThreatFox (abuse.ch) IOC lookup — links indicators to malware families/campaigns."""
    return await threatfox.threatfox_search(ioc)


@mcp.tool()
async def wayback(url: str) -> dict:
    """Wayback Machine availability for a URL/domain."""
    return await wayback.wayback_snapshots(url)


if __name__ == "__main__":
    mcp.run()
