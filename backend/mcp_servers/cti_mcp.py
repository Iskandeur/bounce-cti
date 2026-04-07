"""MCP server exposing CTI source lookups to the agent."""
import asyncio
from mcp.server.fastmcp import FastMCP

from ..sources import crtsh, rdap, dns_tools, virustotal, urlscan, onyphe, shodan, otx, threatfox, wayback

mcp = FastMCP("bounce-cti")


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


@mcp.tool()
def dns_resolve(domain: str) -> dict:
    """Resolve A/AAAA/MX/NS/TXT/CNAME/SOA records for a domain."""
    return _run(dns_tools.resolve_all(domain))


@mcp.tool()
def reverse_dns(ip: str) -> list[str]:
    """PTR lookup for an IP."""
    return _run(dns_tools.reverse_dns(ip))


@mcp.tool()
def crtsh_subdomains(domain: str) -> list[dict]:
    """Query crt.sh for certificates / subdomains of a domain (great for enumeration)."""
    return _run(crtsh.subdomains_for(domain))


@mcp.tool()
def rdap_domain(domain: str) -> dict:
    """RDAP lookup for a domain (registrar, registrant, dates, nameservers)."""
    return _run(rdap.rdap_domain(domain))


@mcp.tool()
def rdap_ip(ip: str) -> dict:
    """RDAP lookup for an IP (ASN, netname, country, abuse contact)."""
    return _run(rdap.rdap_ip(ip))


@mcp.tool()
def virustotal_domain(domain: str) -> dict:
    """VirusTotal v3 domain report."""
    return _run(virustotal.vt_domain(domain))


@mcp.tool()
def virustotal_ip(ip: str) -> dict:
    """VirusTotal v3 IP report."""
    return _run(virustotal.vt_ip(ip))


@mcp.tool()
def virustotal_file(hash: str) -> dict:
    """VirusTotal v3 file report by md5/sha1/sha256."""
    return _run(virustotal.vt_file(hash))


@mcp.tool()
def virustotal_resolutions_domain(domain: str) -> dict:
    """Historical passive DNS resolutions for a domain (VT)."""
    return _run(virustotal.vt_domain_resolutions(domain))


@mcp.tool()
def virustotal_resolutions_ip(ip: str) -> dict:
    """Historical passive DNS resolutions for an IP (VT) — co-resident domains."""
    return _run(virustotal.vt_ip_resolutions(ip))


@mcp.tool()
def urlscan_search(query: str) -> dict:
    """URLScan.io search. Examples: domain:example.com, ip:1.2.3.4, hash:..."""
    return _run(urlscan.urlscan_search(query))


@mcp.tool()
def onyphe_domain(domain: str) -> dict:
    """Onyphe summary for a domain."""
    return _run(onyphe.onyphe_summary_domain(domain))


@mcp.tool()
def onyphe_ip(ip: str) -> dict:
    """Onyphe summary for an IP."""
    return _run(onyphe.onyphe_summary_ip(ip))


@mcp.tool()
def shodan_host(ip: str) -> dict:
    """Shodan host info (open ports, banners, vulns)."""
    return _run(shodan.shodan_host(ip))


@mcp.tool()
def shodan_search(query: str) -> dict:
    """Shodan search query (e.g. http.favicon.hash:-12345, ssl.cert.serial:..., http.title:...)."""
    return _run(shodan.shodan_search(query))


@mcp.tool()
def otx_domain(domain: str) -> dict:
    """AlienVault OTX domain general report."""
    return _run(otx.otx_domain(domain))


@mcp.tool()
def otx_ip(ip: str) -> dict:
    """AlienVault OTX IP general report."""
    return _run(otx.otx_ip(ip))


@mcp.tool()
def otx_file(hash: str) -> dict:
    """AlienVault OTX file general report."""
    return _run(otx.otx_file(hash))


@mcp.tool()
def threatfox_search(ioc: str) -> dict:
    """ThreatFox (abuse.ch) IOC lookup — links indicators to malware families/campaigns."""
    return _run(threatfox.threatfox_search(ioc))


@mcp.tool()
def wayback(url: str) -> dict:
    """Wayback Machine availability for a URL/domain."""
    return _run(wayback.wayback_snapshots(url))


if __name__ == "__main__":
    mcp.run()
