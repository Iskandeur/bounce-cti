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
async def reverse_dns(ip: str) -> dict:
    """PTR lookup for an IP. Returns {"ip", "hostnames", "count", "_pivot_hints"?}."""
    hostnames = await _src("dns_tools").reverse_dns(ip)
    response = {"ip": ip, "hostnames": hostnames, "count": len(hostnames)}
    return with_hints("reverse_dns", response, ip)


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
async def whois_domain(domain: str) -> dict:
    """Classic WHOIS lookup for a domain via TCP/43 (RFC 3912).

    Complements rdap_domain: returns fields some registries don't yet
    publish over RDAP — abuse contacts on certain ccTLDs, full registrant
    org for thin TLDs after referral, registrar abuse mailbox. Use this
    when rdap_domain returns sparse data or when you need the raw
    registry text for audit purposes. Cached 24h."""
    return with_hints("whois_domain", await _src("whois").whois_domain(domain), domain)


@mcp.tool()
async def whois_ip(ip_or_asn: str) -> dict:
    """Classic WHOIS lookup for an IP address or ASN via TCP/43.

    Accepts ``8.8.8.8``, ``2001:4860::``, or ``AS15169`` / ``15169``.
    Two-hop: IANA refers to the responsible RIR (ARIN/RIPE/APNIC/LACNIC/
    AFRINIC) which holds the allocation record. Yields netname, org,
    country, CIDR, and OrgAbuseEmail. Cached 24h."""
    return with_hints("whois_ip", await _src("whois").whois_ip(ip_or_asn), ip_or_asn)


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
async def malwarebazaar_filename(filename: str, limit: int = 20) -> dict:
    """abuse.ch MalwareBazaar — list samples ever reported with this filename.

    Primary pivot for `executable_name` seeds: the analyst only has the
    filename (no binary, no hash). Each returned entry exposes a sha256_hash
    you can graph as a `hash` node and run the full hash workflow on.
    Response is trimmed per-sample (hash fields, file_name/type, first_seen, signature, tags).
    """
    return await _src("abusech").mb_filename(filename, limit=limit)


@mcp.tool()
async def malwarebazaar_imphash(imphash: str, limit: int = 25) -> dict:
    """abuse.ch MalwareBazaar — list PE samples sharing this import hash.

    One-call cluster expansion for PE loaders: pass the imphash from a sample's
    static analysis (or VT) to recover the sibling family without N manual VT
    queries. Each entry exposes a sha256_hash you can graph as a `hash` node.
    """
    return await _src("abusech").mb_imphash(imphash, limit=limit)


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


@mcp.tool()
async def opencti_lookup_indicator(value: str) -> dict:
    """OpenCTI community knowledge-graph lookup for an IOC (domain / IP / hash /
    URL). Exact-match — no fuzzy substring hits. Returns score, curated labels
    (often malware-family names like "socgholish" / "mintsloader"), and walks
    relationships to surface attribution: linked Malware, IntrusionSet,
    ThreatActor, Campaign, AttackPattern (MITRE ATT&CK). Also includes any
    OpenCTI Reports the IOC belongs to ("OSINT - NSO related domains", etc.).

    Coverage is sparse — many normal IOCs return {"hit": false}. Treat as
    best-effort attribution; do NOT promote labels to add_node tags without
    corroboration from at least one other source. When `hit=true` and
    `relationships[].name` surfaces a named actor or family, call
    opencti_search_actor / virustotal_* / threatfox_search to corroborate.
    """
    return await _src("opencti").lookup_indicator(value)


@mcp.tool()
async def opencti_search_actor(name: str) -> dict:
    """OpenCTI fuzzy search for a threat-actor / intrusion-set by name. Use
    when opencti_lookup_indicator surfaces an actor name (e.g. "TAG-124",
    "APT28") and you want the alias list + description for normalisation
    and cross-referencing in the final report. Returns up to 5 matches with
    aliases, description (capped), first/last seen, labels."""
    return await _src("opencti").search_intrusion_set(name)


@mcp.tool()
async def opencti_search_report(name: str) -> dict:
    """OpenCTI fuzzy search for a report by title. Use when a relationships
    walk surfaces a report name (e.g. "MintsLoader Malware Analysis") and
    you want its description + external_references (links to the source
    analysis on the open web). Returns up to 5 matches."""
    return await _src("opencti").search_report(name)


# ------------------------------------------------------------------ #
# Tier 1 / Tier 2 sources (added 2026-05-21)
# ------------------------------------------------------------------ #


@mcp.tool()
async def dnsdumpster_domain(domain: str) -> dict:
    """DNSDumpster passive subdomain enum + DNS dump for a domain.
    Free 50 req/day. Surfaces subdomains that never landed in CT logs."""
    return with_hints("dnsdumpster_domain",
                       await _src("dnsdumpster").domain_lookup(domain), domain)


@mcp.tool()
async def hackertarget_reverse_ip(ip: str) -> dict:
    """HackerTarget reverse-IP: list of hosts pointing at an IP. Free
    fallback for VirusTotal/Shodan reverse resolutions; works without an
    API key but is throttled to ~50 anonymous queries/day per IP."""
    return with_hints("hackertarget_reverse_ip",
                       await _src("hackertarget").reverse_ip(ip), ip)


@mcp.tool()
async def hackertarget_hosts(domain: str) -> dict:
    """HackerTarget passive subdomain discovery. Returns
    ``sub.domain.tld,1.2.3.4`` lines."""
    return with_hints("hackertarget_hosts",
                       await _src("hackertarget").host_search(domain), domain)


@mcp.tool()
async def hackertarget_geoip(ip: str) -> dict:
    """HackerTarget geoip — fallback for ip_api when the latter is
    unreachable / quota-exhausted."""
    return with_hints("hackertarget_geoip",
                       await _src("hackertarget").geoip(ip), ip)


@mcp.tool()
async def leakix_host(value: str) -> dict:
    """LeakIX aggregate: open ports, software banners, exposed
    databases, leaked secrets, geoip for an IP or domain. Works
    anonymously, richer with a free API key."""
    return with_hints("leakix_host",
                       await _src("leakix").host(value), value)


@mcp.tool()
async def leakix_search(query: str, page: int = 0, scope: str = "leak") -> dict:
    """LeakIX generic search (Lucene). `scope` in {"leak","service"}.
    Use for pivots on a specific software/banner string."""
    return await _src("leakix").search(query, page=page, scope=scope)


@mcp.tool()
async def pulsedive_indicator(value: str) -> dict:
    """Pulsedive lookup for an existing indicator (domain/IP/URL/hash).
    Returns risk score, threat list, and linked threats. 1 req/call."""
    return with_hints("pulsedive_indicator",
                       await _src("pulsedive").indicator(value), value)


@mcp.tool()
async def pulsedive_analyze(value: str, probe: bool = False) -> dict:
    """Pulsedive on-demand scan. ``probe=False`` returns cached/quick
    verdict (1 req); ``probe=True`` schedules an active scan (bulk
    credit). Default false to preserve quota."""
    return await _src("pulsedive").analyze(value, probe=probe)


@mcp.tool()
async def pulsedive_threat(name: str) -> dict:
    """Pulsedive threat profile by name (malware family / actor / campaign)
    + linked indicators."""
    return await _src("pulsedive").threat(name)


@mcp.tool()
async def phishtank_check(url: str) -> dict:
    """PhishTank verdict for a URL. Independent of OpenPhish — useful
    second opinion. Anonymous calls work but are rate-limited."""
    return with_hints("phishtank_check",
                       await _src("phishtank").check_url(url), url)


@mcp.tool()
async def circl_hash_lookup(value: str) -> dict:
    """CIRCL Hashlookup — NSRL + known-good corpus lookup for an MD5,
    SHA-1 or SHA-256 hex hash. A hit (``found=true``, ``source="NSRL"``)
    means the file is a legitimate OS/vendor artefact. The graph layer
    auto-tags the hash node with ``nsrl_known`` and stops further pivots.
    No auth."""
    return with_hints("circl_hash_lookup",
                       await _src("circl_lu").hash_lookup(value), value)


@mcp.tool()
async def circl_cve(cve_id: str) -> dict:
    """CIRCL Vulnerability-Lookup — full CVE record (NVD + CAPEC + CWE +
    CPE). Use to translate a Shodan/Censys banner into a CVE list."""
    return await _src("circl_lu").cve(cve_id)


@mcp.tool()
async def alienvault_reputation(ip: str) -> dict:
    """AlienVault IP reputation feed lookup (mirrored locally, refreshed
    every 6h). A hit corroborates VT/OTX/AbuseIPDB verdicts. No auth."""
    return with_hints("alienvault_reputation",
                       await _src("alienvault_rep").check_ip(ip), ip)


@mcp.tool()
async def censys_host(ip: str) -> dict:
    """Censys host view — services, cert chain, names, location for an IP.
    Free community tier: 250 queries / month."""
    return with_hints("censys_host",
                       await _src("censys").host_view(ip), ip)


@mcp.tool()
async def censys_search(query: str, per_page: int = 25) -> dict:
    """Censys host search. Same query syntax as the web UI. Use for
    pivots on a TLS cert SHA-256, JARM, or banner string."""
    return await _src("censys").host_search(query, per_page=per_page)


@mcp.tool()
async def emailrep_check(email: str) -> dict:
    """EmailRep.io reputation for an email address — useful to grade a
    registrant email surfaced via RDAP/Whoxy. Free: 10/day anonymous,
    250/month authenticated."""
    return with_hints("emailrep_check",
                       await _src("emailrep").check(email), email)


@mcp.tool()
async def username_enumerate(username: str) -> dict:
    """Enumerate public profiles for a username across ~22 well-known platforms
    (dev, social, forum, blog, gaming) — free, no API key, Sherlock-style.
    Only checks whether a *public* profile page exists; fetches no private data.
    Use on a `username` seed or an actor/forum/Telegram handle surfaced mid-
    investigation. Returns found:[{app,category,url}] + an `unknown` list for
    sites that blocked the probe (absence of evidence ≠ evidence of absence) —
    add a node per found profile and link it to the username/handle."""
    return await _src("username_enum").enumerate_username(username)


@mcp.tool()
async def gravatar_email(email: str) -> dict:
    """Look up a public Gravatar profile for an email address (free, no API
    key) — maps MD5(email) to whatever the owner made public: display name,
    preferred username, linked social accounts, personal URLs. Strong email→
    identity pivot. Returns {found, display_name, preferred_username,
    accounts:[{service,username,url}], urls}. `found=False` just means no
    public Gravatar (not that the person doesn't exist) — add a node per
    linked account/username and link it to the email."""
    return await _src("gravatar").lookup_email(email)


@mcp.tool()
async def github_profile(username: str) -> dict:
    """Enrich a GitHub username with its public profile (free, no API key) —
    real name, company, location, bio, blog URL, self-declared Twitter/X
    handle, account age. Strong identity-correlation pivot after a username
    sweep shows a GitHub presence: the blog / twitter_username / company fields
    often link a handle to a person or other accounts. `found=False` just means
    no public GitHub user by that login. Add nodes for the linked
    blog/twitter/email and link them to the username."""
    return await _src("github_profile").lookup_user(username)


@mcp.tool()
async def phone_lookup(number: str) -> dict:
    """Enrich a phone number (offline, no key) — validity, country / region,
    carrier, line type (mobile / fixed-line / VoIP / toll-free / …), timezones,
    and canonical E.164 / international formats, from Google's libphonenumber
    metadata. Supply E.164 (`+countrycode…`). Use it to qualify a phone seed/IOC
    before pivoting: a VoIP / invalid / toll-free line is a strong burner or
    spoofing signal. Set metadata.country / carrier / line_type on the phone node
    and tag `voip_line` / `invalid_number` when applicable."""
    return await _src("phone_enrich").lookup_phone(number)


@mcp.tool()
async def wallet_enrich(address: str) -> dict:
    """Enrich a cryptocurrency wallet with on-chain activity. BTC (bech32 /
    legacy) via blockstream.info (free, no key): balance, total received/sent,
    tx count, recent activity window, and a counterparty sample. ETH (`0x…`)
    via Etherscan (needs ETHERSCAN_API_KEY; degrades to chain-only when absent).
    XMR / unknown formats return non-traceable. This tells a live, high-volume
    ransom/scam wallet apart from a dormant or burner one and surfaces
    counterparty addresses to pivot on — set `metadata.chain` and the
    balance/volume on the wallet node, and add the sampled counterparties as
    `wallet_address` nodes linked with a `transacts_with` edge."""
    return await _src("wallet_enrich").lookup_wallet(address)


@mcp.tool()
async def project_honeypot_check(ip: str) -> dict:
    """Project Honey Pot http:BL DNSBL lookup. Returns threat score
    (0..255, 25+ is bad) and type flags (suspicious/harvester/comment
    spammer). IPv4 only. Free, requires PROJECTHONEYPOT_API_KEY."""
    return with_hints("project_honeypot_check",
                       await _src("project_honeypot").check_ip(ip), ip)


@mcp.tool()
async def tor_exit_check(ip: str) -> dict:
    """Check whether an IP is on the live Tor exit-relay list (refreshed
    every 30 min from the Tor Project). A hit triggers a ``tor_exit``
    defuse tag — passive DNS at a Tor exit represents thousands of
    unrelated victims, not infrastructure."""
    return with_hints("tor_exit_check",
                       await _src("tor_exits").check_ip(ip), ip)


@mcp.tool()
async def dnstwist_permutations(domain: str, registered_only: bool = True,
                                 mxcheck: bool = False) -> dict:
    """Run a local dnstwist scan against ``domain`` to discover typosquat
    / IDN-homoglyph / bitsquat permutations that resolve. ``registered_only``
    (default true) restricts the output to live permutations. Strictly
    passive — dnstwist only queries DNS/WHOIS, never the target itself."""
    return with_hints("dnstwist_permutations",
                       await _src("dnstwist").permutations(
                           domain, registered_only=registered_only,
                           mxcheck=mxcheck),
                       domain)


@mcp.tool()
async def takeover_check(host: str) -> dict:
    """Subdomain-takeover heuristic check — GET the host and inspect the
    body for fingerprints of abandoned cloud services (S3, Azure,
    GitHub Pages, Heroku, Netlify, Fastly, Shopify, Zendesk, ...).
    Passive: only fetches the host's own root page."""
    return with_hints("takeover_check",
                       await _src("takeover").check_host(host), host)


if __name__ == "__main__":
    mcp.run()
