"""PDF → IOC extraction.

Reads a CTI report PDF, extracts every plausible IOC (domain, IP, hash,
URL, ASN, JARM), refangs them, and dedupes. Used to bootstrap a graph
from a known report so the analyst gets a head start instead of typing
every IOC by hand.

Heuristics:
- Whole text is refanged before regex matching so `evil[.]com`,
  `hxxps://bad(.)site`, etc. all light up.
- Domains drop common file-extension false positives (`report.pdf`,
  `image.png`) and fragments missing a TLD.
- IPv4s drop reserved / RFC1918 ranges that almost never matter in
  threat reports (`0.0.0.0`, `127.0.0.1`, `10.x`, `192.168.x`, `172.16-31.x`,
  `224.x` etc.).
- Hashes are normalized to lowercase; we keep MD5/SHA1/SHA256 lengths.
- Output is sorted by analytic priority: hash > ip > url > domain > asn
  so the first IOC we hand to the agent is the most actionable.
"""
import re
from io import BytesIO
from .refang import refang


# ── Regex set (loose on purpose; we filter post-match) ─────────────────────
_RE_URL     = re.compile(r"\bhttps?://[^\s\)\]\>\<\"\']+", re.I)
_RE_DOMAIN  = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
_RE_IPV4    = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_SHA256  = re.compile(r"\b[a-fA-F0-9]{64}\b")
_RE_SHA1    = re.compile(r"\b[a-fA-F0-9]{40}\b")
_RE_MD5     = re.compile(r"\b[a-fA-F0-9]{32}\b")
_RE_ASN     = re.compile(r"\b(?:AS|ASN)\s?(\d{1,10})\b", re.I)
_RE_JARM    = re.compile(r"\b[0-9a-fA-F]{62}\b")  # exactly 62 hex chars

# Common file extensions / pseudo-domains that aren't really IOCs.
_FILE_EXT_TLDS = {
    # Documents / images / archives / media
    "pdf", "png", "jpg", "jpeg", "gif", "svg", "webp", "ico",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "md", "rtf",
    "zip", "rar", "7z", "tar", "gz", "bz2",
    "mp3", "mp4", "wav", "avi", "mov", "mkv",
    # Source / config / web — `.css`, `.json`, `.yaml`, etc. aren't TLDs
    "css", "scss", "less", "json", "xml", "yaml", "yml", "log",
    "html", "htm", "asp", "aspx", "php", "jsp", "jsx",
    "ttf", "otf", "woff", "woff2",
    # Binaries / scripts that show up as filenames in CTI reports
    # (`payload.exe`, `loader.dll`, `installer.msi`, `script.bat`, …).
    # Country TLDs that overlap with extensions (.sh / Saint Helena,
    # .je / Jersey, .gg / Guernsey, .ai, .io) are deliberately NOT here.
    "exe", "dll", "sys", "msi", "bin", "dat", "ocx", "drv", "sqlite", "db",
    "bat", "cmd", "ps1", "vbs", "py", "pl", "rb", "lua", "jar",
}

# TLDs we accept (small allowlist of structural patterns: 2-24 chars, alpha).
# Better is letting any TLD through and rejecting file-extension TLDs.

# Boilerplate / template domains that appear in CTI reports as examples or
# in the report's own footer / template, never as actionable IOCs.
_BOILERPLATE_DOMAINS = {
    "example.com", "example.org", "example.net",
    "domain.com", "test.com", "localhost.localdomain",
    "schema.org", "w3.org", "creativecommons.org",
}


def _is_routable_ipv4(s: str) -> bool:
    """Drop RFC1918 / loopback / multicast / reserved ranges."""
    try:
        a, b, c, d = (int(x) for x in s.split("."))
    except ValueError:
        return False
    if not all(0 <= x <= 255 for x in (a, b, c, d)):
        return False
    if a == 0 or a == 127 or a >= 224:                # 0.x, loopback, multicast/reserved
        return False
    if a == 10:                                       # RFC1918
        return False
    if a == 172 and 16 <= b <= 31:                    # RFC1918
        return False
    if a == 192 and b == 168:                         # RFC1918
        return False
    if a == 169 and b == 254:                         # link-local
        return False
    if a == 100 and 64 <= b <= 127:                   # CGNAT
        return False
    return True


def _looks_like_filename(domain: str) -> bool:
    parts = domain.lower().rsplit(".", 1)
    if len(parts) != 2:
        return True
    return parts[1] in _FILE_EXT_TLDS


def extract_text(pdf_bytes: bytes) -> str:
    """Read a PDF blob and return concatenated page text. Empty on parse error."""
    try:
        from pypdf import PdfReader
    except ImportError as e:
        raise RuntimeError(f"pypdf not installed: {e}")
    reader = PdfReader(BytesIO(pdf_bytes))
    pages = []
    for p in reader.pages:
        try:
            pages.append(p.extract_text() or "")
        except Exception:
            # Some pages have weird embedded fonts; skip silently.
            continue
    return "\n".join(pages)


def extract_iocs(text: str, max_per_type: int = 100) -> list[dict]:
    """Return [{type, value}, ...] in analytic-priority order, deduped.

    `max_per_type` caps each category so a single PDF can't blow up the
    investigation queue (defensive — agent rate-limits would catch it later).
    """
    if not text:
        return []
    refanged = refang(text)

    seen_lower: set[str] = set()
    by_type: dict[str, list[str]] = {
        "hash": [], "ip": [], "url": [], "domain": [], "asn": [], "jarm": [],
    }

    def push(kind: str, value: str):
        v = value.strip()
        key = f"{kind}|{v.lower()}"
        if not v or key in seen_lower:
            return
        if len(by_type[kind]) >= max_per_type:
            return
        seen_lower.add(key)
        by_type[kind].append(v)

    # Hashes (longest first so we don't double-count an SHA256 also matching
    # SHA1/MD5 prefixes).
    for m in _RE_SHA256.findall(refanged):
        push("hash", m.lower())
    # JARM is also 62 hex; keep distinct.
    for m in _RE_JARM.findall(refanged):
        push("jarm", m.lower())
    for m in _RE_SHA1.findall(refanged):
        push("hash", m.lower())
    for m in _RE_MD5.findall(refanged):
        push("hash", m.lower())

    # IPs
    for m in _RE_IPV4.findall(refanged):
        if _is_routable_ipv4(m):
            push("ip", m)

    # URLs
    for m in _RE_URL.findall(refanged):
        v = m.rstrip(".,;:!?'\"()[]<>")
        push("url", v)

    # ASNs
    for m in _RE_ASN.findall(refanged):
        push("asn", f"AS{m}")

    # Domains (last so URL hosts are already captured, but we also want bare
    # domains that appear without a scheme).
    for m in _RE_DOMAIN.findall(refanged):
        v = m.lower().strip(".")
        if v in _BOILERPLATE_DOMAINS:
            continue
        if _looks_like_filename(v):
            continue
        if len(v) < 4:
            continue
        push("domain", v)

    # Priority order: hashes first (most actionable), then IPs, URLs,
    # domains, ASN, JARM (rarest).
    out = []
    for kind in ("hash", "ip", "url", "domain", "asn", "jarm"):
        for v in by_type[kind]:
            out.append({"type": kind, "value": v})
    return out
