"""Sample / script ingestion.

Turns an arbitrary file upload (malware sample, dropper, script) or pasted
command line into investigation seeds.

Two flavours, one entrypoint per caller:

  * ``handle_file_upload(blob, filename)`` — hashes the binary, sniffs its
    container (PE/ELF/Mach-O/script/text/unknown), tries to recover text
    when the file is script-shaped, and returns the seed shape the API
    handler expects.
  * ``handle_text_paste(text)`` — refangs + IOC-extracts a command line or
    script snippet, and emits a ``command_line`` context node so the agent
    can read the raw text in addition to the extracted IOCs.

Neither helper persists the binary on disk. We only ever keep the hashes,
metadata, and (for scripts) up to ``SCRIPT_TEXT_MAX`` of decoded text.
"""
from __future__ import annotations

import hashlib
import re
from typing import Optional

from .pdf_import import extract_iocs


# Max chars of decoded script text retained on the command_line node. Enough
# to cover virtually any one-liner / dropper script (a few thousand chars is
# already huge for a command), capped so a 10 MB "script" can't blow the row.
SCRIPT_TEXT_MAX = 200_000
SCRIPT_PREVIEW = 80                # label-friendly first chars
SAMPLE_MAX_BYTES = 25 * 1024 * 1024   # 25 MB upload ceiling
TEXT_MAX_BYTES   = 200_000             # ~200 KB of pasted command/script
SAMPLE_MAX_SEEDS = 10                  # same fan-out cap as from_pdf

# Magic-byte signatures we care about. The match runs on the first ~16 bytes
# only, so it's cheap.
_MAGIC = [
    ("pe",     b"MZ"),           # Windows PE / DOS stub
    ("elf",    b"\x7fELF"),      # Linux ELF
    ("macho",  b"\xca\xfe\xba\xbe"),  # Mach-O fat binary
    ("macho",  b"\xcf\xfa\xed\xfe"),  # Mach-O 64-bit
    ("macho",  b"\xfe\xed\xfa\xce"),  # Mach-O 32-bit BE
    ("macho",  b"\xfe\xed\xfa\xcf"),  # Mach-O 64-bit BE
    ("zip",    b"PK\x03\x04"),   # zip / docx / xlsx / jar / apk
    ("pdf",    b"%PDF-"),
    ("gzip",   b"\x1f\x8b"),
    ("7z",     b"7z\xbc\xaf\x27\x1c"),
    ("rar",    b"Rar!\x1a\x07"),
    ("class",  b"\xca\xfe\xba\xbe"),  # also JVM .class (collides with Mach-O fat)
]


def hash_blob(blob: bytes) -> dict:
    """Return {sha256, sha1, md5, size} for an arbitrary byte blob."""
    return {
        "sha256": hashlib.sha256(blob).hexdigest(),
        "sha1":   hashlib.sha1(blob).hexdigest(),
        "md5":    hashlib.md5(blob).hexdigest(),
        "size":   len(blob),
    }


def sniff_file_type(blob: bytes, filename: str | None = None) -> str:
    """Best-effort file-type classification.

    Returns one of: ``pe`` | ``elf`` | ``macho`` | ``zip`` | ``pdf`` |
    ``gzip`` | ``7z`` | ``rar`` | ``script`` | ``text`` | ``unknown``.
    A `text`/`script` verdict means the bytes decode cleanly as printable
    UTF-8 (we treat shebang-led blobs and very short snippets as scripts).
    """
    head = blob[:16]
    for kind, sig in _MAGIC:
        if head.startswith(sig):
            return kind
    # Filename-only fallbacks (binary cores often have no magic)
    fname = (filename or "").lower()
    for ext, kind in (
        (".exe", "pe"), (".dll", "pe"), (".sys", "pe"), (".scr", "pe"),
        (".so",  "elf"), (".dylib", "macho"),
        (".ps1", "script"), (".bat", "script"), (".cmd", "script"),
        (".sh",  "script"), (".bash", "script"), (".zsh", "script"),
        (".py",  "script"), (".pl", "script"), (".rb", "script"),
        (".js",  "script"), (".vbs", "script"), (".hta", "script"),
    ):
        if fname.endswith(ext):
            return kind
    # Heuristic text classification
    if _looks_textual(blob):
        if blob[:2] == b"#!" or _has_script_keyword(blob):
            return "script"
        return "text"
    return "unknown"


def _looks_textual(blob: bytes) -> bool:
    """Crude printable-ratio check on the first 8 KiB."""
    if not blob:
        return False
    sample = blob[:8192]
    try:
        text = sample.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        try:
            text = sample.decode("latin-1")
        except UnicodeDecodeError:
            return False
    printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
    return printable / max(len(text), 1) >= 0.85


_SCRIPT_KEYWORDS = re.compile(
    rb"(?i)\b(powershell|cmd\.exe|/bin/(bash|sh)|invoke-expression|iex|"
    rb"downloadstring|curl\s+http|wget\s+http|certutil\s+-urlcache|"
    rb"base64\s+-d|fromBase64String|net\s+user|new-object\s+net\.webclient)\b"
)


def _has_script_keyword(blob: bytes) -> bool:
    return bool(_SCRIPT_KEYWORDS.search(blob[:8192]))


def decode_text(blob: bytes) -> str:
    """Best-effort decode of a binary blob to text. Truncated to SCRIPT_TEXT_MAX."""
    for enc in ("utf-8", "utf-16-le", "utf-16-be", "latin-1"):
        try:
            text = blob.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        text = blob.decode("latin-1", errors="replace")
    if len(text) > SCRIPT_TEXT_MAX:
        text = text[:SCRIPT_TEXT_MAX] + "\n…[truncated]"
    return text


def script_preview(text: str) -> str:
    """A short single-line preview suitable for a node label."""
    first = (text or "").strip().splitlines()[0] if text and text.strip() else ""
    first = re.sub(r"\s+", " ", first).strip()
    if len(first) > SCRIPT_PREVIEW:
        first = first[:SCRIPT_PREVIEW - 1] + "…"
    return first or "<empty>"


def script_node_id(text: str) -> str:
    """Deterministic short ID used as ``value`` on the command_line node.

    The graph store hashes ``(inv, type, value)`` into the canonical node id,
    so we want a value that's both stable (re-uploading the same text merges)
    and short (the value column is shown verbatim in some panels)."""
    return hashlib.sha256((text or "").encode("utf-8", errors="replace")).hexdigest()[:16]


def handle_file_upload(blob: bytes, filename: str | None) -> dict:
    """Hash + classify a binary or script upload.

    Returns:
        {
          "primary":      {type, value, metadata}   # the seed for the investigation
          "extras":       list[{type, value}]       # extracted IOC peer-seeds, if any
          "context_node": dict | None               # optional command_line node payload
          "report_text":  str | None                # passed as report_context to the agent
          "file_type":    str
          "hashes":       {sha256, sha1, md5, size}
        }
    """
    if not blob:
        raise ValueError("empty file")
    hashes = hash_blob(blob)
    file_type = sniff_file_type(blob, filename)

    # Build the seed: always the SHA256 of the file. The hash workflow already
    # has the right pivots (VirusTotal, MalwareBazaar, OTX, …).
    seed_metadata = {
        "file_name": filename or f"sample_{hashes['sha256'][:8]}",
        "file_type": file_type,
        "size":      hashes["size"],
        "sha1":      hashes["sha1"],
        "md5":       hashes["md5"],
        "source_kind": "user_upload",
    }
    primary = {"type": "hash", "value": hashes["sha256"], "metadata": seed_metadata}

    # If the file decodes as text (script / batch / one-liner), preserve the
    # full text on a command_line node and extract IOCs from it.
    context_node: Optional[dict] = None
    extras: list[dict] = []
    report_text: Optional[str] = None
    if file_type in ("script", "text"):
        text = decode_text(blob)
        report_text = text
        context_node = {
            "type": "command_line",
            "value": script_node_id(text),
            "metadata": {
                "text": text,
                "preview": script_preview(text),
                "file_name": filename,
                "file_type": file_type,
                "size_chars": len(text),
                "source_kind": "user_upload",
            },
        }
        for ioc in extract_iocs(text):
            if ioc["type"] == "hash" and ioc["value"].lower() == hashes["sha256"].lower():
                # Skip self-reference if the file content happens to embed its own hash.
                continue
            extras.append(ioc)

    return {
        "primary":      primary,
        "extras":       extras,
        "context_node": context_node,
        "report_text":  report_text,
        "file_type":    file_type,
        "hashes":       hashes,
    }


def handle_text_paste(text: str) -> dict:
    """Refang + extract IOCs from a pasted command line / script.

    Returns the same shape as ``handle_file_upload``. Raises ``ValueError``
    when neither IOCs nor a non-trivial text body can be extracted.

    Behaviour matrix:
      * ≥1 IOC → primary = strongest IOC, extras = the rest. command_line
        context node carries the raw text and metadata.
      * 0 IOCs → primary = the command_line node itself (so the agent has
        SOMETHING to operate on, even if the only signal is the raw text).
    """
    if not text or not text.strip():
        raise ValueError("empty text")
    if len(text.encode("utf-8")) > TEXT_MAX_BYTES:
        raise ValueError(f"text too large (>{TEXT_MAX_BYTES} bytes)")

    iocs = extract_iocs(text)
    node_id = script_node_id(text)
    preview = script_preview(text)
    cmd_metadata = {
        "text": text if len(text) <= SCRIPT_TEXT_MAX else text[:SCRIPT_TEXT_MAX] + "\n…[truncated]",
        "preview": preview,
        "size_chars": len(text),
        "source_kind": "user_paste",
    }

    if iocs:
        primary = {"type": iocs[0]["type"], "value": iocs[0]["value"]}
        extras = iocs[1:]
        context_node = {
            "type": "command_line",
            "value": node_id,
            "metadata": cmd_metadata,
        }
    else:
        # Fallback: no IOCs, only a command_line. Use it as the primary seed
        # so the investigation exists; the agent will have the raw text in
        # report_context to reason about.
        primary = {
            "type": "command_line",
            "value": node_id,
            "metadata": cmd_metadata,
        }
        extras = []
        context_node = None

    return {
        "primary":      primary,
        "extras":       extras,
        "context_node": context_node,
        "report_text":  text,
        "file_type":    "script",
        "hashes":       None,
    }
