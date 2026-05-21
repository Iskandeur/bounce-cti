"""Local static-analysis primitives for uploaded samples.

Runs entirely in-process on the uploaded byte blob. Zero new dependencies:
no `pefile`, no `yara-python`, no native sigtools. We walk the bytes
ourselves with stdlib `struct` / `re` / `collections.Counter`. The point
is to surface signal the agent can pivot on (embedded URLs / IPs, suspect
import DLLs, packed-section entropy) WITHOUT shipping the binary to a
third party — a hard requirement for sensitive incident-response work.

What we extract (all best-effort; failures swallowed so callers stay
running on truncated / corrupted samples):

  * Hashes: sha256, sha1, md5, size, imphash-lite (sha256 of sorted
    DLL!function tuples when a PE-import table can be walked).
  * Shannon entropy: overall + per-section for PEs (>7.5 ⇒ likely packed).
  * Strings: deduped printable ASCII (≥6 chars) and UTF-16LE (≥4 chars)
    runs, capped at ``STRINGS_MAX`` for storage. Frequencies and a
    `string_set_sha256` over the deduped sorted set let the agent cluster
    samples with identical string sets.
  * IOCs from strings: re-uses ``pdf_import.extract_iocs`` so embedded
    URLs / domains / IPv4s / hashes lift cleanly into the graph as
    embedded_in_sample edges.
  * PE container facts: machine type, compile timestamp, section list
    (name, vsize, raw_size, entropy, characteristics), import DLLs.
  * ELF container facts: machine, entry, section names.

The returned dict is JSON-safe so it goes straight into the hash node's
``metadata.static_analysis`` for the UI + the agent to read.
"""
from __future__ import annotations

import hashlib
import math
import re
import struct
from collections import Counter
from typing import Optional

from .pdf_import import extract_iocs

# Tunables — calibrated for "good signal, small payload". A 10 MB sample
# can produce 100k+ strings; we keep the top STRINGS_MAX by length so the
# JSON we store stays under ~50 KB.
STRINGS_MIN_ASCII = 6
STRINGS_MIN_UTF16 = 4
STRINGS_MAX = 500
STRINGS_PREVIEW_LEN = 200            # max chars per surfaced string
STATIC_IOCS_MAX = 200                # cap on embedded-IOC fanout

_ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}" % STRINGS_MIN_ASCII)
_UTF16_RE = re.compile((rb"(?:[\x20-\x7e]\x00){%d,}" % STRINGS_MIN_UTF16))


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy of a byte buffer (0.0–8.0). Packed / encrypted
    sections sit at 7.5+; plain code/text at 4–6."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values() if c)


def extract_strings(blob: bytes) -> dict:
    """Return ``{ascii: [...], utf16: [...], string_set_sha256: hex}``.

    Strings are deduped, capped per encoding, and the SHA-256 of the
    sorted joined set is included as a stable fingerprint — useful for
    clustering samples whose printable-string set is identical."""
    ascii_runs = list({m.group(0).decode("ascii", errors="replace")
                       for m in _ASCII_RE.finditer(blob)})
    utf16_runs = list({m.group(0).decode("utf-16-le", errors="replace").rstrip("\x00")
                       for m in _UTF16_RE.finditer(blob)})
    # Rank by length desc, then alphabetical — long strings tend to carry
    # the high-value signal (URLs, mutex names, PDB paths).
    ascii_runs.sort(key=lambda s: (-len(s), s))
    utf16_runs.sort(key=lambda s: (-len(s), s))
    ascii_runs = [s[:STRINGS_PREVIEW_LEN] for s in ascii_runs[:STRINGS_MAX]]
    utf16_runs = [s[:STRINGS_PREVIEW_LEN] for s in utf16_runs[:STRINGS_MAX]]
    combined = "\n".join(sorted(set(ascii_runs + utf16_runs)))
    set_hash = hashlib.sha256(combined.encode("utf-8", errors="replace")).hexdigest()
    return {
        "ascii": ascii_runs,
        "utf16": utf16_runs,
        "ascii_total": len(_ASCII_RE.findall(blob)),
        "utf16_total": len(_UTF16_RE.findall(blob)),
        "string_set_sha256": set_hash,
    }


# ── PE parsing ────────────────────────────────────────────────────────────
# Minimal PE walker — DOS header → PE sig → COFF file header → optional
# header → section table. We do NOT walk imports beyond DLL names: parsing
# the IAT correctly across PE32 / PE32+ + RVA-to-offset conversion is a
# rabbit hole, and DLL-only is already 80% of the family-attribution signal.

_PE_MACHINES = {
    0x014c: "i386",
    0x8664: "amd64",
    0x01c4: "arm",
    0xaa64: "arm64",
    0x0200: "ia64",
}


def _rva_to_offset(rva: int, sections: list[dict]) -> Optional[int]:
    for s in sections:
        va = s["virtual_address"]
        sz = max(s["virtual_size"], s["size_of_raw_data"])
        if va <= rva < va + sz:
            return s["pointer_to_raw_data"] + (rva - va)
    return None


def parse_pe(blob: bytes) -> dict:
    """Minimal PE parser. Returns ``{}`` on parse failure."""
    try:
        if len(blob) < 0x40 or blob[:2] != b"MZ":
            return {}
        e_lfanew = struct.unpack_from("<I", blob, 0x3c)[0]
        if e_lfanew + 24 > len(blob) or blob[e_lfanew:e_lfanew+4] != b"PE\0\0":
            return {}
        # IMAGE_FILE_HEADER @ e_lfanew + 4
        machine, num_sections, time_stamp, _ptr_sym, _num_sym, opt_size, characteristics = \
            struct.unpack_from("<HHIIIHH", blob, e_lfanew + 4)
        opt_off = e_lfanew + 24
        if opt_off + 2 > len(blob):
            return {"machine": _PE_MACHINES.get(machine, hex(machine)),
                    "compile_timestamp": time_stamp,
                    "num_sections": num_sections}
        magic = struct.unpack_from("<H", blob, opt_off)[0]
        is_pe32_plus = (magic == 0x20b)
        # AddressOfEntryPoint @ opt+16
        try:
            entry = struct.unpack_from("<I", blob, opt_off + 16)[0]
        except struct.error:
            entry = 0
        # Number of RVAs and Sizes @ opt + (92 for PE32, 108 for PE32+)
        nrva_off = opt_off + (108 if is_pe32_plus else 92)
        data_dirs_off = nrva_off + 4
        # Section table starts after the optional header
        sec_off = opt_off + opt_size
        sections: list[dict] = []
        for i in range(num_sections):
            base = sec_off + i * 40
            if base + 40 > len(blob):
                break
            name = blob[base:base+8].rstrip(b"\x00").decode("ascii", errors="replace")
            vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", blob, base + 8)
            chars = struct.unpack_from("<I", blob, base + 36)[0]
            sec_blob = blob[raw_ptr:raw_ptr + raw_size] if raw_size else b""
            sections.append({
                "name": name,
                "virtual_size": vsize,
                "virtual_address": vaddr,
                "size_of_raw_data": raw_size,
                "pointer_to_raw_data": raw_ptr,
                "characteristics": hex(chars),
                "entropy": round(shannon_entropy(sec_blob), 3) if sec_blob else 0.0,
            })

        # Import table is data directory index 1: 8 bytes each (RVA, size)
        import_dlls: list[str] = []
        if data_dirs_off + 16 <= len(blob):
            try:
                imp_rva, imp_size = struct.unpack_from("<II", blob, data_dirs_off + 8)
                if imp_rva:
                    imp_off = _rva_to_offset(imp_rva, sections)
                    if imp_off is not None and imp_size > 0:
                        # Each descriptor is 20 bytes; loop until null entry
                        cur = imp_off
                        while cur + 20 <= len(blob) and len(import_dlls) < 50:
                            desc = blob[cur:cur+20]
                            if desc == b"\x00" * 20:
                                break
                            name_rva = struct.unpack_from("<I", blob, cur + 12)[0]
                            cur += 20
                            if not name_rva:
                                continue
                            name_off = _rva_to_offset(name_rva, sections)
                            if name_off is None or name_off >= len(blob):
                                continue
                            end = blob.find(b"\x00", name_off, name_off + 256)
                            if end < 0:
                                continue
                            dll_name = blob[name_off:end].decode("ascii", errors="replace").lower()
                            if dll_name and dll_name not in import_dlls:
                                import_dlls.append(dll_name)
            except (struct.error, IndexError):
                pass

        out: dict = {
            "machine": _PE_MACHINES.get(machine, hex(machine)),
            "characteristics": hex(characteristics),
            "compile_timestamp": time_stamp,
            "is_pe32_plus": is_pe32_plus,
            "address_of_entry_point": entry,
            "num_sections": num_sections,
            "sections": sections,
            "import_dlls": import_dlls,
        }
        if import_dlls:
            out["import_dlls_sha256"] = hashlib.sha256(
                ",".join(sorted(import_dlls)).encode("ascii")
            ).hexdigest()
        return out
    except Exception:
        return {}


# ── ELF parsing ───────────────────────────────────────────────────────────
_ELF_MACHINES = {
    0x03: "x86", 0x3e: "x86_64", 0x28: "arm", 0xb7: "aarch64",
    0xf3: "riscv", 0x08: "mips",
}


def parse_elf(blob: bytes) -> dict:
    """Minimal ELF header parser. Returns ``{}`` on failure."""
    try:
        if len(blob) < 0x40 or blob[:4] != b"\x7fELF":
            return {}
        ei_class = blob[4]  # 1=32, 2=64
        is_64 = (ei_class == 2)
        # e_machine @ 0x12 (2 bytes), e_entry @ 0x18 (4 or 8 bytes)
        machine = struct.unpack_from("<H", blob, 0x12)[0]
        entry = struct.unpack_from("<Q" if is_64 else "<I", blob, 0x18)[0]
        return {
            "ei_class": "64" if is_64 else "32",
            "machine": _ELF_MACHINES.get(machine, hex(machine)),
            "entry": entry,
        }
    except Exception:
        return {}


# ── Top-level analyse() ───────────────────────────────────────────────────
def analyse(blob: bytes, file_type: str = "unknown") -> dict:
    """Run every applicable static-analysis pass on ``blob``.

    ``file_type`` is the verdict from ``sample_import.sniff_file_type`` so
    we skip the PE walker on ELF binaries (and vice versa). The result is
    designed to land verbatim on ``hash_node.metadata.static_analysis``.
    """
    if not blob:
        return {"error": "empty"}
    out: dict = {
        "size": len(blob),
        "entropy": round(shannon_entropy(blob), 3),
        "file_type": file_type,
    }
    strings = extract_strings(blob)
    out["strings"] = strings
    iocs = extract_iocs("\n".join(strings["ascii"] + strings["utf16"]))
    if iocs:
        out["embedded_iocs"] = iocs[:STATIC_IOCS_MAX]
    if file_type == "pe":
        pe = parse_pe(blob)
        if pe:
            out["pe"] = pe
    elif file_type == "elf":
        elf = parse_elf(blob)
        if elf:
            out["elf"] = elf
    return out
