"""DNSTwist — local typosquat / IDN-homoglyph permutation engine.

Invoked as a subprocess (`dnstwist --format json --registered <domain>`)
so the Python entry-point version doesn't matter. ``--registered`` filters
the permutation list down to *only* those that resolve to A/MX records —
i.e. likely live phishing/typosquat infrastructure, not theoretical
permutations.

Strictly passive: dnstwist only performs DNS resolution + WHOIS lookups
on the generated permutations; it does not touch the target domain itself.
"""
from __future__ import annotations

import asyncio
import json
import shutil

from ..graph_store import cache_get, cache_set

_BIN_CANDIDATES = ("dnstwist",)


def _find_bin() -> str | None:
    for name in _BIN_CANDIDATES:
        path = shutil.which(name)
        if path:
            return path
    return None


# Homoglyph / common-typo substitution map for the pure-Python fallback.
_HOMOGLYPHS = {
    "o": "0", "0": "o", "l": "1", "1": "l", "i": "1", "e": "3",
    "a": "4", "s": "5", "b": "8", "g": "9",
}
_COMMON_TLDS = (
    "com", "net", "org", "info", "co", "io", "shop", "top", "xyz", "online",
    "cc", "icu", "vip", "live", "store", "site", "click", "app",
)


def _builtin_permutations(domain: str, *, cap: int = 60) -> dict:
    """Pure-Python typo/homoglyph/TLD-swap permutation generator used when the
    dnstwist binary is unavailable on the host. Produces CANDIDATE permutations
    only — it does NOT resolve them (unlike ``dnstwist --registered``), so every
    entry is flagged ``resolved=False``. Honest fallback so the pivot degrades
    to 'here are the campaign-keyword candidates' instead of silently failing.

    Strictly passive: pure string generation, no network I/O at all.
    """
    d = (domain or "").strip().lower().strip(".")
    if "." not in d:
        return {"error": "invalid domain", "results": [], "count": 0}
    label, _, tld = d.partition(".")
    cands: set[str] = set()
    for i in range(len(label)):                       # omission
        cands.add(label[:i] + label[i + 1:] + "." + tld)
    for i in range(len(label)):                       # repetition
        cands.add(label[:i + 1] + label[i] + label[i + 1:] + "." + tld)
    for i in range(len(label) - 1):                   # transposition
        cands.add(label[:i] + label[i + 1] + label[i] + label[i + 2:] + "." + tld)
    for i, ch in enumerate(label):                    # homoglyph / typo
        if ch in _HOMOGLYPHS:
            cands.add(label[:i] + _HOMOGLYPHS[ch] + label[i + 1:] + "." + tld)
    for i in range(1, len(label)):                    # hyphen insertion
        cands.add(label[:i] + "-" + label[i:] + "." + tld)
    for t in _COMMON_TLDS:                             # TLD swap
        if t != tld:
            cands.add(label + "." + t)
    cands.discard(d)
    results = [{"domain": c, "fuzzer": "builtin", "resolved": False}
               for c in sorted(cands)[:cap]]
    return {
        "domain": d,
        "engine": "builtin_fallback",
        "note": ("dnstwist binary unavailable — returning UNRESOLVED candidate "
                 "permutations (string-generated, not DNS-verified). Pivot the "
                 "promising ones via dns_resolve / rdap / virustotal_domain to "
                 "confirm which are live."),
        "results": results,
        "count": len(results),
    }


async def permutations(domain: str, *, registered_only: bool = True,
                        mxcheck: bool = False) -> dict:
    """Run dnstwist for ``domain``.

    ``registered_only=True`` (default) restricts the output to permutations
    that resolve to at least an A record — keeps the response small and
    actionable. ``mxcheck`` enables an extra MX lookup per candidate (slower
    but catches phish kits that only host mail)."""
    binary = _find_bin()
    if not binary:
        # Degrade to the pure-Python generator instead of failing the pivot.
        return _builtin_permutations(domain)
    cache_key = f"dnstwist|{domain}|reg={registered_only}|mx={mxcheck}"
    cached = cache_get(cache_key, ttl=6 * 3600)
    if cached is not None:
        return cached
    args = [binary, "--format", "json"]
    if registered_only:
        args.append("--registered")
    if mxcheck:
        args.append("--mxcheck")
    args.append(domain)
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return {"error": "dnstwist timed out after 180s"}
    if proc.returncode != 0:
        return {
            "error": f"dnstwist exited {proc.returncode}",
            "stderr": (stderr or b"").decode(errors="replace")[:2000],
        }
    try:
        results = json.loads(stdout.decode(errors="replace") or "[]")
    except json.JSONDecodeError:
        return {"error": "dnstwist returned non-JSON output",
                 "stdout": stdout[:2000].decode(errors="replace")}
    out = {"domain": domain, "results": results, "count": len(results)}
    cache_set(cache_key, out)
    return out
