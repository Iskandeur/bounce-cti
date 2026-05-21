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


async def permutations(domain: str, *, registered_only: bool = True,
                        mxcheck: bool = False) -> dict:
    """Run dnstwist for ``domain``.

    ``registered_only=True`` (default) restricts the output to permutations
    that resolve to at least an A record — keeps the response small and
    actionable. ``mxcheck`` enables an extra MX lookup per candidate (slower
    but catches phish kits that only host mail)."""
    binary = _find_bin()
    if not binary:
        return {"error": "dnstwist binary not on PATH — `pip install dnstwist`"}
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
