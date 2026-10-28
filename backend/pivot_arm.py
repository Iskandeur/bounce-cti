"""The mechanical arm of the prospective batch (EVAL_PROTOCOL §4.E, rule 1).

``pivot-1`` is the base rate every other arm is read against: for one seed, run
the mandatory tools of its type (``seeds.mandatory_tools``) on the seed alone,
with NO model, keep what comes back as nodes, and hand it over the way an arm
does. Khalil et al. 2016: a one-hop passive-DNS pivot is already a strong
baseline, so an ``ahead`` count means nothing without it.

What comes back is read mechanically: every string of a tool's answer that is
an IP, a domain, a URL or a file hash becomes a node (keys starting with ``_``
are hints for the agent, not data). Nothing judges them, so none is tagged
malicious. They are then filtered by the SAME neutralisation the exports use:
``defuse_lists.defuse_check`` tags, then ``action_exports._iter_actionable``.

A tool that fails or is missing is reported in ``tools`` (and in the graph's
``metadata``), never turned into an empty answer. Stdlib + the existing tools.
"""
from __future__ import annotations

import ast
import asyncio
import hashlib
import ipaddress
import re

from . import seeds
from .action_exports import _HASH_TYPES, _NETWORK_TYPES, _iter_actionable
from .defuse_lists import defuse_check

ARM = "pivot-1"
TOOL_TIMEOUT_S = 120
MAX_NODES = 300

_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23}$")
_HASH_RE = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")
_URL_RE = re.compile(r"^https?://[^\s\"'<>]+$", re.IGNORECASE)


def parse_call(example: str) -> tuple[str, list, dict]:
    """``tool("a", kw="b")`` → ``("tool", ["a"], {"kw": "b"})``. Literals only."""
    call = ast.parse(example, mode="eval").body
    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
        raise ValueError(f"not a tool call: {example!r}")
    return (call.func.id, [ast.literal_eval(a) for a in call.args],
            {k.arg: ast.literal_eval(k.value) for k in call.keywords if k.arg})


def _classify(s: str) -> tuple[str, str] | None:
    s = s.strip()
    if not s or len(s) > 2048:
        return None
    if _URL_RE.match(s):
        return "url", s
    low = s.lower()
    try:
        ip = ipaddress.ip_address(low)
    except ValueError:
        ip = None
    if ip is not None:
        return ("ip", str(ip)) if ip.is_global else None
    if _HASH_RE.match(low):
        return "hash", low
    if _DOMAIN_RE.match(low.rstrip(".")):
        return "domain", low.rstrip(".")
    return None


def extract(obj, found: dict | None = None) -> dict[tuple[str, str], None]:
    """Every (type, value) a tool answer holds, in first-seen order."""
    found = {} if found is None else found
    if isinstance(obj, str):
        c = _classify(obj)
        if c:
            found.setdefault(c, None)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if not str(k).startswith("_"):
                extract(v, found)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            extract(v, found)
    return found


def _node(ntype: str, value: str, tags: list[str], tool: str | None = None) -> dict:
    nid = hashlib.sha1(f"pivot-1|{ntype}|{value}".encode()).hexdigest()
    return {"id": nid, "type": ntype, "value": value, "tags": tags, "confidence": 0.5,
            "source": tool or "seed", "metadata": {"arm": ARM, "tool": tool} if tool else {"arm": ARM}}


def _defuse_tags(ntype: str, value: str) -> list[str]:
    if ntype not in ("ip", "domain"):
        return []
    return list(defuse_check(ntype, value).get("tags") or [])


async def _call(name: str, args: list, kwargs: dict):
    from .mcp_servers import cti_mcp  # lazy: pulls the whole source pool in
    fn = getattr(cti_mcp, name, None)
    if fn is None:
        raise LookupError(f"tool {name} is not in the cti pool")
    return await asyncio.wait_for(fn(*args, **kwargs), timeout=TOOL_TIMEOUT_S)


async def run(seed_type: str, seed_value: str, *, call=None) -> dict:
    """The arm's ``graph.json`` for one seed, plus ``tools`` (one status each)."""
    plan = seeds.mandatory_tools(seed_type, seed_value)
    if not plan:
        raise ValueError(f"no mandatory tools for seed type {seed_type!r}")
    seed_norm = seed_value.strip().lower().rstrip(".")
    nodes: dict[tuple[str, str], dict] = {}
    seed_node = _node(seed_type, seed_value.strip(), ["seed"])
    tools = []
    for name, example in plan:
        try:
            _, args, kwargs = parse_call(example)
            answer = await (call or _call)(name, args, kwargs)
        except Exception as e:  # noqa: BLE001 — a failed tool is reported, not hidden
            tools.append({"tool": name, "status": "error", "error": f"{type(e).__name__}: {e}"[:300]})
            continue
        got = extract(answer)
        for (t, v) in got:
            if v.lower().rstrip(".") == seed_norm or len(nodes) >= MAX_NODES:
                continue
            nodes.setdefault((t, v), _node(t, v, _defuse_tags(t, v), name))
        tools.append({"tool": name, "status": "ok", "nodes": len(got)})
    all_nodes = [seed_node] + list(nodes.values())
    # The exports' own neutralisation: defused, lead and unverified nodes stay out.
    kept = _iter_actionable(all_nodes, _NETWORK_TYPES | _HASH_TYPES)
    if seed_node["type"] not in (_NETWORK_TYPES | _HASH_TYPES):
        kept = [seed_node] + kept
    dropped = len(all_nodes) - len(kept)
    return {"nodes": kept, "edges": [],
            "metadata": {"arm": ARM, "seed": {"type": seed_type, "value": seed_value},
                         "tools": tools, "neutralised": dropped}}
