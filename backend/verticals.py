"""Vertical registry — the multi-vertical (CTI / OSINT / DD) abstraction.

The investigation engine (graph store, pivot queue, streaming, autonomy loop,
exports) is generic. What differs per product vertical is a small, well-defined
set of knobs:

  - **seed_types**   : which seed types the vertical accepts
  - **source_pool**  : which MCP source pool is mounted at investigation start
  - **agent_name**   : the name the agent answers to in its system prompt
                       ("You are Bounce-CTI / Bounce-OSINT / Bounce-DD")
  - (later) prompt_block / pivots / defuse / exports

This module is the single place that enumerates verticals and their knobs.
Today only ``cti`` is active and it is wired to be byte-for-byte the existing
behaviour (roadmap invariant 4.4); ``osint`` and ``dd`` will be registered here
as their pools / prompts land in Phases 2 and 3. ``Vertical`` deliberately
references the shared seed registry (``backend/seeds.py``) rather than copying
per-seed-type logic.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import seeds


@dataclass(frozen=True)
class Vertical:
    name: str            # canonical id stored in investigations.vertical
    label: str           # short display label ("CTI")
    agent_name: str      # used by the system-prompt builder ("Bounce-CTI")
    seed_types: tuple[str, ...]   # accepted seed types for this vertical
    source_pool: str     # identifier selecting the MCP source pool


# CTI is wired to the existing behaviour: every known seed type, the full
# ("cti") source pool, and the historical agent name.
CTI = Vertical(
    name="cti",
    label="CTI",
    agent_name="Bounce-CTI",
    seed_types=seeds.KNOWN_SEED_TYPES,
    source_pool="cti",
)

# OSINT / DD are intentionally NOT registered yet — they get added here when
# their source pools and prompt blocks exist (Phases 2 / 3). Until then any
# unknown vertical resolves to CTI so the platform never breaks on bad input.
VERTICALS: dict[str, Vertical] = {
    CTI.name: CTI,
}

DEFAULT_VERTICAL = "cti"
KNOWN_VERTICALS: tuple[str, ...] = tuple(VERTICALS)


# Maps a vertical's source_pool id to the MCP server module that exposes that
# pool's CTI/OSINT/DD source tools. The pool id is also used as the MCP server
# *key*, which determines the tool namespace the agent sees
# (``mcp__<pool>__<tool>``). For CTI this is ``cti`` → ``cti_mcp``, i.e. the
# historical ``mcp__cti__*`` namespace, so the agent's tool whitelist and
# prompts stay valid (roadmap invariant 4.4). New pools (osint/dd) register
# their own module here as they land.
SOURCE_POOL_MODULES: dict[str, str] = {
    "cti": "cti_mcp",
}


def source_pool_module(pool: str) -> str:
    """MCP server module name for a source pool id (defaults to the cti pool)."""
    return SOURCE_POOL_MODULES.get(pool, SOURCE_POOL_MODULES["cti"])


def get_vertical(name: str | None) -> Vertical:
    """Resolve a vertical by name, falling back to CTI for unknown/empty input."""
    return VERTICALS.get((name or "").lower(), CTI)


def is_known(name: str | None) -> bool:
    return (name or "").lower() in VERTICALS


def normalise(name: str | None) -> str:
    """Return a known vertical id, defaulting to ``cti``."""
    return get_vertical(name).name
