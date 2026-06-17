"""Vertical registry — the multi-vertical (CTI / OSINT / DD) abstraction.

The investigation engine (graph store, pivot queue, streaming, autonomy loop,
exports) is generic. What differs per product vertical is a small, well-defined
set of knobs:

  - **seed_types**   : which seed types the vertical accepts
  - **source_pool**  : which MCP source pool is mounted at investigation start
  - **agent_name**   : the name the agent answers to in its system prompt
                       ("You are Bounce-CTI / Bounce-OSINT / Bounce-DD")
  - **prompt_block** : vertical-specific addendum the prompt builder appends to
                       the shared {core} system-prompt template (empty for CTI)
  - (later) pivots / defuse / exports

This module is the single place that enumerates verticals and their knobs.
``cti`` is wired to be byte-for-byte the existing behaviour (roadmap invariant
4.4). ``osint`` (Phase 2, slice 1) is registered as an OSINT *lens*: it reuses
the CTI source pool/namespace for v1 and differs only by agent_name + an OSINT
prompt_block (a dedicated source pool is a later slice). ``dd`` will be
registered when its pool / prompt land (Phase 3). ``Vertical`` deliberately
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
    prompt_block: str = ""  # vertical-specific system-prompt addendum appended
                            # to the shared {core} template by the prompt builder
                            # (empty for CTI → historical prompt byte-for-byte)


# CTI is wired to the existing behaviour: every known seed type, the full
# ("cti") source pool, and the historical agent name.
CTI = Vertical(
    name="cti",
    label="CTI",
    agent_name="Bounce-CTI",
    seed_types=seeds.KNOWN_SEED_TYPES,
    source_pool="cti",
)

# OSINT (Phase 2, slice 1) — the open-source-intelligence lens. Same investigation
# engine and, for v1, the same source pool as CTI (``source_pool="cti"`` → the
# working ``mcp__cti__*`` namespace, so allowedTools / call-counting / the {core}
# prompt stay valid). What differs is the *lens*: the agent_name + an OSINT
# prompt_block that reframes the goal from threat-infrastructure attribution to
# identity / entity footprint correlation. Seed types are the actor/identity
# subset of the registry. A dedicated ``mcp__osint__*`` source pool (people-search
# / breach / social tools) is a later slice — it needs allowedTools + the
# CTI-call counter generalised to be namespace-aware, so it is kept separate.
_OSINT_PROMPT_BLOCK = """\
══════════════════════════════════════════════
OSINT LENS — read this AFTER the rules above
══════════════════════════════════════════════
You are operating in OSINT mode (open-source intelligence), not threat-infra
attribution. The graph tools, budget rules, defuse discipline and reporting
contract above all still apply, but your GOAL is different:

- Map an IDENTITY / ENTITY footprint, not a malware C2 cluster. Pivot to
  correlate accounts, registrant identities, shared infrastructure-of-record
  (registrant email / org / nameservers), and cross-source mentions of the same
  actor or organisation.
- Do NOT assign malicious / c2 / phishing labels unless the evidence is
  explicitly about abuse. Benign-by-default: an entity is a subject of research,
  not a suspect. Over-attribution is a worse failure here than under-coverage.
- Favour the identity-signal sources (reverse-WHOIS, email/registrant reputation,
  passive DNS, certificate transparency for shared registration, urlscan/wayback
  for historical presence) and the community knowledge graph for prior mentions.
- The working_hypothesis should describe WHO/WHAT the footprint belongs to and
  its boundaries (confirmed vs. probable links), not a threat category.
"""

OSINT = Vertical(
    name="osint",
    label="OSINT",
    agent_name="Bounce-OSINT",
    seed_types=("username", "email", "domain", "wallet_address", "ip"),
    source_pool="cti",          # v1 reuses the CTI pool/namespace (see note above)
    prompt_block=_OSINT_PROMPT_BLOCK,
)

# DD (due diligence) is intentionally NOT registered yet — it gets added here when
# its source pool and prompt block exist (Phase 3). Any unknown vertical resolves
# to CTI so the platform never breaks on bad input.
VERTICALS: dict[str, Vertical] = {
    CTI.name: CTI,
    OSINT.name: OSINT,
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
