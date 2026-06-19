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
    seed_types=("username", "email", "phone", "domain", "wallet_address", "ip"),
    source_pool="cti",          # v1 reuses the CTI pool/namespace (see note above)
    prompt_block=_OSINT_PROMPT_BLOCK,
)

# ── DD (Due Diligence / KYB) ────────────────────────────────────────────────
# First vertical with its OWN source pool (mcp__dd__*, module dd_mcp) — the
# domain (company registries / sanctions / ownership) is disjoint from CTI, and
# this is the product's monetisation boundary. v1 ships GLEIF (company identity +
# Level-2 hierarchy). Two non-negotiable legal rules are baked into the prompt:
# ownership is ESTIMATED (never authoritative UBO/RBE, gated post-CJUE C-37/20),
# and NO adverse-media / criminal-offence inference (GDPR art.10 / art.46 I&L).
_DD_PROMPT_BLOCK = """\
══════════════════════════════════════════════
DUE-DILIGENCE (KYB) LENS — read this AFTER the rules above
══════════════════════════════════════════════
You are operating in Due-Diligence / KYB mode. The graph tools, budget rules and
reporting contract above still apply, but your subject is a LEGAL ENTITY (or its
corporate group), and your job is factual verification, not threat attribution:

- Establish the company's IDENTITY and CORPORATE HIERARCHY from authoritative,
  factual registry data (start with gleif_lookup): legal name, LEI, jurisdiction,
  status, registered address, and the direct/ultimate parent + subsidiaries.
- Graph each entity as a `company` node (metadata.lei / jurisdiction / status)
  and each relationship as a `parent_of` / `subsidiary_of` edge to another
  `company` node. Expand the group up to the ultimate parent and down one level.
- For UK companies, companies_house_lookup adds OFFICERS (directors) and PSC
  (persons with significant control) — graph each as a `person` node
  (`officer_of` / `significant_control_of` edge). PSC is registry-declared
  control, still ESTIMATED ownership (not authoritative UBO).
- SANCTIONS-SCREEN the subject AND every related company AND every person
  (officer/PSC) you graphed (sanctions_screen,
  OFAC/EU/UK). On a hit, tag the node `sanctioned` + record the programme/list/
  ref. A hit is a CANDIDATE match for human review (name collisions are common),
  NOT an automated determination — say so.
- ⚠️ OWNERSHIP IS ESTIMATED. GLEIF Level-2 and any open-source ownership you
  infer are CORPORATE consolidation data, NOT authoritative beneficial ownership.
  Always label it "estimated / inferred ownership" and state in the report that
  it is NOT the official beneficial owner (RBE) and not a substitute for an
  access-gated registry consultation by an obligated entity.
- ⚠️ DO NOT generate adverse-media, criminal, or wrongdoing claims about any
  natural person from open web text in this mode. Stick to factual registry /
  sanctions-list facts. (Adverse-media screening is a separate, legally-gated
  capability and is OUT OF SCOPE here.)
- Benign-by-default: a company is a subject of verification, not a suspect. The
  working_hypothesis should describe the entity, its group structure, and the
  confidence/limits of what open data establishes.
"""

DD = Vertical(
    name="dd",
    label="Due Diligence",
    agent_name="Bounce-DD",
    seed_types=("company",),
    source_pool="dd",           # dedicated pool → mcp__dd__* (module dd_mcp)
    prompt_block=_DD_PROMPT_BLOCK,
)

# Any unknown vertical resolves to CTI so the platform never breaks on bad input.
VERTICALS: dict[str, Vertical] = {
    CTI.name: CTI,
    OSINT.name: OSINT,
    DD.name: DD,
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
    "dd": "dd_mcp",
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
